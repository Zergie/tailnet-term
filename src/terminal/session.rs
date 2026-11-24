use std::{
    error::Error,
    fmt,
    net::Ipv4Addr,
    path::PathBuf,
    sync::mpsc::TryRecvError,
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use smoltcp::socket::tcp::Socket;

use super::{auth, exec::Exec, pty::Shell};

// Protocol, version 3:
//   server -> client: MAGIC, 32-byte nonce
//   client -> server: 64-byte Ed25519 signature over (context, server IP, nonce)
//   client -> server: one request frame: SHELL (interactive) or EXEC (UTF-8 command)
//   server -> client: one status byte (ACCEPTED, REJECTED or SERVER_FAILURE)
// Frames are [kind: u8][length: u16 LE][payload]. After ACCEPTED:
//   SHELL: client -> server: DATA, RESIZE and HANGUP frames
//          server -> client: raw terminal output
//   EXEC:  client -> server: nothing (closing the connection ends the command)
//          server -> client: STDOUT and STDERR frames, then one EXIT frame (u32 LE)
// Frames are parsed only after the signature has been verified.

pub const MAGIC: &[u8; 8] = b"TNETPTY3";
pub const REJECTED: u8 = 0;
pub const ACCEPTED: u8 = 1;
pub const SERVER_FAILURE: u8 = 2;

const FRAME_DATA: u8 = 0;
const FRAME_RESIZE: u8 = 1;
const FRAME_HANGUP: u8 = 2;
const FRAME_SHELL: u8 = 3;
const FRAME_EXEC: u8 = 4;
const OUTPUT_STDOUT: u8 = 0;
const OUTPUT_STDERR: u8 = 1;
const OUTPUT_EXIT: u8 = 2;
const FRAME_HEADER_LEN: usize = 3;
pub const MAX_FRAME_PAYLOAD: usize = 4096;
/// Longest remote command in UTF-8 bytes. Its Base64 form travels in an environment variable,
/// which stays well below the Windows limit of 32767 characters.
pub const MAX_COMMAND_LEN: usize = 8192;

const AUTH_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a finished session waits for the peer to close after all output was acknowledged.
const CLOSE_TIMEOUT: Duration = Duration::from_secs(10);
/// Upper bound for a finished session, even if the peer stops acknowledging output.
const FINISH_TIMEOUT: Duration = Duration::from_secs(60);
/// Received but not yet decoded client bytes are capped to keep backpressure on the socket.
const MAX_INBOUND_BUFFER: usize = 2 * (FRAME_HEADER_LEN + MAX_COMMAND_LEN);

#[derive(Debug, PartialEq, Eq)]
pub enum Frame {
    /// Keyboard or piped input for the shell.
    Data(Vec<u8>),
    /// The client's visible console size in character cells.
    Resize { columns: u16, rows: u16 },
    /// The client's input ended; the session should end now.
    Hangup,
    /// Request: start an interactive shell.
    Shell,
    /// Request: run one command non-interactively and report its exit code.
    Exec(String),
}

impl Frame {
    pub fn encode(&self, output: &mut Vec<u8>) {
        match self {
            Self::Data(bytes) => encode_data(bytes, output),
            Self::Resize { columns, rows } => {
                push_header(output, FRAME_RESIZE, 4);
                output.extend_from_slice(&columns.to_le_bytes());
                output.extend_from_slice(&rows.to_le_bytes());
            }
            Self::Hangup => push_header(output, FRAME_HANGUP, 0),
            Self::Shell => push_header(output, FRAME_SHELL, 0),
            Self::Exec(command) => {
                push_header(output, FRAME_EXEC, command.len());
                output.extend_from_slice(command.as_bytes());
            }
        }
    }
}

/// What the server sends in exec mode.
#[derive(Debug, PartialEq, Eq)]
pub enum Output {
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
    Exit(u32),
}

impl Output {
    pub fn encode(&self, output: &mut Vec<u8>) {
        let (kind, bytes) = match self {
            Self::Stdout(bytes) => (OUTPUT_STDOUT, bytes),
            Self::Stderr(bytes) => (OUTPUT_STDERR, bytes),
            Self::Exit(code) => {
                push_header(output, OUTPUT_EXIT, 4);
                output.extend_from_slice(&code.to_le_bytes());
                return;
            }
        };
        for chunk in bytes.chunks(MAX_FRAME_PAYLOAD) {
            push_header(output, kind, chunk.len());
            output.extend_from_slice(chunk);
        }
    }
}

/// Appends data frames for `bytes`, split at `MAX_FRAME_PAYLOAD`.
pub fn encode_data(bytes: &[u8], output: &mut Vec<u8>) {
    for chunk in bytes.chunks(MAX_FRAME_PAYLOAD) {
        push_header(output, FRAME_DATA, chunk.len());
        output.extend_from_slice(chunk);
    }
}

fn push_header(output: &mut Vec<u8>, kind: u8, length: usize) {
    let length = u16::try_from(length).expect("frame payload fits in u16");
    output.push(kind);
    output.extend_from_slice(&length.to_le_bytes());
}

#[derive(Debug, PartialEq, Eq)]
pub enum ProtocolError {
    UnknownFrame(u8),
    BadLength { kind: u8, length: usize },
    BadCommand,
    UnexpectedFrame,
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownFrame(kind) => write!(f, "unknown frame type {kind}"),
            Self::BadLength { kind, length } => {
                write!(f, "invalid length {length} for frame type {kind}")
            }
            Self::BadCommand => write!(f, "the command is not valid UTF-8"),
            Self::UnexpectedFrame => write!(f, "frame not allowed in this session state"),
        }
    }
}

impl Error for ProtocolError {}

/// Incremental decoder for client frames; input may be split anywhere.
#[derive(Default)]
pub struct FrameDecoder {
    buffer: Vec<u8>,
}

impl FrameDecoder {
    pub fn extend(&mut self, bytes: &[u8]) {
        self.buffer.extend_from_slice(bytes);
    }

    pub fn buffered(&self) -> usize {
        self.buffer.len()
    }

    pub fn clear(&mut self) {
        self.buffer.clear();
    }

    pub fn next_frame(&mut self) -> Result<Option<Frame>, ProtocolError> {
        let Some((kind, payload)) = take_frame(&mut self.buffer, |kind, length| match kind {
            FRAME_DATA => Some(length <= MAX_FRAME_PAYLOAD),
            FRAME_RESIZE => Some(length == 4),
            FRAME_HANGUP | FRAME_SHELL => Some(length == 0),
            FRAME_EXEC => Some(length <= MAX_COMMAND_LEN),
            _ => None,
        })?
        else {
            return Ok(None);
        };
        Ok(Some(match kind {
            FRAME_DATA => Frame::Data(payload),
            FRAME_RESIZE => Frame::Resize {
                columns: u16::from_le_bytes([payload[0], payload[1]]),
                rows: u16::from_le_bytes([payload[2], payload[3]]),
            },
            FRAME_HANGUP => Frame::Hangup,
            FRAME_SHELL => Frame::Shell,
            _ => Frame::Exec(String::from_utf8(payload).map_err(|_| ProtocolError::BadCommand)?),
        }))
    }
}

/// Incremental decoder for exec-mode server output; input may be split anywhere.
#[derive(Default)]
pub struct OutputDecoder {
    buffer: Vec<u8>,
}

impl OutputDecoder {
    pub fn extend(&mut self, bytes: &[u8]) {
        self.buffer.extend_from_slice(bytes);
    }

    pub fn next_output(&mut self) -> Result<Option<Output>, ProtocolError> {
        let Some((kind, payload)) = take_frame(&mut self.buffer, |kind, length| match kind {
            OUTPUT_STDOUT | OUTPUT_STDERR => Some(length <= MAX_FRAME_PAYLOAD),
            OUTPUT_EXIT => Some(length == 4),
            _ => None,
        })?
        else {
            return Ok(None);
        };
        Ok(Some(match kind {
            OUTPUT_STDOUT => Output::Stdout(payload),
            OUTPUT_STDERR => Output::Stderr(payload),
            _ => Output::Exit(u32::from_le_bytes([
                payload[0], payload[1], payload[2], payload[3],
            ])),
        }))
    }
}

/// Removes one complete frame from `buffer`. `valid` returns `None` for an unknown kind, and
/// otherwise whether the length is allowed for it.
fn take_frame(
    buffer: &mut Vec<u8>,
    valid: impl FnOnce(u8, usize) -> Option<bool>,
) -> Result<Option<(u8, Vec<u8>)>, ProtocolError> {
    let Some(&[kind, low, high]) = buffer.get(..FRAME_HEADER_LEN) else {
        return Ok(None);
    };
    let length = usize::from(u16::from_le_bytes([low, high]));
    match valid(kind, length) {
        None => return Err(ProtocolError::UnknownFrame(kind)),
        Some(false) => return Err(ProtocolError::BadLength { kind, length }),
        Some(true) => {}
    }
    if buffer.len() < FRAME_HEADER_LEN + length {
        return Ok(None);
    }
    let payload = buffer
        .drain(..FRAME_HEADER_LEN + length)
        .skip(FRAME_HEADER_LEN)
        .collect();
    Ok(Some((kind, payload)))
}

pub struct TerminalSession {
    peer_key: auth::PublicKey,
    program: PathBuf,
    local_ip: Ipv4Addr,
    state: State,
    prepared: Option<JoinHandle<Result<Shell, String>>>,
    pending_output: Vec<u8>,
    pending_input: Option<Vec<u8>>,
    inbound: FrameDecoder,
}

enum State {
    Waiting,
    Authenticating {
        sent: Instant,
        challenge: auth::Challenge,
        proof: Vec<u8>,
    },
    /// Authenticated; waiting for the SHELL or EXEC request.
    AwaitingRequest {
        sent: Instant,
    },
    AwaitingShell,
    AwaitingExec(JoinHandle<Result<Exec, String>>),
    Active {
        shell: Shell,
        exited: Option<Instant>,
    },
    Executing(Exec),
    Finished {
        since: Instant,
    },
}

/// How a session ends.
enum End {
    /// Send the remaining output, then close with FIN.
    Close,
    /// Discard pending output and reset the connection.
    Abort,
}

impl TerminalSession {
    pub fn new(peer_key: auth::PublicKey, program: PathBuf, local_ip: Ipv4Addr) -> Self {
        let prepared = Some(prepare_shell(program.clone()));
        Self {
            peer_key,
            program,
            local_ip,
            state: State::Waiting,
            prepared,
            pending_output: Vec::new(),
            pending_input: None,
            inbound: FrameDecoder::default(),
        }
    }

    /// Advances the session. Returns `Ok(true)` once the connection is closed and the caller
    /// should listen again and call `reset`. Per-session failures are logged and end the
    /// session; they never surface as `Err`.
    pub fn poll(&mut self, socket: &mut Socket<'_>) -> Result<bool, Box<dyn Error>> {
        if !socket.is_open() {
            if matches!(self.state, State::Active { .. } | State::Executing(_)) {
                eprintln!("Terminal connection closed");
            }
            // Dropping an active shell here kills its process tree.
            self.state = State::Finished {
                since: Instant::now(),
            };
            return Ok(true);
        }
        match &mut self.state {
            State::Waiting if socket.may_send() && socket.may_recv() => match auth::challenge() {
                Ok(challenge) => {
                    self.pending_output.extend_from_slice(MAGIC);
                    self.pending_output.extend_from_slice(&challenge);
                    self.state = State::Authenticating {
                        sent: Instant::now(),
                        challenge,
                        proof: Vec::new(),
                    };
                }
                Err(error) => {
                    eprintln!("Terminal challenge generation failed: {error}");
                    self.finish(socket, End::Abort);
                }
            },
            State::Waiting => {}
            State::Authenticating {
                sent,
                challenge,
                proof,
            } => {
                if sent.elapsed() >= AUTH_TIMEOUT || !socket.may_recv() {
                    eprintln!("Client authentication timed out or disconnected");
                    self.finish(socket, End::Close);
                } else if socket.can_recv() {
                    let mut chunk = [0; auth::SIGNATURE_LEN];
                    let needed = auth::SIGNATURE_LEN - proof.len();
                    match socket.recv_slice(&mut chunk[..needed]) {
                        Ok(count) => proof.extend_from_slice(&chunk[..count]),
                        Err(error) => {
                            eprintln!("Terminal receive failed: {error}");
                            self.finish(socket, End::Abort);
                            return Ok(false);
                        }
                    }
                    if proof.len() == auth::SIGNATURE_LEN {
                        if auth::verify(&self.peer_key, self.local_ip, challenge, proof) {
                            self.state = State::AwaitingRequest {
                                sent: Instant::now(),
                            };
                        } else {
                            eprintln!("Client key rejected");
                            self.pending_output.push(REJECTED);
                            self.finish(socket, End::Close);
                        }
                    }
                }
            }
            State::AwaitingShell => {
                if !socket.may_send() {
                    eprintln!("Client disconnected before PowerShell was ready");
                    self.finish(socket, End::Close);
                } else if self.prepared.as_ref().is_some_and(JoinHandle::is_finished) {
                    let prepared = self.prepared.take().expect("prepared shell task exists");
                    match prepared.join() {
                        Ok(Ok(shell)) => {
                            self.pending_output.push(ACCEPTED);
                            self.state = State::Active {
                                shell,
                                exited: None,
                            };
                            eprintln!("Client key accepted; prepared PowerShell assigned");
                        }
                        Ok(Err(error)) => {
                            eprintln!("PowerShell could not be started: {error}");
                            self.pending_output.push(SERVER_FAILURE);
                            self.finish(socket, End::Close);
                        }
                        Err(_) => {
                            eprintln!("PowerShell preparation thread panicked");
                            self.pending_output.push(SERVER_FAILURE);
                            self.finish(socket, End::Close);
                        }
                    }
                } else if self.prepared.is_none() {
                    // Not expected: `new` and `reset` always prepare a shell.
                    self.prepared = Some(prepare_shell(self.program.clone()));
                }
            }
            State::AwaitingRequest { sent } => {
                if sent.elapsed() >= AUTH_TIMEOUT || !socket.may_recv() {
                    eprintln!("Client request timed out or client disconnected");
                    self.finish(socket, End::Close);
                } else if let Some(end) = self.poll_request(socket) {
                    self.finish(socket, end);
                }
            }
            State::AwaitingExec(spawning) => {
                if !socket.may_send() {
                    eprintln!("Client disconnected before the command started");
                    self.finish(socket, End::Close);
                } else if spawning.is_finished() {
                    let State::AwaitingExec(spawning) =
                        std::mem::replace(&mut self.state, State::AwaitingShell)
                    else {
                        unreachable!("matched above");
                    };
                    match spawning.join() {
                        Ok(Ok(exec)) => {
                            self.pending_output.push(ACCEPTED);
                            self.state = State::Executing(exec);
                            eprintln!("Client key accepted; running a command");
                        }
                        Ok(Err(error)) => {
                            eprintln!("The command could not be started: {error}");
                            self.pending_output.push(SERVER_FAILURE);
                            self.finish(socket, End::Close);
                        }
                        Err(_) => {
                            eprintln!("Command start thread panicked");
                            self.pending_output.push(SERVER_FAILURE);
                            self.finish(socket, End::Close);
                        }
                    }
                }
            }
            State::Active { .. } => {
                if let Some(end) = self.poll_active(socket) {
                    self.finish(socket, end);
                }
            }
            State::Executing(_) => {
                if let Some(end) = self.poll_exec(socket) {
                    self.finish(socket, end);
                }
            }
            State::Finished { .. } => {}
        }
        if !self.pending_output.is_empty() && socket.can_send() {
            match socket.send_slice(&self.pending_output) {
                Ok(count) => {
                    self.pending_output.drain(..count);
                }
                Err(error) => {
                    eprintln!("Terminal send failed: {error}");
                    self.finish(socket, End::Abort);
                }
            }
        }
        if let State::Finished { since } = self.state {
            if !socket.may_send() {
                // The peer can no longer receive anything we still hold.
                self.pending_output.clear();
            }
            if self.pending_output.is_empty() && socket.may_send() {
                socket.close();
            }
            let idle = self.pending_output.is_empty() && socket.send_queue() == 0;
            if socket.is_open()
                && ((idle && since.elapsed() >= CLOSE_TIMEOUT) || since.elapsed() >= FINISH_TIMEOUT)
            {
                // Report completion on the next poll so the reset segment is dispatched before
                // the caller re-arms the listener.
                socket.abort();
            }
        }
        Ok(false)
    }

    /// Relays one round of input and output. Returns how to end the session, if it should end.
    fn poll_active(&mut self, socket: &mut Socket<'_>) -> Option<End> {
        let State::Active { shell, exited } = &mut self.state else {
            return None;
        };
        if !socket.may_send() {
            eprintln!("Client stopped receiving terminal output");
            return Some(End::Close);
        }
        if exited.is_none() {
            match shell.exited() {
                Ok(true) => *exited = Some(Instant::now()),
                Ok(false) => {}
                Err(error) => {
                    eprintln!("PowerShell status check failed: {error}");
                    return Some(End::Close);
                }
            }
        }
        if exited.is_none() {
            if self.inbound.buffered() < MAX_INBOUND_BUFFER && socket.can_recv() {
                let mut bytes = [0; 2048];
                let room = (MAX_INBOUND_BUFFER - self.inbound.buffered()).min(bytes.len());
                match socket.recv_slice(&mut bytes[..room]) {
                    Ok(count) => self.inbound.extend(&bytes[..count]),
                    Err(error) => {
                        eprintln!("Terminal receive failed: {error}");
                        return Some(End::Abort);
                    }
                }
            }
            loop {
                if let Some(bytes) = self.pending_input.take() {
                    match shell.input(bytes) {
                        Ok(None) => {}
                        Ok(Some(bytes)) => {
                            self.pending_input = Some(bytes);
                            break;
                        }
                        Err(error) => {
                            eprintln!("{error}");
                            return Some(End::Close);
                        }
                    }
                }
                match self.inbound.next_frame() {
                    Ok(Some(Frame::Data(bytes))) => {
                        if !bytes.is_empty() {
                            self.pending_input = Some(bytes);
                        }
                    }
                    Ok(Some(Frame::Resize { columns, rows })) => {
                        if let Err(error) = shell.resize(columns, rows) {
                            eprintln!("Terminal resize to {columns}x{rows} failed: {error}");
                        }
                    }
                    Ok(Some(Frame::Hangup)) => {
                        eprintln!("Client input ended");
                        return Some(End::Close);
                    }
                    Ok(Some(Frame::Shell | Frame::Exec(_))) => {
                        eprintln!(
                            "Terminal protocol error: {}",
                            ProtocolError::UnexpectedFrame
                        );
                        return Some(End::Abort);
                    }
                    Ok(None) => break,
                    Err(error) => {
                        eprintln!("Terminal protocol error: {error}");
                        return Some(End::Abort);
                    }
                }
            }
            if !socket.may_recv() && self.pending_input.is_none() {
                // The client sent FIN (or vanished after one) and everything it sent was
                // delivered: end the session rather than keep an idle shell holding the slot.
                eprintln!("Client closed its input");
                return Some(End::Close);
            }
        }
        if self.pending_output.is_empty() {
            match shell.output() {
                Ok(Some(bytes)) => self.pending_output = bytes,
                Ok(None)
                    if exited
                        .is_some_and(|exited| exited.elapsed() >= Duration::from_millis(250)) =>
                {
                    return Some(End::Close);
                }
                Ok(None) => {}
                Err(TryRecvError::Disconnected) => return Some(End::Close),
                Err(TryRecvError::Empty) => unreachable!(),
            }
        }
        None
    }

    /// Reads the client's SHELL or EXEC request. Returns how to end the session, if it should end.
    fn poll_request(&mut self, socket: &mut Socket<'_>) -> Option<End> {
        if let Err(end) = self.receive(socket) {
            return Some(end);
        }
        match self.inbound.next_frame() {
            Ok(None) => None,
            Ok(Some(Frame::Shell)) => {
                self.state = State::AwaitingShell;
                None
            }
            Ok(Some(Frame::Exec(command))) => {
                let program = self.program.clone();
                self.state = State::AwaitingExec(thread::spawn(move || {
                    Exec::spawn(&program, &command).map_err(|error| error.to_string())
                }));
                None
            }
            Ok(Some(_)) => {
                eprintln!(
                    "Terminal protocol error: {}",
                    ProtocolError::UnexpectedFrame
                );
                Some(End::Abort)
            }
            Err(error) => {
                eprintln!("Terminal protocol error: {error}");
                Some(End::Abort)
            }
        }
    }

    /// Relays a command's output and exit code. The client sends nothing in exec mode; anything
    /// it does send is discarded so the connection keeps its receive window.
    fn poll_exec(&mut self, socket: &mut Socket<'_>) -> Option<End> {
        if !socket.may_send() {
            eprintln!("Client stopped receiving command output");
            return Some(End::Close);
        }
        while socket.can_recv() {
            let mut discard = [0; 2048];
            if let Err(error) = socket.recv_slice(&mut discard) {
                eprintln!("Terminal receive failed: {error}");
                return Some(End::Abort);
            }
        }
        if !socket.may_recv() {
            // The client never half-closes in exec mode: a FIN means it was stopped.
            eprintln!("Client closed the connection; stopping the command");
            return Some(End::Close);
        }
        let State::Executing(exec) = &mut self.state else {
            return None;
        };
        while self.pending_output.len() < MAX_FRAME_PAYLOAD {
            match exec.poll() {
                Ok(Some(output)) => {
                    output.encode(&mut self.pending_output);
                    if let Output::Exit(code) = output {
                        eprintln!("Command exited with code {code}");
                        return Some(End::Close);
                    }
                }
                Ok(None) => break,
                Err(error) => {
                    eprintln!("Command status check failed: {error}");
                    return Some(End::Close);
                }
            }
        }
        None
    }

    /// Moves received client bytes into the frame decoder, keeping it bounded.
    fn receive(&mut self, socket: &mut Socket<'_>) -> Result<(), End> {
        if self.inbound.buffered() < MAX_INBOUND_BUFFER && socket.can_recv() {
            let mut bytes = [0; 2048];
            let room = (MAX_INBOUND_BUFFER - self.inbound.buffered()).min(bytes.len());
            match socket.recv_slice(&mut bytes[..room]) {
                Ok(count) => self.inbound.extend(&bytes[..count]),
                Err(error) => {
                    eprintln!("Terminal receive failed: {error}");
                    return Err(End::Abort);
                }
            }
        }
        Ok(())
    }

    /// Ends the session: drops the shell (killing its process tree) and starts closing the
    /// connection.
    fn finish(&mut self, socket: &mut Socket<'_>, end: End) {
        self.state = State::Finished {
            since: Instant::now(),
        };
        self.pending_input = None;
        self.inbound.clear();
        if matches!(end, End::Abort) {
            self.pending_output.clear();
            socket.abort();
        }
    }

    pub fn reset(&mut self) {
        self.state = State::Waiting;
        self.pending_output.clear();
        self.pending_input = None;
        self.inbound.clear();
        if self.prepared.is_none() {
            self.prepared = Some(prepare_shell(self.program.clone()));
        }
    }
}

impl Drop for TerminalSession {
    fn drop(&mut self) {
        if let Some(prepared) = self.prepared.take() {
            // Drop the unused shell before the server exits so its child is reaped.
            let _ = prepared.join();
        }
    }
}

fn prepare_shell(program: PathBuf) -> JoinHandle<Result<Shell, String>> {
    thread::spawn(move || Shell::spawn(&program).map_err(|error| error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encoded(frames: &[Frame]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for frame in frames {
            frame.encode(&mut bytes);
        }
        bytes
    }

    #[test]
    fn decodes_frames_split_at_every_byte() {
        let frames = [
            Frame::Resize {
                columns: 120,
                rows: 40,
            },
            Frame::Data(b"dir\r\x03\x1a".to_vec()),
            Frame::Resize {
                columns: 1,
                rows: u16::MAX,
            },
            Frame::Hangup,
            Frame::Shell,
            Frame::Exec("Get-Item 'C:\\ä'; exit 3".to_owned()),
        ];
        let bytes = encoded(&frames);
        let mut decoder = FrameDecoder::default();
        let mut decoded = Vec::new();
        for byte in bytes {
            decoder.extend(&[byte]);
            while let Some(frame) = decoder.next_frame().unwrap() {
                decoded.push(frame);
            }
        }
        assert_eq!(decoded, frames);
        assert_eq!(decoder.buffered(), 0);
    }

    #[test]
    fn splits_large_input_into_bounded_frames() {
        let input: Vec<u8> = (0..=255).cycle().take(MAX_FRAME_PAYLOAD * 2 + 5).collect();
        let mut bytes = Vec::new();
        encode_data(&input, &mut bytes);
        let mut decoder = FrameDecoder::default();
        decoder.extend(&bytes);
        let mut joined = Vec::new();
        let mut count = 0;
        while let Some(frame) = decoder.next_frame().unwrap() {
            let Frame::Data(chunk) = frame else {
                panic!("unexpected frame")
            };
            assert!(chunk.len() <= MAX_FRAME_PAYLOAD);
            joined.extend(chunk);
            count += 1;
        }
        assert_eq!(count, 3);
        assert_eq!(joined, input);
    }

    #[test]
    fn rejects_malformed_frames() {
        let mut decoder = FrameDecoder::default();
        decoder.extend(&[9, 0, 0]);
        assert_eq!(decoder.next_frame(), Err(ProtocolError::UnknownFrame(9)));

        let mut decoder = FrameDecoder::default();
        decoder.extend(&[FRAME_RESIZE, 3, 0, 1, 2, 3]);
        assert_eq!(
            decoder.next_frame(),
            Err(ProtocolError::BadLength {
                kind: FRAME_RESIZE,
                length: 3
            })
        );

        let mut decoder = FrameDecoder::default();
        let oversized = u16::try_from(MAX_FRAME_PAYLOAD + 1).unwrap().to_le_bytes();
        decoder.extend(&[FRAME_DATA, oversized[0], oversized[1]]);
        assert!(matches!(
            decoder.next_frame(),
            Err(ProtocolError::BadLength { .. })
        ));

        let mut decoder = FrameDecoder::default();
        decoder.extend(&[FRAME_HANGUP, 1, 0, 0]);
        assert!(decoder.next_frame().is_err());
    }

    #[test]
    fn decodes_exec_output_split_at_every_byte() {
        let large: Vec<u8> = (0..=255).cycle().take(MAX_FRAME_PAYLOAD + 7).collect();
        let mut bytes = Vec::new();
        for output in [
            Output::Stdout(b"out\r\n".to_vec()),
            Output::Stderr(large.clone()),
            Output::Exit(0xC000_013A),
        ] {
            output.encode(&mut bytes);
        }
        let mut decoder = OutputDecoder::default();
        let mut decoded = Vec::new();
        for byte in bytes {
            decoder.extend(&[byte]);
            while let Some(output) = decoder.next_output().unwrap() {
                decoded.push(output);
            }
        }
        assert_eq!(
            decoded,
            [
                Output::Stdout(b"out\r\n".to_vec()),
                Output::Stderr(large[..MAX_FRAME_PAYLOAD].to_vec()),
                Output::Stderr(large[MAX_FRAME_PAYLOAD..].to_vec()),
                Output::Exit(0xC000_013A),
            ]
        );
    }

    #[test]
    fn rejects_oversized_or_invalid_commands() {
        let mut decoder = FrameDecoder::default();
        let oversized = u16::try_from(MAX_COMMAND_LEN + 1).unwrap().to_le_bytes();
        decoder.extend(&[FRAME_EXEC, oversized[0], oversized[1]]);
        assert!(matches!(
            decoder.next_frame(),
            Err(ProtocolError::BadLength { .. })
        ));

        let mut decoder = FrameDecoder::default();
        decoder.extend(&[FRAME_EXEC, 1, 0, 0xFF]);
        assert_eq!(decoder.next_frame(), Err(ProtocolError::BadCommand));

        let mut decoder = OutputDecoder::default();
        decoder.extend(&[OUTPUT_EXIT, 3, 0]);
        assert!(decoder.next_output().is_err());
    }

    #[test]
    fn waits_for_complete_frames() {
        let mut decoder = FrameDecoder::default();
        decoder.extend(&[FRAME_DATA, 3, 0, b'a']);
        assert_eq!(decoder.next_frame(), Ok(None));
        decoder.extend(b"bc");
        assert_eq!(decoder.next_frame(), Ok(Some(Frame::Data(b"abc".to_vec()))));
    }
}

/// Drives `TerminalSession` over two smoltcp stacks, with a real PowerShell for exec requests.
#[cfg(test)]
mod loopback_tests {
    use super::*;
    use crate::tcp_probe::{PacketDevice, interface, server_socket, tcp_socket};
    use auth::Challenge;
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use smoltcp::{
        iface::{Interface, SocketHandle, SocketSet},
        time::Instant as TcpTime,
        wire::IpAddress,
    };

    const SERVER_IP: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 2);
    const PORT: u16 = 7681;

    struct Loopback {
        start: Instant,
        client_device: PacketDevice,
        server_device: PacketDevice,
        client: Interface,
        server: Interface,
        client_sockets: SocketSet<'static>,
        server_sockets: SocketSet<'static>,
        client_handle: SocketHandle,
        server_handle: SocketHandle,
        session: TerminalSession,
        key: Ed25519KeyPair,
        received: Vec<u8>,
    }

    impl Loopback {
        fn new() -> Self {
            let root = std::env::var_os("SystemRoot").unwrap();
            let shell =
                std::path::Path::new(&root).join(r"System32\WindowsPowerShell\v1.0\powershell.exe");
            let key = Ed25519KeyPair::from_seed_unchecked(&[9; 32]).unwrap();
            let public = key.public_key().as_ref().try_into().unwrap();
            let mut client_device = PacketDevice::default();
            let mut server_device = PacketDevice::default();
            let client = interface(&mut client_device, Ipv4Addr::new(100, 64, 0, 1), 24);
            let server = interface(&mut server_device, SERVER_IP, 24);
            let mut server_sockets = SocketSet::new(vec![]);
            let mut listener = server_socket();
            listener.listen(PORT).unwrap();
            let server_handle = server_sockets.add(listener);
            let mut loopback = Self {
                start: Instant::now(),
                client_device,
                server_device,
                client,
                server,
                client_sockets: SocketSet::new(vec![]),
                server_sockets,
                client_handle: SocketHandle::default(),
                server_handle,
                session: TerminalSession::new(public, shell, SERVER_IP),
                key,
                received: Vec::new(),
            };
            loopback.connect(49152);
            loopback
        }

        fn connect(&mut self, local_port: u16) {
            let mut connector = tcp_socket();
            connector
                .connect(
                    self.client.context(),
                    (IpAddress::Ipv4(SERVER_IP), PORT),
                    local_port,
                )
                .unwrap();
            self.client_sockets = SocketSet::new(vec![]);
            self.client_handle = self.client_sockets.add(connector);
            self.received.clear();
        }

        fn client_socket(&mut self) -> &mut Socket<'static> {
            self.client_sockets.get_mut::<Socket>(self.client_handle)
        }

        /// One round of both stacks and the session, re-arming the listener like the server.
        fn step(&mut self) {
            let now = TcpTime::from_millis(self.start.elapsed().as_millis() as i64);
            self.client
                .poll(now, &mut self.client_device, &mut self.client_sockets);
            self.server_device
                .incoming
                .extend(self.client_device.outgoing.drain(..));
            self.server
                .poll(now, &mut self.server_device, &mut self.server_sockets);
            self.client_device
                .incoming
                .extend(self.server_device.outgoing.drain(..));
            let socket = self.server_sockets.get_mut::<Socket>(self.server_handle);
            if !socket.is_open() {
                self.session.reset();
                socket.listen(PORT).unwrap();
            }
            self.session.poll(socket).unwrap();
            let client = self.client_sockets.get_mut::<Socket>(self.client_handle);
            while client.can_recv() {
                let mut buffer = [0; 2048];
                let count = client.recv_slice(&mut buffer).unwrap();
                self.received.extend_from_slice(&buffer[..count]);
            }
            thread::sleep(Duration::from_millis(1));
        }

        /// Steps until `done` holds, failing after 30 s.
        fn until(&mut self, mut done: impl FnMut(&mut Self) -> bool) {
            let deadline = Instant::now() + Duration::from_secs(30);
            while !done(self) {
                assert!(
                    Instant::now() < deadline,
                    "timed out: received {:?}, client {}",
                    self.received.clone(),
                    self.client_sockets
                        .get::<Socket>(self.client_handle)
                        .state()
                );
                self.step();
            }
        }

        /// Authenticates with `request` and returns the status byte.
        fn open(&mut self, request: Frame) -> u8 {
            let challenge_len = MAGIC.len() + 32;
            self.until(|this| this.received.len() >= challenge_len);
            assert_eq!(&self.received[..MAGIC.len()], MAGIC);
            let nonce: Challenge = self.received[MAGIC.len()..challenge_len]
                .try_into()
                .unwrap();
            let mut hello = auth::sign(&self.key, SERVER_IP, &nonce).to_vec();
            request.encode(&mut hello);
            self.client_socket().send_slice(&hello).unwrap();
            self.until(|this| this.received.len() > challenge_len);
            self.received.drain(..challenge_len);
            self.received.remove(0)
        }

        /// Decodes everything received in exec mode, up to and including the exit code.
        fn outputs(&self) -> (Vec<u8>, Option<u32>) {
            let mut decoder = OutputDecoder::default();
            decoder.extend(&self.received);
            let mut stdout = Vec::new();
            while let Some(output) = decoder.next_output().unwrap() {
                match output {
                    Output::Stdout(bytes) => stdout.extend(bytes),
                    Output::Stderr(_) => {}
                    Output::Exit(code) => return (stdout, Some(code)),
                }
            }
            (stdout, None)
        }
    }

    #[test]
    fn runs_commands_back_to_back_and_closes() {
        let mut loopback = Loopback::new();
        assert_eq!(loopback.open(Frame::Exec("'one'; exit 4".into())), ACCEPTED);
        loopback.until(|this| this.outputs().1.is_some() && !this.client_socket().may_recv());
        assert_eq!(loopback.outputs(), (b"one\r\n".to_vec(), Some(4)));
        loopback.client_socket().close();
        loopback.until(|this| !this.client_socket().is_open());
        loopback.connect(49153);
        assert_eq!(loopback.open(Frame::Exec("'two'".into())), ACCEPTED);
        loopback.until(|this| this.outputs().1.is_some());
        assert_eq!(loopback.outputs(), (b"two\r\n".to_vec(), Some(0)));
    }

    #[test]
    fn client_close_stops_a_running_command() {
        let mut loopback = Loopback::new();
        assert_eq!(
            loopback.open(Frame::Exec("'started'; Start-Sleep 60".into())),
            ACCEPTED
        );
        loopback.until(|this| !this.outputs().0.is_empty());
        let started = Instant::now();
        loopback.client_socket().close();
        loopback
            .until(|this| matches!(this.session.state, State::Finished { .. } | State::Waiting));
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[test]
    fn accepts_an_interactive_request() {
        // Under the test harness the prepared "shell" is this test binary, which exits at once;
        // only the handshake order is checked here.
        let mut loopback = Loopback::new();
        assert_eq!(loopback.open(Frame::Shell), ACCEPTED);
    }
}
