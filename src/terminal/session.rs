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

use super::{auth, pty::Shell};

// Protocol, version 2:
//   server -> client: MAGIC, 32-byte nonce
//   client -> server: 64-byte Ed25519 signature over (context, server IP, nonce)
//   server -> client: one status byte (ACCEPTED, REJECTED or SERVER_FAILURE)
//   after ACCEPTED, client -> server: frames [kind: u8][length: u16 LE][payload]
//                   server -> client: raw terminal output
// Frames are parsed only after the signature has been verified.

pub const MAGIC: &[u8; 8] = b"TNETPTY2";
pub const REJECTED: u8 = 0;
pub const ACCEPTED: u8 = 1;
pub const SERVER_FAILURE: u8 = 2;

const FRAME_DATA: u8 = 0;
const FRAME_RESIZE: u8 = 1;
const FRAME_HANGUP: u8 = 2;
const FRAME_HEADER_LEN: usize = 3;
pub const MAX_FRAME_PAYLOAD: usize = 4096;

const AUTH_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a finished session waits for the peer to close after all output was acknowledged.
const CLOSE_TIMEOUT: Duration = Duration::from_secs(10);
/// Upper bound for a finished session, even if the peer stops acknowledging output.
const FINISH_TIMEOUT: Duration = Duration::from_secs(60);
/// Received but not yet decoded client bytes are capped to keep backpressure on the socket.
const MAX_INBOUND_BUFFER: usize = 2 * (FRAME_HEADER_LEN + MAX_FRAME_PAYLOAD);

#[derive(Debug, PartialEq, Eq)]
pub enum Frame {
    /// Keyboard or piped input for the shell.
    Data(Vec<u8>),
    /// The client's visible console size in character cells.
    Resize { columns: u16, rows: u16 },
    /// The client's input ended; the session should end now.
    Hangup,
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
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownFrame(kind) => write!(f, "unknown frame type {kind}"),
            Self::BadLength { kind, length } => {
                write!(f, "invalid length {length} for frame type {kind}")
            }
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
        let Some(&[kind, low, high]) = self.buffer.get(..FRAME_HEADER_LEN) else {
            return Ok(None);
        };
        let length = usize::from(u16::from_le_bytes([low, high]));
        let valid = match kind {
            FRAME_DATA => length <= MAX_FRAME_PAYLOAD,
            FRAME_RESIZE => length == 4,
            FRAME_HANGUP => length == 0,
            _ => return Err(ProtocolError::UnknownFrame(kind)),
        };
        if !valid {
            return Err(ProtocolError::BadLength { kind, length });
        }
        if self.buffer.len() < FRAME_HEADER_LEN + length {
            return Ok(None);
        }
        let payload: Vec<u8> = self
            .buffer
            .drain(..FRAME_HEADER_LEN + length)
            .skip(FRAME_HEADER_LEN)
            .collect();
        Ok(Some(match kind {
            FRAME_DATA => Frame::Data(payload),
            FRAME_RESIZE => Frame::Resize {
                columns: u16::from_le_bytes([payload[0], payload[1]]),
                rows: u16::from_le_bytes([payload[2], payload[3]]),
            },
            _ => Frame::Hangup,
        }))
    }
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
    AwaitingShell,
    Active {
        shell: Shell,
        exited: Option<Instant>,
    },
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
            if matches!(self.state, State::Active { .. }) {
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
                            self.state = State::AwaitingShell;
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
            State::Active { .. } => {
                if let Some(end) = self.poll_active(socket) {
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
    fn waits_for_complete_frames() {
        let mut decoder = FrameDecoder::default();
        decoder.extend(&[FRAME_DATA, 3, 0, b'a']);
        assert_eq!(decoder.next_frame(), Ok(None));
        decoder.extend(b"bc");
        assert_eq!(decoder.next_frame(), Ok(Some(Frame::Data(b"abc".to_vec()))));
    }
}
