use std::{
    error::Error,
    io::{self, IsTerminal, Read, Write},
    net::{Ipv4Addr, Shutdown, SocketAddrV4, TcpStream},
    path::Path,
    ptr::null,
    sync::{
        Arc, Mutex,
        mpsc::{self, Receiver, RecvTimeoutError},
    },
    thread,
    time::{Duration, Instant},
};

use windows_sys::Win32::{
    Foundation::HANDLE,
    System::Console::{
        CONSOLE_SCREEN_BUFFER_INFO, ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT, ENABLE_PROCESSED_INPUT,
        ENABLE_VIRTUAL_TERMINAL_INPUT, ENABLE_VIRTUAL_TERMINAL_PROCESSING, GetConsoleMode,
        GetConsoleScreenBufferInfo, GetStdHandle, ReadConsoleW, STD_INPUT_HANDLE,
        STD_OUTPUT_HANDLE, SetConsoleMode,
    },
};

use super::{
    auth,
    session::{self, ACCEPTED, Frame, MAGIC, REJECTED, SERVER_FAILURE},
};

const RESIZE_POLL_INTERVAL: Duration = Duration::from_millis(250);

/// Exit code when the connection ends without the command's exit code (as ssh uses 255).
pub const CONNECTION_LOST: u32 = 255;

/// Runs `command` on the server and returns its exit code, or opens an interactive session
/// when `command` is `None` and returns 0.
pub fn run(
    target: Ipv4Addr,
    key_file: &Path,
    command: Option<String>,
) -> Result<u32, Box<dyn Error>> {
    match command {
        Some(command) => {
            if command.len() > session::MAX_COMMAND_LEN {
                return Err(format!(
                    "the command is longer than {} bytes",
                    session::MAX_COMMAND_LEN
                )
                .into());
            }
            let (stream, _) = connect(target, key_file, &Frame::Exec(command))?;
            execute(stream)
        }
        None => interactive(target, key_file).map(|()| 0),
    }
}

/// Relays exec-mode output. Standard input is never read and the connection is never
/// half-closed: the server treats a closed connection as cancellation.
fn execute(mut stream: TcpStream) -> Result<u32, Box<dyn Error>> {
    let mut decoder = session::OutputDecoder::default();
    let mut stdout = io::stdout().lock();
    let mut stderr = io::stderr().lock();
    let mut buffer = [0; 8192];
    loop {
        let count = match stream.read(&mut buffer) {
            Ok(0) => {
                eprintln!("Error: connection closed before the command finished");
                return Ok(CONNECTION_LOST);
            }
            Ok(count) => count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => {
                eprintln!("Error: {error}");
                return Ok(CONNECTION_LOST);
            }
        };
        decoder.extend(&buffer[..count]);
        while let Some(output) = decoder.next_output()? {
            match output {
                session::Output::Stdout(bytes) => {
                    stdout.write_all(&bytes)?;
                    stdout.flush()?;
                }
                session::Output::Stderr(bytes) => {
                    stderr.write_all(&bytes)?;
                    stderr.flush()?;
                }
                session::Output::Exit(code) => return Ok(code),
            }
        }
    }
}

/// Connects, authenticates and sends `request`. Returns the stream once the server accepted.
fn connect(
    target: Ipv4Addr,
    key_file: &Path,
    request: &Frame,
) -> Result<(TcpStream, Instant), Box<dyn Error>> {
    if target.octets()[0] != 100 || !(64..=127).contains(&target.octets()[1]) {
        return Err("server must be a Tailnet IPv4 address in 100.64.0.0/10".into());
    }
    let key = auth::load_key(key_file)?;
    let address = SocketAddrV4::new(target, crate::echo::PORT).into();
    let timing = std::env::var_os("TS_TERMINAL_TIMING").is_some();
    let started = Instant::now();
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(10))?;
    let connected = Instant::now();
    if timing {
        eprintln!("TCP connected: {} ms", (connected - started).as_millis());
    }
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    let mut handshake = [0; MAGIC.len() + 32];
    stream.read_exact(&mut handshake)?;
    if handshake[..MAGIC.len()] != *MAGIC {
        return Err("server did not send a compatible terminal challenge".into());
    }
    let nonce = handshake[MAGIC.len()..].try_into()?;
    let mut hello = auth::sign(&key, target, &nonce).to_vec();
    request.encode(&mut hello);
    stream.write_all(&hello)?;
    let mut status = [0];
    stream.read_exact(&mut status)?;
    match status[0] {
        ACCEPTED => {}
        REJECTED => return Err("the terminal server rejected the client key".into()),
        SERVER_FAILURE => return Err("the terminal server could not start PowerShell".into()),
        other => return Err(format!("unexpected terminal server response {other}").into()),
    }
    let authenticated = Instant::now();
    if timing {
        eprintln!(
            "Authentication: {} ms",
            (authenticated - connected).as_millis()
        );
    }
    stream.set_read_timeout(None)?;
    Ok((stream, authenticated))
}

fn interactive(target: Ipv4Addr, key_file: &Path) -> Result<(), Box<dyn Error>> {
    let timing = std::env::var_os("TS_TERMINAL_TIMING").is_some();
    let (mut stream, authenticated) = connect(target, key_file, &Frame::Shell)?;

    let keyboard = io::stdin().is_terminal();
    let display = io::stdout().is_terminal();
    let _input_mode = keyboard.then(ConsoleMode::keyboard).transpose()?;
    let _output_mode = display.then(ConsoleMode::display).transpose()?;
    let writer = Arc::new(Mutex::new(stream.try_clone()?));
    if display {
        let mut size = console_size();
        if let Some((columns, rows)) = size {
            send_frame(&writer, &Frame::Resize { columns, rows })?;
        }
        let writer = Arc::clone(&writer);
        thread::spawn(move || {
            loop {
                thread::sleep(RESIZE_POLL_INTERVAL);
                let current = console_size();
                if let Some((columns, rows)) = current
                    && current != size
                {
                    size = current;
                    if send_frame(&writer, &Frame::Resize { columns, rows }).is_err() {
                        break;
                    }
                }
            }
        });
    }
    {
        let writer = Arc::clone(&writer);
        thread::spawn(move || {
            let result = if keyboard {
                send_keyboard_input(&writer)
            } else {
                send_piped_input(&writer)
            };
            // The server ends the session on a half-close, so piped input keeps the write side
            // open after `exit` and lets PowerShell finish and close the connection itself.
            let how = match result {
                Ok(()) if keyboard => Some(Shutdown::Write),
                Ok(()) => None,
                Err(_) => Some(Shutdown::Both),
            };
            if let Some(how) = how
                && let Ok(stream) = writer.lock()
            {
                let _ = stream.shutdown(how);
            }
        });
    }
    if timing && stream.peek(&mut [0])? != 0 {
        eprintln!(
            "First shell output: {} ms after authentication",
            authenticated.elapsed().as_millis()
        );
    }
    if display {
        copy_terminal_output(&mut stream, &mut io::stdout().lock())?;
    } else {
        let mut output = strip_ansi_escapes::Writer::new(io::stdout().lock());
        io::copy(&mut stream, &mut output)?;
        output.flush()?;
    }
    Ok(())
}

fn send_frame(writer: &Mutex<TcpStream>, frame: &Frame) -> io::Result<()> {
    let mut bytes = Vec::new();
    frame.encode(&mut bytes);
    write_frames(writer, &bytes)
}

fn send_data(writer: &Mutex<TcpStream>, data: &[u8]) -> io::Result<()> {
    let mut bytes = Vec::with_capacity(data.len() + 3);
    session::encode_data(data, &mut bytes);
    write_frames(writer, &bytes)
}

/// Writes whole frames under the lock so the input and resize threads never interleave.
fn write_frames(writer: &Mutex<TcpStream>, bytes: &[u8]) -> io::Result<()> {
    let mut stream = writer
        .lock()
        .map_err(|_| io::Error::other("terminal writer lock poisoned"))?;
    stream.write_all(bytes)
}

fn copy_terminal_output(input: &mut impl Read, output: &mut impl Write) -> io::Result<()> {
    let mut buffer = [0; 8192];
    let mut filter = OutputFilter::default();
    let mut filtered = Vec::with_capacity(buffer.len());
    loop {
        match input.read(&mut buffer) {
            Ok(0) => {
                output.write_all(filter.finish())?;
                return output.flush();
            }
            Ok(count) => {
                filtered.clear();
                filter.filter(&buffer[..count], &mut filtered);
                output.write_all(&filtered)?;
                output.flush()?;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
}

/// The server's pseudoconsole asks its terminal for win32-input-mode. Passed on, the request
/// switches the local console to report each typed character as a win32 key sequence. When the
/// local terminal delivers an arrow key as the characters `ESC [ A` (terminals that host the
/// client through a pseudoconsole do), the server then receives three plain characters and
/// PowerShell shows `^[[A`. Without it, the console sends standard VT key sequences, which the
/// server parses.
const WIN32_INPUT_MODE: &[u8] = b"\x1b[?9001h";

/// Removes `WIN32_INPUT_MODE` from terminal output, including when split across reads.
#[derive(Default)]
struct OutputFilter {
    held: Vec<u8>,
}

impl OutputFilter {
    fn filter(&mut self, bytes: &[u8], output: &mut Vec<u8>) {
        let mut data = std::mem::take(&mut self.held);
        data.extend_from_slice(bytes);
        let mut rest = &data[..];
        while let Some(start) = rest.iter().position(|&byte| byte == 0x1B) {
            output.extend_from_slice(&rest[..start]);
            rest = &rest[start..];
            if rest.starts_with(WIN32_INPUT_MODE) {
                rest = &rest[WIN32_INPUT_MODE.len()..];
            } else if WIN32_INPUT_MODE.starts_with(rest) {
                // Possibly the start of the request: wait for the next read.
                self.held = rest.to_vec();
                return;
            } else {
                output.push(0x1B);
                rest = &rest[1..];
            }
        }
        output.extend_from_slice(rest);
    }

    fn finish(&mut self) -> &[u8] {
        &self.held
    }
}

/// Reads the console directly. Unlike `std::io::stdin`, `ReadConsoleW` without a read-control
/// structure returns Ctrl+Z (0x1A) as an ordinary character instead of end of input.
fn send_keyboard_input(writer: &Mutex<TcpStream>) -> io::Result<()> {
    let (keys, received) = mpsc::channel();
    thread::spawn(move || {
        // The standard input handle belongs to this process's console and stays open.
        let handle = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
        let mut units = [0u16; 512];
        let mut decoder = Utf16Decoder::default();
        // A failed read means the console is gone or unreadable: the real end of input.
        while let Ok(count) = read_console(handle, &mut units) {
            if count == 0 {
                // Woken without input (no line editing or Ctrl+C processing is active).
                thread::sleep(Duration::from_millis(10));
                continue;
            }
            let mut bytes = Vec::with_capacity(count * 3);
            decoder.decode(&units[..count], &mut bytes);
            if !bytes.is_empty() && keys.send(bytes).is_err() {
                break;
            }
        }
    });
    forward_keys(&received, ESCAPE_WAIT, |bytes| send_data(writer, bytes))?;
    send_frame(writer, &Frame::Hangup)
}

/// How long an unfinished escape sequence waits for the rest of its bytes.
const ESCAPE_WAIT: Duration = Duration::from_millis(50);

/// Forwards keyboard bytes, keeping each escape sequence in one write.
///
/// A console may return an arrow key's ESC and `[A` from separate reads. The server's
/// pseudoconsole reads an ESC that ends a write as the Escape key, so the remote shell would see
/// `[A` as text. An unfinished sequence waits up to `wait` for its remaining bytes; a lone Escape
/// key press is sent once that time has passed.
fn forward_keys(
    keys: &Receiver<Vec<u8>>,
    wait: Duration,
    mut send: impl FnMut(&[u8]) -> io::Result<()>,
) -> io::Result<()> {
    let mut pending = Vec::new();
    loop {
        let next = if pending.is_empty() {
            keys.recv().map_err(|_| RecvTimeoutError::Disconnected)
        } else {
            keys.recv_timeout(wait)
        };
        let held = match next {
            Ok(bytes) => {
                pending.extend_from_slice(&bytes);
                unfinished_escape(&pending)
            }
            Err(RecvTimeoutError::Timeout) => 0,
            Err(RecvTimeoutError::Disconnected) => {
                if !pending.is_empty() {
                    send(&pending)?;
                }
                return Ok(());
            }
        };
        if pending.len() > held {
            send(&pending[..pending.len() - held])?;
            pending.drain(..pending.len() - held);
        }
    }
}

/// Length of an escape sequence that `bytes` ends with but does not complete.
fn unfinished_escape(bytes: &[u8]) -> usize {
    let Some(start) = bytes.iter().rposition(|&byte| byte == 0x1B) else {
        return 0;
    };
    let tail = &bytes[start..];
    let unfinished = match tail {
        [_] => true,
        // SS3 (ESC O A) takes one more byte.
        [_, b'O'] => true,
        // CSI is unfinished while only parameter and intermediate bytes follow.
        [_, b'[', rest @ ..] => rest.iter().all(|byte| (0x20..0x40).contains(byte)),
        _ => false,
    };
    if unfinished { tail.len() } else { 0 }
}

fn read_console(handle: HANDLE, units: &mut [u16]) -> io::Result<usize> {
    let mut read = 0;
    // The buffer is borrowed for the call; the length is in UTF-16 units.
    if unsafe {
        ReadConsoleW(
            handle,
            units.as_mut_ptr().cast(),
            units.len() as u32,
            &mut read,
            null(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(read as usize)
}

fn send_piped_input(writer: &Mutex<TcpStream>) -> io::Result<()> {
    let mut input = io::stdin().lock();
    let mut buffer = [0; 1024];
    let mut last_was_cr = false;
    loop {
        let count = match input.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        let mut translated = Vec::with_capacity(count + 8);
        for &byte in &buffer[..count] {
            if byte == b'\n' && !last_was_cr {
                translated.push(b'\r');
            }
            if byte != b'\n' {
                translated.push(byte);
            }
            last_was_cr = byte == b'\r';
        }
        send_data(writer, &translated)?;
    }
    send_data(writer, b"\rexit\r")
}

/// Converts console UTF-16 to UTF-8, keeping a high surrogate split across reads.
#[derive(Default)]
struct Utf16Decoder {
    high_surrogate: Option<u16>,
}

impl Utf16Decoder {
    fn decode(&mut self, units: &[u16], output: &mut Vec<u8>) {
        let mut pending: Vec<u16> = self.high_surrogate.take().into_iter().collect();
        pending.extend_from_slice(units);
        if let Some(&last) = pending.last()
            && (0xD800..0xDC00).contains(&last)
        {
            self.high_surrogate = pending.pop();
        }
        let mut utf8 = [0; 4];
        for character in char::decode_utf16(pending) {
            let character = character.unwrap_or(char::REPLACEMENT_CHARACTER);
            output.extend_from_slice(character.encode_utf8(&mut utf8).as_bytes());
        }
    }
}

/// The visible window size of the console attached to standard output.
fn console_size() -> Option<(u16, u16)> {
    let mut info = CONSOLE_SCREEN_BUFFER_INFO::default();
    // The standard output handle belongs to this process's console and stays open.
    if unsafe { GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &mut info) } == 0 {
        return None;
    }
    window_size(
        info.srWindow.Left,
        info.srWindow.Top,
        info.srWindow.Right,
        info.srWindow.Bottom,
    )
}

fn window_size(left: i16, top: i16, right: i16, bottom: i16) -> Option<(u16, u16)> {
    let columns = u16::try_from(i32::from(right) - i32::from(left) + 1).ok()?;
    let rows = u16::try_from(i32::from(bottom) - i32::from(top) + 1).ok()?;
    (columns > 0 && rows > 0).then_some((columns, rows))
}

struct ConsoleMode {
    handle: HANDLE,
    previous: u32,
}

impl ConsoleMode {
    fn keyboard() -> io::Result<Self> {
        Self::set(STD_INPUT_HANDLE, |mode| {
            (mode | ENABLE_VIRTUAL_TERMINAL_INPUT)
                & !(ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT)
        })
    }

    fn display() -> io::Result<Self> {
        Self::set(STD_OUTPUT_HANDLE, |mode| {
            mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING
        })
    }

    fn set(which: u32, update: impl FnOnce(u32) -> u32) -> io::Result<Self> {
        let mut previous = 0;
        // The handle belongs to the parent console and stays open for this process.
        unsafe {
            let handle = GetStdHandle(which);
            if GetConsoleMode(handle, &mut previous) == 0
                || SetConsoleMode(handle, update(previous)) == 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(Self { handle, previous })
        }
    }
}

impl Drop for ConsoleMode {
    fn drop(&mut self) {
        unsafe {
            SetConsoleMode(self.handle, self.previous);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[test]
    fn displays_echo_before_reading_more_input() {
        let visible = RefCell::new(Vec::new());
        let mut output = io::LineWriter::new(VisibleOutput(&visible));
        let mut sent = false;
        let mut input = EchoInput(&visible, &mut sent);
        copy_terminal_output(&mut input, &mut output).unwrap();
    }

    #[test]
    fn decodes_console_input_including_control_characters() {
        let mut decoder = Utf16Decoder::default();
        let mut output = Vec::new();
        decoder.decode(&[0x1A], &mut output);
        assert_eq!(output, [0x1A]);
        output.clear();
        decoder.decode(&[u16::from(b'a'), 0x03, 0x1A], &mut output);
        assert_eq!(output, b"a\x03\x1a");
    }

    #[test]
    fn keeps_surrogate_pairs_split_across_reads() {
        let mut decoder = Utf16Decoder::default();
        let mut output = Vec::new();
        let units: Vec<u16> = "x\u{1F600}".encode_utf16().collect();
        decoder.decode(&units[..2], &mut output);
        assert_eq!(output, b"x");
        decoder.decode(&units[2..], &mut output);
        assert_eq!(output, "x\u{1F600}".as_bytes());
        output.clear();
        decoder.decode(&[0xDC00, u16::from(b'b')], &mut output);
        assert_eq!(output, "\u{FFFD}b".as_bytes());
    }

    #[test]
    fn removes_win32_input_mode_request() {
        let stream = b"\x1b[?9001h\x1b[?1004h\x1b[2JPS> \x1b[?9001h\x1b[A";
        let expected = b"\x1b[?1004h\x1b[2JPS> \x1b[A";
        for cut in 0..=stream.len() {
            let mut filter = OutputFilter::default();
            let mut output = Vec::new();
            filter.filter(&stream[..cut], &mut output);
            filter.filter(&stream[cut..], &mut output);
            output.extend_from_slice(filter.finish());
            assert_eq!(output, expected, "split at {cut}");
        }
        let mut filter = OutputFilter::default();
        let mut output = Vec::new();
        filter.filter(b"x\x1b[?90", &mut output);
        assert_eq!(output, b"x");
        assert_eq!(filter.finish(), b"\x1b[?90");
    }

    #[test]
    fn finds_unfinished_escape_sequences() {
        assert_eq!(unfinished_escape(b"abc"), 0);
        assert_eq!(unfinished_escape(b"a\x1b"), 1);
        assert_eq!(unfinished_escape(b"\x1b["), 2);
        assert_eq!(unfinished_escape(b"x\x1b[1;5"), 5);
        assert_eq!(unfinished_escape(b"\x1bO"), 2);
        assert_eq!(unfinished_escape(b"\x1b[A"), 0);
        assert_eq!(unfinished_escape(b"\x1bOA"), 0);
        assert_eq!(unfinished_escape(b"\x1b[38;72;0;1;288;1_"), 0);
        assert_eq!(unfinished_escape(b"\x1ba"), 0);
        assert_eq!(unfinished_escape(b"\x1b[A\x1b[3"), 3);
    }

    #[test]
    fn keeps_split_escape_sequences_together() {
        let (keys, received) = mpsc::channel();
        for chunk in [&b"ab\x1b"[..], b"[", b"Acd"] {
            keys.send(chunk.to_vec()).unwrap();
        }
        drop(keys);
        let mut sent = Vec::new();
        forward_keys(&received, Duration::from_secs(5), |bytes| {
            sent.push(bytes.to_vec());
            Ok(())
        })
        .unwrap();
        assert_eq!(sent, [b"ab".to_vec(), b"\x1b[Acd".to_vec()]);
    }

    #[test]
    fn sends_lone_escape_after_waiting() {
        let (keys, received) = mpsc::channel();
        keys.send(b"\x1b".to_vec()).unwrap();
        let sender = thread::spawn(move || {
            thread::sleep(Duration::from_millis(200));
            keys.send(b"x".to_vec()).unwrap();
        });
        let mut sent = Vec::new();
        forward_keys(&received, Duration::from_millis(20), |bytes| {
            sent.push(bytes.to_vec());
            Ok(())
        })
        .unwrap();
        sender.join().unwrap();
        assert_eq!(sent, [b"\x1b".to_vec(), b"x".to_vec()]);
    }

    #[test]
    fn computes_visible_window_size() {
        assert_eq!(window_size(0, 10, 119, 39), Some((120, 30)));
        assert_eq!(window_size(5, 0, 4, 0), None);
    }

    struct EchoInput<'a>(&'a RefCell<Vec<u8>>, &'a mut bool);

    impl Read for EchoInput<'_> {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if *self.1 {
                assert_eq!(self.0.borrow().as_slice(), b"a");
                return Ok(0);
            }
            *self.1 = true;
            buffer[0] = b'a';
            Ok(1)
        }
    }

    struct VisibleOutput<'a>(&'a RefCell<Vec<u8>>);

    impl Write for VisibleOutput<'_> {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.borrow_mut().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
}
