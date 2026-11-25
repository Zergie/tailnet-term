//! Experimental bridge from a classic Windows console to the terminal byte stream.

mod keys;
mod screen;

use std::{
    fs::{File, OpenOptions},
    io::{self, Read},
    os::windows::io::{AsRawHandle, BorrowedHandle},
    path::Path,
    process::{Command, Stdio},
    ptr::null_mut,
    sync::mpsc::{RecvTimeoutError, sync_channel},
    thread,
    time::{Duration, Instant},
};

use windows_sys::Win32::{
    Foundation::{ERROR_BROKEN_PIPE, INVALID_HANDLE_VALUE},
    System::{
        Console::{GetStdHandle, STD_INPUT_HANDLE, SetConsoleCtrlHandler},
        Pipes::PeekNamedPipe,
    },
};

use super::{
    conpty::DEFAULT_SIZE,
    session::{Frame, FrameDecoder},
};

pub fn run(executable: &Path) -> io::Result<()> {
    let arguments: &[&str] = match executable.file_name().and_then(|name| name.to_str()) {
        Some(name) if name.eq_ignore_ascii_case("cmd.exe") => &["/D"],
        Some(name) if name.eq_ignore_ascii_case("pwsh.exe")
            || name.eq_ignore_ascii_case("powershell.exe") => &["-NoLogo", "-NoProfile"],
        _ => return Err(io::Error::new(io::ErrorKind::Unsupported,
            "The classic terminal supports cmd.exe, pwsh.exe and powershell.exe.")),
    };
    let transport = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
    if transport.is_null() || transport == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let mut incoming =
        File::from(unsafe { BorrowedHandle::borrow_raw(transport) }.try_clone_to_owned()?);
    // Reject direct launches with a console on stdin before creating a shell.
    available(&incoming)?;

    let tty_input = OpenOptions::new().read(true).write(true).open("CONIN$")?;
    let tty_output = OpenOptions::new().read(true).write(true).open("CONOUT$")?;
    let input_handle = tty_input.as_raw_handle();
    let output_handle = tty_output.as_raw_handle();
    screen::resize(output_handle, DEFAULT_SIZE.0, DEFAULT_SIZE.1)?;
    let mut screen = screen::Screen::new(output_handle)?;
    checked(unsafe { SetConsoleCtrlHandler(None, 0) })?;
    let mut shell = Command::new(executable)
        .args(arguments)
        .stdin(Stdio::from(tty_input.try_clone()?))
        .stdout(Stdio::from(tty_output.try_clone()?))
        .stderr(Stdio::from(tty_output.try_clone()?))
        .spawn()?;
    // The child inherits normal Ctrl+C handling. The bridge survives the broadcast.
    checked(unsafe { SetConsoleCtrlHandler(None, 1) })?;

    let (sender, receiver) = sync_channel(4);
    thread::spawn(move || {
        let mut bytes = [0; 8192];
        loop {
            match incoming.read(&mut bytes) {
                Ok(0) => break,
                Ok(count) => {
                    if sender.send(Ok(bytes[..count].to_vec())).is_err() {
                        break;
                    }
                }
                Err(error) => {
                    if error.raw_os_error() != Some(ERROR_BROKEN_PIPE as i32) {
                        let _ = sender.send(Err(error));
                    }
                    break;
                }
            }
        }
    });

    let mut frames = FrameDecoder::default();
    let mut keyboard = keys::Keyboard::default();
    let mut client = io::stdout().lock();
    let mut activity = Instant::now();
    loop {
        let exited = shell.try_wait()?.is_some();
        if screen.render(output_handle, &mut client)? {
            activity = Instant::now();
        }
        if exited {
            return Ok(());
        }
        // Incoming keys wake the bridge immediately. Only console output needs polling.
        let interval = if activity.elapsed() < Duration::from_millis(200) {
            Duration::from_millis(8)
        } else {
            Duration::from_millis(40)
        };
        match receiver.recv_timeout(interval) {
            Ok(bytes) => {
                activity = Instant::now();
                frames.extend(&bytes?);
                while let Some(frame) = frames.next_frame().map_err(io::Error::other)? {
                    match frame {
                        Frame::Data(bytes) => keyboard.send(input_handle, &bytes)?,
                        Frame::Resize { columns, rows } => {
                            if let Err(error) = screen::resize(output_handle, columns, rows) {
                                eprintln!("Classic terminal resize to {columns}x{rows}: {error}");
                            }
                        }
                        Frame::Hangup => return Ok(()),
                        _ => return Err(io::Error::other("invalid classic terminal frame")),
                    }
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return Ok(()),
        }
    }
}

fn available(pipe: &File) -> io::Result<usize> {
    let mut count = 0;
    checked(unsafe {
        PeekNamedPipe(pipe.as_raw_handle(), null_mut(), 0, null_mut(), &mut count, null_mut())
    })?;
    Ok(count as usize)
}

fn checked(result: i32) -> io::Result<()> {
    if result == 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
}
