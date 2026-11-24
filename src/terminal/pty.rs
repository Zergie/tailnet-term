use std::{
    error::Error,
    io::{Read, Write},
    path::Path,
    sync::mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError},
    thread,
};

#[cfg(feature = "diagnostics")]
use std::time::Duration;

use super::conpty::{self, Child, Console, Job};

/// Field order is drop order: the job kills the process tree before the pseudoconsole closes.
pub struct Shell {
    input: SyncSender<Vec<u8>>,
    output: Receiver<Vec<u8>>,
    _job: Job,
    child: Child,
    terminal: Console,
}

impl Shell {
    pub fn spawn(executable: &Path) -> Result<Self, Box<dyn Error>> {
        if !executable.is_absolute() || !executable.is_file() {
            return Err("the PowerShell executable must be an existing absolute path".into());
        }
        let conpty::Pty {
            job,
            child,
            console,
            output: mut reader,
            input: mut writer,
        } = conpty::open(executable)?;
        let (input, input_rx) = mpsc::sync_channel::<Vec<u8>>(8);
        let (output_tx, output) = mpsc::sync_channel(8);
        thread::spawn(move || {
            // Bytes, including 0x03, go to the pseudoconsole unchanged. Conhost turns 0x03 into
            // CTRL_C_EVENT while the foreground program has processed input enabled and delivers
            // it as a key otherwise (for example to PSReadLine or full-screen programs).
            while let Ok(bytes) = input_rx.recv() {
                if let Err(error) = writer.write_all(&bytes).and_then(|()| writer.flush()) {
                    eprintln!("ConPTY input: {error}");
                    break;
                }
            }
        });
        thread::spawn(move || {
            let mut buffer = [0; 1024];
            let mut forwards_output = true;
            while let Ok(count) = reader.read(&mut buffer) {
                if count == 0 {
                    break;
                }
                if forwards_output {
                    forwards_output = output_tx.send(buffer[..count].to_vec()).is_ok();
                }
            }
        });
        Ok(Self {
            input,
            output,
            _job: job,
            child,
            terminal: console,
        })
    }

    pub fn input(&self, bytes: Vec<u8>) -> Result<Option<Vec<u8>>, Box<dyn Error>> {
        match self.input.try_send(bytes) {
            Ok(()) => Ok(None),
            Err(TrySendError::Full(bytes)) => Ok(Some(bytes)),
            Err(TrySendError::Disconnected(_)) => Err("PowerShell input closed".into()),
        }
    }

    pub fn output(&self) -> Result<Option<Vec<u8>>, TryRecvError> {
        match self.output.try_recv() {
            Ok(bytes) => Ok(Some(bytes)),
            Err(TryRecvError::Empty) => Ok(None),
            Err(error) => Err(error),
        }
    }

    pub fn exited(&mut self) -> Result<bool, Box<dyn Error>> {
        Ok(self.child.exited()?)
    }

    pub fn resize(&self, columns: u16, rows: u16) -> Result<(), Box<dyn Error>> {
        Ok(self.terminal.resize(columns, rows)?)
    }
}

#[cfg(feature = "diagnostics")]
pub fn probe(executable: &Path) -> Result<(), Box<dyn Error>> {
    let shell = Shell::spawn(executable)?;
    wait_for(&shell, b">")?;
    send(
        &shell,
        b"$prefix='tailnet-'; Write-Output ($prefix + 'pty-ok')\r",
    )?;
    wait_for(&shell, b"tailnet-pty-ok")?;
    println!("PASS: PowerShell command chain returned its result");
    send(
        &shell,
        b"Write-Output ('interrupt-'+'armed'); Start-Sleep -Seconds 60\r",
    )?;
    wait_for(&shell, b"interrupt-armed")?;
    thread::sleep(Duration::from_millis(350));
    send(&shell, b"\x03")?;
    wait_for(&shell, b">")?;
    send(&shell, b"Write-Output ('interrupt-'+'ok')\r")?;
    wait_for(&shell, b"interrupt-ok")?;
    println!("PASS: ConPTY executed a PowerShell command chain and accepted Ctrl+C");
    send(
        &shell,
        b"Write-Output ('native-'+'armed'); ping.exe -t -w 1000 127.0.0.1\r",
    )?;
    wait_for(&shell, b"native-armed")?;
    thread::sleep(Duration::from_millis(1500));
    send(&shell, b"\x03")?;
    wait_for(&shell, b">")?;
    send(&shell, b"Write-Output ('native-'+'ok')\r")?;
    wait_for(&shell, b"native-ok")?;
    println!("PASS: Ctrl+C interrupted a native console program");
    send(&shell, b"abc\x03")?;
    thread::sleep(Duration::from_millis(350));
    send(&shell, b"Write-Output ('idle-'+'ok')\r")?;
    wait_for(&shell, b"idle-ok")?;
    println!("PASS: Ctrl+C at the prompt left the shell usable");
    shell.resize(132, 43)?;
    thread::sleep(Duration::from_millis(200));
    send(
        &shell,
        b"Write-Output ('size-' + $Host.UI.RawUI.WindowSize.Width + 'x' + $Host.UI.RawUI.WindowSize.Height)\r",
    )?;
    wait_for(&shell, b"size-132x43")?;
    println!("PASS: ConPTY resize reached PowerShell");
    send(
        &shell,
        b"$p = Start-Process -PassThru -WindowStyle Hidden ping.exe '-t 127.0.0.1'; Write-Output ('detached-pid-' + $p.Id + '-e' + 'nd')\r",
    )?;
    let output = wait_for(&shell, b"-end")?;
    let pid = detached_pid(&output).ok_or("detached child PID not found")?;
    drop(shell);
    let started = std::time::Instant::now();
    while process_alive(pid) {
        if started.elapsed() > Duration::from_secs(5) {
            return Err(format!("detached child {pid} survived the session").into());
        }
        thread::sleep(Duration::from_millis(100));
    }
    println!("PASS: session teardown killed a detached child process");
    Ok(())
}

#[cfg(feature = "diagnostics")]
fn detached_pid(output: &[u8]) -> Option<u32> {
    let text = String::from_utf8_lossy(output);
    let marker = "detached-pid-";
    text.match_indices(marker).find_map(|(index, _)| {
        let rest = &text[index + marker.len()..];
        let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
        rest[digits.len()..]
            .starts_with("-end")
            .then(|| digits.parse().ok())
            .flatten()
    })
}

#[cfg(feature = "diagnostics")]
fn process_alive(pid: u32) -> bool {
    use windows_sys::Win32::{
        Foundation::{CloseHandle, WAIT_TIMEOUT},
        System::Threading::{OpenProcess, PROCESS_SYNCHRONIZE, WaitForSingleObject},
    };
    // A failed open means the process no longer exists (or is inaccessible).
    unsafe {
        let handle = OpenProcess(PROCESS_SYNCHRONIZE, 0, pid);
        if handle.is_null() {
            return false;
        }
        let alive = WaitForSingleObject(handle, 0) == WAIT_TIMEOUT;
        CloseHandle(handle);
        alive
    }
}

#[cfg(feature = "diagnostics")]
fn send(shell: &Shell, input: &[u8]) -> Result<(), Box<dyn Error>> {
    if shell.input(input.to_vec())?.is_some() {
        return Err("PowerShell input queue unexpectedly full".into());
    }
    Ok(())
}

#[cfg(feature = "diagnostics")]
fn wait_for(shell: &Shell, expected: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut output = Vec::new();
    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_secs(10) {
        match shell.output() {
            Ok(Some(chunk)) => output.extend_from_slice(&chunk),
            Ok(None) => {}
            Err(error) => return Err(error.into()),
        }
        let visible = if expected.contains(&0x1b) {
            output.clone()
        } else {
            strip_ansi_escapes::strip(&output)
        };
        if visible
            .windows(expected.len())
            .any(|slice| slice == expected)
        {
            return Ok(visible);
        }
        thread::sleep(Duration::from_millis(20));
    }
    Err(format!(
        "ConPTY did not return {:?}; received {:?}",
        String::from_utf8_lossy(expected),
        String::from_utf8_lossy(&output)
    )
    .into())
}
