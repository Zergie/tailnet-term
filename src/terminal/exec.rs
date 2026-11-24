//! Runs one non-interactive PowerShell command on plain pipes, like `ssh host command`.

use std::{
    fs::File,
    io::{self, Read},
    path::Path,
    sync::mpsc::{self, Receiver, SyncSender, TryRecvError},
    thread,
    time::{Duration, Instant},
};

use super::{
    conpty::{self, Child, Job},
    session::{MAX_FRAME_PAYLOAD, Output},
};
use crate::tailscale_core::control_link::base64_encode;

/// Environment variable carrying the Base64 UTF-8 script. The bootstrap removes it before the
/// script runs.
const SCRIPT_VARIABLE: &str = "TAILNET_TERM_SCRIPT";

/// Fixed PowerShell arguments that run the script from `SCRIPT_VARIABLE`. `-EncodedCommand` is
/// avoided because Windows PowerShell then writes errors as CLIXML; passing the script in the
/// environment also avoids command line quoting.
const BOOTSTRAP: &str = "-NoLogo -NoProfile -NonInteractive -Command \"\
    $s = $env:TAILNET_TERM_SCRIPT; Remove-Item Env:TAILNET_TERM_SCRIPT; \
    . ([ScriptBlock]::Create([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($s))))\"";

/// How long to wait for the output pipes to close after the command exited. Background
/// processes that inherited the pipes would otherwise keep the session open.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(1);

enum Event {
    Output(Output),
    Eof,
}

/// A running command. Field order is drop order: the job kills the whole process tree first.
pub struct Exec {
    events: Receiver<Event>,
    open_streams: usize,
    exited: Option<(Instant, u32)>,
    done: bool,
    _job: Job,
    child: Child,
}

impl Exec {
    pub fn spawn(shell: &Path, command: &str) -> io::Result<Self> {
        if !shell.is_absolute() || !shell.is_file() {
            return Err(io::Error::other(
                "the PowerShell executable must be an existing absolute path",
            ));
        }
        let conpty::Piped {
            job,
            child,
            stdout,
            stderr,
        } = conpty::spawn_piped(
            shell,
            BOOTSTRAP,
            (
                SCRIPT_VARIABLE,
                &base64_encode(wrap_command(command).as_bytes()),
            ),
        )?;
        let (sender, events) = mpsc::sync_channel(8);
        forward(stdout, sender.clone(), Output::Stdout);
        forward(stderr, sender, Output::Stderr);
        Ok(Self {
            events,
            open_streams: 2,
            exited: None,
            done: false,
            _job: job,
            child,
        })
    }

    /// Returns the next output, then `Output::Exit` once the command has exited and its output
    /// was drained, then `None` forever.
    pub fn poll(&mut self) -> io::Result<Option<Output>> {
        if self.done {
            return Ok(None);
        }
        while self.open_streams > 0 {
            match self.events.try_recv() {
                Ok(Event::Output(output)) => return Ok(Some(output)),
                Ok(Event::Eof) => self.open_streams -= 1,
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => self.open_streams = 0,
            }
        }
        if self.exited.is_none()
            && let Some(code) = self.child.exit_code()?
        {
            self.exited = Some((Instant::now(), code));
        }
        match self.exited {
            Some((since, code)) if self.open_streams == 0 || since.elapsed() >= DRAIN_TIMEOUT => {
                self.done = true;
                Ok(Some(Output::Exit(code)))
            }
            _ => Ok(None),
        }
    }
}

fn forward(mut pipe: File, sender: SyncSender<Event>, wrap: fn(Vec<u8>) -> Output) {
    thread::spawn(move || {
        let mut buffer = [0; MAX_FRAME_PAYLOAD];
        loop {
            match pipe.read(&mut buffer) {
                Ok(0) => break,
                Ok(count) => {
                    if sender
                        .send(Event::Output(wrap(buffer[..count].to_vec())))
                        .is_err()
                    {
                        return;
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                // A broken pipe is the normal end once every writer has exited.
                Err(_) => break,
            }
        }
        let _ = sender.send(Event::Eof);
    });
}

/// Wraps the command so output is UTF-8 and the process exit code is meaningful: an explicit
/// `exit N` wins; otherwise a failed last command exits with its native exit code, or 1.
fn wrap_command(command: &str) -> String {
    format!(
        "$ProgressPreference = 'SilentlyContinue'\n\
         [Console]::OutputEncoding = $OutputEncoding = [Text.UTF8Encoding]::new($false)\n\
         $global:LASTEXITCODE = 0\n\
         {command}\n\
         if ($?) {{ exit 0 }} elseif ($LASTEXITCODE) {{ exit $LASTEXITCODE }} else {{ exit 1 }}\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn powershell() -> Option<std::path::PathBuf> {
        let root = std::env::var_os("SystemRoot")?;
        let path = Path::new(&root).join(r"System32\WindowsPowerShell\v1.0\powershell.exe");
        path.is_file().then_some(path)
    }

    /// Installed PowerShell 7 from PATH, if any.
    fn pwsh() -> Option<std::path::PathBuf> {
        std::env::split_paths(&std::env::var_os("PATH")?)
            .map(|dir| dir.join("pwsh.exe"))
            .find(|path| path.is_file())
    }

    /// Every installed PowerShell; Windows PowerShell is always expected.
    fn shells() -> Vec<std::path::PathBuf> {
        let mut shells = vec![powershell().expect("Windows PowerShell is installed")];
        shells.extend(pwsh());
        shells
    }

    fn run_in(shell: &Path, command: &str) -> (Vec<u8>, Vec<u8>, u32) {
        let mut exec = Exec::spawn(shell, command).unwrap();
        let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            assert!(Instant::now() < deadline, "command did not finish");
            match exec.poll().unwrap() {
                Some(Output::Stdout(bytes)) => stdout.extend(bytes),
                Some(Output::Stderr(bytes)) => stderr.extend(bytes),
                Some(Output::Exit(code)) => return (stdout, stderr, code),
                None => thread::sleep(Duration::from_millis(5)),
            }
        }
    }

    #[test]
    fn keeps_the_command_on_its_own_lines() {
        assert!(wrap_command("x # comment").contains("\nx # comment\n"));
    }

    #[test]
    fn reports_exit_codes_and_plain_errors() {
        for shell in shells() {
            let code = |command| run_in(&shell, command).2;
            assert_eq!(code("cmd /c exit 5"), 5, "{shell:?}");
            assert_eq!(code("exit 7"), 7, "{shell:?}");
            assert_eq!(code("Write-Output ok"), 0, "{shell:?}");
            assert_eq!(
                code("Get-Item C:\\does-not-exist-tailnet-term"),
                1,
                "{shell:?}"
            );
            assert_eq!(code("cmd /c exit 3; Write-Output after"), 0, "{shell:?}");
            let (_, stderr, code) = run_in(&shell, "Write-Error boom");
            let stderr = String::from_utf8(stderr).unwrap();
            assert_eq!(code, 1, "{shell:?}");
            assert!(
                stderr.contains("boom") && !stderr.contains("CLIXML"),
                "{stderr}"
            );
        }
    }

    #[test]
    fn separates_streams_as_utf8() {
        for shell in shells() {
            let (stdout, stderr, code) = run_in(
                &shell,
                "'äöü'; cmd /c echo ÄÖÜ; [Console]::Error.WriteLine('err')",
            );
            assert_eq!(code, 0, "{shell:?}");
            assert_eq!(String::from_utf8(stdout).unwrap(), "äöü\r\nÄÖÜ\r\n");
            assert_eq!(String::from_utf8(stderr).unwrap(), "err\r\n");
        }
    }

    #[test]
    fn keeps_long_lines_and_large_output() {
        for shell in shells() {
            let (stdout, _, code) = run_in(&shell, "'x' * 500; 1..20000");
            assert_eq!(code, 0, "{shell:?}");
            let text = String::from_utf8(stdout).unwrap();
            let mut lines = text.lines();
            assert_eq!(lines.next().unwrap().len(), 500);
            assert_eq!(lines.clone().count(), 20000);
            assert_eq!(lines.last(), Some("20000"));
        }
    }

    #[test]
    fn hides_tailscale_credentials() {
        // SAFETY: tests in this module do not read this variable concurrently.
        unsafe { std::env::set_var("TS_AUTH_KEY", "tskey-test") };
        for shell in shells() {
            let (stdout, _, _) = run_in(
                &shell,
                "\"[$env:TS_AUTH_KEY][$env:TAILNET_TERM_SCRIPT]\"; cmd /c echo [%TS_AUTH_KEY%]",
            );
            assert_eq!(
                String::from_utf8(stdout).unwrap(),
                "[][]\r\n[%TS_AUTH_KEY%]\r\n"
            );
        }
    }
}
