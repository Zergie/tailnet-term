use std::{
    ffi::{OsStr, OsString},
    fs::File,
    io,
    mem::size_of,
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    path::Path,
    ptr::{null, null_mut},
};

use windows_sys::Win32::{
    Foundation::{
        HANDLE, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, SetHandleInformation, WAIT_OBJECT_0,
        WAIT_TIMEOUT,
    },
    System::{
        Console::{COORD, HPCON, SetConsoleCtrlHandler},
        JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
            SetInformationJobObject, TerminateJobObject,
        },
        LibraryLoader::{GetModuleHandleW, GetProcAddress},
        Pipes::CreatePipe,
        Threading::{
            CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessW,
            DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT, GetExitCodeProcess,
            INFINITE, InitializeProcThreadAttributeList, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
            PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, PROCESS_INFORMATION, ResumeThread,
            STARTF_USESTDHANDLES, STARTUPINFOEXW, STARTUPINFOW, TerminateProcess,
            UpdateProcThreadAttribute, WaitForSingleObject,
        },
    },
};

/// Console size used until the client reports its own.
pub const DEFAULT_SIZE: (u16, u16) = (100, 30);

/// Environment variables carrying the server's Tailscale credentials. They never reach the
/// remote shell. Windows environment names are case-insensitive.
const SECRET_ENVIRONMENT: &[&str] = &[
    "TS_AUTH_KEY",
    "TS_AUTHKEY",
    "TAILSCALE_AUTH_KEY",
    "TAILSCALE_AUTHKEY",
    "TAILSCALE_API_KEY",
    "TAILSCALE_OAUTH_CLIENT_ID",
    "TAILSCALE_OAUTH_CLIENT_SECRET",
];

type CreateConsole = unsafe extern "system" fn(COORD, HANDLE, HANDLE, u32, *mut HPCON) -> i32;
type ResizeConsole = unsafe extern "system" fn(HPCON, COORD) -> i32;
type CloseConsole = unsafe extern "system" fn(HPCON);

struct ConsoleApi {
    create: CreateConsole,
    resize: ResizeConsole,
    close: CloseConsole,
}

impl ConsoleApi {
    fn load() -> io::Result<Self> {
        // Kernel32 is loaded for the lifetime of the process.
        let kernel = unsafe { GetModuleHandleW(windows_sys::w!("kernel32.dll")) };
        if kernel.is_null() {
            return Err(io::Error::last_os_error());
        }
        let unavailable = || {
            io::Error::new(
                io::ErrorKind::Unsupported,
                "ConPTY is unavailable. Use the legacy-support build for interactive sessions on this server.",
            )
        };
        // Each pointer is converted to the corresponding Windows API signature.
        unsafe {
            let create = GetProcAddress(kernel, c"CreatePseudoConsole".as_ptr().cast())
                .ok_or_else(unavailable)?;
            let resize = GetProcAddress(kernel, c"ResizePseudoConsole".as_ptr().cast())
                .ok_or_else(unavailable)?;
            let close = GetProcAddress(kernel, c"ClosePseudoConsole".as_ptr().cast())
                .ok_or_else(unavailable)?;
            Ok(Self {
                create: std::mem::transmute::<_, CreateConsole>(create),
                resize: std::mem::transmute::<_, ResizeConsole>(resize),
                close: std::mem::transmute::<_, CloseConsole>(close),
            })
        }
    }
}

pub struct Console(HPCON, ConsoleApi);

impl Console {
    pub fn resize(&self, columns: u16, rows: u16) -> io::Result<()> {
        // The pseudoconsole handle stays valid until this wrapper is dropped.
        let result = unsafe { (self.1.resize)(self.0, coord(columns, rows)) };
        if result < 0 {
            return Err(io::Error::other(format!(
                "ResizePseudoConsole returned 0x{result:08x}"
            )));
        }
        Ok(())
    }
}

impl Drop for Console {
    fn drop(&mut self) {
        // The output worker drains the pipe while this closes the host console.
        unsafe {
            (self.1.close)(self.0);
        }
    }
}

fn coord(columns: u16, rows: u16) -> COORD {
    let clamp = |value: u16| value.clamp(1, i16::MAX as u16) as i16;
    COORD {
        X: clamp(columns),
        Y: clamp(rows),
    }
}

/// A job object that kills every process assigned to it, including descendants, when dropped.
pub struct Job(OwnedHandle);

impl Job {
    fn new() -> io::Result<Self> {
        // An unnamed job with default security. The handle is owned immediately.
        let handle = unsafe { CreateJobObjectW(null(), null()) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        let job = Self(unsafe { OwnedHandle::from_raw_handle(handle) });
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        // Win32 copies the structure during the call.
        if unsafe {
            SetInformationJobObject(
                job.0.as_raw_handle(),
                JobObjectExtendedLimitInformation,
                (&raw const limits).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(job)
    }
}

impl Drop for Job {
    fn drop(&mut self) {
        // Closing the handle kills the job too; terminating explicitly does not depend on
        // this being the last handle.
        unsafe {
            TerminateJobObject(self.0.as_raw_handle(), 1);
        }
    }
}

struct Attributes(Vec<usize>);

impl Drop for Attributes {
    fn drop(&mut self) {
        unsafe {
            DeleteProcThreadAttributeList(self.0.as_mut_ptr().cast());
        }
    }
}

pub struct Child(OwnedHandle);

impl Child {
    pub fn exited(&self) -> io::Result<bool> {
        // The process handle is owned and stays valid through this call.
        match unsafe { WaitForSingleObject(self.0.as_raw_handle(), 0) } {
            WAIT_OBJECT_0 => Ok(true),
            WAIT_TIMEOUT => Ok(false),
            _ => Err(io::Error::last_os_error()),
        }
    }

    /// The exit code, once the process has exited.
    pub fn exit_code(&self) -> io::Result<Option<u32>> {
        if !self.exited()? {
            return Ok(None);
        }
        let mut code = 0;
        // The process handle is owned and stays valid through this call.
        if unsafe { GetExitCodeProcess(self.0.as_raw_handle(), &mut code) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Some(code))
    }
}

impl Drop for Child {
    fn drop(&mut self) {
        if !matches!(self.exited(), Ok(true)) {
            unsafe {
                TerminateProcess(self.0.as_raw_handle(), 1);
                WaitForSingleObject(self.0.as_raw_handle(), 2000);
            }
        }
    }
}

fn pipe() -> io::Result<(OwnedHandle, OwnedHandle)> {
    let mut read = null_mut();
    let mut write = null_mut();
    // The kernel initializes both non-inheritable pipe handles on success.
    if unsafe { CreatePipe(&mut read, &mut write, null(), 0) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe {
        (
            OwnedHandle::from_raw_handle(read),
            OwnedHandle::from_raw_handle(write),
        )
    })
}

/// A shell supervisor inside its own pseudoconsole.
///
/// Field order is drop order: the job kills the whole process tree first, then the
/// pseudoconsole is closed while the output worker still drains its pipe.
pub struct Pty<T = Console> {
    pub job: Job,
    pub child: Child,
    pub console: T,
    pub output: File,
    pub input: File,
}

pub fn open(executable: &Path) -> io::Result<Pty> {
    let api = ConsoleApi::load()?;
    let timing = std::env::var_os("TS_TERMINAL_TIMING").is_some();
    let started = std::time::Instant::now();
    let (input_read, input_write) = pipe()?;
    let (output_read, output_write) = pipe()?;
    let mut console = 0;
    // The shell is prepared before a client connects, so it starts at the default size and is
    // resized when the client reports its console size. Zero flags avoid requiring a cursor
    // position reply from the client.
    let result = unsafe {
        (api.create)(
            coord(DEFAULT_SIZE.0, DEFAULT_SIZE.1),
            input_read.as_raw_handle(),
            output_write.as_raw_handle(),
            0,
            &mut console,
        )
    };
    if result < 0 {
        return Err(io::Error::other(format!(
            "CreatePseudoConsole returned 0x{result:08x}"
        )));
    }
    let console = Console(console, api);
    let console_ready = std::time::Instant::now();
    drop(input_read);
    drop(output_write);
    let job = Job::new()?;
    let child = spawn(executable, &console, &job)?;
    if timing {
        eprintln!(
            "ConPTY creation: {} ms; supervisor process creation: {} ms",
            (console_ready - started).as_millis(),
            console_ready.elapsed().as_millis()
        );
    }
    Ok(Pty {
        job,
        child,
        console,
        output: File::from(output_read),
        input: File::from(input_write),
    })
}

impl Attributes {
    /// An initialized attribute list with room for one attribute.
    fn new() -> io::Result<Self> {
        let mut size = 0;
        // The first call queries the allocation size. usize storage preserves the required
        // alignment.
        unsafe {
            InitializeProcThreadAttributeList(null_mut(), 1, 0, &mut size);
        }
        if size == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut buffer = vec![0usize; size.div_ceil(size_of::<usize>())];
        if unsafe { InitializeProcThreadAttributeList(buffer.as_mut_ptr().cast(), 1, 0, &mut size) }
            == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(buffer))
    }
}

fn spawn(executable: &Path, console: &Console, job: &Job) -> io::Result<Child> {
    let mut attributes = Attributes::new()?;
    let list = attributes.0.as_mut_ptr().cast();
    // The pseudoconsole attribute takes the HPCON value, not the address of the wrapper.
    if unsafe {
        UpdateProcThreadAttribute(
            list,
            0,
            PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE as usize,
            console.0 as _,
            size_of::<HPCON>(),
            null_mut(),
            null(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let mut startup = STARTUPINFOEXW::default();
    startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = INVALID_HANDLE_VALUE;
    startup.StartupInfo.hStdOutput = INVALID_HANDLE_VALUE;
    startup.StartupInfo.hStdError = INVALID_HANDLE_VALUE;
    startup.lpAttributeList = list;
    let mut child = PROCESS_INFORMATION::default();
    let current = std::env::current_exe()?;
    let path: Vec<u16> = current.as_os_str().encode_wide().chain([0]).collect();
    // The second argument is a legacy interrupt handle slot kept for command-line
    // compatibility; Ctrl+C now travels through the pseudoconsole input as 0x03.
    let arguments = "\" console-child 0 \"";
    let mut command: Vec<u16> = [u16::from(b'"')]
        .into_iter()
        .chain(current.as_os_str().encode_wide())
        .chain(OsStr::new(arguments).encode_wide())
        .chain(executable.as_os_str().encode_wide())
        .chain([u16::from(b'"')])
        .chain([0])
        .collect();
    let environment = shell_environment(None);
    // The process starts suspended so it is inside the job before it can create children.
    // Win32 borrows all buffers for the duration of this call and returns owned handles.
    if unsafe {
        CreateProcessW(
            path.as_ptr(),
            command.as_mut_ptr(),
            null(),
            null(),
            0,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED,
            environment.as_ptr().cast(),
            null(),
            &startup.StartupInfo,
            &mut child,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let (process, thread) = unsafe {
        (
            Child(OwnedHandle::from_raw_handle(child.hProcess)),
            OwnedHandle::from_raw_handle(child.hThread),
        )
    };
    // Dropping `process` on an error path terminates the suspended supervisor.
    if unsafe { AssignProcessToJobObject(job.0.as_raw_handle(), process.0.as_raw_handle()) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { ResumeThread(thread.as_raw_handle()) } == u32::MAX {
        return Err(io::Error::last_os_error());
    }
    Ok(process)
}

/// A process on plain pipes with a hidden console and no standard input.
///
/// Field order is drop order: the job kills the whole process tree first.
pub struct Piped {
    pub job: Job,
    pub child: Child,
    pub stdout: File,
    pub stderr: File,
}

#[cfg(feature = "classic-pty")]
pub(crate) fn spawn_console_helper(executable: &Path) -> io::Result<Pty<()>> {
    let current = std::env::current_exe()?;
    let mut arguments = OsString::from("classic-console-child \"");
    arguments.push(executable);
    arguments.push("\"");
    let (input, writer) = pipe()?;
    let Piped { job, child, stdout, stderr } =
        spawn_with_pipes(&current, &arguments, None, input, true)?;
    std::thread::spawn(move || {
        let _ = io::copy(&mut &stderr, &mut io::stderr());
    });
    Ok(Pty {
        job,
        child,
        console: (),
        output: stdout,
        input: File::from(writer),
    })
}

/// Starts `"executable" arguments` inside a new job, with `variable` added to its environment.
/// Only the three standard handles are inherited, and the Tailscale credentials are removed
/// from its environment.
pub fn spawn_piped(
    executable: &Path,
    arguments: &str,
    variable: (&str, &str),
) -> io::Result<Piped> {
    let stdin = OwnedHandle::from(File::open("NUL")?);
    spawn_with_pipes(executable, OsStr::new(arguments), Some(variable), stdin, false)
}

fn spawn_with_pipes(
    executable: &Path,
    arguments: &OsStr,
    variable: Option<(&str, &str)>,
    stdin: OwnedHandle,
    new_console: bool,
) -> io::Result<Piped> {
    let (stdout, stdout_write) = pipe()?;
    let (stderr, stderr_write) = pipe()?;
    let inherited = [
        stdin.as_raw_handle(),
        stdout_write.as_raw_handle(),
        stderr_write.as_raw_handle(),
    ];
    for handle in inherited {
        // The handles are owned above and stay open through this call.
        if unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) } == 0 {
            return Err(io::Error::last_os_error());
        }
    }
    let mut attributes = Attributes::new()?;
    let list = attributes.0.as_mut_ptr().cast();
    // The handle list restricts inheritance to the child's standard handles. Win32 keeps a
    // pointer to `inherited`, which outlives the CreateProcessW call below.
    if unsafe {
        UpdateProcThreadAttribute(
            list,
            0,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
            inherited.as_ptr().cast(),
            size_of_val(&inherited),
            null_mut(),
            null(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let mut startup = STARTUPINFOEXW::default();
    startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = inherited[0];
    startup.StartupInfo.hStdOutput = inherited[1];
    startup.StartupInfo.hStdError = inherited[2];
    let console_flags = if new_console {
        use windows_sys::Win32::System::Threading::{CREATE_NEW_CONSOLE, STARTF_USESHOWWINDOW};
        startup.StartupInfo.dwFlags |= STARTF_USESHOWWINDOW;
        startup.StartupInfo.wShowWindow = 0; // SW_HIDE
        CREATE_NEW_CONSOLE
    } else {
        CREATE_NO_WINDOW
    };
    startup.lpAttributeList = list;
    let path: Vec<u16> = executable.as_os_str().encode_wide().chain([0]).collect();
    let mut command: Vec<u16> = [u16::from(b'"')]
        .into_iter()
        .chain(executable.as_os_str().encode_wide())
        .chain(OsStr::new("\" ").encode_wide())
        .chain(arguments.encode_wide())
        .chain([0])
        .collect();
    let environment = shell_environment(variable);
    let job = Job::new()?;
    let mut child = PROCESS_INFORMATION::default();
    // The process starts suspended so it is inside the job before it can create children. A
    // hidden console (rather than none) lets PowerShell switch native programs to UTF-8.
    // Win32 borrows all buffers for the duration of this call and returns owned handles.
    if unsafe {
        CreateProcessW(
            path.as_ptr(),
            command.as_mut_ptr(),
            null(),
            null(),
            1,
            EXTENDED_STARTUPINFO_PRESENT
                | CREATE_UNICODE_ENVIRONMENT
                | CREATE_SUSPENDED
                | console_flags,
            environment.as_ptr().cast(),
            null(),
            &startup.StartupInfo,
            &mut child,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let (process, thread) = unsafe {
        (
            Child(OwnedHandle::from_raw_handle(child.hProcess)),
            OwnedHandle::from_raw_handle(child.hThread),
        )
    };
    // Dropping `process` on an error path terminates the suspended child.
    if unsafe { AssignProcessToJobObject(job.0.as_raw_handle(), process.0.as_raw_handle()) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { ResumeThread(thread.as_raw_handle()) } == u32::MAX {
        return Err(io::Error::last_os_error());
    }
    // The child holds its own copies; the readers see end of file once every writer exits.
    drop((stdin, stdout_write, stderr_write));
    Ok(Piped {
        job,
        child: process,
        stdout: File::from(stdout),
        stderr: File::from(stderr),
    })
}

/// Runs inside the pseudoconsole: starts PowerShell with a cleared Ctrl+C ignore flag and waits
/// for it. `_legacy_handle` is the former interrupt event slot and is ignored.
pub fn supervise_console(_legacy_handle: usize, executable: &Path) -> io::Result<()> {
    if !executable.is_absolute() || !executable.is_file() {
        return Err(io::Error::other("invalid console child arguments"));
    }
    let input = File::open("CONIN$")?;
    let output = std::fs::OpenOptions::new().write(true).open("CONOUT$")?;
    for handle in [input.as_raw_handle(), output.as_raw_handle()] {
        if unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) } == 0 {
            return Err(io::Error::last_os_error());
        }
    }
    let mut startup = STARTUPINFOW {
        cb: size_of::<STARTUPINFOW>() as u32,
        ..Default::default()
    };
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = input.as_raw_handle();
    startup.hStdOutput = output.as_raw_handle();
    startup.hStdError = output.as_raw_handle();
    let mut child = PROCESS_INFORMATION::default();
    let path: Vec<u16> = executable.as_os_str().encode_wide().chain([0]).collect();
    let mut command: Vec<u16> = [u16::from(b'"')]
        .into_iter()
        .chain(executable.as_os_str().encode_wide())
        .chain(OsStr::new("\" -NoLogo -NoProfile").encode_wide())
        .chain([0])
        .collect();
    // The server may run with an inherited "ignore Ctrl+C" flag (for example when started in a
    // new process group). Clearing it here lets PowerShell inherit normal Ctrl+C handling, so
    // conhost's CTRL_C_EVENT for an input 0x03 interrupts the running command.
    unsafe {
        if SetConsoleCtrlHandler(None, 0) == 0 {
            return Err(io::Error::last_os_error());
        }
        if CreateProcessW(
            path.as_ptr(),
            command.as_mut_ptr(),
            null(),
            null(),
            1,
            0,
            null(),
            null(),
            &startup,
            &mut child,
        ) == 0
        {
            return Err(io::Error::last_os_error());
        }
        drop(OwnedHandle::from_raw_handle(child.hThread));
        let child = Child(OwnedHandle::from_raw_handle(child.hProcess));
        // Ignore Ctrl+C in the supervisor only after spawning PowerShell so PowerShell does not
        // inherit the flag; conhost delivers CTRL_C_EVENT to every process on the console.
        if SetConsoleCtrlHandler(None, 1) == 0 {
            return Err(io::Error::last_os_error());
        }
        match WaitForSingleObject(child.0.as_raw_handle(), INFINITE) {
            WAIT_OBJECT_0 => Ok(()),
            _ => Err(io::Error::last_os_error()),
        }
    }
}

fn is_secret_variable(name: &OsStr) -> bool {
    let name = name.to_string_lossy();
    SECRET_ENVIRONMENT
        .iter()
        .any(|secret| name.eq_ignore_ascii_case(secret))
}

fn filtered_environment(
    vars: impl IntoIterator<Item = (OsString, OsString)>,
) -> Vec<(OsString, OsString)> {
    let mut vars: Vec<_> = vars
        .into_iter()
        .filter(|(key, _)| !is_secret_variable(key))
        .collect();
    vars.sort_by_cached_key(|(key, _)| key.to_string_lossy().to_uppercase());
    vars
}

fn shell_environment(extra: Option<(&str, &str)>) -> Vec<u16> {
    let mut block = Vec::new();
    let extra = extra.map(|(name, value)| (OsString::from(name), OsString::from(value)));
    for (name, value) in filtered_environment(std::env::vars_os().chain(extra)) {
        block.extend(name.encode_wide());
        block.push(u16::from(b'='));
        block.extend(value.encode_wide());
        block.push(0);
    }
    if block.is_empty() {
        block.push(0);
    }
    block.push(0);
    block
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removes_tailscale_credentials_case_insensitively() {
        let input = [
            ("Path", "C:\\Windows"),
            ("ts_auth_key", "tskey-auth-1"),
            ("TAILSCALE_API_KEY", "tskey-api-1"),
            ("Tailscale_OAuth_Client_Id", "id"),
            ("TAILSCALE_OAUTH_CLIENT_SECRET", "secret"),
            ("TS_DERP_REGION", "1"),
            ("TS_AUTH_KEY_HINT", "kept"),
        ]
        .map(|(key, value)| (OsString::from(key), OsString::from(value)));
        let kept: Vec<_> = filtered_environment(input)
            .into_iter()
            .map(|(key, _)| key.into_string().unwrap())
            .collect();
        assert_eq!(kept, ["Path", "TS_AUTH_KEY_HINT", "TS_DERP_REGION"]);
    }

    #[test]
    fn clamps_console_size() {
        let size = coord(0, u16::MAX);
        assert_eq!((size.X, size.Y), (1, i16::MAX));
        let size = coord(120, 40);
        assert_eq!((size.X, size.Y), (120, 40));
    }
}
