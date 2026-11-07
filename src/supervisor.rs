//! A per-user private Unix socket retains service state after a transport disconnect.
use crate::serve_session;
use buntrail_services::Services;
use std::{
    fs, io,
    os::unix::{
        fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt},
        net::{UnixListener, UnixStream},
        process::CommandExt,
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub const RETENTION: Duration = Duration::from_secs(1800);

pub fn default_socket() -> io::Result<PathBuf> {
    let base = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache")))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "HOME or XDG_RUNTIME_DIR is required",
            )
        })?;
    Ok(base
        .join("id.bungamungil.buntrail.app")
        .join("helper-v1.sock"))
}
fn private_parent(path: &Path) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("socket requires a parent directory"))?;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(parent)?;
    let metadata = fs::symlink_metadata(parent)?;
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::getuid() }
        || metadata.mode() & 0o077 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "helper socket parent must be a private directory owned by this user",
        ));
    }
    Ok(())
}
fn validate_socket(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != unsafe { libc::getuid() }
        || metadata.mode() & 0o077 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "helper endpoint is not a private socket owned by this user",
        ));
    }
    Ok(())
}
pub fn bridge(path: &Path) -> io::Result<()> {
    private_parent(path)?;
    let stream = match connect(path) {
        Ok(stream) => stream,
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
            ) =>
        {
            let mut command = Command::new(std::env::current_exe()?);
            command
                .arg("--supervisor")
                .arg(path)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            unsafe {
                command.pre_exec(|| {
                    if libc::setsid() < 0 {
                        return Err(io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            let mut child = command.spawn()?;
            let until = Instant::now() + Duration::from_secs(10);
            loop {
                if let Ok(stream) = connect(path) {
                    break stream;
                }
                if Instant::now() >= until {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "helper supervisor startup timed out",
                    ));
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        }
        Err(error) => return Err(error),
    };
    let mut writer = stream.try_clone()?;
    let input = std::thread::spawn(move || {
        let result = io::copy(&mut io::stdin().lock(), &mut writer);
        let _ = writer.shutdown(std::net::Shutdown::Write);
        result
    });
    let mut reader = stream;
    let result = io::copy(&mut reader, &mut io::stdout().lock());
    // On ordinary EOF, the input thread has already completed. Avoid waiting forever
    // for a disconnected remote's still-open stdin after a supervisor failure.
    if input.is_finished() {
        let _ = input.join();
    }
    result.map(|_| ())
}
fn connect(path: &Path) -> io::Result<UnixStream> {
    validate_socket(path)?;
    UnixStream::connect(path)
}

pub fn run(path: &Path, retention: Duration) -> io::Result<()> {
    private_parent(path)?;
    if path.exists() {
        validate_socket(path)?;
        match UnixStream::connect(path) {
            Ok(_) => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
                fs::remove_file(path)?
            }
            Err(error) => return Err(error),
        }
    }
    let listener = UnixListener::bind(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    listener.set_nonblocking(true)?;
    let services = Arc::new(Services::new());
    let clients = Arc::new(AtomicUsize::new(0));
    let last_disconnect = Arc::new(Mutex::new(Instant::now()));
    let instance = format!(
        "{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_nanos()
    );
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false)?;
                let services = services.clone();
                let clients = clients.clone();
                let last_disconnect = last_disconnect.clone();
                let instance = instance.clone();
                clients.fetch_add(1, Ordering::SeqCst);
                std::thread::spawn(move || {
                    if let Ok(input) = stream.try_clone() {
                        let _ = serve_session(input, stream, &services, &instance);
                    }
                    if let Ok(mut last) = last_disconnect.lock() {
                        *last = Instant::now();
                    }
                    clients.fetch_sub(1, Ordering::SeqCst);
                });
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if clients.load(Ordering::SeqCst) == 0
                    && last_disconnect
                        .lock()
                        .map_err(|_| io::Error::other("supervisor state poisoned"))?
                        .elapsed()
                        >= retention
                {
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(error) => return Err(error),
        }
    }
    drop(listener);
    fs::remove_file(path)?;
    Ok(())
}
