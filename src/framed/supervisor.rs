use crate::framed::{dispatcher::Dispatcher, leases::Leases};
use buntrail_services::connections::local::identity;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::{
        fd::AsRawFd,
        unix::{
            fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
            net::{UnixListener, UnixStream},
            process::CommandExt,
        },
    },
    path::Path,
    process::{Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant, SystemTime},
};
pub const IDLE: Duration = Duration::from_secs(30);
#[cfg(all(test, target_os = "linux"))]
mod linux_socket_tests {
    use super::*;
    #[test]
    fn linux_long_socket_keeps_live_peer_and_rejects_unsafe_state() {
        let fixture = tempfile::tempdir().unwrap();
        let parent = fixture.path().join("long-private-directory-".repeat(6));
        private(&parent).unwrap();
        let path = parent.join("supervisor.sock");
        assert!(path.as_os_str().len() > 107);
        assert!(UnixListener::bind(&path).is_err());
        let listener = socket_call(&path, |address| UnixListener::bind(address)).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let before = fs::symlink_metadata(&path).unwrap().ino();
        let client = checked_connect(&path).unwrap();
        let (server, _) = listener.accept().unwrap();
        drop((client, server));
        assert!(
            serve(&path)
                .unwrap_err()
                .to_string()
                .contains("live supervisor remains running")
        );
        assert_eq!(fs::symlink_metadata(&path).unwrap().ino(), before);
        let _connection = listener.accept().unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(checked_connect(&path).is_err());
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(private(&parent).is_err());
        let alias = fixture.path().join("parent-alias");
        std::os::unix::fs::symlink(&parent, &alias).unwrap();
        assert!(
            socket_call(&alias.join("supervisor.sock"), |address| {
                UnixStream::connect(address)
            })
            .is_err()
        );
    }
}
pub(crate) fn error(message: impl std::fmt::Display) -> io::Error {
    io::Error::other(message.to_string())
}
pub fn uuid(id: [u8; 16]) -> String {
    let s = hex(&id);
    format!(
        "{}-{}-{}-{}-{}",
        &s[..8],
        &s[8..12],
        &s[12..16],
        &s[16..20],
        &s[20..]
    )
}
pub(crate) fn hex(b: &[u8]) -> String {
    b.iter().map(|v| format!("{v:02x}")).collect()
}
pub(crate) fn id(s: &str) -> io::Result<[u8; 16]> {
    if !buntrail_protocol::types::uuid(s) {
        return Err(error("invalid UUID"));
    }
    let s = s.replace('-', "");
    let mut bytes = [0; 16];
    for (i, v) in bytes.iter_mut().enumerate() {
        *v = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(error)?;
    }
    Ok(bytes)
}
fn private(path: &Path) -> io::Result<()> {
    match fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }
    let m = fs::symlink_metadata(path)?;
    if !m.is_dir() || m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o077 != 0 {
        return Err(error("state directory must be private and user-owned"));
    }
    Ok(())
}
fn lock_file(directory: &Path, name: &str) -> io::Result<File> {
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(directory.join(name))?;
    let m = f.metadata()?;
    if !m.is_file()
        || m.uid() != unsafe { libc::geteuid() }
        || m.mode() & 0o077 != 0
        || m.nlink() != 1
    {
        return Err(error("unsafe lock file"));
    }
    Ok(f)
}
fn peer(s: &UnixStream) -> io::Result<()> {
    #[cfg(target_os = "macos")]
    let uid = {
        let mut uid = 0;
        let mut gid = 0;
        if unsafe { libc::getpeereid(s.as_raw_fd(), &mut uid, &mut gid) } != 0 {
            return Err(io::Error::last_os_error());
        }
        uid
    };
    #[cfg(target_os = "linux")]
    let uid = {
        let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
        let mut n = std::mem::size_of_val(&cred) as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                s.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut cred as *mut libc::ucred).cast(),
                &mut n,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        cred.uid
    };
    if uid != unsafe { libc::geteuid() } {
        return Err(error("socket peer user mismatch"));
    }
    Ok(())
}
fn checked_connect(socket: &Path) -> io::Result<UnixStream> {
    let m = fs::symlink_metadata(socket)?;
    if !m.file_type().is_socket() || m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o077 != 0
    {
        return Err(error("unsafe supervisor socket"));
    }
    let s = socket_call(socket, |address| UnixStream::connect(address))?;
    peer(&s)?;
    Ok(s)
}
fn socket_call<T>(socket: &Path, call: impl FnOnce(&Path) -> io::Result<T>) -> io::Result<T> {
    #[cfg(target_os = "linux")]
    {
        // Keep the verified directory pinned without spending sun_path on its absolute name.
        let parent = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(
                socket
                    .parent()
                    .ok_or_else(|| error("socket parent missing"))?,
            )?;
        let address = std::path::PathBuf::from(format!("/proc/self/fd/{}", parent.as_raw_fd()))
            .join(
                socket
                    .file_name()
                    .ok_or_else(|| error("socket name missing"))?,
            );
        call(&address)
    }
    #[cfg(not(target_os = "linux"))]
    call(socket)
}
pub fn bridge(socket: &Path) -> io::Result<()> {
    bridge_with_peer(socket, None)
}
pub(crate) fn bridge_with_peer(socket: &Path, peer_key: Option<&str>) -> io::Result<()> {
    bridge_with_binding(socket, peer_key, None)
}
pub(crate) fn bridge_with_container(
    socket: &Path,
    binding: &buntrail_services::connections::container_identity::ContainerBinding,
) -> io::Result<()> {
    binding.current_target().map_err(error)?;
    bridge_with_binding(socket, None, Some(binding))
}
fn bridge_with_binding(
    socket: &Path,
    peer_key: Option<&str>,
    container: Option<&buntrail_services::connections::container_identity::ContainerBinding>,
) -> io::Result<()> {
    if !socket.is_absolute() {
        return Err(error("socket path must be absolute"));
    }
    let parent = socket
        .parent()
        .ok_or_else(|| error("socket parent missing"))?;
    private(parent)?;
    let startup = lock_file(parent, "startup.lock")?;
    startup.lock()?;
    let stream = match checked_connect(socket) {
        Ok(s) => s,
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
            ) =>
        {
            let mut cmd = Command::new(std::env::current_exe()?);
            cmd.arg(if container.is_some() {
                "serve-container"
            } else if peer_key.is_some() {
                "serve-ssh"
            } else {
                "serve"
            })
            .arg("--socket")
            .arg(socket)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
            if let Some(peer) = peer_key {
                cmd.arg("--peer-key").arg(peer);
            }
            if let Some(binding) = container {
                use base64::{Engine, engine::general_purpose::STANDARD};
                cmd.arg("--binding")
                    .arg(STANDARD.encode(serde_json::to_vec(binding).map_err(error)?));
            }
            let max = unsafe { libc::sysconf(libc::_SC_OPEN_MAX) };
            // Only async-signal-safe syscalls run between fork and exec; every inherited nonstdio fd closes at exec.
            unsafe {
                cmd.pre_exec(move || {
                    if libc::setsid() < 0 {
                        return Err(io::Error::last_os_error());
                    }
                    for fd in 3..max {
                        libc::fcntl(fd as i32, libc::F_SETFD, libc::FD_CLOEXEC);
                    }
                    Ok(())
                });
            }
            let mut child = cmd.spawn()?;
            let until = Instant::now() + Duration::from_secs(5);
            let stream = loop {
                if let Ok(s) = checked_connect(socket) {
                    break s;
                }
                if child.try_wait()?.is_some() || Instant::now() >= until {
                    return Err(error("supervisor startup failed"));
                }
                std::thread::sleep(Duration::from_millis(10));
            };
            std::thread::spawn(move || {
                let _ = child.wait();
            });
            stream
        }
        Err(e) => return Err(e),
    };
    startup.unlock()?;
    let mut input = stream.try_clone()?;
    std::thread::spawn(move || {
        let _ = io::copy(&mut io::stdin().lock(), &mut input);
        let _ = input.shutdown(std::net::Shutdown::Write);
    });
    let mut stream = stream;
    let mut stdout = io::stdout().lock();
    let mut bytes = [0; 65536];
    loop {
        let n = stream.read(&mut bytes)?;
        if n == 0 {
            break;
        }
        stdout.write_all(&bytes[..n])?;
        stdout.flush()?;
    }
    Ok(())
}
struct IdleClock {
    since: Instant,
    had_owners: bool,
}
impl IdleClock {
    fn new(now: Instant) -> Self {
        Self {
            since: now,
            had_owners: false,
        }
    }
    fn observe(&mut self, owners: bool, now: Instant) {
        if owners || self.had_owners {
            self.since = now;
        }
        self.had_owners = owners;
    }
    fn deadline(&self) -> Instant {
        self.since + IDLE
    }
}

pub(crate) struct Shared {
    pub wake: crate::framed::wait::Signal,
    pub directory: std::path::PathBuf,
    pub dispatcher: Arc<Dispatcher>,
    pub leases: Mutex<Leases>,
    pub runtime: String,
    pub binding: String,
    pub clients: AtomicUsize,
    pub workers: AtomicUsize,
    pub controls: AtomicUsize,
    pub requests: AtomicUsize,
    pub watchers: AtomicUsize,
    pub searches: AtomicUsize,
    pub mutation_admission_closed: AtomicBool,
}
impl Shared {
    fn has_owners(&self, now: Instant) -> io::Result<bool> {
        let mut leases = self.leases.lock().map_err(error)?;
        self.dispatcher.terminal.expire(&mut leases, now);
        Ok(self.dispatcher.terminal.service.has_sessions()
            || !leases.is_empty()
            || self.clients.load(Ordering::SeqCst) != 0
            || self.workers.load(Ordering::SeqCst) != 0
            || self.controls.load(Ordering::SeqCst) != 0
            || self.requests.load(Ordering::SeqCst) != 0
            || self.watchers.load(Ordering::SeqCst) != 0
            || self.searches.load(Ordering::SeqCst) != 0)
    }
    fn next_wake(
        &self,
        idle: Option<Instant>,
        reap: Instant,
        maintenance: Instant,
        now: Instant,
    ) -> io::Result<Instant> {
        let mut at = reap.min(maintenance);
        if let Some(idle) = idle {
            at = at.min(idle);
        }
        if let Some(expiry) = self.leases.lock().map_err(error)?.next_expiration() {
            at = at.min(expiry);
        }
        // PTY workers still expose retirement through the existing bounded readiness check.
        if self.dispatcher.terminal.service.has_sessions() {
            at = at.min(now + Duration::from_millis(5));
        }
        Ok(at)
    }
    fn maintain(&self, now: SystemTime) {
        let result = sweep_uploads(&self.directory.join("uploads"), now)
            .and_then(|_| self.dispatcher.compact(&self.directory).map_err(error));
        self.mutation_admission_closed
            .store(result.is_err(), Ordering::SeqCst);
        if result.is_err() {
            // The caller retries once per minute; existing workers and control traffic retain ownership.
            eprintln!("buntrail-helper: maintenance failed; mutation admission paused");
        }
    }
}
struct Count(Arc<Shared>);
impl Drop for Count {
    fn drop(&mut self) {
        self.0.clients.fetch_sub(1, Ordering::SeqCst);
        self.0.wake.notify();
    }
}
pub fn serve(socket: &Path) -> io::Result<()> {
    serve_with_peer(socket, None)
}
pub fn serve_with_peer(socket: &Path, peer_key: Option<&str>) -> io::Result<()> {
    let target = identity().map_err(error)?;
    let target = if let Some(peer) = peer_key {
        buntrail_services::connections::bootstrap::Platform::current().map_err(error)?;
        buntrail_services::connections::bootstrap::ssh_identity(target, peer).map_err(error)?
    } else {
        target
    };

    serve_target(socket, target, None)
}
pub fn serve_with_container(
    socket: &Path,
    binding: &buntrail_services::connections::container_identity::ContainerBinding,
) -> io::Result<()> {
    serve_target(
        socket,
        binding.current_target().map_err(error)?,
        binding.start_generation.clone(),
    )
}
fn serve_target(
    socket: &Path,
    target: buntrail_core::contracts::TargetIdentity,
    start: Option<Vec<u8>>,
) -> io::Result<()> {
    if !socket.is_absolute() {
        return Err(error("socket path must be absolute"));
    }
    let parent = socket
        .parent()
        .ok_or_else(|| error("socket parent missing"))?;
    private(parent)?;
    let owner = lock_file(parent, "owner.lock")?;
    owner.try_lock().map_err(error)?;
    if let Ok(m) = fs::symlink_metadata(socket) {
        if !m.file_type().is_socket() || m.uid() != unsafe { libc::geteuid() } {
            return Err(error("unsafe stale socket"));
        }
        match socket_call(socket, |address| UnixStream::connect(address)) {
            Ok(_) => return Err(error("live supervisor remains running")),
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound
                ) => {}
            Err(e) => return Err(e),
        }
        fs::remove_file(socket)?;
    }
    let binding = hex(&Sha256::digest(serde_json::to_vec(&target).map_err(error)?));
    let dispatcher =
        Arc::new(Dispatcher::new_with_start(target, parent.join("files"), start).map_err(error)?);
    #[cfg(feature = "test-support")]
    if std::env::var_os("BUNTRAIL_FIXTURE_SAVE_COMPLETION_LOSS").as_deref()
        == Some(std::ffi::OsStr::new("1"))
    {
        dispatcher
            .files
            .set_failpoint(buntrail_services::files::FailPoint::Completion);
    }
    let runtime = uuid(dispatcher.terminal.runtime.supervisor_boot);
    let shared = Arc::new(Shared {
        wake: crate::framed::wait::Signal::new()?,
        directory: parent.to_path_buf(),
        dispatcher,
        leases: Mutex::new(Leases::default()),
        runtime,
        binding,
        clients: AtomicUsize::new(0),
        workers: AtomicUsize::new(0),
        controls: AtomicUsize::new(0),
        requests: AtomicUsize::new(0),
        watchers: AtomicUsize::new(0),
        searches: AtomicUsize::new(0),
        mutation_admission_closed: AtomicBool::new(false),
    });
    private(&parent.join("uploads"))?;
    let listener = socket_call(socket, |address| UnixListener::bind(address))?;
    fs::set_permissions(socket, fs::Permissions::from_mode(0o600))?;
    listener.set_nonblocking(true)?;
    let inode = fs::symlink_metadata(socket)?.ino();
    let mut next = 0;
    let mut idle = IdleClock::new(Instant::now());
    let mut maintenance = Instant::now();
    let mut proof_reaping = Instant::now();
    shared.maintain(SystemTime::now());
    loop {
        shared.wake.drain()?;
        match listener.accept() {
            Ok((stream, _)) => {
                idle.since = Instant::now();
                if peer(&stream).is_ok() && shared.clients.load(Ordering::SeqCst) < 32 {
                    next += 1;
                    let serial = next;
                    shared.clients.fetch_add(1, Ordering::SeqCst);
                    idle.observe(true, Instant::now());
                    let state = shared.clone();
                    std::thread::spawn(move || {
                        let _count = Count(state.clone());
                        let _ = crate::framed::transport::connection(stream, &state, serial);
                        if let Ok(mut leases) = state.leases.lock() {
                            leases.disconnect(serial, Instant::now());
                        }
                        state.dispatcher.git.reap_observations();
                    });
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e),
        }
        let now = Instant::now();
        let owners = shared.has_owners(now)?;
        idle.observe(owners, now);
        if !owners && now >= idle.deadline() {
            break;
        }
        if proof_reaping.elapsed() >= Duration::from_secs(1) {
            shared.dispatcher.git.reap_observations();
            proof_reaping = Instant::now();
        }
        if maintenance.elapsed() >= Duration::from_secs(60) {
            shared.maintain(SystemTime::now());
            maintenance = Instant::now();
        }
        let deadline = shared.next_wake(
            (!owners).then(|| idle.deadline()),
            proof_reaping + Duration::from_secs(1),
            maintenance + Duration::from_secs(60),
            Instant::now(),
        )?;
        shared.wake.wait(&listener, false, Some(deadline))?;
    }
    if fs::symlink_metadata(socket).is_ok_and(|m| m.ino() == inode) {
        fs::remove_file(socket)?;
    }
    drop(owner);
    Ok(())
}

fn sweep_uploads(directory: &Path, now: SystemTime) -> io::Result<()> {
    for entry in fs::read_dir(directory)? {
        sweep_upload(&entry?.path(), now)?;
    }
    Ok(())
}
fn sweep_upload(path: &Path, now: SystemTime) -> io::Result<()> {
    let file = match OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    sweep_open_upload(path, file, now)
}
fn sweep_open_upload(path: &Path, file: File, now: SystemTime) -> io::Result<()> {
    let m = file.metadata()?;
    if !m.is_file() || m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o077 != 0 {
        return Err(error("unsafe upload staging"));
    }
    if now.duration_since(m.modified()?).unwrap_or_default() < Duration::from_secs(600) {
        return Ok(());
    }
    match file.try_lock() {
        Ok(()) => {
            match fs::remove_file(path) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
                Err(e) => return Err(e),
            }
            File::open(
                path.parent()
                    .ok_or_else(|| error("missing staging parent"))?,
            )?
            .sync_all()?;
        }
        Err(std::fs::TryLockError::WouldBlock) => {}
        Err(e) => return Err(error(e)),
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn shared_fixture() -> (tempfile::TempDir, Arc<Shared>) {
        let dir = tempfile::tempdir().unwrap();
        let shared = Arc::new(Shared {
            wake: crate::framed::wait::Signal::new().unwrap(),
            directory: dir.path().into(),
            dispatcher: Arc::new(
                Dispatcher::new(identity().unwrap(), dir.path().join("files")).unwrap(),
            ),
            leases: Mutex::new(Leases::default()),
            runtime: "runtime".into(),
            binding: "target".into(),
            clients: AtomicUsize::new(0),
            workers: AtomicUsize::new(0),
            controls: AtomicUsize::new(0),
            requests: AtomicUsize::new(0),
            watchers: AtomicUsize::new(0),
            searches: AtomicUsize::new(0),
            mutation_admission_closed: AtomicBool::new(false),
        });
        (dir, shared)
    }

    #[test]
    fn expired_upload_cleanup_keeps_owned_staging() {
        let dir = tempfile::tempdir().unwrap();
        let owned = tempfile::NamedTempFile::new_in(dir.path()).unwrap();
        owned.as_file().lock().unwrap();
        let abandoned = tempfile::NamedTempFile::new_in(dir.path())
            .unwrap()
            .keep()
            .unwrap();
        drop(abandoned.0);
        sweep_uploads(dir.path(), SystemTime::now() + Duration::from_secs(601)).unwrap();
        assert!(owned.path().exists());
        assert!(!abandoned.1.exists());
    }
    #[test]
    fn disappearing_staging_between_enumeration_and_open_is_benign() {
        let dir = tempfile::tempdir().unwrap();
        let temporary = tempfile::NamedTempFile::new_in(dir.path()).unwrap();
        let path = fs::read_dir(dir.path())
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        drop(temporary);
        sweep_upload(&path, SystemTime::now() + Duration::from_secs(601)).unwrap();
    }
    #[test]
    fn disappearing_staging_between_open_and_remove_is_benign() {
        let dir = tempfile::tempdir().unwrap();
        let temporary = tempfile::NamedTempFile::new_in(dir.path()).unwrap();
        let path = temporary.path().to_path_buf();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        drop(temporary);
        sweep_open_upload(&path, file, SystemTime::now() + Duration::from_secs(601)).unwrap();
    }

    #[test]
    fn retained_lease_expiry_precedes_idle_eligibility_at_exact_deadline() {
        use buntrail_protocol::types::Context;
        let (_directory, shared) = shared_fixture();
        let now = Instant::now();
        assert!(!shared.has_owners(now).unwrap());
        let context = Context {
            client_id: "client".into(),
            workspace_id: "workspace".into(),
            target_binding: "target".into(),
            runtime_generation: "runtime".into(),
        };
        {
            let mut leases = shared.leases.lock().unwrap();
            leases.register("lease".into(), context, 1).unwrap();
            leases.disconnect(1, now);
        }
        assert_eq!(crate::framed::leases::RETENTION, Duration::from_secs(1800));
        assert!(
            shared
                .has_owners(now + crate::framed::leases::RETENTION - Duration::from_nanos(1))
                .unwrap()
        );
        assert!(
            !shared
                .has_owners(now + crate::framed::leases::RETENTION)
                .unwrap()
        );
    }

    #[test]
    fn final_client_count_drop_wakes_a_quiet_supervisor_after_decrement() {
        use std::sync::mpsc;
        let (_directory, shared) = shared_fixture();
        shared.clients.store(1, Ordering::SeqCst);
        let (mut peer, stream) = UnixStream::pair().unwrap();
        let (started, entering) = mpsc::sync_channel(1);
        let (done, completed) = mpsc::sync_channel(1);
        let waiting = shared.clone();
        let worker = std::thread::spawn(move || {
            started.send(()).unwrap();
            waiting
                .wake
                .wait(
                    &stream,
                    false,
                    Some(Instant::now() + Duration::from_secs(5)),
                )
                .unwrap();
            done.send(waiting.clients.load(Ordering::SeqCst)).unwrap();
        });
        entering.recv().unwrap();
        assert!(matches!(
            completed.recv_timeout(Duration::from_millis(100)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        drop(Count(shared.clone()));
        let observed = completed.recv_timeout(Duration::from_secs(1));
        if observed.is_err() {
            peer.write_all(b"cleanup").unwrap();
            completed.recv_timeout(Duration::from_secs(2)).unwrap();
        }
        worker.join().unwrap();
        assert_eq!(
            observed.ok(),
            Some(0),
            "last client drop failed to wake or published before decrement"
        );
    }

    #[test]
    fn event_wait_owner_transition_gets_a_full_thirty_seconds_not_a_stale_sample() {
        let now = Instant::now();
        let mut idle = IdleClock::new(now);
        idle.observe(true, now);
        idle.observe(false, now + Duration::from_secs(1));
        assert!(
            now + Duration::from_secs(30) < idle.deadline(),
            "long quiet wait reused the previous owner sample and retired early"
        );
        assert_eq!(idle.deadline(), now + Duration::from_secs(31));
        idle.observe(false, now + Duration::from_secs(2));
        assert_eq!(
            idle.deadline(),
            now + Duration::from_secs(31),
            "unchanged idle state must not push retirement forever"
        );
    }

    #[test]
    fn event_wait_earliest_existing_timer_replaces_unrelated_poll_ticks() {
        use buntrail_protocol::types::Context;
        let (_directory, shared) = shared_fixture();
        let now = Instant::now();
        let at = |seconds| now + Duration::from_secs(seconds);
        assert_eq!(
            shared.next_wake(Some(at(30)), at(1), at(60), now).unwrap(),
            at(1)
        );
        assert_eq!(
            shared.next_wake(Some(at(30)), at(20), at(5), now).unwrap(),
            at(5)
        );
        assert_eq!(
            shared.next_wake(Some(at(2)), at(20), at(60), now).unwrap(),
            at(2)
        );
        let context = Context {
            client_id: "c".into(),
            workspace_id: "w".into(),
            target_binding: "t".into(),
            runtime_generation: "r".into(),
        };
        let mut leases = shared.leases.lock().unwrap();
        leases.register("lease".into(), context, 1).unwrap();
        leases.disconnect(1, now - Duration::from_secs(1799));
        drop(leases);
        assert_eq!(shared.next_wake(None, at(20), at(60), now).unwrap(), at(1));
    }
}
