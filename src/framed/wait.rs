use std::{
    io::{self, Read},
    net::Shutdown,
    os::{fd::AsRawFd, unix::net::UnixStream},
    sync::Arc,
    task::{Wake, Waker},
    time::Instant,
};

struct Notify(UnixStream);
impl Notify {
    fn notify(&self) {
        loop {
            #[cfg(target_os = "linux")]
            let flags = libc::MSG_NOSIGNAL;
            #[cfg(not(target_os = "linux"))]
            let flags = 0;
            let byte = [1u8];
            let written = unsafe { libc::send(self.0.as_raw_fd(), byte.as_ptr().cast(), 1, flags) };
            if written == 1 {
                return;
            }
            if written == 0 {
                let _ = self.0.shutdown(Shutdown::Write);
                return;
            }
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            if error.kind() == io::ErrorKind::WouldBlock {
                return;
            }
            // Fail the reader through EOF instead of silently losing a wake or signaling the process.
            let _ = self.0.shutdown(Shutdown::Write);
            return;
        }
    }
}
impl Wake for Notify {
    fn wake(self: Arc<Self>) {
        self.notify();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.notify();
    }
}

pub(crate) struct Signal {
    reader: UnixStream,
    notify: Arc<Notify>,
}
impl Signal {
    pub(crate) fn new() -> io::Result<Self> {
        let (reader, writer) = UnixStream::pair()?;
        reader.set_nonblocking(true)?;
        writer.set_nonblocking(true)?;
        #[cfg(target_os = "macos")]
        {
            let enabled: libc::c_int = 1;
            if unsafe {
                libc::setsockopt(
                    writer.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_NOSIGPIPE,
                    (&enabled as *const libc::c_int).cast(),
                    std::mem::size_of_val(&enabled) as _,
                )
            } != 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(Self {
            reader,
            notify: Arc::new(Notify(writer)),
        })
    }
    pub(crate) fn waker(&self) -> Waker {
        Waker::from(self.notify.clone())
    }
    pub(crate) fn notify(&self) {
        self.notify.notify();
    }
    pub(crate) fn drain(&self) -> io::Result<()> {
        // One bounded read per turn keeps input/control serviceable under continuous wakeups.
        let mut bytes = [0u8; 64];
        loop {
            match (&self.reader).read(&mut bytes) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "wake socket closed",
                    ));
                }
                Ok(_) => return Ok(()),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(e) => return Err(e),
            }
        }
    }
    pub(crate) fn wait(
        &self,
        socket: &impl AsRawFd,
        write: bool,
        deadline: Option<Instant>,
    ) -> io::Result<()> {
        let events = libc::POLLIN | if write { libc::POLLOUT } else { 0 };
        let mut fds = [
            libc::pollfd {
                fd: socket.as_raw_fd(),
                events,
                revents: 0,
            },
            libc::pollfd {
                fd: self.reader.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        loop {
            let timeout = deadline.map_or(-1, |at| {
                at.saturating_duration_since(Instant::now())
                    .as_nanos()
                    .div_ceil(1_000_000)
                    .min(i32::MAX as u128) as i32
            });
            let result = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as _, timeout) };
            if result >= 0 {
                if fds.iter().any(|fd| fd.revents & libc::POLLNVAL != 0) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "closed readiness descriptor",
                    ));
                }
                return Ok(());
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io::Write, sync::mpsc, thread, time::Duration};

    fn socket(stream: &UnixStream, write: bool, deadline: Option<Instant>) -> io::Result<()> {
        Signal::new()?.wait(stream, write, deadline)
    }

    #[test]
    fn quiet_socket_stays_asleep_until_input_instead_of_returning_on_a_poll_tick() {
        let (mut peer, stream) = UnixStream::pair().unwrap();
        let (started, entering) = mpsc::sync_channel(1);
        let (done, completed) = mpsc::sync_channel(1);
        let worker = thread::spawn(move || {
            started.send(()).unwrap();
            done.send(socket(&stream, false, None)).unwrap();
        });
        entering.recv().unwrap();
        let early = completed.recv_timeout(Duration::from_millis(100));
        peer.write_all(b"input").unwrap();
        if early.is_err() {
            completed
                .recv_timeout(Duration::from_secs(2))
                .unwrap()
                .unwrap();
        }
        worker.join().unwrap();
        assert!(
            matches!(early, Err(mpsc::RecvTimeoutError::Timeout)),
            "quiet connection woke without input or a deadline: {early:?}"
        );
    }

    #[test]
    fn quiet_socket_waits_for_its_absolute_deadline() {
        let (_peer, stream) = UnixStream::pair().unwrap();
        let deadline = Instant::now() + Duration::from_millis(100);
        socket(&stream, false, Some(deadline)).unwrap();
        assert!(
            Instant::now() >= deadline,
            "returned before deadline without socket readiness"
        );
    }

    #[test]
    fn peer_eof_wakes_the_connection_wait() {
        let (peer, stream) = UnixStream::pair().unwrap();
        drop(peer);
        socket(&stream, false, None).unwrap();
    }

    #[test]
    fn completion_wake_interrupts_quiet_socket_without_client_input() {
        let (mut peer, stream) = UnixStream::pair().unwrap();
        let signal = Signal::new().unwrap();
        let wake = signal.waker();
        let (started, entering) = mpsc::sync_channel(1);
        let (done, completed) = mpsc::sync_channel(1);
        let worker = thread::spawn(move || {
            started.send(()).unwrap();
            done.send(signal.wait(
                &stream,
                false,
                Some(Instant::now() + Duration::from_secs(5)),
            ))
            .unwrap();
        });
        entering.recv().unwrap();
        assert!(matches!(
            completed.recv_timeout(Duration::from_millis(100)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        wake.wake_by_ref();
        let observed = completed.recv_timeout(Duration::from_secs(1));
        if observed.is_err() {
            peer.write_all(b"cleanup").unwrap();
            completed
                .recv_timeout(Duration::from_secs(2))
                .unwrap()
                .unwrap();
        }
        worker.join().unwrap();
        assert!(
            observed.is_ok(),
            "completion did not wake quiet connection without a new input packet"
        );
    }

    #[test]
    fn wake_published_after_drain_but_before_wait_is_not_lost() {
        let (mut peer, stream) = UnixStream::pair().unwrap();
        let signal = Signal::new().unwrap();
        signal.drain().unwrap();
        signal.notify();
        let (done, completed) = mpsc::sync_channel(1);
        let worker = thread::spawn(move || {
            done.send(signal.wait(
                &stream,
                false,
                Some(Instant::now() + Duration::from_secs(5)),
            ))
            .unwrap()
        });
        let observed = completed.recv_timeout(Duration::from_secs(1));
        if observed.is_err() {
            peer.write_all(b"cleanup").unwrap();
            completed
                .recv_timeout(Duration::from_secs(2))
                .unwrap()
                .unwrap();
        }
        worker.join().unwrap();
        assert!(
            observed.is_ok(),
            "wake lost between state inspection and readiness wait"
        );
    }

    #[test]
    fn drain_leaves_a_bounded_flood_pending_instead_of_starving_control() {
        let signal = Signal::new().unwrap();
        for _ in 0..1024 {
            signal.notify();
        }
        signal.drain().unwrap();
        let mut remaining = [0; 1];
        assert_eq!(
            (&signal.reader).read(&mut remaining).unwrap(),
            1,
            "unbounded drain consumed the entire wake flood"
        );
    }

    #[test]
    fn late_wake_does_not_signal_the_process_or_retain_the_reader() {
        let signal = Signal::new().unwrap();
        let reader = signal.reader.as_raw_fd();
        let writer = signal.notify.0.as_raw_fd();
        let lifetime = Arc::downgrade(&signal.notify);
        let wake = signal.waker();
        drop(signal);
        assert_eq!(unsafe { libc::fcntl(reader, libc::F_GETFD) }, -1);
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EBADF));
        wake.wake_by_ref();
        wake.wake_by_ref();
        drop(wake);
        assert!(lifetime.upgrade().is_none());
        assert_eq!(unsafe { libc::fcntl(writer, libc::F_GETFD) }, -1);
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EBADF));
    }

    #[test]
    fn closed_primary_descriptor_is_an_error_instead_of_a_spin() {
        use std::os::fd::IntoRawFd;
        struct Closed(i32);
        impl AsRawFd for Closed {
            fn as_raw_fd(&self) -> i32 {
                self.0
            }
        }
        let signal = Signal::new().unwrap();
        let (_peer, stream) = UnixStream::pair().unwrap();
        let fd = stream.into_raw_fd();
        assert_eq!(unsafe { libc::close(fd) }, 0);
        let error = signal
            .wait(
                &Closed(fd),
                false,
                Some(Instant::now() + Duration::from_secs(1)),
            )
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn listener_readiness_wakes_without_a_timer_tick() {
        use std::os::unix::net::UnixListener;
        let dir = tempfile::tempdir_in("/tmp").unwrap();
        let path = dir.path().join("listener");
        let listener = UnixListener::bind(&path).unwrap();
        let signal = Signal::new().unwrap();
        let (started, entering) = mpsc::sync_channel(1);
        let (done, completed) = mpsc::sync_channel(1);
        let worker = thread::spawn(move || {
            started.send(()).unwrap();
            done.send(signal.wait(
                &listener,
                false,
                Some(Instant::now() + Duration::from_secs(5)),
            ))
            .unwrap();
        });
        entering.recv().unwrap();
        assert!(matches!(
            completed.recv_timeout(Duration::from_millis(100)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        let _client = UnixStream::connect(&path).unwrap();
        completed
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .unwrap();
        worker.join().unwrap();
    }

    #[test]
    fn input_control_stays_readable_while_the_outbound_socket_is_full() {
        let (mut peer, mut stream) = UnixStream::pair().unwrap();
        stream.set_nonblocking(true).unwrap();
        let mut blocked = false;
        for _ in 0..256 {
            match stream.write(&[0; 65536]) {
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    blocked = true;
                    break;
                }
                Err(error) => panic!("{error}"),
            }
        }
        assert!(blocked, "fixture must actually fill the outbound socket");
        let signal = Signal::new().unwrap();
        let (started, entering) = mpsc::sync_channel(1);
        let (done, completed) = mpsc::sync_channel(1);
        let worker = thread::spawn(move || {
            started.send(()).unwrap();
            let result = signal.wait(&stream, true, Some(Instant::now() + Duration::from_secs(5)));
            let mut control = [0; 7];
            let result = result.and_then(|_| stream.read_exact(&mut control).map(|_| control));
            done.send(result).unwrap();
        });
        entering.recv().unwrap();
        assert!(matches!(
            completed.recv_timeout(Duration::from_millis(100)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        peer.write_all(b"control").unwrap();
        let observed = completed.recv_timeout(Duration::from_secs(1));
        if observed.is_err() {
            drop(peer);
            let _ = completed.recv_timeout(Duration::from_secs(2));
        }
        worker.join().unwrap();
        assert_eq!(observed.unwrap().unwrap(), *b"control");
    }
}
