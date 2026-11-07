#![cfg(unix)]
#[path = "framed_support.rs"]
mod support;
use std::{
    process::{Command, Stdio},
    thread,
};
use support::*;
#[test]
fn supervisor_single_owner() {
    let server = Server::start();
    let socket = server.socket.clone();
    let attempts: Vec<_> = (0..8)
        .map(|_| {
            let p = socket.clone();
            thread::spawn(move || {
                Command::new(env!("CARGO_BIN_EXE_buntrail-helper"))
                    .args(["serve", "--socket"])
                    .arg(p)
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .unwrap()
            })
        })
        .collect();
    for a in attempts {
        assert!(!a.join().unwrap().success());
    }
    let mut s = server.connect();
    send(&mut s, &hello());
    let first = receive(&mut s).0;
    let mut other = server.connect();
    send(&mut other, &hello());
    assert_eq!(
        first["metadata"]["runtime_generation"],
        receive(&mut other).0["metadata"]["runtime_generation"]
    );
}
#[test]
fn spoofed_binding_and_unsafe_state_are_rejected() {
    use serde_json::json;
    use std::{io::Read, os::unix::fs::PermissionsExt};
    let server = Server::start();
    let mut s = server.connect();
    send(&mut s, &hello());
    let _ = receive(&mut s);
    send(
        &mut s,
        &header(
            "lease.register",
            json!({"lease_id":"33333333-3333-4333-8333-333333333333","client_id":"11111111-1111-4111-8111-111111111111","workspace_id":"22222222-2222-4222-8222-222222222222","target_binding":"spoofed","runtime_generation":"11111111-1111-4111-8111-111111111111"}),
        ),
    );
    assert_eq!(s.read(&mut [0; 1]).unwrap(), 0);
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(
        !Command::new(env!("CARGO_BIN_EXE_buntrail-helper"))
            .args(["serve", "--socket"])
            .arg(dir.path().join("socket"))
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success()
    );
}
#[test]
fn idle_supervisor_removes_only_its_socket_after_thirty_seconds() {
    use std::time::{Duration, Instant};
    let mut server = Server::start();
    let started = Instant::now();
    while server.child.try_wait().unwrap().is_none() && started.elapsed() < Duration::from_secs(34)
    {
        thread::sleep(Duration::from_millis(50));
    }
    assert!(started.elapsed() >= Duration::from_secs(29));
    assert!(server.child.try_wait().unwrap().unwrap().success());
    assert!(!server.socket.exists());
    assert!(server.socket.parent().unwrap().join("owner.lock").exists());
}
#[test]
fn incompatible_client_leaves_owner_running_and_stdout_is_protocol_only() {
    use serde_json::json;
    use std::io::Read;
    let server = Server::start();
    let mut s = server.connect();
    let mut h = hello();
    h["major"] = json!(2);
    send(&mut s, &h);
    assert_eq!(s.read(&mut [0; 1]).unwrap(), 0);
    let mut good = server.connect();
    send(&mut good, &hello());
    assert_eq!(receive(&mut good).0["kind"], "welcome");
    let output = Command::new(env!("CARGO_BIN_EXE_buntrail-helper"))
        .arg("probe")
        .output()
        .unwrap();
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["helper"], "buntrail-helper");
    assert!(output.stderr.is_empty());
}
#[test]
fn concurrent_bridges_start_one_detached_owner_without_transport_descriptors() {
    use std::{
        io::Write,
        sync::{Arc, Barrier},
        time::{Duration, Instant},
    };
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    let socket = dir.path().join("state/socket");
    let barrier = Arc::new(Barrier::new(8));
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let socket = socket.clone();
            let barrier = barrier.clone();
            thread::spawn(move || {
                barrier.wait();
                let mut child = Command::new(env!("CARGO_BIN_EXE_buntrail-helper"))
                    .args(["bridge", "--socket"])
                    .arg(&socket)
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .unwrap();
                child
                    .stdin
                    .as_mut()
                    .unwrap()
                    .write_all(&encode(&hello(), &[]))
                    .unwrap();
                use std::os::fd::AsRawFd;
                let mut poll = libc::pollfd {
                    fd: child.stdout.as_ref().unwrap().as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                if unsafe { libc::poll(&mut poll, 1, 5000) } != 1 {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("bridge did not flush protocol response");
                }
                let runtime =
                    receive(child.stdout.as_mut().unwrap()).0["metadata"]["runtime_generation"]
                        .clone();
                drop(child.stdin.take());
                let until = Instant::now() + Duration::from_secs(4);
                while child.try_wait().unwrap().is_none() && Instant::now() < until {
                    thread::sleep(Duration::from_millis(10));
                }
                assert!(
                    child.try_wait().unwrap().is_some(),
                    "supervisor retained bridge descriptors"
                );
                let output = child.wait_with_output().unwrap();
                assert!(output.status.success());
                assert!(output.stderr.is_empty());
                assert!(output.stdout.is_empty());
                runtime
            })
        })
        .collect();
    let runtimes: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    assert!(runtimes.iter().all(|r| r == &runtimes[0]));
    let until = Instant::now() + Duration::from_secs(34);
    while socket.exists() && Instant::now() < until {
        thread::sleep(Duration::from_millis(50));
    }
    assert!(
        !socket.exists(),
        "owned detached supervisor did not exit after idle deadline"
    );
}
#[test]
fn two_workspaces_share_one_bridge_and_release_only_their_lease() {
    use serde_json::json;
    let server = Server::start();
    let mut s = server.connect();
    let first = register(&mut s);
    let mut second = first.clone();
    second["workspace_id"] = json!("66666666-6666-4666-8666-666666666666");
    let mut h = header(
        "lease.register",
        json!({"lease_id":"77777777-7777-4777-8777-777777777777","client_id":second["client_id"],"workspace_id":second["workspace_id"],"target_binding":second["target_binding"],"runtime_generation":second["runtime_generation"]}),
    );
    h["request_id"] = json!(3);
    send(&mut s, &h);
    assert_eq!(receive(&mut s).0["kind"], "ack");
    h = header(
        "lease.release",
        json!({"lease_id":"33333333-3333-4333-8333-333333333333","intent":"resolved_workspace_closure"}),
    );
    h["context"] = first;
    send(&mut s, &h);
    assert_eq!(receive(&mut s).0["kind"], "ack");
    h = header(
        "operation.inspect",
        json!({"operation_id":"44444444-4444-4444-8444-444444444444"}),
    );
    h["context"] = second;
    h["operation_id"] = h["metadata"]["operation_id"].clone();
    send(&mut s, &h);
    assert_eq!(receive(&mut s).0["metadata"]["state"], "unknown");
}

#[test]
fn final_bridge_loss_retains_owner_until_resume_and_resolved_close() {
    use serde_json::json;
    use std::time::{Duration, Instant};
    let mut server = Server::start();
    let mut s = server.connect();
    let first = register(&mut s);
    drop(s);
    thread::sleep(Duration::from_secs(32));
    assert!(
        server.child.try_wait().unwrap().is_none(),
        "retained disconnected lease must outlive the30s transport idle deadline"
    );
    let mut s = server.connect();
    let resumed = register(&mut s);
    assert_eq!(resumed["runtime_generation"], first["runtime_generation"]);
    let mut release = header(
        "lease.release",
        json!({"lease_id":"33333333-3333-4333-8333-333333333333","intent":"resolved_workspace_closure"}),
    );
    release["context"] = resumed;
    release["request_id"] = json!(3);
    send(&mut s, &release);
    assert_eq!(receive(&mut s).0["kind"], "ack");
    drop(s);
    let start = Instant::now();
    while server.child.try_wait().unwrap().is_none() && start.elapsed() < Duration::from_secs(34) {
        thread::sleep(Duration::from_millis(50));
    }
    assert!(start.elapsed() >= Duration::from_secs(29));
    assert!(server.child.try_wait().unwrap().unwrap().success());
    assert!(!server.socket.exists());
}
