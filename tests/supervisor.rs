#![cfg(unix)]
use buntrail_helper::supervisor;
use serde_json::{Value, json};
use std::{
    io::{Read, Write},
    os::unix::net::UnixStream,
    time::{Duration, Instant},
};
fn call(stream: &mut UnixStream, value: Value) -> Value {
    let bytes = serde_json::to_vec(&value).unwrap();
    stream
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .unwrap();
    stream.write_all(&bytes).unwrap();
    let mut length = [0; 4];
    stream.read_exact(&mut length).unwrap();
    let mut bytes = vec![0; u32::from_be_bytes(length) as usize];
    stream.read_exact(&mut bytes).unwrap();
    let reply: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(reply["ok"], true, "{reply}");
    reply["value"].clone()
}
#[test]
fn reconnect_retains_real_terminal_then_lease_expiry_reaps_it() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = dir.path().join("helper.sock");
    let supervisor_path = path.clone();
    let server = std::thread::spawn(move || {
        supervisor::run(&supervisor_path, Duration::from_millis(200)).unwrap()
    });
    let until = Instant::now() + Duration::from_secs(3);
    let mut first = loop {
        if let Ok(stream) = UnixStream::connect(&path) {
            break stream;
        }
        assert!(Instant::now() < until, "supervisor failed to start");
        std::thread::sleep(Duration::from_millis(10));
    };
    first
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let identity = call(&mut first, json!({"protocol":1}))["instance"].clone();
    let id = call(
        &mut first,
        json!({"command":"terminal.start","root":dir.path(),"shell":"/bin/sh"}),
    )["id"]
        .clone();
    call(
        &mut first,
        json!({"command":"terminal.write","id":id,"text":"printf '\nLEASE_PID=%s\n' $$\n"}),
    );
    drop(first);
    let mut second = UnixStream::connect(&path).unwrap();
    second
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    assert_eq!(
        call(&mut second, json!({"protocol":1}))["instance"],
        identity
    );
    let mut output = String::new();
    let until = Instant::now() + Duration::from_secs(3);
    let pid = loop {
        output.push_str(
            call(&mut second, json!({"command":"terminal.read","id":id}))["output"]
                .as_str()
                .unwrap(),
        );
        if let Some(pid) = output.lines().find_map(|line| {
            line.trim()
                .strip_prefix("LEASE_PID=")
                .and_then(|pid| pid.parse::<i32>().ok())
        }) {
            break pid;
        }
        assert!(Instant::now() < until, "{output}");
        std::thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(unsafe { libc::kill(pid, 0) }, 0);
    drop(second);
    server.join().unwrap();
    assert!(!path.exists());
    assert_eq!(
        unsafe { libc::kill(pid, 0) },
        -1,
        "terminal survived lease expiry"
    );
}
#[test]
fn rejects_public_socket_directory() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(
        supervisor::run(&dir.path().join("socket"), Duration::ZERO)
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::PermissionDenied
    );
}
