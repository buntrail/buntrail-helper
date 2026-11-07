#![cfg(unix)]
#![allow(dead_code)]
use serde_json::{Value, json};
use std::{
    fs,
    io::{Read, Write},
    os::unix::net::UnixStream,
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
pub struct Server {
    pub dir: tempfile::TempDir,
    pub child: Child,
    pub socket: PathBuf,
}
impl Server {
    pub fn start() -> Self {
        Self::start_with_setup(|_| {})
    }
    pub fn start_with_setup(setup: impl FnOnce(&std::path::Path)) -> Self {
        let dir = tempfile::tempdir_in("/tmp").unwrap();
        // /tmp may inherit wheel on macOS; fixture files must match the shared save ownership policy.
        std::os::unix::fs::chown(dir.path(), None, Some(unsafe { libc::getegid() })).unwrap();
        let socket = dir.path().join("state/socket");
        setup(socket.parent().unwrap());
        let child = Command::new(env!("CARGO_BIN_EXE_buntrail-helper"))
            .args(["serve", "--socket"])
            .arg(&socket)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let mut s = Self { dir, child, socket };
        let deadline = Instant::now() + Duration::from_secs(3);
        while UnixStream::connect(&s.socket).is_err()
            && Instant::now() < deadline
            && s.child.try_wait().unwrap().is_none()
        {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(s.socket.exists(), "helper must bind protected socket");
        s
    }
    pub fn connect(&self) -> UnixStream {
        let s = UnixStream::connect(&self.socket).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        s
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
pub fn header(kind: &str, metadata: Value) -> Value {
    json!({"major":1,"minor":0,"request_id":1,"context":null,"operation_id":null,"stream_id":null,"sequence":null,"kind":kind,"metadata":metadata})
}
pub fn hello() -> Value {
    header(
        "hello",
        json!({"capabilities":["leases","operations","file.read","file.save","services","terminal"],"max_header":65536,"max_payload":1048576}),
    )
}
pub fn encode(h: &Value, p: &[u8]) -> Vec<u8> {
    let b = serde_json::to_vec(h).unwrap();
    let mut v = (b.len() as u32).to_be_bytes().to_vec();
    v.extend((p.len() as u32).to_be_bytes());
    v.extend(b);
    v.extend(p);
    v
}
pub fn send(s: &mut UnixStream, h: &Value) {
    s.write_all(&encode(h, &[])).unwrap();
}
pub fn receive(s: &mut impl Read) -> (Value, Vec<u8>) {
    let mut p = [0; 8];
    s.read_exact(&mut p).unwrap();
    let n = u32::from_be_bytes(p[..4].try_into().unwrap()) as usize;
    let m = u32::from_be_bytes(p[4..].try_into().unwrap()) as usize;
    assert!(n <= 65536 && m <= 1048576);
    let mut h = vec![0; n];
    s.read_exact(&mut h).unwrap();
    let mut p = vec![0; m];
    s.read_exact(&mut p).unwrap();
    (serde_json::from_slice(&h).unwrap(), p)
}
pub fn register(s: &mut UnixStream) -> Value {
    send(s, &hello());
    let (welcome, _) = receive(s);
    let c = json!({"client_id":"11111111-1111-4111-8111-111111111111","workspace_id":"22222222-2222-4222-8222-222222222222","target_binding":welcome["metadata"]["target_binding"],"runtime_generation":welcome["metadata"]["runtime_generation"]});
    let mut h = header(
        "lease.register",
        json!({"lease_id":"33333333-3333-4333-8333-333333333333","client_id":c["client_id"],"workspace_id":c["workspace_id"],"target_binding":c["target_binding"],"runtime_generation":c["runtime_generation"]}),
    );
    h["request_id"] = json!(2);
    send(s, &h);
    assert_eq!(receive(s).0["kind"], "ack");
    c
}
pub fn golden(name: &str) -> Vec<u8> {
    fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("protocol/v1/golden")
            .join(name),
    )
    .unwrap()
}
