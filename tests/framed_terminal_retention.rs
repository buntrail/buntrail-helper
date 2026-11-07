#![cfg(unix)]
#[path = "framed_support.rs"]
mod support;
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use serde_json::{Value, json};
use std::os::unix::net::UnixStream;
use support::*;

const LEASE: &str = "33333333-3333-4333-8333-333333333333";
const SESSION: &str = "44444444-4444-4444-8444-444444444444";
const OP: &str = "55555555-5555-4555-8555-555555555555";
fn call(s: &mut UnixStream, context: &Value, n: u64, mut value: Value) -> Value {
    use std::io::Write;
    let bytes = if value["method"] == "terminal_input" {
        B64.decode(
            value
                .as_object_mut()
                .unwrap()
                .remove("bytes_base64")
                .unwrap()
                .as_str()
                .unwrap(),
        )
        .unwrap()
    } else {
        Vec::new()
    };
    let mut h = header("service.call", json!({"call":value}));
    h["context"] = context.clone();
    h["request_id"] = json!(n);
    if value["method"] == "terminal_open" || value["method"] == "inspect" {
        h["operation_id"] = json!(OP);
    }
    s.write_all(&encode(&h, &bytes)).unwrap();
    let (response, payload) = receive(s);
    assert_eq!(response["kind"], "service.event", "{response}");
    credit(s, &response, payload.len());
    serde_json::from_slice(&payload).unwrap()
}
fn launch(s: &mut UnixStream, c: &Value, server: &Server) -> Value {
    call(
        s,
        c,
        3,
        json!({"method":"terminal_open","lease_id":LEASE,"session_id":SESSION,
        "directory_base64":B64.encode(server.dir.path().as_os_str().as_encoded_bytes()),
        "shell_base64":B64.encode(b"/bin/sh"),"columns":80,"rows":24}),
    )
}
#[test]
fn last_client_disconnect_retention() {
    let server = Server::start();
    let mut a = server.connect();
    let c = register(&mut a);
    let receipt = launch(&mut a, &c, &server);
    assert_eq!(receipt["receipt"]["state"], "confirmed");
    drop(a);
    let mut b = server.connect();
    let c2 = register(&mut b);
    assert_eq!(c["runtime_generation"], c2["runtime_generation"]);
    let inspected = call(&mut b, &c2, 4, json!({"method":"inspect"}));
    assert_eq!(inspected["receipt"]["result"]["session_id"], SESSION);
    let end = call(
        &mut b,
        &c2,
        5,
        json!({"method":"terminal_end","lease_id":LEASE,"session_id":SESSION,"intent":"explicit_close"}),
    );
    assert_eq!(end["kind"], "terminal_ack");
}
#[test]
fn replay_gap_and_no_input_replay() {
    let server = Server::start();
    let mut a = server.connect();
    let c = register(&mut a);
    assert_eq!(launch(&mut a, &c, &server)["receipt"]["state"], "confirmed");
    let r = call(
        &mut a,
        &c,
        4,
        json!({"method":"terminal_input","lease_id":LEASE,"session_id":SESSION,"bytes_base64":B64.encode(b"printf 'retained-once\\n'; exit\n")}),
    );
    assert_eq!(r["kind"], "terminal_ack");
    drop(a);
    let mut b = server.connect();
    let c = register(&mut b);
    let attached = call(
        &mut b,
        &c,
        5,
        json!({"method":"terminal_attach","lease_id":LEASE,"session_id":SESSION,"last_output_sequence":0}),
    );
    assert_eq!(attached["event"]["kind"], "reattached");
}

fn wait_file(path: &std::path::Path) -> String {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    loop {
        if let Ok(s) = std::fs::read_to_string(path)
            && !s.is_empty()
        {
            return s;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "fixture output missing: {}",
            path.display()
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}
#[test]
fn launch_authentication_snapshot_does_not_rewrite_existing_shell() {
    let server = Server::start();
    let mut socket = server.connect();
    let c = register(&mut socket);
    let auth = |s: &mut UnixStream, n, path: Option<&[u8]>| {
        let mut h = header(
            "connection.authentication",
            json!({"ssh_auth_sock":path.map(|p|B64.encode(p))}),
        );
        h["request_id"] = json!(n);
        h["context"] = c.clone();
        send(s, &h);
        assert_eq!(receive(s).0["kind"], "ack");
    };
    auth(
        &mut socket,
        10,
        Some(b"/private/tmp/buntrail-fake-agent-old"),
    );
    assert_eq!(
        launch(&mut socket, &c, &server)["receipt"]["state"],
        "confirmed"
    );
    auth(
        &mut socket,
        11,
        Some(b"/private/tmp/buntrail-fake-agent-new"),
    );
    assert_eq!(
        launch(&mut socket, &c, &server)["receipt"]["state"],
        "confirmed"
    );
    call(
        &mut socket,
        &c,
        12,
        json!({"method":"terminal_input","lease_id":LEASE,"session_id":SESSION,"bytes_base64":B64.encode(b"printf '%s' \"${SSH_AUTH_SOCK-unset}\" > old-env\n")}),
    );
    let old = wait_file(&server.dir.path().join("old-env"));
    call(
        &mut socket,
        &c,
        13,
        json!({"method":"terminal_end","lease_id":LEASE,"session_id":SESSION,"intent":"explicit_close"}),
    );
    assert_eq!(old, "/private/tmp/buntrail-fake-agent-old");
    for (index, expected) in [(6u8, "/private/tmp/buntrail-fake-agent-new"), (7, "unset")] {
        if index == 7 {
            auth(&mut socket, 20, None);
        }
        let session = buntrail_protocol::services::uuid([index; 16]);
        let operation = buntrail_protocol::services::uuid([index + 10; 16]);
        send(
            &mut socket,
            &launch_header(
                &c,
                &server,
                std::path::Path::new("/bin/sh"),
                &session,
                &operation,
                21,
            ),
        );
        let (h, p) = receive(&mut socket);
        credit(&mut socket, &h, p.len());
        assert_eq!(
            serde_json::from_slice::<Value>(&p).unwrap()["receipt"]["state"],
            "confirmed"
        );
        let command = format!("printf '%s' \"${{SSH_AUTH_SOCK-unset}}\" > env-{index}\n");
        call(
            &mut socket,
            &c,
            22,
            json!({"method":"terminal_input","lease_id":LEASE,"session_id":session,"bytes_base64":B64.encode(command)}),
        );
        assert_eq!(
            wait_file(&server.dir.path().join(format!("env-{index}"))),
            expected
        );
        call(
            &mut socket,
            &c,
            23,
            json!({"method":"terminal_end","lease_id":LEASE,"session_id":session,"intent":"explicit_close"}),
        );
    }
}

mod clocked {
    use buntrail_core::contracts::*;
    use buntrail_helper::framed::{
        leases::{Leases, RETENTION},
        terminal::SessionManager,
    };
    use buntrail_services::{contracts::TerminalService, files::LocalFileService};
    use std::{
        sync::Arc,
        task::{Context, Poll, Waker},
        time::{Duration, Instant},
    };
    struct Fixture {
        manager: SessionManager,
        leases: Leases,
        dir: tempfile::TempDir,
        target: TargetIdentity,
    }
    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir_in("/tmp").unwrap();
            let target = buntrail_services::connections::local::identity().unwrap();
            let files =
                Arc::new(LocalFileService::new(target.clone(), dir.path().join("files")).unwrap());
            Self {
                manager: SessionManager::new(files, &dir.path().join("runtime")).unwrap(),
                leases: Leases::default(),
                dir,
                target,
            }
        }
        fn register(&mut self, n: u8, bridge: u64) -> WorkspaceLease {
            let runtime = self.manager.runtime.clone();
            let owner = WorkspaceLease {
                client: ClientID([1; 16]),
                workspace: WorkspaceID([n; 16]),
                lease: WorkspaceLeaseID([n; 16]),
                runtime,
            };
            let context = buntrail_protocol::types::Context {
                client_id: buntrail_protocol::services::uuid(owner.client.0),
                workspace_id: buntrail_protocol::services::uuid(owner.workspace.0),
                target_binding: "fixture".into(),
                runtime_generation: buntrail_protocol::services::uuid(
                    owner.runtime.supervisor_boot,
                ),
            };
            self.leases
                .register(
                    buntrail_protocol::services::uuid(owner.lease.0),
                    context,
                    bridge,
                )
                .unwrap();
            self.manager.service.register_owner(owner.clone()).unwrap();
            owner
        }
        fn open(&self, owner: &WorkspaceLease, n: u8) -> TerminalSessionID {
            let session = TerminalSessionID([n; 16]);
            let r = self.manager.service.open_sync(TerminalOpenRequest {
                operation: OperationID([n; 16]),
                session,
                owner: owner.clone(),
                target: self.target.clone(),
                runtime: self.manager.runtime.clone(),
                directory: TargetPath::posix(
                    self.dir.path().as_os_str().as_encoded_bytes().to_vec(),
                )
                .unwrap(),
                shell: TargetPath::posix(b"/bin/sh".to_vec()).unwrap(),
                size: buntrail_protocol::terminal::size(80, 24).unwrap(),
            });
            assert!(
                matches!(
                    r.state,
                    OperationState::Confirmed(MutationResult::TerminalOpened { .. })
                ),
                "{r:?}"
            );
            session
        }
        fn attach(
            &self,
            owner: &WorkspaceLease,
            session: TerminalSessionID,
        ) -> buntrail_core::contracts::async_types::EventStream<TerminalEvent> {
            let mut future = self.manager.service.attach(TerminalAttachRequest {
                session,
                owner: owner.clone(),
                runtime: self.manager.runtime.clone(),
                last_output_sequence: 0,
            });
            match future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
            {
                Poll::Ready(r) => r.unwrap(),
                Poll::Pending => panic!("attach pending"),
            }
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            self.manager.service.shutdown();
            let deadline = Instant::now() + Duration::from_secs(5);
            while !self.manager.service.shutdown_ready() {
                assert!(Instant::now() < deadline, "PTY cleanup incomplete");
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    }
    #[test]
    fn last_client_disconnect_retention_exact_monotonic_deadline() {
        let mut f = Fixture::new();
        let now = Instant::now();
        let a = f.register(2, 1);
        let b = f.register(3, 2);
        let sa = f.open(&a, 4);
        let sb = f.open(&b, 5);
        f.leases.disconnect(1, now);
        f.manager
            .expire(&mut f.leases, now + RETENTION - Duration::from_nanos(1));
        assert!(f.manager.service.verify_session(sa, &a).is_ok());
        assert!(f.manager.service.verify_session(sb, &b).is_ok());
        f.register(2, 3); // Only the original owner resumes its original session.
        f.manager.expire(&mut f.leases, now + RETENTION);
        assert!(f.manager.service.verify_session(sa, &a).is_ok());
        f.leases.disconnect(2, now + RETENTION);
        f.leases.disconnect(3, now + RETENTION);
        let mut output = f.attach(&a, sa);
        f.manager.expire(&mut f.leases, now + RETENTION + RETENTION);
        assert!(f.manager.service.verify_session(sa, &a).is_err());
        assert!(f.manager.service.verify_session(sb, &b).is_err());
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut expired = false;
        while Instant::now() < deadline {
            match output
                .as_mut()
                .poll_next(&mut Context::from_waker(Waker::noop()))
            {
                Poll::Ready(Some(Ok(TerminalEvent::Expired))) => {
                    expired = true;
                    break;
                }
                Poll::Ready(None) => break,
                _ => std::thread::sleep(Duration::from_millis(2)),
            }
        }
        assert!(expired);
        assert_eq!(RETENTION, Duration::from_secs(1800));
    }
    #[test]
    fn shared_bridge_workspace_ownership_and_unrelated_reconnect() {
        let mut f = Fixture::new();
        let now = Instant::now();
        let a = f.register(2, 1);
        let b = f.register(3, 1);
        let sa = f.open(&a, 4);
        let sb = f.open(&b, 5);
        f.leases.disconnect(1, now);
        f.register(2, 2);
        f.manager.expire(&mut f.leases, now + RETENTION);
        assert!(f.manager.service.verify_session(sa, &a).is_ok());
        assert!(f.manager.service.verify_session(sb, &b).is_err());
        f.manager
            .service
            .revoke_owner(a.lease, TerminalEndIntent::FinalWorkspaceClose);
        assert!(f.manager.service.verify_session(sa, &a).is_err());
        let deadline = Instant::now() + Duration::from_secs(3);
        while f.manager.service.has_sessions() {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(2));
        }
    }
    #[test]
    fn view_detached_owner_expires_while_shared_bridge_owner_stays_live() {
        for resume in [false, true] {
            let mut f = Fixture::new();
            let now = Instant::now();
            let a = f.register(2, 1);
            let b = f.register(3, 1);
            let sa = f.open(&a, 4);
            let sb = f.open(&b, 5);
            let context = buntrail_protocol::types::Context {
                client_id: buntrail_protocol::services::uuid(a.client.0),
                workspace_id: buntrail_protocol::services::uuid(a.workspace.0),
                target_binding: "fixture".into(),
                runtime_generation: buntrail_protocol::services::uuid(a.runtime.supervisor_boot),
            };
            f.leases
                .release(
                    &buntrail_protocol::services::uuid(a.lease.0),
                    &context,
                    1,
                    buntrail_protocol::types::ReleaseIntent::ViewDetachment,
                    now,
                )
                .unwrap();
            f.manager
                .expire(&mut f.leases, now + RETENTION - Duration::from_nanos(1));
            assert!(f.manager.service.verify_session(sa, &a).is_ok());
            assert!(f.manager.service.verify_session(sb, &b).is_ok());
            if resume {
                f.register(2, 1);
            }
            f.manager.expire(&mut f.leases, now + RETENTION);
            assert_eq!(
                f.manager.service.verify_session(sa, &a).is_ok(),
                resume,
                "view-detached session survived its exact deadline without owner resume"
            );
            assert!(f.manager.service.verify_session(sb, &b).is_ok());
        }
    }
    #[test]
    fn replaced_renderer_cannot_consume_and_stale_runtime_cannot_attach() {
        let mut f = Fixture::new();
        let owner = f.register(2, 1);
        let session = f.open(&owner, 4);
        let mut old = f.attach(&owner, session);
        let _new = f.attach(&owner, session);
        assert!(matches!(
            old.as_mut()
                .poll_next(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(None)
        ));
        let mut request = TerminalAttachRequest {
            session,
            owner: owner.clone(),
            runtime: owner.runtime.clone(),
            last_output_sequence: 0,
        };
        request.runtime.supervisor_boot = [0; 16];
        let mut future = f.manager.service.attach(request);
        assert!(matches!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Err(_))
        ));
    }
}

fn credit(s: &mut UnixStream, response: &Value, bytes: usize) {
    let mut h = response.clone();
    h["kind"] = json!("stream.credit");
    h["sequence"] = Value::Null;
    h["metadata"] = json!({"bytes":bytes});
    send(s, &h);
}
fn launch_header(
    c: &Value,
    server: &Server,
    shell: &std::path::Path,
    session: &str,
    operation: &str,
    n: u64,
) -> Value {
    let mut h = header(
        "service.call",
        json!({"call":{"method":"terminal_open","lease_id":LEASE,"session_id":session,"directory_base64":B64.encode(server.dir.path().as_os_str().as_encoded_bytes()),"shell_base64":B64.encode(shell.as_os_str().as_encoded_bytes()),"columns":80,"rows":24}}),
    );
    h["context"] = c.clone();
    h["request_id"] = json!(n);
    h["operation_id"] = json!(operation);
    h
}
fn script(server: &Server, text: &str) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = server.dir.path().join("shell-fixture");
    std::fs::write(&path, text).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    path
}
#[test]
fn launch_acknowledgement_loss_recovers_original_session_once() {
    let server = Server::start();
    let shell = script(&server, "#!/bin/sh\necho $$ >> launches\nexec /bin/sh\n");
    let mut first = server.connect();
    let c = register(&mut first);
    let h = launch_header(&c, &server, &shell, SESSION, OP, 3);
    send(&mut first, &h);
    let pid = wait_file(&server.dir.path().join("launches"));
    drop(first);
    let mut resumed = server.connect();
    let c = register(&mut resumed);
    let receipt = call(&mut resumed, &c, 4, json!({"method":"inspect"}));
    assert_eq!(receipt["receipt"]["result"]["session_id"], SESSION);
    let mut h = h;
    h["context"] = c.clone();
    h["request_id"] = json!(5);
    send(&mut resumed, &h);
    let (response, bytes) = receive(&mut resumed);
    credit(&mut resumed, &response, bytes.len());
    let duplicate: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(duplicate, receipt);
    assert_eq!(wait_file(&server.dir.path().join("launches")), pid);
    call(
        &mut resumed,
        &c,
        6,
        json!({"method":"terminal_end","lease_id":LEASE,"session_id":SESSION,"intent":"explicit_close"}),
    );
}
#[test]
fn replay_overflow_is_visible_and_input_is_not_repeated() {
    let server = Server::start();
    let shell = script(
        &server,
        "#!/bin/sh\nstty -echo\nprintf ready > ready\nIFS= read -r line\nprintf '%s\\n' \"$line\" >> inputs\ni=0; while [ $i -lt 14000 ]; do printf 'retained-line-%s\\n' \"$i\"; i=$((i+1)); done\nprintf done > done\nexit 7\n",
    );
    let mut socket = server.connect();
    let c = register(&mut socket);
    send(
        &mut socket,
        &launch_header(&c, &server, &shell, SESSION, OP, 3),
    );
    let (h, p) = receive(&mut socket);
    credit(&mut socket, &h, p.len());
    assert_eq!(
        serde_json::from_slice::<Value>(&p).unwrap()["receipt"]["state"],
        "confirmed"
    );
    wait_file(&server.dir.path().join("ready"));
    call(
        &mut socket,
        &c,
        4,
        json!({"method":"terminal_input","lease_id":LEASE,"session_id":SESSION,"bytes_base64":B64.encode(b"one-input\n")}),
    );
    wait_file(&server.dir.path().join("done"));
    std::thread::sleep(std::time::Duration::from_millis(100));
    drop(socket);
    let mut socket = server.connect();
    let c = register(&mut socket);
    let initial = call(
        &mut socket,
        &c,
        5,
        json!({"method":"terminal_attach","lease_id":LEASE,"session_id":SESSION,"last_output_sequence":0}),
    );
    assert_eq!(initial["event"]["kind"], "reattached");
    let mut gap = false;
    let mut bytes = 0;
    let mut lines = 0;
    loop {
        let (h, p) = receive(&mut socket);
        credit(&mut socket, &h, p.len());
        let value: Value = serde_json::from_slice(&p).unwrap();
        match value["event"]["kind"].as_str().unwrap() {
            "gap" => {
                gap = true;
                assert!(
                    value["event"]["last"].as_u64().unwrap()
                        >= value["event"]["first"].as_u64().unwrap()
                )
            }
            "output" => {
                let b = B64
                    .decode(value["event"]["bytes_base64"].as_str().unwrap())
                    .unwrap();
                bytes += b.len();
                lines += b.iter().filter(|b| **b == b'\n').count();
            }
            "process_exit" => {
                assert_eq!(value["event"]["code"], 7);
                assert_eq!(h["metadata"]["terminal"], true);
                break;
            }
            other => panic!("unexpected event {other}"),
        }
    }
    assert!(gap);
    assert!(bytes <= 8 * 1024 * 1024);
    assert!(lines <= 10000);
    assert_eq!(wait_file(&server.dir.path().join("inputs")), "one-input\n");
    call(
        &mut socket,
        &c,
        6,
        json!({"method":"terminal_end","lease_id":LEASE,"session_id":SESSION,"intent":"explicit_close"}),
    );
}
#[test]
fn intentional_end_event_is_backend_confirmed_and_distinct_from_process_exit() {
    let server = Server::start();
    let shell = script(&server, "#!/bin/sh\necho $$ > pid\nexec /bin/sh\n");
    let mut socket = server.connect();
    let c = register(&mut socket);
    send(
        &mut socket,
        &launch_header(&c, &server, &shell, SESSION, OP, 3),
    );
    let (h, p) = receive(&mut socket);
    credit(&mut socket, &h, p.len());
    let pid: i32 = wait_file(&server.dir.path().join("pid"))
        .trim()
        .parse()
        .unwrap();
    call(
        &mut socket,
        &c,
        4,
        json!({"method":"terminal_attach","lease_id":LEASE,"session_id":SESSION,"last_output_sequence":0}),
    );
    let mut end = header(
        "service.call",
        json!({"call":{"method":"terminal_end","lease_id":LEASE,"session_id":SESSION,"intent":"explicit_close"}}),
    );
    end["context"] = c;
    end["request_id"] = json!(5);
    send(&mut socket, &end);
    let mut ack = false;
    let mut ended = false;
    while !ack || !ended {
        let (h, p) = receive(&mut socket);
        credit(&mut socket, &h, p.len());
        let v: Value = serde_json::from_slice(&p).unwrap();
        if h["request_id"] == 5 {
            assert_eq!(v["kind"], "terminal_ack");
            ack = true;
        } else if v["event"]["kind"] != "output" {
            assert_eq!(v["event"]["kind"], "ended");
            assert_eq!(v["event"]["intent"], "explicit_close");
            assert_eq!(
                unsafe { libc::kill(pid, 0) },
                -1,
                "ended requires actual reaping"
            );
            ended = true;
        }
    }
}
#[test]
fn cancel_completed_launch_remains_unknown_after_receipt_delivery() {
    let server = Server::start();
    let mut socket = server.connect();
    let c = register(&mut socket);
    assert_eq!(
        launch(&mut socket, &c, &server)["receipt"]["state"],
        "confirmed"
    );
    std::thread::sleep(std::time::Duration::from_millis(30));
    let mut h = header("cancel", json!({"request_id":3}));
    h["context"] = c.clone();
    h["request_id"] = json!(4);
    send(&mut socket, &h);
    assert_eq!(receive(&mut socket).0["metadata"]["outcome"], "unknown");
    call(
        &mut socket,
        &c,
        5,
        json!({"method":"terminal_end","lease_id":LEASE,"session_id":SESSION,"intent":"explicit_close"}),
    );
}
#[test]
fn helper_restart_does_not_resurrect_old_session_or_launch() {
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};
    let mut server = Server::start();
    let shell = script(&server, "#!/bin/sh\necho $$ > pid\nexec /bin/sh\n");
    let mut first = server.connect();
    let old = register(&mut first);
    send(
        &mut first,
        &launch_header(&old, &server, &shell, SESSION, OP, 3),
    );
    let (h, p) = receive(&mut first);
    credit(&mut first, &h, p.len());
    let pid: i32 = wait_file(&server.dir.path().join("pid"))
        .trim()
        .parse()
        .unwrap();
    server.child.kill().unwrap();
    server.child.wait().unwrap();
    drop(first);
    let deadline = Instant::now() + Duration::from_secs(3);
    while unsafe { libc::kill(pid, 0) } == 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(
        unsafe { libc::kill(pid, 0) },
        -1,
        "PTY hangup must end the owned fixture shell"
    );
    server.child = Command::new(env!("CARGO_BIN_EXE_buntrail-helper"))
        .args(["serve", "--socket"])
        .arg(&server.socket)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if UnixStream::connect(&server.socket).is_ok() {
            break;
        }
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(5));
    }
    let mut socket = server.connect();
    let new = register(&mut socket);
    assert_ne!(old["runtime_generation"], new["runtime_generation"]);
    let inspected = call(&mut socket, &new, 4, json!({"method":"inspect"}));
    assert_eq!(
        inspected["receipt"]["result"]["runtime_generation"],
        old["runtime_generation"]
    );
    let mut h = header(
        "service.call",
        json!({"call":{"method":"terminal_attach","lease_id":LEASE,"session_id":SESSION,"last_output_sequence":0}}),
    );
    h["context"] = new;
    h["request_id"] = json!(5);
    send(&mut socket, &h);
    let (response, _) = receive(&mut socket);
    assert_eq!(response["kind"], "error");
    assert_eq!(response["metadata"]["code"], "Unavailable");
}
#[test]
fn group_termination_is_process_exit_and_no_automatic_restart() {
    let server = Server::start();
    let shell = script(&server, "#!/bin/sh\necho $$ > pid\nexec /bin/sh\n");
    let mut socket = server.connect();
    let c = register(&mut socket);
    send(
        &mut socket,
        &launch_header(&c, &server, &shell, SESSION, OP, 3),
    );
    let (h, p) = receive(&mut socket);
    credit(&mut socket, &h, p.len());
    let pid: i32 = wait_file(&server.dir.path().join("pid"))
        .trim()
        .parse()
        .unwrap();
    assert_eq!(unsafe { libc::kill(-pid, libc::SIGKILL) }, 0);
    call(
        &mut socket,
        &c,
        4,
        json!({"method":"terminal_attach","lease_id":LEASE,"session_id":SESSION,"last_output_sequence":0}),
    );
    loop {
        let (h, p) = receive(&mut socket);
        credit(&mut socket, &h, p.len());
        let v: Value = serde_json::from_slice(&p).unwrap();
        if v["event"]["kind"] == "process_exit" {
            assert!(v["event"]["code"].is_null());
            break;
        }
    }
    assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
    call(
        &mut socket,
        &c,
        5,
        json!({"method":"terminal_end","lease_id":LEASE,"session_id":SESSION,"intent":"explicit_close"}),
    );
}
#[test]
fn new_durable_launch_honors_maintenance_pause() {
    use std::os::unix::fs::PermissionsExt;
    let server = Server::start_with_setup(|state| {
        std::fs::create_dir_all(state.join("uploads")).unwrap();
        for p in [state.to_path_buf(), state.join("uploads")] {
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        std::fs::write(state.join("uploads/unsafe"), b"fault").unwrap();
        std::fs::set_permissions(
            state.join("uploads/unsafe"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
    });
    let mut socket = server.connect();
    let c = register(&mut socket);
    send(
        &mut socket,
        &launch_header(&c, &server, std::path::Path::new("/bin/sh"), SESSION, OP, 3),
    );
    let (h, _) = receive(&mut socket);
    assert_eq!(h["kind"], "operation.receipt");
    assert_eq!(h["metadata"]["state"], "failed");
    assert_eq!(h["metadata"]["failure"]["effect"], "proven_no_effect");
}
#[test]
fn closing_or_detaching_either_workspace_on_one_bridge_preserves_the_other() {
    for (close_first, detach) in [(true, false), (false, false), (true, true), (false, true)] {
        let server = Server::start();
        let mut socket = server.connect();
        let first = register(&mut socket);
        let mut second = first.clone();
        second["workspace_id"] = json!("66666666-6666-4666-8666-666666666666");
        let second_lease = "77777777-7777-4777-8777-777777777777";
        let second_session = "88888888-8888-4888-8888-888888888888";
        let mut h = header(
            "lease.register",
            json!({"lease_id":second_lease,"client_id":second["client_id"],"workspace_id":second["workspace_id"],"target_binding":second["target_binding"],"runtime_generation":second["runtime_generation"]}),
        );
        h["request_id"] = json!(10);
        send(&mut socket, &h);
        assert_eq!(receive(&mut socket).0["kind"], "ack");
        assert_eq!(
            launch(&mut socket, &first, &server)["receipt"]["state"],
            "confirmed"
        );
        let mut h = launch_header(
            &second,
            &server,
            std::path::Path::new("/bin/sh"),
            second_session,
            "99999999-9999-4999-8999-999999999999",
            11,
        );
        h["metadata"]["call"]["lease_id"] = json!(second_lease);
        send(&mut socket, &h);
        let (h, p) = receive(&mut socket);
        credit(&mut socket, &h, p.len());
        assert_eq!(
            serde_json::from_slice::<Value>(&p).unwrap()["receipt"]["state"],
            "confirmed"
        );
        let (closed, closed_lease, active, active_lease, active_session) = if close_first {
            (&first, LEASE, &second, second_lease, second_session)
        } else {
            (&second, second_lease, &first, LEASE, SESSION)
        };
        let closed_session = if close_first { SESSION } else { second_session };
        if detach {
            call(
                &mut socket,
                closed,
                15,
                json!({"method":"terminal_input","lease_id":closed_lease,"session_id":closed_session,"bytes_base64":B64.encode(b"printf '%s' $$ > before-detach\n")}),
            );
            wait_file(&server.dir.path().join("before-detach"));
        }
        let mut h = header(
            "lease.release",
            json!({"lease_id":closed_lease,"intent":if detach { "view_detachment" } else { "resolved_workspace_closure" }}),
        );
        h["context"] = closed.clone();
        h["request_id"] = json!(12);
        send(&mut socket, &h);
        assert_eq!(receive(&mut socket).0["kind"], "ack");
        call(
            &mut socket,
            active,
            13,
            json!({"method":"terminal_input","lease_id":active_lease,"session_id":active_session,"bytes_base64":B64.encode(b"printf alive > survived\n")}),
        );
        assert_eq!(wait_file(&server.dir.path().join("survived")), "alive");
        if detach {
            let mut h = header(
                "lease.register",
                json!({"lease_id":closed_lease,
                "client_id":closed["client_id"],"workspace_id":closed["workspace_id"],
                "target_binding":closed["target_binding"],"runtime_generation":closed["runtime_generation"]}),
            );
            h["request_id"] = json!(16);
            send(&mut socket, &h);
            assert_eq!(receive(&mut socket).0["kind"], "ack");
            call(
                &mut socket,
                closed,
                17,
                json!({"method":"terminal_input","lease_id":closed_lease,"session_id":closed_session,"bytes_base64":B64.encode(b"printf '%s' $$ > after-detach\n")}),
            );
            let after = wait_file(&server.dir.path().join("after-detach"));
            assert_eq!(after, wait_file(&server.dir.path().join("before-detach")));
            call(
                &mut socket,
                closed,
                18,
                json!({"method":"terminal_end","lease_id":closed_lease,"session_id":closed_session,"intent":"explicit_close"}),
            );
        }
        call(
            &mut socket,
            active,
            14,
            json!({"method":"terminal_end","lease_id":active_lease,"session_id":active_session,"intent":"explicit_close"}),
        );
    }
}
#[test]
fn bash_and_zsh_real_pty_reconnect_probes() {
    for command in ["exec /bin/bash --noprofile --norc", "exec /bin/zsh -f"] {
        let server = Server::start();
        let shell = script(&server, &format!("#!/bin/sh\n{command}\n"));
        let mut socket = server.connect();
        let c = register(&mut socket);
        send(
            &mut socket,
            &launch_header(&c, &server, &shell, SESSION, OP, 3),
        );
        let (h, p) = receive(&mut socket);
        credit(&mut socket, &h, p.len());
        assert_eq!(
            serde_json::from_slice::<Value>(&p).unwrap()["receipt"]["state"],
            "confirmed"
        );
        call(
            &mut socket,
            &c,
            4,
            json!({"method":"terminal_input","lease_id":LEASE,"session_id":SESSION,"bytes_base64":B64.encode("stty -echo; printf '界😀' > shell-probe; printf '%s' $$ > pid\n")}),
        );
        assert_eq!(wait_file(&server.dir.path().join("shell-probe")), "界😀");
        let pid = wait_file(&server.dir.path().join("pid"));
        drop(socket);
        let mut socket = server.connect();
        let c = register(&mut socket);
        call(
            &mut socket,
            &c,
            5,
            json!({"method":"terminal_input","lease_id":LEASE,"session_id":SESSION,"bytes_base64":B64.encode(b"printf '%s' $$ > pid-after\n")}),
        );
        assert_eq!(wait_file(&server.dir.path().join("pid-after")), pid);
        call(
            &mut socket,
            &c,
            6,
            json!({"method":"terminal_end","lease_id":LEASE,"session_id":SESSION,"intent":"explicit_close"}),
        );
    }
}
#[test]
fn byte_overflow_without_lines_has_gap_and_bounded_replay() {
    let server = Server::start();
    let shell = script(
        &server,
        "#!/bin/sh\nhead -c 9437184 /dev/zero | tr '\\000' x\nprintf done > byte-done\n",
    );
    let mut socket = server.connect();
    let c = register(&mut socket);
    send(
        &mut socket,
        &launch_header(&c, &server, &shell, SESSION, OP, 3),
    );
    let (h, p) = receive(&mut socket);
    credit(&mut socket, &h, p.len());
    wait_file(&server.dir.path().join("byte-done"));
    std::thread::sleep(std::time::Duration::from_millis(100));
    call(
        &mut socket,
        &c,
        4,
        json!({"method":"terminal_attach","lease_id":LEASE,"session_id":SESSION,"last_output_sequence":0}),
    );
    let mut gap = false;
    let mut bytes = 0;
    loop {
        let (h, p) = receive(&mut socket);
        credit(&mut socket, &h, p.len());
        let v: Value = serde_json::from_slice(&p).unwrap();
        match v["event"]["kind"].as_str().unwrap() {
            "gap" => gap = true,
            "output" => {
                bytes += B64
                    .decode(v["event"]["bytes_base64"].as_str().unwrap())
                    .unwrap()
                    .len()
            }
            "process_exit" => break,
            other => panic!("{other}"),
        }
    }
    assert!(gap);
    assert!(bytes <= 8 * 1024 * 1024);
    assert!(bytes > 0);
    println!(
        "byte-only real PTY replay retained {bytes} bytes within 8 MiB and existing 4096-chunk bounds"
    );
    call(
        &mut socket,
        &c,
        5,
        json!({"method":"terminal_end","lease_id":LEASE,"session_id":SESSION,"intent":"explicit_close"}),
    );
}

#[test]
fn pipelined_wire_input_is_delivered_exactly_once_in_order() {
    use std::io::Write;
    let server = Server::start();
    let shell = script(
        &server,
        "#!/bin/sh\nstty -echo\nprintf ready > ready\nwhile IFS= read -r line; do\n[ \"$line\" = STOP ] && break\nprintf '%s\\n' \"$line\" >> received\ndone\nprintf done > done\n",
    );
    let mut socket = server.connect();
    let c = register(&mut socket);
    send(
        &mut socket,
        &launch_header(&c, &server, &shell, SESSION, OP, 3),
    );
    let (h, p) = receive(&mut socket);
    credit(&mut socket, &h, p.len());
    assert_eq!(
        serde_json::from_slice::<Value>(&p).unwrap()["receipt"]["state"],
        "confirmed"
    );
    wait_file(&server.dir.path().join("ready"));
    for (n, bytes) in [(4, b"first\n".as_slice()), (5, b"second\n".as_slice())] {
        let mut h = header(
            "service.call",
            json!({"call":{"method":"terminal_input","lease_id":LEASE,"session_id":SESSION}}),
        );
        h["context"] = c.clone();
        h["request_id"] = json!(n);
        socket.write_all(&encode(&h, bytes)).unwrap();
    }
    let mut responses = Vec::new();
    for _ in 0..2 {
        let (h, p) = receive(&mut socket);
        responses.push(h["request_id"].as_u64().unwrap());
        credit(&mut socket, &h, p.len());
        assert_eq!(
            serde_json::from_slice::<Value>(&p).unwrap()["kind"],
            "terminal_ack"
        );
    }
    responses.sort();
    assert_eq!(responses, vec![4, 5]);
    call(
        &mut socket,
        &c,
        6,
        json!({"method":"terminal_input","lease_id":LEASE,"session_id":SESSION,"bytes_base64":B64.encode(b"STOP\n")}),
    );
    wait_file(&server.dir.path().join("done"));
    let bytes = std::fs::read(server.dir.path().join("received")).unwrap();
    call(
        &mut socket,
        &c,
        7,
        json!({"method":"terminal_end","lease_id":LEASE,"session_id":SESSION,"intent":"explicit_close"}),
    );
    assert_eq!(bytes, b"first\nsecond\n");
}

#[test]
fn detached_stream_late_credit_and_drop_preserve_shared_bridge() {
    use std::io::Write;
    for subscription in [true, false] {
        let server = Server::start();
        let mut socket = server.connect();
        let a = register(&mut socket);
        let mut b = a.clone();
        b["workspace_id"] = json!("66666666-6666-4666-8666-666666666666");
        let b_lease = "77777777-7777-4777-8777-777777777777";
        let b_session = "88888888-8888-4888-8888-888888888888";
        let mut h = header(
            "lease.register",
            json!({"lease_id":b_lease,"client_id":b["client_id"],"workspace_id":b["workspace_id"],"target_binding":b["target_binding"],"runtime_generation":b["runtime_generation"]}),
        );
        h["request_id"] = json!(10);
        send(&mut socket, &h);
        assert_eq!(receive(&mut socket).0["kind"], "ack");
        let mut h = launch_header(
            &b,
            &server,
            std::path::Path::new("/bin/sh"),
            b_session,
            "99999999-9999-4999-8999-999999999999",
            11,
        );
        h["metadata"]["call"]["lease_id"] = json!(b_lease);
        send(&mut socket, &h);
        let (h, p) = receive(&mut socket);
        credit(&mut socket, &h, p.len());
        assert_eq!(
            serde_json::from_slice::<Value>(&p).unwrap()["receipt"]["state"],
            "confirmed"
        );
        send(
            &mut socket,
            &launch_header(&a, &server, std::path::Path::new("/bin/sh"), SESSION, OP, 3),
        );
        let (opened, payload) = receive(&mut socket);
        assert_eq!(
            serde_json::from_slice::<Value>(&payload).unwrap()["receipt"]["state"],
            "confirmed"
        );
        let mut outstanding = vec![];
        let request = if subscription {
            credit(&mut socket, &opened, payload.len());
            let mut h = header(
                "service.call",
                json!({"call":{"method":"terminal_attach","lease_id":LEASE,"session_id":SESSION,"last_output_sequence":0}}),
            );
            h["context"] = a.clone();
            h["request_id"] = json!(20);
            send(&mut socket, &h);
            let (h, p) = receive(&mut socket);
            assert_eq!(
                serde_json::from_slice::<Value>(&p).unwrap()["event"]["kind"],
                "reattached"
            );
            outstanding.push((h, p.len()));
            20
        } else {
            // A completed effectful result remains unconsumed across detachment.
            outstanding.push((opened, payload.len()));
            3
        };
        let mut release = header(
            "lease.release",
            json!({"lease_id":LEASE,"intent":"view_detachment"}),
        );
        release["context"] = a.clone();
        release["request_id"] = json!(21);
        send(&mut socket, &release);
        loop {
            let (h, p) = receive(&mut socket);
            if h["request_id"] == 21 {
                assert_eq!(h["kind"], "ack");
                break;
            }
            assert_eq!(h["request_id"], request);
            outstanding.push((h, p.len()));
        }
        for (h, n) in outstanding {
            credit(&mut socket, &h, n);
        }
        let mut cancel = header("cancel", json!({"request_id":request}));
        cancel["context"] = a.clone();
        cancel["request_id"] = json!(22);
        send(&mut socket, &cancel);
        let (cancelled, _) = receive(&mut socket);
        assert_eq!(
            cancelled["kind"], "cancel.result",
            "late drop closed the shared bridge"
        );
        if !subscription {
            assert_eq!(cancelled["metadata"]["outcome"], "unknown");
        }
        let mut input = header(
            "service.call",
            json!({"call":{"method":"terminal_input","lease_id":LEASE,"session_id":SESSION}}),
        );
        input["context"] = a.clone();
        input["request_id"] = json!(23);
        socket
            .write_all(&encode(&input, b"printf forbidden > forbidden\n"))
            .unwrap();
        let (refused, _) = receive(&mut socket);
        assert_eq!(refused["kind"], "error");
        assert_eq!(refused["metadata"]["code"], "unavailable");
        call(
            &mut socket,
            &b,
            24,
            json!({"method":"terminal_input","lease_id":b_lease,"session_id":b_session,"bytes_base64":B64.encode(b"printf 'B-ORIGINAL-RUNTIME\\n'\n")}),
        );
        let attached = call(
            &mut socket,
            &b,
            25,
            json!({"method":"terminal_attach","lease_id":b_lease,"session_id":b_session,"last_output_sequence":0}),
        );
        assert_eq!(attached["event"]["kind"], "reattached");
        loop {
            let (h, p) = receive(&mut socket);
            assert_eq!(h["context"]["runtime_generation"], b["runtime_generation"]);
            credit(&mut socket, &h, p.len());
            let event: Value = serde_json::from_slice(&p).unwrap();
            if let Some(bytes) = event["event"]["bytes_base64"].as_str()
                && B64
                    .decode(bytes)
                    .unwrap()
                    .windows(18)
                    .any(|v| v == b"B-ORIGINAL-RUNTIME")
            {
                break;
            }
        }
        cancel["context"] = b.clone();
        cancel["request_id"] = json!(26);
        cancel["metadata"] = json!({"request_id":25});
        send(&mut socket, &cancel);
        loop {
            let (h, _) = receive(&mut socket);
            if h["request_id"] == 26 {
                assert_eq!(h["kind"], "cancel.result");
                break;
            }
            assert_eq!(
                h["request_id"], 25,
                "only already-queued B output may precede cancellation"
            );
        }
        let mut resume = header(
            "lease.register",
            json!({"lease_id":LEASE,"client_id":a["client_id"],"workspace_id":a["workspace_id"],"target_binding":a["target_binding"],"runtime_generation":a["runtime_generation"]}),
        );
        resume["request_id"] = json!(27);
        send(&mut socket, &resume);
        assert_eq!(receive(&mut socket).0["kind"], "ack");
        call(
            &mut socket,
            &a,
            28,
            json!({"method":"terminal_input","lease_id":LEASE,"session_id":SESSION,"bytes_base64":B64.encode(b"printf resumed > resumed\n")}),
        );
        assert_eq!(wait_file(&server.dir.path().join("resumed")), "resumed");
        for (c, lease, session, n) in [(&a, LEASE, SESSION, 29), (&b, b_lease, b_session, 30)] {
            call(
                &mut socket,
                c,
                n,
                json!({"method":"terminal_end","lease_id":lease,"session_id":session,"intent":"explicit_close"}),
            );
        }
        assert!(!server.dir.path().join("forbidden").exists());
    }
}

#[test]
fn terminal_credit_and_cancel_cannot_use_another_owner_or_stale_runtime() {
    use std::io::Read;
    let server = Server::start();
    let mut socket = server.connect();
    let a = register(&mut socket);
    assert_eq!(
        launch(&mut socket, &a, &server)["receipt"]["state"],
        "confirmed"
    );
    let mut b = a.clone();
    b["workspace_id"] = json!("66666666-6666-4666-8666-666666666666");
    let mut h = header(
        "lease.register",
        json!({"lease_id":"77777777-7777-4777-8777-777777777777","client_id":b["client_id"],"workspace_id":b["workspace_id"],"target_binding":b["target_binding"],"runtime_generation":b["runtime_generation"]}),
    );
    h["request_id"] = json!(10);
    send(&mut socket, &h);
    assert_eq!(receive(&mut socket).0["kind"], "ack");
    let mut h = header(
        "service.call",
        json!({"call":{"method":"terminal_attach","lease_id":LEASE,"session_id":SESSION,"last_output_sequence":0}}),
    );
    h["context"] = a.clone();
    h["request_id"] = json!(20);
    send(&mut socket, &h);
    let (issued, p) = receive(&mut socket);
    let mut deferred = vec![];
    let mut bad = issued.clone();
    bad["context"] = b.clone();
    bad["kind"] = json!("stream.credit");
    bad["sequence"] = Value::Null;
    bad["metadata"] = json!({"bytes":p.len()});
    send(&mut socket, &bad);
    loop {
        let (h, p) = receive(&mut socket);
        if h["kind"] == "error" {
            assert_eq!(h["request_id"], 20);
            break;
        }
        assert_eq!(h["kind"], "service.event");
        deferred.push((h, p.len()));
    }
    let mut cancel = header("cancel", json!({"request_id":20}));
    cancel["context"] = b;
    cancel["request_id"] = json!(21);
    send(&mut socket, &cancel);
    loop {
        let (h, p) = receive(&mut socket);
        if h["kind"] == "cancel.result" {
            assert_eq!(h["metadata"]["outcome"], "unknown");
            break;
        }
        assert_eq!(h["kind"], "service.event");
        deferred.push((h, p.len()));
    }
    // Exact original credit must still fit; the wrong owner did not alter its budget.
    credit(&mut socket, &issued, p.len());
    for (h, n) in deferred {
        credit(&mut socket, &h, n);
    }
    let mut input = header(
        "service.call",
        json!({"call":{"method":"terminal_input","lease_id":LEASE,"session_id":SESSION}}),
    );
    input["context"] = a.clone();
    input["request_id"] = json!(22);
    use std::io::Write;
    socket
        .write_all(&encode(
            &input,
            b"printf owner-intact > owner-intact; printf 'OWNER-CONTROL\\n'\n",
        ))
        .unwrap();
    let mut saw_ack = false;
    let mut saw_output = false;
    while !saw_ack || !saw_output {
        let (h, p) = receive(&mut socket);
        assert_eq!(
            h["kind"], "service.event",
            "wrong-owner credit must not consume original budget"
        );
        credit(&mut socket, &h, p.len());
        let value: Value = serde_json::from_slice(&p).unwrap();
        if h["request_id"] == 22 {
            assert_eq!(value["kind"], "terminal_ack");
            saw_ack = true;
        }
        if let Some(bytes) = value["event"]["bytes_base64"].as_str()
            && B64
                .decode(bytes)
                .unwrap()
                .windows(13)
                .any(|v| v == b"OWNER-CONTROL")
        {
            saw_output = true;
        }
    }
    assert_eq!(
        wait_file(&server.dir.path().join("owner-intact")),
        "owner-intact"
    );
    // Stale runtime is not an authenticated context and cannot reach credit/cancel logic.
    bad["context"] = a.clone();
    bad["context"]["runtime_generation"] = json!("00000000-0000-4000-8000-000000000000");
    send(&mut socket, &bad);
    let mut bytes = [0; 8192];
    loop {
        if socket.read(&mut bytes).unwrap() == 0 {
            break;
        }
    }
    drop(socket);
    let mut resumed = server.connect();
    let context = register(&mut resumed);
    assert_eq!(context["runtime_generation"], a["runtime_generation"]);
    assert_eq!(
        call(&mut resumed, &context, 30, json!({"method":"inspect"}))["receipt"]["result"]["session_id"],
        SESSION
    );
    call(
        &mut resumed,
        &context,
        31,
        json!({"method":"terminal_end","lease_id":LEASE,"session_id":SESSION,"intent":"explicit_close"}),
    );
}
