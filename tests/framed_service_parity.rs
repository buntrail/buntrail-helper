#![cfg(unix)]
#[path = "framed_support.rs"]
mod support;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use buntrail_core::contracts::*;
use buntrail_services::connections::local::LocalConnection;
use serde_json::json;
use std::{fs, os::unix::ffi::OsStrExt};
use support::*;
#[test]
fn local_remote_directory_parity() {
    let server = Server::start();
    let root = server.dir.path().join("project");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("hello.txt"), b"hello parity\n").unwrap();
    let local = LocalConnection::open(server.dir.path().join("local-state")).unwrap();
    let entries = local
        .files
        .list_sync(FileRef {
            target: local.identity.clone(),
            path: TargetPath::posix(root.as_os_str().as_bytes().to_vec()).unwrap(),
            resolved_identity: None,
        })
        .unwrap();
    let mut socket = server.connect();
    let context = register(&mut socket);
    let mut request = header(
        "file.list",
        json!({"path_base64": STANDARD.encode(root.as_os_str().as_bytes())}),
    );
    request["request_id"] = json!(3);
    request["context"] = context;
    send(&mut socket, &request);
    let (response, _) = receive(&mut socket);
    assert_eq!(
        response["kind"],
        "service.event",
        "shared local lists {} entry; real helper must implement the same operation: {response}",
        entries.len()
    );
}

#[test]
fn remote_search_and_git_handlers_are_available() {
    let server = Server::start();
    let root = server.dir.path().join("project");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("hello"), b"parity\n").unwrap();
    let file = json!({"path_base64":STANDARD.encode(root.as_os_str().as_bytes()),"resolved_identity":null});
    let mut socket = server.connect();
    let context = register(&mut socket);
    for (i,call) in [json!({"method":"discover","file":file}),json!({"method":"search","request":{"root":file,"expression":"parity","regex":false,"case_sensitive":true,"whole_word":false,"includes":[],"excludes":[],"hidden":false,"ignored":false}})].iter().enumerate(){
        let mut h=header("service.call",json!({"call":call})); h["context"]=context.clone(); h["request_id"]=json!(10+i);
        send(&mut socket,&h); let (response,_)=receive(&mut socket); assert_eq!(response["kind"],"service.event","{response}");
    }
}
#[test]
fn cancelled_search_releases_request_and_control_inspection_remains_available() {
    let server = Server::start();
    let root = server.dir.path().join("tree");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("many"), "match\n".repeat(50000)).unwrap();
    let mut socket = server.connect();
    let context = register(&mut socket);
    let file = json!({"path_base64":STANDARD.encode(root.as_os_str().as_bytes()),"resolved_identity":null});
    let mut search = header(
        "service.call",
        json!({"call":{"method":"search","request":{"root":file,"expression":"match","regex":false,"case_sensitive":true,"whole_word":false,"includes":[],"excludes":[],"hidden":false,"ignored":false}}}),
    );
    search["context"] = context.clone();
    search["request_id"] = json!(8);
    send(&mut socket, &search);
    let mut cancel = header("cancel", json!({"request_id":8}));
    cancel["context"] = context.clone();
    cancel["request_id"] = json!(9);
    send(&mut socket, &cancel);
    loop {
        let (h, _) = receive(&mut socket);
        if h["request_id"] == 9 {
            assert_eq!(h["metadata"]["outcome"], "confirmed_cancel");
            break;
        }
    }
    let mut inspect = header("service.call", json!({"call":{"method":"inspect"}}));
    inspect["context"] = context;
    inspect["request_id"] = json!(10);
    inspect["operation_id"] = json!("44444444-4444-4444-8444-444444444444");
    send(&mut socket, &inspect);
    loop {
        let (h, payload) = receive(&mut socket);
        if h["request_id"] == 10 {
            assert_eq!(h["kind"], "service.event");
            let reply: serde_json::Value = serde_json::from_slice(&payload).unwrap();
            assert_eq!(reply["receipt"]["state"], "unknown");
            break;
        }
    }
}
#[test]
fn maintenance_pause_covers_new_mutations_and_preserves_inspection() {
    use std::os::unix::fs::PermissionsExt;
    let server = Server::start_with_setup(|state| {
        fs::create_dir(state).unwrap();
        fs::set_permissions(state, fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(state.join("uploads")).unwrap();
        fs::set_permissions(state.join("uploads"), fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(state.join("uploads/unsafe"), b"maintenance fault").unwrap();
        fs::set_permissions(
            state.join("uploads/unsafe"),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
    });
    let mut socket = server.connect();
    let context = register(&mut socket);
    let path = server.dir.path().join("must-not-exist");
    let mut h = header(
        "service.call",
        json!({"call":{"method":"file_mutate","file":{"path_base64":STANDARD.encode(path.as_os_str().as_bytes()),"resolved_identity":null},"expected":null,"command":{"kind":"create_directory"}}}),
    );
    h["context"] = context.clone();
    h["operation_id"] = json!("55555555-5555-4555-8555-555555555555");
    h["request_id"] = json!(5);
    send(&mut socket, &h);
    assert_eq!(
        receive(&mut socket).0["metadata"]["failure"]["code"],
        "Unavailable"
    );
    assert!(!path.exists());
    h["kind"] = json!("file.create.commit");
    h["metadata"] = json!({"transfer_id":"55555555-5555-4555-8555-555555555555"});
    h["request_id"] = json!(6);
    send(&mut socket, &h);
    assert_eq!(
        receive(&mut socket).0["metadata"]["failure"]["code"],
        "Unavailable"
    );
    h["kind"] = json!("file.upload.begin");
    h["request_id"] = json!(8);
    h["stream_id"] = json!("55555555-5555-4555-8555-555555555555");
    h["metadata"] = json!({"transfer_id":h["stream_id"],"path_base64":STANDARD.encode(path.as_os_str().as_bytes()),"total_length":0});
    send(&mut socket, &h);
    let refusal = receive(&mut socket).0;
    assert_eq!(refusal["kind"], "error");
    assert_eq!(refusal["metadata"]["code"], "unavailable");
    h["stream_id"] = serde_json::Value::Null;
    h["kind"] = json!("service.call");
    h["metadata"] = json!({"call":{"method":"inspect"}});
    h["request_id"] = json!(7);
    send(&mut socket, &h);
    let (header, payload) = receive(&mut socket);
    assert_eq!(header["kind"], "service.event");
    let value: serde_json::Value = serde_json::from_slice(&payload).unwrap();
    assert_eq!(value["receipt"]["state"], "unknown");
}
#[test]
fn shared_watch_overflow_maps_to_explicit_remote_rescan() {
    use buntrail_helper::framed::dispatcher::{Dispatcher, Request, Response};
    use buntrail_protocol::services::{Call, File, Reply};
    use std::{
        sync::{Arc, atomic::AtomicBool},
        task::{Context, Poll, Waker},
        time::Duration,
    };
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("root");
    fs::create_dir(&root).unwrap();
    let p = root.join("file");
    fs::write(&p, b"first").unwrap();
    let d = Dispatcher::new(
        buntrail_services::connections::local::identity().unwrap(),
        dir.path().join("state"),
    )
    .unwrap();
    let file = File {
        path_base64: STANDARD.encode(root.as_os_str().as_bytes()),
        resolved_identity: None,
    };
    let Response::Events(mut stream) = d
        .handle_sync(Request::Service {
            call: Call::Watch { file: file.clone() },
            operation: None,
            request: 1,
            binding: "verified".into(),
            owner: None,
            payload: Vec::new(),
            authentication: None,
            cancel: Arc::new(AtomicBool::new(false)),
        })
        .unwrap()
    else {
        panic!("watch stream")
    };
    fs::write(&p, b"second").unwrap();
    std::thread::sleep(Duration::from_millis(350));
    fs::write(&p, b"third").unwrap();
    std::thread::sleep(Duration::from_millis(350));
    let Poll::Ready(Some(Ok(Reply::Watch {
        file: observed,
        event,
    }))) = stream
        .as_mut()
        .poll_next(&mut Context::from_waker(Waker::noop()))
    else {
        panic!("rescan required")
    };
    assert_eq!(event, "rescan_required");
    assert_eq!(observed.path_base64, file.path_base64);
}

fn git_fixture(root: &std::path::Path, args: &[&str]) -> Vec<u8> {
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    out.stdout
}
fn completed_mutation_cancel(kind: &str) {
    use buntrail_protocol::services as w;
    use sha2::{Digest, Sha256};
    use std::{
        io::Write,
        os::unix::fs::{MetadataExt, PermissionsExt},
        sync::atomic::AtomicBool,
    };
    let server = Server::start();
    let root = fs::canonicalize(server.dir.path()).unwrap().join("project");
    fs::create_dir(&root).unwrap();
    let path = root.join("effect");
    let local = LocalConnection::open(server.dir.path().join("local")).unwrap();
    let mut socket = server.connect();
    let context = register(&mut socket);
    let op = "99999999-9999-4999-8999-999999999999";
    let mut h = header(
        "service.call",
        json!({"call":{"method":"file_mutate","file":{"path_base64":STANDARD.encode(path.as_os_str().as_bytes()),"resolved_identity":null},"expected":null,"command":{"kind":"create_directory"}}}),
    );
    h["context"] = context.clone();
    h["request_id"] = json!(20);
    h["operation_id"] = json!(op);
    if kind == "git" {
        git_fixture(&root, &["init", "-b", "main"]);
        git_fixture(&root, &["config", "user.name", "Fixture"]);
        git_fixture(&root, &["config", "user.email", "fixture@example.invalid"]);
        fs::write(&path, b"original").unwrap();
        git_fixture(&root, &["add", "effect"]);
        let hook = root.join(".git/hooks/pre-commit");
        fs::write(&hook, b"#!/bin/sh\necho attempt >> .git/attempts\n").unwrap();
        fs::set_permissions(hook, fs::Permissions::from_mode(0o700)).unwrap();
        let file = FileRef {
            target: local.identity.clone(),
            path: TargetPath::posix(root.as_os_str().as_bytes().to_vec()).unwrap(),
            resolved_identity: None,
        };
        let cancel = AtomicBool::new(false);
        let wt = local.git.discover_sync(file, &cancel).unwrap().unwrap();
        let state = local.git.status_sync(wt.clone(), &cancel).unwrap().state;
        h["metadata"] = json!({"call":w::Call::GitMutate { worktree: w::Worktree::from_core(&wt).unwrap(), expected: w::GitState::from_core(&state), command: w::GitCommand::Commit { message: "once".into() } }});
    } else if kind == "create" {
        h["kind"] = json!("file.upload.begin");
        h["stream_id"] = json!(op);
        h["metadata"] = json!({"transfer_id":op,"path_base64":STANDARD.encode(path.as_os_str().as_bytes()),"total_length":8});
        send(&mut socket, &h);
        assert_eq!(receive(&mut socket).0["kind"], "ack");
        h["kind"] = json!("file.upload.chunk");
        h["metadata"] = json!({"transfer_id":op,"offset":0});
        socket.write_all(&encode(&h, b"original")).unwrap();
        assert_eq!(receive(&mut socket).0["kind"], "stream.credit");
        h["kind"] = json!("file.upload.end");
        h["metadata"] = json!({"transfer_id":op,"sha256":w::hex(&Sha256::digest(b"original"))});
        send(&mut socket, &h);
        assert_eq!(receive(&mut socket).0["kind"], "ack");
        h["kind"] = json!("file.create.commit");
        h["metadata"] = json!({"transfer_id":op});
    }
    send(&mut socket, &h);
    let (result, bytes) = receive(&mut socket);
    assert_eq!(result["kind"], "service.event");
    assert_eq!(result["metadata"]["terminal"], true);
    let original: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(original["receipt"]["state"], "confirmed", "{original}");
    let before = fs::metadata(&path).unwrap();
    // Completion has crossed Pending -> ServiceStream; retain its credit deliberately.
    let mut cancel = header("cancel", json!({"request_id":20}));
    cancel["context"] = context.clone();
    cancel["request_id"] = json!(21);
    send(&mut socket, &cancel);
    assert_eq!(
        receive(&mut socket).0["metadata"]["outcome"],
        "unknown",
        "completed {kind} cannot claim no effects"
    );
    let mut inspect = header("service.call", json!({"call":{"method":"inspect"}}));
    inspect["context"] = context;
    inspect["request_id"] = json!(22);
    inspect["operation_id"] = json!(op);
    send(&mut socket, &inspect);
    let (_, bytes) = receive(&mut socket);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
        original
    );
    cancel["request_id"] = json!(23);
    cancel["metadata"] = json!({"request_id":22});
    send(&mut socket, &cancel);
    assert_eq!(
        receive(&mut socket).0["metadata"]["outcome"],
        "confirmed_cancel",
        "read-only inspection delivery is cancellable"
    );
    let after = fs::metadata(&path).unwrap();
    assert_eq!(
        (before.ino(), before.mtime(), before.mtime_nsec()),
        (after.ino(), after.mtime(), after.mtime_nsec())
    );
    if kind == "git" {
        assert_eq!(fs::read(root.join(".git/attempts")).unwrap(), b"attempt\n");
        assert_eq!(git_fixture(&root, &["rev-list", "--count", "HEAD"]), b"1\n");
    }
}
#[test]
fn completed_file_mutation_cancel_preserves_original_effect() {
    completed_mutation_cancel("file");
}
#[test]
fn completed_git_mutation_cancel_preserves_original_effect() {
    completed_mutation_cancel("git");
}
#[test]
fn completed_create_commit_cancel_preserves_original_effect() {
    completed_mutation_cancel("create");
}

#[test]
fn watch_change_arrives_without_a_followup_client_packet() {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    use std::time::Duration;
    let server = Server::start();
    let root = server.dir.path().join("watch-root");
    fs::create_dir(&root).unwrap();
    let path = root.join("file");
    fs::write(&path, b"initial").unwrap();
    let mut socket = server.connect();
    let context = register(&mut socket);
    let file = json!({"path_base64":STANDARD.encode(root.as_os_str().as_bytes()),"resolved_identity":null});
    let mut request = header(
        "service.call",
        json!({"call":{"method":"watch","file":file}}),
    );
    request["request_id"] = json!(3);
    request["context"] = context.clone();
    send(&mut socket, &request);
    // Let the subscription become quiet; repeated edits tolerate registration scheduling.
    std::thread::sleep(Duration::from_millis(350));
    let stop = Arc::new(AtomicBool::new(false));
    let writing = stop.clone();
    let writer = std::thread::spawn(move || {
        for n in 0..100 {
            if writing.load(Ordering::SeqCst) {
                break;
            }
            fs::write(&path, format!("change {n}")).unwrap();
            std::thread::sleep(Duration::from_millis(20));
        }
    });
    let observed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| receive(&mut socket)));
    stop.store(true, Ordering::SeqCst);
    writer.join().unwrap();
    let (response, payload) =
        observed.expect("watch source did not wake the quiet wire connection");
    assert_eq!(response["kind"], "service.event");
    assert_eq!(response["request_id"], 3);
    assert_eq!(response["context"], context);
    let value: serde_json::Value = serde_json::from_slice(&payload).unwrap();
    assert!(
        value["event"] == "changed" || value["event"] == "rescan_required",
        "{value}"
    );
    assert_eq!(value["file"]["path_base64"], file["path_base64"]);
    let mut cancel = header("cancel", json!({"request_id":3}));
    cancel["request_id"] = json!(4);
    cancel["context"] = context;
    send(&mut socket, &cancel);
    assert_eq!(receive(&mut socket).0["kind"], "cancel.result");
}
