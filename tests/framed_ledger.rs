#![cfg(unix)]
#[path = "framed_support.rs"]
mod support;
use serde_json::json;
use support::*;
#[test]
fn missing_receipt_is_unknown() {
    let server = Server::start();
    let mut s = server.connect();
    let c = register(&mut s);
    let mut h = header(
        "operation.inspect",
        json!({"operation_id":"44444444-4444-4444-8444-444444444444"}),
    );
    h["context"] = c;
    h["operation_id"] = h["metadata"]["operation_id"].clone();
    send(&mut s, &h);
    assert_eq!(receive(&mut s).0["metadata"]["state"], "unknown");
}

#[test]
fn duplicate_operation_digest() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use sha2::{Digest, Sha256};
    use std::io::Write;
    let server = Server::start();
    let mut s = server.connect();
    let c = register(&mut s);
    let path = server.dir.path().join("saved");
    for (i, bytes) in [
        b"original".as_slice(),
        b"original".as_slice(),
        b"different".as_slice(),
    ]
    .into_iter()
    .enumerate()
    {
        let transfer = format!("55555555-5555-4555-8555-{:012}", i);
        let mut h = header(
            "file.upload.begin",
            json!({"transfer_id":transfer,"path_base64":STANDARD.encode(path.as_os_str().as_encoded_bytes()),"total_length":bytes.len()}),
        );
        h["context"] = c.clone();
        h["operation_id"] = json!("44444444-4444-4444-8444-444444444444");
        h["stream_id"] = json!(transfer);
        send(&mut s, &h);
        assert_eq!(receive(&mut s).0["kind"], "ack");
        h["kind"] = json!("file.upload.chunk");
        h["metadata"] = json!({"transfer_id":transfer,"offset":0});
        s.write_all(&encode(&h, bytes)).unwrap();
        assert_eq!(receive(&mut s).0["kind"], "stream.credit");
        h["kind"] = json!("file.upload.end");
        h["metadata"] =
            json!({"transfer_id":transfer,"sha256":format!("{:x}",Sha256::digest(bytes))});
        send(&mut s, &h);
        assert_eq!(receive(&mut s).0["kind"], "ack");
        h["kind"] = json!("file.save.commit");
        h["metadata"] =
            json!({"transfer_id":transfer,"submitted_revision":1,"expected_version":null});
        send(&mut s, &h);
        let response = receive(&mut s).0;
        assert_eq!(
            response["metadata"]["state"],
            if i < 2 { "confirmed" } else { "failed" }
        );
        if i == 2 {
            assert_eq!(
                response["metadata"]["failure"]["effect"],
                "proven_no_effect"
            );
            assert_eq!(response["metadata"]["failure"]["code"], "InvalidArgument");
        }
        assert_eq!(std::fs::read(&path).unwrap(), b"original");
    }
}
#[test]
fn crash_writer_fixture() {
    let Some(root) = std::env::var_os("BUNTRAIL_CRASH_FIXTURE") else {
        return;
    };
    use buntrail_core::contracts::*;
    use buntrail_services::{
        connections::local::identity,
        files::{FailPoint, LocalFileService},
    };
    let root = std::path::PathBuf::from(root);
    std::fs::create_dir(root.join("state")).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(root.join("state"), std::fs::Permissions::from_mode(0o700)).unwrap();
    let target = identity().unwrap();
    let files = LocalFileService::new(target.clone(), root.join("state/files")).unwrap();
    files.set_failpoint(FailPoint::Completion);
    let receipt = files.save_sync(SaveRequest {
        operation: OperationID([9; 16]),
        file: FileRef {
            target,
            path: TargetPath::posix(root.join("effect").as_os_str().as_encoded_bytes().to_vec())
                .unwrap(),
            resolved_identity: None,
        },
        expected_version: None,
        submitted_revision: BufferRevision(1),
        source: ByteSource::Memory(b"durable effect".as_slice().into()),
    });
    assert!(matches!(receipt.state, OperationState::Unknown(_)));
    std::process::exit(23);
}
#[test]
fn crash_after_side_effect_before_completion_is_unknown_and_recovered() {
    use buntrail_core::contracts::*;
    use buntrail_services::{connections::local::identity, operations::ledger::Ledger};
    use std::{
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    let status = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "crash_writer_fixture"])
        .env("BUNTRAIL_CRASH_FIXTURE", dir.path())
        .stdout(Stdio::null())
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(23));
    assert_eq!(
        std::fs::read(dir.path().join("effect")).unwrap(),
        b"durable effect"
    );
    let ledger = Ledger::open(dir.path().join("state/files/operations")).unwrap();
    assert!(matches!(
        ledger
            .inspect(OperationID([9; 16]), identity().unwrap())
            .unwrap()
            .state,
        OperationState::Unknown(_)
    ));
    let socket = dir.path().join("state/socket");
    let child = Command::new(env!("CARGO_BIN_EXE_buntrail-helper"))
        .args(["serve", "--socket"])
        .arg(&socket)
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    let server = Server { dir, child, socket };
    let until = Instant::now() + Duration::from_secs(3);
    while !server.socket.exists() && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        matches!(
            ledger
                .read(OperationID([9; 16]))
                .unwrap()
                .unwrap()
                .receipt
                .state,
            OperationState::Unknown(_)
        ),
        "startup must durably recover interrupted receipt"
    );
}
#[test]
fn disconnected_uncommitted_upload_leaves_project_unchanged() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use std::{
        io::Write,
        time::{Duration, Instant},
    };
    let server = Server::start();
    let path = server.dir.path().join("untouched");
    std::fs::write(&path, b"before").unwrap();
    let mut s = server.connect();
    let c = register(&mut s);
    let transfer = "55555555-5555-4555-8555-555555555555";
    let mut h = header(
        "file.upload.begin",
        json!({"transfer_id":transfer,"path_base64":STANDARD.encode(path.as_os_str().as_encoded_bytes()),"total_length":10}),
    );
    h["context"] = c;
    h["operation_id"] = json!("44444444-4444-4444-8444-444444444444");
    h["stream_id"] = json!(transfer);
    send(&mut s, &h);
    assert_eq!(receive(&mut s).0["kind"], "ack");
    h["kind"] = json!("file.upload.chunk");
    h["metadata"] = json!({"transfer_id":transfer,"offset":0});
    s.write_all(&encode(&h, b"half")).unwrap();
    assert_eq!(receive(&mut s).0["kind"], "stream.credit");
    drop(s);
    let until = Instant::now() + Duration::from_secs(2);
    while std::fs::read_dir(server.socket.parent().unwrap().join("uploads"))
        .unwrap()
        .count()
        > 0
        && Instant::now() < until
    {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(std::fs::read(&path).unwrap(), b"before");
    assert_eq!(
        std::fs::read_dir(server.socket.parent().unwrap().join("uploads"))
            .unwrap()
            .count(),
        0
    );
}
#[test]
fn disconnect_keeps_submitted_mutation_source_owned_until_completion() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use buntrail_core::contracts::*;
    use buntrail_services::operations::ledger::Ledger;
    use sha2::{Digest, Sha256};
    use std::{
        io::Write,
        time::{Duration, Instant},
    };
    let server = Server::start();
    let mut s = server.connect();
    let c = register(&mut s);
    let path = server.dir.path().join("owned-save");
    let bytes = b"owned after disconnect";
    let operation = "44444444-4444-4444-8444-444444444444";
    let transfer = "55555555-5555-4555-8555-555555555555";
    let mut h = header(
        "file.upload.begin",
        json!({"transfer_id":transfer,"path_base64":STANDARD.encode(path.as_os_str().as_encoded_bytes()),"total_length":bytes.len()}),
    );
    h["context"] = c.clone();
    h["operation_id"] = json!(operation);
    h["stream_id"] = json!(transfer);
    h["request_id"] = json!(10);
    send(&mut s, &h);
    assert_eq!(receive(&mut s).0["kind"], "ack");
    h["kind"] = json!("file.upload.chunk");
    h["metadata"] = json!({"transfer_id":transfer,"offset":0});
    s.write_all(&encode(&h, bytes)).unwrap();
    assert_eq!(receive(&mut s).0["kind"], "stream.credit");
    h["kind"] = json!("file.upload.end");
    h["metadata"] = json!({"transfer_id":transfer,"sha256":format!("{:x}",Sha256::digest(bytes))});
    send(&mut s, &h);
    assert_eq!(receive(&mut s).0["kind"], "ack");
    let ledger = Ledger::open(server.socket.parent().unwrap().join("files/operations")).unwrap();
    let lock = ledger.lock().unwrap();
    h["kind"] = json!("file.save.commit");
    h["metadata"] = json!({"transfer_id":transfer,"submitted_revision":7,"expected_version":null});
    h["request_id"] = json!(11);
    send(&mut s, &h);
    let mut cancel = header("cancel", json!({"request_id":11}));
    cancel["context"] = c;
    cancel["request_id"] = json!(12);
    send(&mut s, &cancel);
    let response = receive(&mut s).0;
    assert_eq!(response["kind"], "cancel.result");
    assert_eq!(response["metadata"]["outcome"], "unknown");
    drop(s);
    drop(lock);
    let until = Instant::now() + Duration::from_secs(4);
    let id = OperationID([
        0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x84, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
        0x44,
    ]);
    loop {
        if ledger
            .read(id)
            .unwrap()
            .is_some_and(|r| matches!(r.receipt.state, OperationState::Confirmed(_)))
        {
            break;
        }
        assert!(
            Instant::now() < until,
            "submitted save lost ownership on disconnect"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(std::fs::read(path).unwrap(), bytes);
}

#[test]
fn completed_upload_is_revalidated_before_durable_acceptance() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use buntrail_core::contracts::*;
    use buntrail_services::operations::ledger::Ledger;
    use sha2::{Digest, Sha256};
    use std::io::Write;
    let server = Server::start();
    let mut s = server.connect();
    let c = register(&mut s);
    let path = server.dir.path().join("owned-save");
    let bytes = b"owned after disconnect";
    let operation = "44444444-4444-4444-8444-444444444444";
    let transfer = "55555555-5555-4555-8555-555555555555";
    let mut h = header(
        "file.upload.begin",
        json!({"transfer_id":transfer,"path_base64":STANDARD.encode(path.as_os_str().as_encoded_bytes()),"total_length":bytes.len()}),
    );
    h["context"] = c.clone();
    h["operation_id"] = json!(operation);
    h["stream_id"] = json!(transfer);
    h["request_id"] = json!(10);
    send(&mut s, &h);
    assert_eq!(receive(&mut s).0["kind"], "ack");
    h["kind"] = json!("file.upload.chunk");
    h["metadata"] = json!({"transfer_id":transfer,"offset":0});
    s.write_all(&encode(&h, bytes)).unwrap();
    assert_eq!(receive(&mut s).0["kind"], "stream.credit");
    h["kind"] = json!("file.upload.end");
    h["metadata"] = json!({"transfer_id":transfer,"sha256":format!("{:x}",Sha256::digest(bytes))});
    send(&mut s, &h);
    assert_eq!(receive(&mut s).0["kind"], "ack");
    let staged = std::fs::read_dir(server.socket.parent().unwrap().join("uploads"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    std::fs::write(staged, vec![b'x'; bytes.len()]).unwrap();
    h["kind"] = json!("file.save.commit");
    h["metadata"] = json!({"transfer_id":transfer,"submitted_revision":7,"expected_version":null});
    h["request_id"] = json!(11);
    send(&mut s, &h);
    assert_eq!(receive(&mut s).0["kind"], "error");
    assert!(!path.exists());
    let ledger = Ledger::open(server.socket.parent().unwrap().join("files/operations")).unwrap();
    assert!(
        ledger
            .read(OperationID([
                0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x84, 0x44, 0x44, 0x44, 0x44, 0x44,
                0x44, 0x44
            ]))
            .unwrap()
            .is_none()
    );
}

fn stage_fix_save(
    s: &mut std::os::unix::net::UnixStream,
    context: &serde_json::Value,
    path: &std::path::Path,
) -> serde_json::Value {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use sha2::{Digest, Sha256};
    use std::io::Write;
    let bytes = b"fix owned save";
    let transfer = "55555555-5555-4555-8555-555555555555";
    let mut h = header(
        "file.upload.begin",
        json!({"transfer_id":transfer,"path_base64":STANDARD.encode(path.as_os_str().as_encoded_bytes()),"total_length":bytes.len()}),
    );
    h["context"] = context.clone();
    h["operation_id"] = json!("44444444-4444-4444-8444-444444444444");
    h["stream_id"] = json!(transfer);
    h["request_id"] = json!(10);
    send(s, &h);
    assert_eq!(receive(s).0["kind"], "ack");
    h["kind"] = json!("file.upload.chunk");
    h["metadata"] = json!({"transfer_id":transfer,"offset":0});
    s.write_all(&encode(&h, bytes)).unwrap();
    assert_eq!(receive(s).0["kind"], "stream.credit");
    h["kind"] = json!("file.upload.end");
    h["metadata"] = json!({"transfer_id":transfer,"sha256":format!("{:x}",Sha256::digest(bytes))});
    send(s, &h);
    assert_eq!(receive(s).0["kind"], "ack");
    h["kind"] = json!("file.save.commit");
    h["metadata"] = json!({"transfer_id":transfer,"submitted_revision":1,"expected_version":null});
    h["request_id"] = json!(11);
    h
}
fn cancellation_collision(reverse: bool) {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use buntrail_services::operations::ledger::Ledger;
    use std::time::{Duration, Instant};
    let server = Server::start();
    let mut s = server.connect();
    let context = register(&mut s);
    let path = server.dir.path().join("fix-effect");
    let save = stage_fix_save(&mut s, &context, &path);
    let ledger = Ledger::open(server.socket.parent().unwrap().join("files/operations")).unwrap();
    let lock = ledger.lock().unwrap();
    let transfer = "66666666-6666-4666-8666-666666666666";
    let mut upload = header(
        "file.upload.begin",
        json!({"transfer_id":transfer,"path_base64":STANDARD.encode(server.dir.path().join("unused").as_os_str().as_encoded_bytes()),"total_length":4}),
    );
    upload["context"] = context.clone();
    upload["operation_id"] = json!("77777777-7777-4777-8777-777777777777");
    upload["stream_id"] = json!(transfer);
    upload["request_id"] = json!(11);
    if reverse {
        send(&mut s, &upload);
        assert_eq!(receive(&mut s).0["kind"], "ack");
        send(&mut s, &save);
    } else {
        send(&mut s, &save);
        send(&mut s, &upload);
    }
    let refused = receive(&mut s).0;
    assert_eq!(
        refused["kind"], "error",
        "colliding live request must be refused before admission"
    );
    assert_eq!(refused["metadata"]["code"], "invalid_argument");
    let mut cancel = header("cancel", json!({"request_id":11}));
    cancel["context"] = context;
    cancel["request_id"] = json!(12);
    send(&mut s, &cancel);
    let response = receive(&mut s).0;
    assert_eq!(
        response["metadata"]["outcome"],
        if reverse {
            "confirmed_cancel"
        } else {
            "unknown"
        }
    );
    drop(lock);
    if reverse {
        assert!(!path.exists());
    } else {
        let until = Instant::now() + Duration::from_secs(3);
        while !path.exists() && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(std::fs::read(&path).unwrap(), b"fix owned save");
    }
}
#[test]
fn upload_id_collision_cannot_confirm_cancellation_of_pending_save() {
    cancellation_collision(false);
}
#[test]
fn save_id_collision_with_existing_upload_is_refused_before_admission() {
    cancellation_collision(true);
}

#[test]
fn maintenance_fault_preserves_owned_save_and_drains_to_clean_idle_exit() {
    use buntrail_services::operations::ledger::Ledger;
    use std::{
        os::unix::fs::PermissionsExt,
        time::{Duration, Instant},
    };
    let mut server = Server::start();
    let mut s = server.connect();
    let context = register(&mut s);
    let path = server.dir.path().join("maintenance-effect");
    let save = stage_fix_save(&mut s, &context, &path);
    let ledger = Ledger::open(server.socket.parent().unwrap().join("files/operations")).unwrap();
    let lock = ledger.lock().unwrap();
    send(&mut s, &save);
    let mut cancel = header("cancel", json!({"request_id":11}));
    cancel["context"] = context.clone();
    cancel["request_id"] = json!(12);
    send(&mut s, &cancel);
    assert_eq!(receive(&mut s).0["metadata"]["outcome"], "unknown");
    let fault = server
        .socket
        .parent()
        .unwrap()
        .join("uploads/unsafe-fixture");
    std::fs::write(&fault, b"fixture").unwrap();
    std::fs::set_permissions(&fault, std::fs::Permissions::from_mode(0o644)).unwrap();
    std::thread::sleep(Duration::from_secs(62));
    assert!(
        server.child.try_wait().unwrap().is_none(),
        "maintenance fault must not abandon the live owned save"
    );
    let mut begin = save.clone();
    begin["kind"] = json!("file.upload.begin");
    begin["metadata"] = json!({"transfer_id":"66666666-6666-4666-8666-666666666666","path_base64":"L3VudXNlZA==","total_length":0});
    begin["stream_id"] = json!("66666666-6666-4666-8666-666666666666");
    begin["request_id"] = json!(20);
    send(&mut s, &begin);
    let refused = receive(&mut s).0;
    assert_eq!(refused["kind"], "error");
    assert_eq!(refused["metadata"]["code"], "unavailable");
    drop(lock);
    let until = Instant::now() + Duration::from_secs(3);
    while !path.exists() && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(std::fs::read(&path).unwrap(), b"fix owned save");
    let mut inspect = header(
        "operation.inspect",
        json!({"operation_id":"44444444-4444-4444-8444-444444444444"}),
    );
    inspect["context"] = context.clone();
    inspect["operation_id"] = inspect["metadata"]["operation_id"].clone();
    inspect["request_id"] = json!(21);
    send(&mut s, &inspect);
    assert_eq!(receive(&mut s).0["metadata"]["state"], "confirmed");
    let mut release = header(
        "lease.release",
        json!({"lease_id":"33333333-3333-4333-8333-333333333333","intent":"resolved_workspace_closure"}),
    );
    release["context"] = context;
    release["request_id"] = json!(22);
    send(&mut s, &release);
    assert_eq!(receive(&mut s).0["kind"], "ack");
    drop(s);
    let start = Instant::now();
    while server.child.try_wait().unwrap().is_none() && start.elapsed() < Duration::from_secs(34) {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(server.child.try_wait().unwrap().unwrap().success());
    assert!(!server.socket.exists());
}
