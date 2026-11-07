#![cfg(unix)]
#[path = "framed_support.rs"]
mod support;
use std::io::Write;
use support::*;
#[test]
fn frame_boundaries_and_limits() {
    let server = Server::start();
    for chunk in [1, 2, 7, 13, 512] {
        let mut s = server.connect();
        for bytes in golden("valid-hello.bin").chunks(chunk) {
            s.write_all(bytes).unwrap();
        }
        let (h, p) = receive(&mut s);
        assert_eq!(h["kind"], "welcome");
        assert!(p.is_empty());
        assert_eq!(h["metadata"]["initial_credit"], 524288);
    }
}
#[test]
fn exhausted_credit_keeps_control_responsive_and_cancel_stops_stream() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use serde_json::json;
    use std::{fs, io::Read, time::Duration};
    let server = Server::start();
    let path = server.dir.path().join("large");
    fs::write(&path, vec![b'a'; 768 * 1024]).unwrap();
    let mut s = server.connect();
    let c = register(&mut s);
    let mut h = header(
        "file.read",
        json!({"path_base64":STANDARD.encode(path.as_os_str().as_encoded_bytes())}),
    );
    h["context"] = c.clone();
    h["request_id"] = json!(10);
    send(&mut s, &h);
    assert_eq!(receive(&mut s).0["kind"], "file.read.begin");
    let mut total = 0;
    for _ in 0..8 {
        let (h, p) = receive(&mut s);
        assert_eq!(h["kind"], "file.read.chunk");
        total += p.len();
    }
    assert_eq!(total, 512 * 1024);
    s.set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    assert!(s.read(&mut [0; 1]).is_err());
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let mut cancel = header("cancel", json!({"request_id":10}));
    cancel["context"] = c;
    cancel["request_id"] = json!(11);
    send(&mut s, &cancel);
    assert_eq!(receive(&mut s).0["kind"], "cancel.result");
    s.set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    assert!(s.read(&mut [0; 1]).is_err());
}
#[test]
fn all_golden_frames_keep_the_shared_decoder_contract() {
    use buntrail_protocol::{frame::Decoder, types::Context};
    let context: Context = serde_json::from_slice(&golden("context.json")).unwrap();
    let fixtures: serde_json::Value = serde_json::from_slice(&golden("manifest.json")).unwrap();
    for item in fixtures.as_array().unwrap() {
        let bytes = golden(item["file"].as_str().unwrap());
        for chunk in [1, 3, 17, 8192] {
            let mut d = Decoder::default();
            let mut valid = true;
            for b in bytes.chunks(chunk) {
                if d.push(b, Some(&context)).is_err() {
                    valid = false;
                    break;
                }
            }
            valid &= d.finish().is_ok();
            assert_eq!(
                valid,
                item["valid"].as_bool().unwrap(),
                "{} chunk {}",
                item["file"],
                chunk
            );
        }
    }
}
#[test]
fn credit_replenishment_finishes_the_original_snapshot() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use std::{io::Read, time::Duration};
    let server = Server::start();
    let path = server.dir.path().join("large");
    let bytes = vec![b'x'; 600 * 1024];
    std::fs::write(&path, &bytes).unwrap();
    let mut s = server.connect();
    let c = register(&mut s);
    let mut h = header(
        "file.read",
        json!({"path_base64":STANDARD.encode(path.as_os_str().as_encoded_bytes())}),
    );
    h["context"] = c;
    h["request_id"] = json!(10);
    send(&mut s, &h);
    let begin = receive(&mut s).0;
    let stream = begin["stream_id"].clone();
    let mut actual = vec![];
    for _ in 0..8 {
        let (h, p) = receive(&mut s);
        assert_eq!(h["metadata"]["offset"], actual.len());
        actual.extend(p);
    }
    h["kind"] = json!("stream.credit");
    h["metadata"] = json!({"bytes":524288});
    h["stream_id"] = stream;
    h["request_id"] = json!(11);
    send(&mut s, &h);
    let (refusal, payload) = receive(&mut s);
    assert_eq!(refusal["kind"], "error");
    assert_eq!(refusal["request_id"], 11);
    assert_eq!(refusal["metadata"]["code"], "invalid_argument");
    assert!(payload.is_empty());
    s.set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    assert!(
        s.read(&mut [0; 1]).is_err(),
        "foreign credit unblocked the original stream"
    );
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    h["request_id"] = json!(10);
    send(&mut s, &h);
    loop {
        let (h, p) = receive(&mut s);
        if h["kind"] == "file.read.end" {
            assert_eq!(
                h["metadata"]["sha256"],
                format!("{:x}", Sha256::digest(&bytes))
            );
            break;
        }
        assert_eq!(h["metadata"]["offset"], actual.len());
        actual.extend(p);
    }
    assert_eq!(actual, bytes);
}
#[test]
fn inspection_remains_serviceable_when_all_read_slots_have_no_credit() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use serde_json::json;
    let server = Server::start();
    let path = server.dir.path().join("large");
    std::fs::write(&path, vec![0; 600 * 1024]).unwrap();
    let mut s = server.connect();
    let c = register(&mut s);
    for request in 10..14 {
        let mut h = header(
            "file.read",
            json!({"path_base64":STANDARD.encode(path.as_os_str().as_encoded_bytes())}),
        );
        h["context"] = c.clone();
        h["request_id"] = json!(request);
        send(&mut s, &h);
        assert_eq!(receive(&mut s).0["kind"], "file.read.begin");
        for _ in 0..8 {
            assert_eq!(receive(&mut s).0["kind"], "file.read.chunk");
        }
    }
    let mut h = header(
        "operation.inspect",
        json!({"operation_id":"44444444-4444-4444-8444-444444444444"}),
    );
    h["context"] = c;
    h["operation_id"] = h["metadata"]["operation_id"].clone();
    h["request_id"] = json!(99);
    send(&mut s, &h);
    assert_eq!(receive(&mut s).0["metadata"]["state"], "unknown");
}
