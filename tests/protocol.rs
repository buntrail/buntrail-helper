use buntrail_helper::{MAX_FRAME_BYTES, serve};
use serde_json::{Value, json};
fn frame(value: &Value) -> Vec<u8> {
    let data = serde_json::to_vec(value).unwrap();
    let mut frame = (data.len() as u32).to_be_bytes().to_vec();
    frame.extend(data);
    frame
}
fn replies(mut output: &[u8]) -> Vec<Value> {
    let mut result = Vec::new();
    while !output.is_empty() {
        let size = u32::from_be_bytes(output[..4].try_into().unwrap()) as usize;
        result.push(serde_json::from_slice(&output[4..4 + size]).unwrap());
        output = &output[4 + size..];
    }
    result
}
#[test]
fn handshake_and_malformed_request_are_explicit() {
    let mut input = frame(&json!({"command":"fs.read","path":"/missing"}));
    input.extend(frame(&json!({"protocol":1})));
    input.extend_from_slice(&[0, 0, 0, 1, b'{']);
    input.extend(frame(&json!({"command":"unknown"})));
    let mut output = Vec::new();
    serve(input.as_slice(), &mut output).unwrap();
    let replies = replies(&output);
    assert_eq!(replies[0]["error"]["code"], "protocol_mismatch");
    assert_eq!(replies[1]["value"]["protocol"], 1);
    assert_eq!(replies[2]["error"]["code"], "invalid_json");
    assert_eq!(replies[3]["error"]["code"], "service_error");
}
#[test]
fn rejects_oversized_and_partial_frames() {
    let mut output = Vec::new();
    assert!(
        serve(
            (MAX_FRAME_BYTES as u32 + 1).to_be_bytes().as_slice(),
            &mut output
        )
        .is_err()
    );
    assert_eq!(replies(&output)[0]["error"]["code"], "invalid_frame");
    assert!(serve(&[0, 0][..], Vec::new()).is_err());
    assert!(serve(&[0, 0, 0, 4, b'{'][..], Vec::new()).is_err());
}

#[test]
fn executable_serves_real_file_operations_over_framed_stdio() {
    use std::{
        io::{Read, Write},
        process::{Command, Stdio},
    };
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("literal ; name.txt");
    let mut child = Command::new(env!("CARGO_BIN_EXE_buntrail-helper"))
        .arg("--stdio")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    let mut output = child.stdout.take().unwrap();
    let mut exchange = |request: Value| -> Value {
        input.write_all(&frame(&request)).unwrap();
        input.flush().unwrap();
        let mut length = [0; 4];
        output.read_exact(&mut length).unwrap();
        let mut bytes = vec![0; u32::from_be_bytes(length) as usize];
        output.read_exact(&mut bytes).unwrap();
        serde_json::from_slice(&bytes).unwrap()
    };
    assert_eq!(exchange(json!({"protocol":1}))["value"]["protocol"], 1);
    assert_eq!(
        exchange(json!({"command":"fs.create","path":path,"text":"across stdio"}))["ok"],
        true
    );
    assert_eq!(
        exchange(json!({"command":"fs.read","path":path}))["value"]["text"],
        "across stdio"
    );
    drop(exchange);
    drop(input);
    assert!(child.wait().unwrap().success());
}
