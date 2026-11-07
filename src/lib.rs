//! Remote services library and helper executable.
//!
//! See the repository README for usage, prerequisites and platform limitations.
//! A local/remote stdio transport: four-byte big-endian length followed by UTF-8 JSON.
use buntrail_services::Services;
use serde_json::{Value, json};
use std::io::{self, Read, Write};

pub const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;
#[cfg(unix)]
pub mod supervisor;

pub fn serve(mut input: impl Read, mut output: impl Write) -> io::Result<()> {
    let services = Services::new();
    let instance = format!(
        "{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_nanos()
    );
    serve_session(&mut input, &mut output, &services, &instance)
}
pub fn serve_session(
    mut input: impl Read,
    mut output: impl Write,
    services: &Services,
    instance: &str,
) -> io::Result<()> {
    let mut ready = false;
    loop {
        let mut length = [0u8; 4];
        match input.read(&mut length[..1]) {
            Ok(0) => return Ok(()),
            Ok(_) => input.read_exact(&mut length[1..])?,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        }
        let size = u32::from_be_bytes(length) as usize;
        if size == 0 || size > MAX_FRAME_BYTES {
            reply(
                &mut output,
                &json!({"ok":false,"error":{"code":"invalid_frame","message":"frame length must be between 1 and 8388608"}}),
            )?;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid frame length",
            ));
        }
        let mut bytes = vec![0; size];
        input.read_exact(&mut bytes)?;
        let request = match serde_json::from_slice::<Value>(&bytes) {
            Ok(value) if value.is_object() => value,
            _ => {
                reply(
                    &mut output,
                    &json!({"ok":false,"error":{"code":"invalid_json","message":"request must be a JSON object"}}),
                )?;
                continue;
            }
        };
        let response = if !ready {
            if request["protocol"] == 1 {
                ready = true;
                json!({"ok":true,"value":{"protocol":1,"instance":instance,"transport":"length-prefixed-json","terminal_encoding":"utf8-lossy","max_frame_bytes":MAX_FRAME_BYTES}})
            } else {
                json!({"ok":false,"error":{"code":"protocol_mismatch","message":"first request must negotiate protocol 1"}})
            }
        } else {
            match services.call(&request) {
                Ok(value) => json!({"ok":true,"value":value}),
                Err(message) => {
                    json!({"ok":false,"error":{"code":"service_error","message":message}})
                }
            }
        };
        reply(&mut output, &response)?;
    }
}
fn reply(output: &mut impl Write, response: &Value) -> io::Result<()> {
    let mut bytes = serde_json::to_vec(response)?;
    if bytes.len() > MAX_FRAME_BYTES {
        bytes = serde_json::to_vec(
            &json!({"ok":false,"error":{"code":"response_too_large","message":"response exceeds frame limit"}}),
        )?;
    }
    output.write_all(&(bytes.len() as u32).to_be_bytes())?;
    output.write_all(&bytes)?;
    output.flush()
}

#[cfg(unix)]
pub mod framed;
