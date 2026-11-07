pub mod dispatcher;
pub mod leases;
pub mod supervisor;
mod transport;

mod services;

pub mod terminal;

pub mod ssh;

mod wait;

use std::path::Path;
pub fn run(args: &[std::ffi::OsString]) -> Option<std::io::Result<()>> {
    Some(match args {
        [verb, flag, path, key, binding]
            if verb == "serve-container" && flag == "--socket" && key == "--binding" =>
        {
            use base64::{Engine, engine::general_purpose::STANDARD};
            (|| {
                let binding = binding
                    .to_str()
                    .filter(|s| s.len() <= 65536)
                    .ok_or_else(|| std::io::Error::other("Invalid container binding"))?;
                let bytes = STANDARD.decode(binding).map_err(std::io::Error::other)?;
                let binding = serde_json::from_slice(&bytes).map_err(std::io::Error::other)?;
                supervisor::serve_with_container(Path::new(path), &binding)
            })()
        }
        [verb] if verb == "ssh-install" => ssh::install(),
        [verb] if verb == "ssh-bridge" => ssh::bridge(),
        [verb, flag, path, key, peer]
            if verb == "serve-ssh" && flag == "--socket" && key == "--peer-key" =>
        {
            match peer.to_str() {
                Some(peer) => supervisor::serve_with_peer(Path::new(path), Some(peer)),
                None => Err(std::io::Error::other("Invalid peer binding")),
            }
        }
        [verb] if verb == "probe" => {
            println!("{{\"helper\":\"buntrail-helper\",\"major\":1,\"minor\":0}}");
            Ok(())
        }
        [verb, flag, path] if flag == "--socket" && verb == "serve" => {
            supervisor::serve(Path::new(path))
        }
        [verb, flag, path] if flag == "--socket" && verb == "bridge" => {
            supervisor::bridge(Path::new(path))
        }
        _ => return None,
    })
}
