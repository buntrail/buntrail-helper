//! Fixed SSH bootstrap entry points. No caller-controlled shell text or project paths.
use crate::framed::supervisor::error;
use buntrail_services::connections::bootstrap::*;
use std::{
    io::{self, Read, Write},
    path::PathBuf,
};
pub fn install() -> io::Result<()> {
    let mut bytes = Vec::new();
    io::stdin()
        .lock()
        .take((MAX_ARTIFACT_BYTES * 4 / 3 + 65536) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() >= MAX_ARTIFACT_BYTES * 4 / 3 + 65536 {
        return Err(error("Bootstrap payload too large"));
    }
    let input = serde_json::from_slice(&bytes).map_err(error)?;
    let descriptor = install_uploaded(input).map_err(error)?;
    serde_json::to_writer(io::stdout().lock(), &descriptor).map_err(error)
}
pub fn bridge() -> io::Result<()> {
    Platform::current().map_err(error)?;
    let input: BridgeInput =
        serde_json::from_slice(&read_line(&mut io::stdin().lock()).map_err(error)?)
            .map_err(error)?;
    let target = if let Some(binding) = input.container.as_ref() {
        binding.current_target().map_err(error)?
    } else {
        ssh_identity(
            buntrail_services::connections::local::identity().map_err(error)?,
            &input.peer_key,
        )
        .map_err(error)?
    };
    let prelude =
        BridgePrelude::current(target.clone(), std::env::var_os("SSH_AUTH_SOCK").as_deref())
            .map_err(error)?;
    {
        let mut output = io::stdout().lock();
        serde_json::to_writer(&mut output, &prelude).map_err(error)?;
        output.write_all(b"\n")?;
        output.flush()?;
    }
    if target != input.expected_target {
        return Err(error("SSH target changed"));
    }
    let cache =
        PathBuf::from(std::env::var_os("HOME").ok_or_else(|| error("Target home unavailable"))?)
            .join(".buntrail-app");
    if !cache.is_absolute() {
        return Err(error("Target home must be absolute"));
    }
    private(&cache)?;
    let runtimes = cache.join("runtimes");
    private(&runtimes)?;
    use sha2::Digest;
    let binding = sha2::Sha256::digest(serde_json::to_vec(&target).map_err(error)?);
    let directory = runtimes.join(
        binding
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
    );
    private(&directory)?;
    if let Some(binding) = input.container.as_ref() {
        crate::framed::supervisor::bridge_with_container(
            &directory.join("supervisor.sock"),
            binding,
        )
    } else {
        crate::framed::supervisor::bridge_with_peer(
            &directory.join("supervisor.sock"),
            Some(&input.peer_key),
        )
    }
}
fn private(path: &std::path::Path) -> io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    match std::fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }
    let m = std::fs::symlink_metadata(path)?;
    if !m.is_dir() || m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o077 != 0 {
        return Err(error("Private user-owned SSH cache required"));
    }
    Ok(())
}
