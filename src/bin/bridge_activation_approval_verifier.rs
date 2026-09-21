//! Auditable external verifier for the v2 activation approval package.

use bloch_l2_bridge::activation_approval::{verify_activation_approval, ApprovalCheckpoint};
use sha2::{Digest, Sha256};
use std::{
    env,
    fs::OpenOptions,
    io::{self, Read},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};

const REQUEST_DOMAIN: &[u8] = b"BLOCH-BRIDGE-ACTIVATION-READINESS-v2\0";
const MAX_REQUEST_BYTES: u64 = 128 * 1024;
const MAX_CHECKPOINT_BYTES: u64 = 4096;

fn word(value: &str) -> Result<[u8; 32], String> {
    let value = value.strip_prefix("0x").ok_or("digest lacks 0x prefix")?;
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("invalid SHA-256 digest".into());
    }
    let mut result = [0; 32];
    for (index, slot) in result.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| "invalid SHA-256 digest")?;
    }
    Ok(result)
}

fn checkpoint(path: &Path, expected: &str) -> Result<ApprovalCheckpoint, String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| e.to_string())?;
    let metadata = file.metadata().map_err(|e| e.to_string())?;
    if !metadata.file_type().is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_CHECKPOINT_BYTES
        || metadata.mode() & 0o022 != 0
    {
        return Err("checkpoint must be a small, non-writable regular file".into());
    }
    let mut bytes = Vec::new();
    file.take(MAX_CHECKPOINT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 != metadata.len() {
        return Err("checkpoint changed or exceeded its bound while reading".into());
    }
    if Sha256::digest(&bytes).as_slice() != word(expected)? {
        return Err("checkpoint checksum mismatch".into());
    }
    let checkpoint: ApprovalCheckpoint =
        serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    if checkpoint.schema != "postern.bridge-activation-approval-checkpoint.v2" {
        return Err("unsupported approval checkpoint".into());
    }
    Ok(checkpoint)
}

fn run() -> Result<(), String> {
    let args: Vec<_> = env::args().collect();
    if args.len() != 4 {
        return Err("usage: verifier POLICY_SHA256 CHECKPOINT CHECKPOINT_SHA256".into());
    }
    let state = checkpoint(Path::new(&args[2]), &args[3])?;
    let mut request = Vec::new();
    io::stdin()
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut request)
        .map_err(|e| e.to_string())?;
    if request.len() > MAX_REQUEST_BYTES as usize || !request.starts_with(REQUEST_DOMAIN) {
        return Err("invalid readiness request framing".into());
    }
    let bundle =
        serde_json::from_slice(&request[REQUEST_DOMAIN.len()..]).map_err(|e| e.to_string())?;
    verify_activation_approval(&bundle, &args[1], &state)?;
    println!("{:x}", Sha256::digest(&request));
    Ok(())
}

fn main() {
    if run().is_err() {
        std::process::exit(1);
    }
}
