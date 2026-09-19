// SPDX-License-Identifier: MIT OR Apache-2.0
//! Atomic local persistence for a staged block source and its versioned seal.
//!
//! The snapshot file and anti-rollback floor deliberately live behind
//! different interfaces. The file is replaced atomically only AFTER the floor
//! reports the new generation durable. A crash in between can make the old
//! snapshot unusable, but can never silently authorize rollback. The floor
//! implementation must be independently protected; a second file in the same
//! rollbackable directory is not an independent security domain.

use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::watcher::{
    L1Block, MemorySource, VersionedMemorySource, VersionedSourceRestoreError, VersionedSourceSeal,
};

const STORE_VERSION: u32 = 1;

/// Independently durable monotonic generation floor.
///
/// `advance_generation` MUST durably store at least `generation` before it
/// returns and MUST never lower the stored value. Implementations may use an
/// HSM/NVRAM counter, an authenticated database in another failure domain, or
/// equivalent host infrastructure. This crate intentionally provides no local
/// file implementation because colocating it with the snapshot would pretend
/// to provide rollback protection that does not exist.
pub trait SourceGenerationFloor {
    fn current_generation(&self) -> std::io::Result<u64>;
    fn advance_generation(&self, generation: u64) -> std::io::Result<()>;
}

#[derive(Debug)]
pub enum SourceStoreError {
    Io(std::io::Error),
    Json(serde_json::Error),
    UnsafePath(&'static str),
    InvalidSizeLimit,
    TooLarge { limit: u64 },
    InvalidSource(&'static str),
    Rollback { minimum: u64, found: u64 },
    FloorChanged { expected: u64, actual: u64 },
    Seal(VersionedSourceRestoreError),
}

impl core::fmt::Display for SourceStoreError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "source store I/O failed: {error}"),
            Self::Json(error) => write!(f, "source store JSON is invalid: {error}"),
            Self::UnsafePath(reason) => write!(f, "unsafe source store path: {reason}"),
            Self::InvalidSizeLimit => write!(f, "source store size limit cannot be u64::MAX"),
            Self::TooLarge { limit } => write!(f, "source store exceeds {limit} bytes"),
            Self::InvalidSource(reason) => write!(f, "invalid staged source: {reason}"),
            Self::Rollback { minimum, found } => {
                write!(f, "source generation {found} is below floor {minimum}")
            }
            Self::FloorChanged { expected, actual } => write!(
                f,
                "source generation floor changed concurrently: expected {expected}, got {actual}"
            ),
            Self::Seal(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for SourceStoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Json(error) => Some(error),
            Self::Seal(error) => Some(error),
            _ => None,
        }
    }
}

impl From<std::io::Error> for SourceStoreError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for SourceStoreError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

impl From<VersionedSourceRestoreError> for SourceStoreError {
    fn from(error: VersionedSourceRestoreError) -> Self {
        Self::Seal(error)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceBundle {
    version: u32,
    blocks: Vec<L1Block>,
    seal: VersionedSourceSeal,
}

struct BoundedBuffer {
    bytes: Vec<u8>,
    limit: u64,
    exceeded: bool,
}

impl BoundedBuffer {
    fn new(limit: u64) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
            exceeded: false,
        }
    }
}

impl Write for BoundedBuffer {
    fn write(&mut self, value: &[u8]) -> std::io::Result<usize> {
        let next = (self.bytes.len() as u64).checked_add(value.len() as u64);
        if next.is_none_or(|next| next > self.limit) {
            self.exceeded = true;
            return Err(std::io::Error::other(
                "serialized source exceeds configured limit",
            ));
        }
        self.bytes.extend_from_slice(value);
        Ok(value.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn resolved_store_path(path: &Path) -> Result<PathBuf, SourceStoreError> {
    let name = path
        .file_name()
        .ok_or(SourceStoreError::UnsafePath("missing file name"))?;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let parent_meta = fs::symlink_metadata(parent)?;
    if parent_meta.file_type().is_symlink()
        || !parent_meta.is_dir()
        || parent_meta.permissions().mode() & 0o077 != 0
    {
        return Err(SourceStoreError::UnsafePath(
            "parent must be a private non-symlink directory",
        ));
    }
    Ok(parent.canonicalize()?.join(name))
}

fn validate_existing(path: &Path, limit: u64) -> Result<fs::Metadata, SourceStoreError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(SourceStoreError::UnsafePath(
            "snapshot must be a private single-link regular file",
        ));
    }
    if metadata.len() > limit {
        return Err(SourceStoreError::TooLarge { limit });
    }
    Ok(metadata)
}

fn temporary_path(path: &Path) -> PathBuf {
    let mut value: OsString = path.as_os_str().to_owned();
    value.push(".tmp");
    PathBuf::from(value)
}

/// Persist snapshot+seal atomically after advancing the independent floor.
///
/// A leftover `.tmp` file is refused rather than overwritten; it is explicit
/// crash evidence requiring operator reconciliation. `max_bytes` bounds JSON
/// materialization before any floor or filesystem state is changed.
pub fn persist_versioned_source<F: SourceGenerationFloor>(
    path: &Path,
    source: &VersionedMemorySource,
    floor: &F,
    max_bytes: u64,
) -> Result<(), SourceStoreError> {
    let path = resolved_store_path(path)?;
    match fs::symlink_metadata(&path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink()
                || !metadata.is_file()
                || metadata.nlink() != 1
                || metadata.permissions().mode() & 0o077 != 0
            {
                return Err(SourceStoreError::UnsafePath("unsafe existing snapshot"));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let temporary = temporary_path(&path);
    match fs::symlink_metadata(&temporary) {
        Ok(_) => return Err(SourceStoreError::UnsafePath("stale temporary snapshot")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }

    let (blocks, seal) = source.snapshot_and_seal()?;
    let mut encoded = BoundedBuffer::new(max_bytes);
    let serialize_result = serde_json::to_writer(
        &mut encoded,
        &SourceBundle {
            version: STORE_VERSION,
            blocks,
            seal,
        },
    );
    if encoded.exceeded {
        return Err(SourceStoreError::TooLarge { limit: max_bytes });
    }
    serialize_result?;

    let current = floor.current_generation()?;
    if seal.generation() < current {
        return Err(SourceStoreError::Rollback {
            minimum: current,
            found: seal.generation(),
        });
    }
    floor.advance_generation(seal.generation())?;
    let confirmed = floor.current_generation()?;
    if confirmed != seal.generation() {
        return Err(SourceStoreError::FloorChanged {
            expected: seal.generation(),
            actual: confirmed,
        });
    }

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    file.write_all(&encoded.bytes)?;
    file.sync_all()?;
    fs::rename(&temporary, &path)?;
    File::open(path.parent().expect("resolved path has parent"))?.sync_all()?;
    Ok(())
}

/// Restore a bounded snapshot against the independently protected floor.
pub fn restore_versioned_source<F: SourceGenerationFloor>(
    path: &Path,
    floor: &F,
    max_bytes: u64,
) -> Result<VersionedMemorySource, SourceStoreError> {
    let read_limit = max_bytes
        .checked_add(1)
        .ok_or(SourceStoreError::InvalidSizeLimit)?;
    let path = resolved_store_path(path)?;
    let before = validate_existing(&path, max_bytes)?;
    let mut file = File::open(&path)?;
    let opened = file.metadata()?;
    if before.dev() != opened.dev() || before.ino() != opened.ino() {
        return Err(SourceStoreError::UnsafePath(
            "snapshot changed while opening",
        ));
    }
    let mut encoded = Vec::new();
    Read::by_ref(&mut file)
        .take(read_limit)
        .read_to_end(&mut encoded)?;
    if encoded.len() as u64 > max_bytes {
        return Err(SourceStoreError::TooLarge { limit: max_bytes });
    }
    let bundle: SourceBundle = serde_json::from_slice(&encoded)?;
    if bundle.version != STORE_VERSION {
        return Err(SourceStoreError::UnsafePath(
            "unsupported source store version",
        ));
    }
    let mut source = MemorySource::new();
    for block in bundle.blocks {
        source
            .push(block)
            .map_err(SourceStoreError::InvalidSource)?;
    }
    let minimum = floor.current_generation()?;
    VersionedMemorySource::restore(source, bundle.seal, minimum).map_err(Into::into)
}
