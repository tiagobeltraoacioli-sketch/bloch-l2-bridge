// SPDX-License-Identifier: MIT OR Apache-2.0
//! Durable Unix backend for the staged-source generation floor.
//!
//! The floor directory must be provisioned separately from the snapshot
//! directory and protected from rollback by the host. This backend provides
//! process-safe monotonic updates, crash recovery, and authenticated records on
//! a local Unix filesystem. Authentication prevents record forgery and binds a
//! floor to one configured domain, but coherent rollback of the entire floor
//! directory by a storage administrator remains undetectable.

use std::fs::{self, File, OpenOptions};
use std::io::{Error, ErrorKind, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use tiny_keccak::{Hasher, Kmac};
use zeroize::Zeroize;

use crate::source_store::SourceGenerationFloor;

const FLOOR_FILE: &str = ".source-generation-floor";
const TEMPORARY_FILE: &str = ".source-generation-floor.tmp";
const LOCK_FILE: &str = ".source-generation-floor.lock";
const FLOOR_MAGIC: &[u8] = b"BLOCH-L2-SOURCE-FLOOR-v2\0";
const KMAC_CUSTOMIZATION: &[u8] = b"BLOCH-L2-SOURCE-FLOOR-AUTH-v1\0";
const RECORD_SIZE: usize = FLOOR_MAGIC.len() + 8 + 32;

const LOCK_EXCLUSIVE: i32 = 2;
const LOCK_NONBLOCKING: i32 = 4;
const LOCK_RELEASE: i32 = 8;

unsafe extern "C" {
    fn flock(file_descriptor: i32, operation: i32) -> i32;
}

fn invalid_data(message: &'static str) -> Error {
    Error::new(ErrorKind::InvalidData, message)
}

fn permission_denied(message: &'static str) -> Error {
    Error::new(ErrorKind::PermissionDenied, message)
}

fn validate_private_directory(path: &Path) -> std::io::Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(permission_denied(
            "generation floor directory must be a non-symlink directory",
        ));
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(permission_denied(
            "generation floor directory must not grant group or world access",
        ));
    }
    Ok(metadata)
}

fn validate_private_file(
    metadata: &fs::Metadata,
    description: &'static str,
) -> std::io::Result<()> {
    if !metadata.is_file() || metadata.nlink() != 1 || metadata.permissions().mode() & 0o077 != 0 {
        return Err(permission_denied(description));
    }
    Ok(())
}

/// Credentials for one authenticated generation-floor domain.
///
/// `domain` is a public, stable, deployment-specific identifier. `key` must be
/// an independently provisioned 256-bit secret and must not be stored beside
/// the rollbackable snapshot or floor record. The key is zeroized when these
/// credentials are dropped and is deliberately omitted from `Debug` output.
pub struct UnixFloorAuthentication {
    key: [u8; 32],
    domain: [u8; 32],
}

impl UnixFloorAuthentication {
    /// Build credentials from a secret 256-bit key and a public, stable
    /// 256-bit deployment-domain identifier. Null values are refused as
    /// obvious fail-open provisioning mistakes.
    pub fn new(mut key: [u8; 32], domain: [u8; 32]) -> std::io::Result<Self> {
        if key == [0; 32] {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "generation floor authentication key must not be all zero",
            ));
        }
        if domain == [0; 32] {
            key.zeroize();
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "generation floor authentication domain must not be all zero",
            ));
        }
        Ok(Self { key, domain })
    }
}

impl core::fmt::Debug for UnixFloorAuthentication {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("UnixFloorAuthentication")
            .field("key", &"[REDACTED]")
            .field("domain", &self.domain)
            .finish()
    }
}

impl Drop for UnixFloorAuthentication {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

fn authentication_tag(authentication: &UnixFloorAuthentication, prefix: &[u8]) -> [u8; 32] {
    let mut mac = Kmac::v256(&authentication.key, KMAC_CUSTOMIZATION);
    mac.update(&authentication.domain);
    mac.update(prefix);
    let mut result = [0; 32];
    mac.finalize(&mut result);
    result
}

fn tags_equal(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .fold(0_u8, |difference, (left, right)| {
                difference | (left ^ right)
            })
            == 0
}

fn encode_record(generation: u64, authentication: &UnixFloorAuthentication) -> [u8; RECORD_SIZE] {
    let mut record = [0; RECORD_SIZE];
    record[..FLOOR_MAGIC.len()].copy_from_slice(FLOOR_MAGIC);
    let generation_end = FLOOR_MAGIC.len() + 8;
    record[FLOOR_MAGIC.len()..generation_end].copy_from_slice(&generation.to_be_bytes());
    let tag = authentication_tag(authentication, &record[..generation_end]);
    record[generation_end..].copy_from_slice(&tag);
    record
}

fn decode_record(record: &[u8], authentication: &UnixFloorAuthentication) -> std::io::Result<u64> {
    if record.len() != RECORD_SIZE || &record[..FLOOR_MAGIC.len()] != FLOOR_MAGIC {
        return Err(invalid_data("invalid generation floor record"));
    }
    let generation_end = FLOOR_MAGIC.len() + 8;
    let expected = authentication_tag(authentication, &record[..generation_end]);
    if !tags_equal(&record[generation_end..], &expected) {
        return Err(invalid_data("generation floor authentication failed"));
    }
    let generation: [u8; 8] = record[FLOOR_MAGIC.len()..generation_end]
        .try_into()
        .expect("generation record slice has fixed length");
    Ok(u64::from_be_bytes(generation))
}

fn read_record(
    path: &Path,
    authentication: &UnixFloorAuthentication,
) -> std::io::Result<Option<u64>> {
    let before = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if before.file_type().is_symlink() {
        return Err(permission_denied(
            "generation floor record must not be a symlink",
        ));
    }
    validate_private_file(
        &before,
        "generation floor record is not a private single-link file",
    )?;
    if before.len() != RECORD_SIZE as u64 {
        return Err(invalid_data("generation floor record has invalid length"));
    }

    let mut file = File::open(path)?;
    let opened = file.metadata()?;
    validate_private_file(&opened, "opened generation floor record is unsafe")?;
    if before.dev() != opened.dev() || before.ino() != opened.ino() {
        return Err(permission_denied(
            "generation floor record changed while opening",
        ));
    }
    let mut record = [0; RECORD_SIZE];
    file.read_exact(&mut record)?;
    let mut trailing = [0; 1];
    if file.read(&mut trailing)? != 0 {
        return Err(invalid_data("generation floor record has trailing data"));
    }
    decode_record(&record, authentication).map(Some)
}

fn sync_directory(path: &Path) -> std::io::Result<()> {
    File::open(path)?.sync_all()
}

#[derive(Debug)]
struct ExclusiveLock(File);

impl ExclusiveLock {
    fn acquire(path: &Path, directory: &Path) -> std::io::Result<Self> {
        let file = loop {
            match fs::symlink_metadata(path) {
                Ok(before) => {
                    if before.file_type().is_symlink() {
                        return Err(permission_denied(
                            "generation floor lock must not be a symlink",
                        ));
                    }
                    validate_private_file(
                        &before,
                        "generation floor lock is not a private single-link file",
                    )?;
                    let file = OpenOptions::new().read(true).write(true).open(path)?;
                    let opened = file.metadata()?;
                    validate_private_file(&opened, "opened generation floor lock is unsafe")?;
                    if before.dev() != opened.dev() || before.ino() != opened.ino() {
                        return Err(permission_denied(
                            "generation floor lock changed while opening",
                        ));
                    }
                    break file;
                }
                Err(error) if error.kind() == ErrorKind::NotFound => {
                    match OpenOptions::new()
                        .read(true)
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(path)
                    {
                        Ok(file) => {
                            file.sync_all()?;
                            sync_directory(directory)?;
                            break file;
                        }
                        Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
                        Err(error) => return Err(error),
                    }
                }
                Err(error) => return Err(error),
            }
        };

        // SAFETY: `file` owns a live Unix file descriptor for the duration of
        // the call and the returned guard. The operation constants are the
        // POSIX/BSD `flock(2)` values shared by supported Unix targets.
        if unsafe { flock(file.as_raw_fd(), LOCK_EXCLUSIVE | LOCK_NONBLOCKING) } != 0 {
            return Err(Error::last_os_error());
        }
        let path_metadata = fs::symlink_metadata(path)?;
        let opened = file.metadata()?;
        validate_private_file(
            &path_metadata,
            "generation floor lock became unsafe while locking",
        )?;
        validate_private_file(&opened, "opened generation floor lock became unsafe")?;
        if path_metadata.file_type().is_symlink()
            || path_metadata.dev() != opened.dev()
            || path_metadata.ino() != opened.ino()
        {
            return Err(permission_denied(
                "generation floor lock changed while locking",
            ));
        }
        Ok(Self(file))
    }
}

impl Drop for ExclusiveLock {
    fn drop(&mut self) {
        // SAFETY: the guard still owns this live descriptor. Unlock failure
        // cannot be reported from Drop; closing the descriptor also releases
        // its advisory lock.
        let _ = unsafe { flock(self.0.as_raw_fd(), LOCK_RELEASE) };
    }
}

/// Durable local-filesystem generation floor for Unix hosts.
///
/// The snapshot and floor directories must be distinct and neither may
/// contain the other. The host remains responsible for placing `floor_dir` in
/// a separately protected, non-rollbackable storage domain. This type detects
/// torn/corrupt/forged records and serializes cooperating processes. It cannot
/// detect a coherent replay of an older, correctly authenticated floor; the
/// directory must therefore still reside in a non-rollbackable domain.
#[derive(Debug)]
pub struct UnixGenerationFloor {
    directory: PathBuf,
    directory_device: u64,
    directory_inode: u64,
    authentication: UnixFloorAuthentication,
}

impl UnixGenerationFloor {
    /// Open a pre-provisioned, authenticated private floor directory,
    /// explicitly separated from the snapshot path. Both parent directories
    /// must already exist. Existing unauthenticated v1 records are refused.
    pub fn open_authenticated_separate(
        floor_dir: &Path,
        snapshot_path: &Path,
        authentication: UnixFloorAuthentication,
    ) -> std::io::Result<Self> {
        let floor_metadata = validate_private_directory(floor_dir)?;
        let floor_dir = floor_dir.canonicalize()?;
        let snapshot_parent = snapshot_path.parent().unwrap_or_else(|| Path::new("."));
        let snapshot_metadata = validate_private_directory(snapshot_parent)?;
        let snapshot_parent = snapshot_parent.canonicalize()?;
        if (floor_metadata.dev() == snapshot_metadata.dev()
            && floor_metadata.ino() == snapshot_metadata.ino())
            || floor_dir == snapshot_parent
            || floor_dir.starts_with(&snapshot_parent)
            || snapshot_parent.starts_with(&floor_dir)
        {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "floor and snapshot directories must be separate and non-nested",
            ));
        }
        Ok(Self {
            directory: floor_dir,
            directory_device: floor_metadata.dev(),
            directory_inode: floor_metadata.ino(),
            authentication,
        })
    }

    fn validate_directory(&self) -> std::io::Result<()> {
        let metadata = validate_private_directory(&self.directory)?;
        if metadata.dev() != self.directory_device || metadata.ino() != self.directory_inode {
            return Err(permission_denied(
                "generation floor directory changed after opening",
            ));
        }
        Ok(())
    }

    fn with_lock<T>(
        &self,
        operation: impl FnOnce(&Self) -> std::io::Result<T>,
    ) -> std::io::Result<T> {
        self.validate_directory()?;
        let _lock = ExclusiveLock::acquire(&self.directory.join(LOCK_FILE), &self.directory)?;
        self.validate_directory()?;
        operation(self)
    }

    fn recover_and_read(&self) -> std::io::Result<u64> {
        let floor_path = self.directory.join(FLOOR_FILE);
        let temporary_path = self.directory.join(TEMPORARY_FILE);
        let current = read_record(&floor_path, &self.authentication)?;
        if let Some(pending) = read_record(&temporary_path, &self.authentication)? {
            if current.is_some_and(|current| pending < current) {
                return Err(invalid_data(
                    "temporary generation floor would roll back durable state",
                ));
            }
            fs::rename(&temporary_path, &floor_path)?;
            sync_directory(&self.directory)?;
            return Ok(pending);
        }
        match current {
            Some(generation) => Ok(generation),
            None => {
                self.write_record(0)?;
                Ok(0)
            }
        }
    }

    fn write_record(&self, generation: u64) -> std::io::Result<()> {
        let temporary_path = self.directory.join(TEMPORARY_FILE);
        let floor_path = self.directory.join(FLOOR_FILE);
        let mut temporary = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary_path)?;
        temporary.write_all(&encode_record(generation, &self.authentication))?;
        temporary.sync_all()?;
        fs::rename(&temporary_path, &floor_path)?;
        sync_directory(&self.directory)
    }
}

impl SourceGenerationFloor for UnixGenerationFloor {
    fn current_generation(&self) -> std::io::Result<u64> {
        self.with_lock(Self::recover_and_read)
    }

    fn advance_generation(&self, generation: u64) -> std::io::Result<()> {
        self.with_lock(|floor| {
            let current = floor.recover_and_read()?;
            if generation < current {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "generation floor cannot move backwards",
                ));
            }
            if generation > current {
                floor.write_record(generation)?;
            }
            Ok(())
        })
    }
}
