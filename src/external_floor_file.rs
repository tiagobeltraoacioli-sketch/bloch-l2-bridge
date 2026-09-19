// SPDX-License-Identifier: MIT OR Apache-2.0
//! Privileged-host Unix filesystem backend for external-floor replay state.
//!
//! The directory must live in a separately protected, non-rollbackable
//! failure domain. This backend provides a process lock, strict records and a
//! durable atomic CAS; it cannot make a rollbackable filesystem trustworthy.

use std::ffi::CString;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Error, ErrorKind, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use tiny_keccak::{Hasher, Keccak};

use crate::external_floor_auth::{
    CustodiedDurableAuthenticatedExternalFloorServer, ExternalFloorDurableReplayError,
    ExternalFloorPeerAuthentication, ExternalFloorReplayCasOutcome, ExternalFloorReplayCheckpoint,
    ExternalFloorReplayStore,
};
use crate::ExternalFloorBoundary;
use zeroize::Zeroize;

const STATE_FILE: &str = ".external-floor-replay";
const TEMP_FILE: &str = ".external-floor-replay.tmp";
const LOCK_FILE: &str = ".external-floor-replay.lock";
const MAGIC: [u8; 4] = *b"BXFR";
const VERSION: u8 = 1;
const PREFIX_LEN: usize = 56;
/// Exact size of one canonical replay record.
pub const EXTERNAL_FLOOR_REPLAY_RECORD_LEN: usize = PREFIX_LEN + 32;
const HASH_DOMAIN: &[u8] = b"BLOCH-L2-EXTERNAL-FLOOR-REPLAY-v1\0";

fn invalid(message: &'static str) -> Error {
    Error::new(ErrorKind::InvalidData, message)
}

fn denied(message: &'static str) -> Error {
    Error::new(ErrorKind::PermissionDenied, message)
}

fn name(value: &'static str) -> CString {
    CString::new(value).expect("fixed replay filename contains no NUL")
}

fn open_at(directory: RawFd, filename: &'static str, flags: i32, mode: u32) -> io::Result<File> {
    // SAFETY: `directory` is a live directory descriptor owned by the caller;
    // the fixed CString is NUL terminated, and a successful descriptor is
    // transferred exactly once to `File`.
    let descriptor = unsafe {
        libc::openat(
            directory,
            name(filename).as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            mode as libc::c_uint,
        )
    };
    if descriptor < 0 {
        Err(Error::last_os_error())
    } else {
        // SAFETY: `openat` returned a new owned descriptor.
        Ok(unsafe { File::from_raw_fd(descriptor) })
    }
}

fn validate_directory(file: &File) -> io::Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(denied(
            "replay directory must be owned by this user and deny group/world access",
        ));
    }
    Ok(())
}

fn validate_file(file: &File, description: &'static str) -> io::Result<()> {
    let metadata = file.metadata()?;
    // Recheck the opened object, not a path. Requiring one link rejects an
    // attacker-controlled alias even if it was installed before startup.
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(denied(description));
    }
    Ok(())
}

fn encode(checkpoint: ExternalFloorReplayCheckpoint) -> [u8; EXTERNAL_FLOOR_REPLAY_RECORD_LEN] {
    let mut record = [0_u8; EXTERNAL_FLOOR_REPLAY_RECORD_LEN];
    record[..4].copy_from_slice(&MAGIC);
    record[4] = VERSION;
    // bytes 5..8 are reserved and canonically zero
    record[8..16].copy_from_slice(&checkpoint.revision.to_be_bytes());
    record[16..48].copy_from_slice(&checkpoint.session_nonce);
    record[48..56].copy_from_slice(&checkpoint.next_sequence.to_be_bytes());
    let mut hash = Keccak::v256();
    hash.update(HASH_DOMAIN);
    hash.update(&record[..PREFIX_LEN]);
    hash.finalize(&mut record[PREFIX_LEN..]);
    record
}

fn decode(record: &[u8]) -> io::Result<ExternalFloorReplayCheckpoint> {
    if record.len() != EXTERNAL_FLOOR_REPLAY_RECORD_LEN {
        return Err(invalid("replay record has invalid length"));
    }
    if record[..4] != MAGIC || record[4] != VERSION || record[5..8] != [0; 3] {
        return Err(invalid("replay record has invalid canonical header"));
    }
    let mut expected = [0_u8; 32];
    let mut hash = Keccak::v256();
    hash.update(HASH_DOMAIN);
    hash.update(&record[..PREFIX_LEN]);
    hash.finalize(&mut expected);
    if record[PREFIX_LEN..] != expected {
        return Err(invalid("replay record checksum mismatch"));
    }
    let revision = u64::from_be_bytes(record[8..16].try_into().expect("fixed slice"));
    let session_nonce = record[16..48].try_into().expect("fixed slice");
    let next_sequence = u64::from_be_bytes(record[48..56].try_into().expect("fixed slice"));
    if session_nonce == [0; 32] {
        return Err(invalid("replay record has a zero session nonce"));
    }
    Ok(ExternalFloorReplayCheckpoint {
        revision,
        session_nonce,
        next_sequence,
    })
}

fn read_state(directory: &File) -> io::Result<ExternalFloorReplayCheckpoint> {
    let mut file = open_at(directory.as_raw_fd(), STATE_FILE, libc::O_RDONLY, 0)?;
    validate_file(
        &file,
        "replay state must be a private single-link regular file",
    )?;
    let mut record = [0_u8; EXTERNAL_FLOOR_REPLAY_RECORD_LEN];
    file.read_exact(&mut record)?;
    let mut trailing = [0_u8; 1];
    if file.read(&mut trailing)? != 0 {
        return Err(invalid("replay record has trailing data"));
    }
    decode(&record)
}

fn reject_temporary_entry(directory: &File) -> io::Result<()> {
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `directory` owns a live directory descriptor, the fixed name is
    // NUL terminated, and `metadata` is read only when `fstatat` succeeds.
    let result = unsafe {
        libc::fstatat(
            directory.as_raw_fd(),
            name(TEMP_FILE).as_ptr(),
            metadata.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result == 0 {
        return Err(invalid(
            "temporary replay state exists and requires operator reconciliation",
        ));
    }
    let error = Error::last_os_error();
    if error.kind() == ErrorKind::NotFound {
        Ok(())
    } else {
        Err(error)
    }
}

fn rename_temp(directory: &File) -> io::Result<()> {
    // SAFETY: both names are fixed valid C strings and both directory
    // descriptors remain live for the call.
    let result = unsafe {
        libc::renameat(
            directory.as_raw_fd(),
            name(TEMP_FILE).as_ptr(),
            directory.as_raw_fd(),
            name(STATE_FILE).as_ptr(),
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(Error::last_os_error())
    }
}

fn write_temp(directory: &File, checkpoint: ExternalFloorReplayCheckpoint) -> io::Result<()> {
    let mut temporary = open_at(
        directory.as_raw_fd(),
        TEMP_FILE,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        0o600,
    )?;
    validate_file(
        &temporary,
        "temporary replay state must be a private single-link regular file",
    )?;
    temporary.write_all(&encode(checkpoint))?;
    temporary.sync_all()
}

#[derive(Debug)]
struct ExclusiveLock(File);

impl ExclusiveLock {
    fn acquire(directory: &File) -> io::Result<Self> {
        let lock = match open_at(
            directory.as_raw_fd(),
            LOCK_FILE,
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
            0o600,
        ) {
            Ok(created) => {
                created.sync_all()?;
                directory.sync_all()?;
                created
            }
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {
                open_at(directory.as_raw_fd(), LOCK_FILE, libc::O_RDWR, 0)?
            }
            Err(error) => return Err(error),
        };
        validate_file(
            &lock,
            "replay lock must be a private single-link regular file",
        )?;
        // SAFETY: the lock owns a live descriptor and the constants are the
        // platform definitions supplied by libc.
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(Error::last_os_error());
        }
        validate_file(&lock, "replay lock became unsafe while acquiring the lock")?;
        Ok(Self(lock))
    }
}

impl Drop for ExclusiveLock {
    fn drop(&mut self) {
        // The persistent lock file is deliberately never unlinked. Removing
        // it would allow two processes to lock different inodes.
        let _ = unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
    }
}

/// Local Unix implementation of the exact external-floor replay CAS.
///
/// `provision` is a one-time administrative operation. Every later `open`
/// requires the exact independently retained checkpoint. The exclusive lock
/// is held for this object's full lifetime, so a second server fails instead
/// of waiting indefinitely. A leftover temporary file is never silently
/// removed or adopted; it requires operator reconciliation.
#[derive(Debug)]
pub struct UnixExternalFloorReplayStore {
    directory: File,
    _lock: ExclusiveLock,
    #[cfg(test)]
    uncertain_after_rename: std::cell::Cell<bool>,
}

/// Explicit inputs required to construct the privileged Unix server path.
///
/// This type deliberately contains no defaults and no environment lookup.
/// The checkpoint custodian supplied to [`Self::open`] must be independently
/// administered and outside the replay directory's rollback domain.
pub struct UnixExternalFloorServerConfig {
    replay_directory: std::path::PathBuf,
    trusted_checkpoint: ExternalFloorReplayCheckpoint,
    authentication_key: [u8; 32],
    client_peer: [u8; 32],
    boundary_peer: [u8; 32],
}

impl core::fmt::Debug for UnixExternalFloorServerConfig {
    fn fmt(&self, output: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        output
            .debug_struct("UnixExternalFloorServerConfig")
            .field("replay_directory", &self.replay_directory)
            .field("trusted_checkpoint", &self.trusted_checkpoint)
            .field("authentication_key", &"[REDACTED]")
            .field("client_peer", &self.client_peer)
            .field("boundary_peer", &self.boundary_peer)
            .finish()
    }
}

impl Drop for UnixExternalFloorServerConfig {
    fn drop(&mut self) {
        self.authentication_key.zeroize();
    }
}

#[derive(Debug)]
pub enum UnixExternalFloorServerOpenError {
    InvalidConfiguration(&'static str),
    Store(io::Error),
    Replay(ExternalFloorDurableReplayError),
}

impl core::fmt::Display for UnixExternalFloorServerOpenError {
    fn fmt(&self, output: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            output,
            "Unix external-floor server refused to open: {self:?}"
        )
    }
}

impl std::error::Error for UnixExternalFloorServerOpenError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Store(error) => Some(error),
            Self::Replay(error) => Some(error),
            Self::InvalidConfiguration(_) => None,
        }
    }
}

/// Concrete server type produced by [`UnixExternalFloorServerConfig`].
pub type UnixCustodiedExternalFloorServer<C, B> =
    CustodiedDurableAuthenticatedExternalFloorServer<UnixExternalFloorReplayStore, C, B>;

impl UnixExternalFloorServerConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        replay_directory: std::path::PathBuf,
        trusted_checkpoint: ExternalFloorReplayCheckpoint,
        mut authentication_key: [u8; 32],
        client_peer: [u8; 32],
        boundary_peer: [u8; 32],
    ) -> Result<Self, UnixExternalFloorServerOpenError> {
        if !replay_directory.is_absolute() {
            authentication_key.zeroize();
            return Err(UnixExternalFloorServerOpenError::InvalidConfiguration(
                "replay directory must be an absolute path",
            ));
        }
        if trusted_checkpoint.session_nonce == [0; 32] {
            authentication_key.zeroize();
            return Err(UnixExternalFloorServerOpenError::InvalidConfiguration(
                "trusted checkpoint session nonce is all zero",
            ));
        }
        if authentication_key == [0; 32] {
            authentication_key.zeroize();
            return Err(UnixExternalFloorServerOpenError::InvalidConfiguration(
                "authentication key is all zero",
            ));
        }
        if client_peer == [0; 32] || boundary_peer == [0; 32] {
            authentication_key.zeroize();
            return Err(UnixExternalFloorServerOpenError::InvalidConfiguration(
                "peer identity is all zero",
            ));
        }
        if client_peer == boundary_peer {
            authentication_key.zeroize();
            return Err(UnixExternalFloorServerOpenError::InvalidConfiguration(
                "client and boundary identities are equal",
            ));
        }
        Ok(Self {
            replay_directory,
            trusted_checkpoint,
            authentication_key,
            client_peer,
            boundary_peer,
        })
    }

    /// Construct the only Unix production-oriented server path exposed by
    /// this module: concrete durable replay plus a mandatory independent CAS
    /// custodian. No socket or runtime is started.
    pub fn open<C: ExternalFloorReplayStore, B: ExternalFloorBoundary>(
        mut self,
        custodian: C,
        boundary: B,
    ) -> Result<UnixCustodiedExternalFloorServer<C, B>, UnixExternalFloorServerOpenError> {
        let canonical = self
            .replay_directory
            .canonicalize()
            .map_err(UnixExternalFloorServerOpenError::Store)?;
        if canonical != self.replay_directory {
            return Err(UnixExternalFloorServerOpenError::InvalidConfiguration(
                "replay directory path must already be canonical",
            ));
        }
        let authentication = ExternalFloorPeerAuthentication::new(
            core::mem::take(&mut self.authentication_key),
            self.client_peer,
            self.boundary_peer,
        )
        .map_err(|_| {
            UnixExternalFloorServerOpenError::InvalidConfiguration(
                "invalid peer authentication configuration",
            )
        })?;
        let store =
            UnixExternalFloorReplayStore::open(&self.replay_directory, self.trusted_checkpoint)
                .map_err(UnixExternalFloorServerOpenError::Store)?;
        CustodiedDurableAuthenticatedExternalFloorServer::open(
            store,
            custodian,
            self.trusted_checkpoint,
            boundary,
            authentication,
        )
        .map_err(UnixExternalFloorServerOpenError::Replay)
    }
}

impl UnixExternalFloorReplayStore {
    /// Create a new mode-0700 directory and its initial durable checkpoint.
    pub fn provision(path: &Path, initial: ExternalFloorReplayCheckpoint) -> io::Result<()> {
        if initial.session_nonce == [0; 32] {
            return Err(Error::new(ErrorKind::InvalidInput, "zero session nonce"));
        }
        let mut builder = DirBuilder::new();
        builder.mode(0o700);
        builder.create(path)?;
        let directory = open_directory(path)?;
        let _lock = ExclusiveLock::acquire(&directory)?;
        reject_temporary_entry(&directory)?;
        write_temp(&directory, initial)?;
        rename_temp(&directory)?;
        directory.sync_all()?;
        if read_state(&directory)? != initial {
            return Err(invalid("initial replay checkpoint readback mismatch"));
        }
        Ok(())
    }

    /// Open only if durable state equals `trusted` byte-for-byte semantically.
    pub fn open(path: &Path, trusted: ExternalFloorReplayCheckpoint) -> io::Result<Self> {
        if trusted.session_nonce == [0; 32] {
            return Err(Error::new(ErrorKind::InvalidInput, "zero session nonce"));
        }
        let directory = open_directory(path)?;
        let lock = ExclusiveLock::acquire(&directory)?;
        reject_temporary_entry(&directory)?;
        let stored = read_state(&directory)?;
        if stored != trusted {
            return Err(invalid(
                "stored replay checkpoint does not equal the externally trusted checkpoint",
            ));
        }
        Ok(Self {
            directory,
            _lock: lock,
            #[cfg(test)]
            uncertain_after_rename: std::cell::Cell::new(false),
        })
    }
}

fn open_directory(path: &Path) -> io::Result<File> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(denied("replay path must be a non-symlink directory"));
    }
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    validate_directory(&directory)?;
    if metadata.dev() != directory.metadata()?.dev()
        || metadata.ino() != directory.metadata()?.ino()
    {
        return Err(denied("replay directory changed while opening"));
    }
    Ok(directory)
}

impl ExternalFloorReplayStore for UnixExternalFloorReplayStore {
    fn load(&self) -> io::Result<ExternalFloorReplayCheckpoint> {
        validate_directory(&self.directory)?;
        reject_temporary_entry(&self.directory)?;
        read_state(&self.directory)
    }

    fn compare_and_swap(
        &self,
        expected: ExternalFloorReplayCheckpoint,
        replacement: ExternalFloorReplayCheckpoint,
    ) -> io::Result<ExternalFloorReplayCasOutcome> {
        validate_directory(&self.directory)?;
        reject_temporary_entry(&self.directory)?;
        if replacement.session_nonce == [0; 32] {
            return Err(Error::new(ErrorKind::InvalidInput, "zero session nonce"));
        }
        let current = read_state(&self.directory)?;
        if current != expected {
            return Ok(ExternalFloorReplayCasOutcome::Conflict(current));
        }
        if replacement.session_nonce != expected.session_nonce
            || expected.revision.checked_add(1) != Some(replacement.revision)
            || expected.next_sequence.checked_add(1) != Some(replacement.next_sequence)
        {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "replacement must advance revision and sequence exactly once in the same session",
            ));
        }
        write_temp(&self.directory, replacement)?;

        // From rename onward an error cannot safely distinguish an uncommitted
        // write from a committed-but-unacknowledged one.
        if rename_temp(&self.directory).is_err() {
            return Ok(ExternalFloorReplayCasOutcome::Uncertain);
        }
        #[cfg(test)]
        if self.uncertain_after_rename.replace(false) {
            return Ok(ExternalFloorReplayCasOutcome::Uncertain);
        }
        if self.directory.sync_all().is_err() {
            return Ok(ExternalFloorReplayCasOutcome::Uncertain);
        }
        match read_state(&self.directory) {
            Ok(readback) if readback == replacement => Ok(ExternalFloorReplayCasOutcome::Committed),
            _ => Ok(ExternalFloorReplayCasOutcome::Uncertain),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEST: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn injected_post_rename_failure_reports_uncertain_even_when_visible() {
        let path = std::env::temp_dir().join(format!(
            "bloch-replay-uncertain-{}-{}",
            std::process::id(),
            NEXT_TEST.fetch_add(1, Ordering::Relaxed)
        ));
        let initial = ExternalFloorReplayCheckpoint {
            revision: 1,
            session_nonce: [0x41; 32],
            next_sequence: 9,
        };
        let replacement = ExternalFloorReplayCheckpoint {
            revision: 2,
            session_nonce: initial.session_nonce,
            next_sequence: 10,
        };
        UnixExternalFloorReplayStore::provision(&path, initial).unwrap();
        let store = UnixExternalFloorReplayStore::open(&path, initial).unwrap();
        store.uncertain_after_rename.set(true);
        assert_eq!(
            store.compare_and_swap(initial, replacement).unwrap(),
            ExternalFloorReplayCasOutcome::Uncertain
        );
        assert_eq!(store.load().unwrap(), replacement);
        drop(store);
        fs::remove_dir_all(path).unwrap();
    }
}
