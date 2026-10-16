// SPDX-License-Identifier: MIT OR Apache-2.0
//! Privileged-host Unix filesystem backend for external-floor replay state.
//!
//! The directory must live in a separately protected, non-rollbackable
//! failure domain. This backend provides a process lock, strict records and a
//! durable atomic CAS; it cannot make a rollbackable filesystem trustworthy.

use std::ffi::CString;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Error, ErrorKind, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, FileExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

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
static NEXT_PROVISION_STAGING: AtomicU64 = AtomicU64::new(0);

fn invalid(message: &'static str) -> Error {
    Error::new(ErrorKind::InvalidData, message)
}

fn denied(message: &'static str) -> Error {
    Error::new(ErrorKind::PermissionDenied, message)
}

fn name(value: &'static str) -> CString {
    CString::new(value).expect("fixed replay filename contains no NUL")
}

fn path_name(value: &std::ffi::OsStr) -> io::Result<CString> {
    CString::new(value.as_bytes()).map_err(|_| invalid("replay path contains NUL"))
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

#[derive(Clone, Copy, PartialEq, Eq)]
struct FileSnapshot {
    dev: u64,
    ino: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    nlink: u64,
    size: u64,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
}

fn metadata_snapshot(metadata: &fs::Metadata) -> FileSnapshot {
    FileSnapshot {
        dev: metadata.dev(),
        ino: metadata.ino(),
        mode: metadata.mode(),
        uid: metadata.uid(),
        gid: metadata.gid(),
        nlink: metadata.nlink(),
        size: metadata.size(),
        mtime: metadata.mtime(),
        mtime_nsec: metadata.mtime_nsec(),
        ctime: metadata.ctime(),
        ctime_nsec: metadata.ctime_nsec(),
    }
}

fn file_snapshot(file: &File) -> io::Result<FileSnapshot> {
    Ok(metadata_snapshot(&file.metadata()?))
}

fn same_stable_snapshot(actual: FileSnapshot, expected: FileSnapshot, nlink: u64) -> bool {
    actual.dev == expected.dev
        && actual.ino == expected.ino
        && actual.mode == expected.mode
        && actual.uid == expected.uid
        && actual.gid == expected.gid
        && actual.nlink == nlink
        && actual.size == expected.size
        && actual.mtime == expected.mtime
        && actual.mtime_nsec == expected.mtime_nsec
}

fn refreshed_evidence(
    file: &File,
    expected_snapshot: FileSnapshot,
    expected_nlink: u64,
    expected_bytes: &[u8; EXTERNAL_FLOOR_REPLAY_RECORD_LEN],
) -> Option<FileSnapshot> {
    let before = file_snapshot(file).ok()?;
    if !same_stable_snapshot(before, expected_snapshot, expected_nlink) {
        return None;
    }
    let actual_bytes = read_record_bytes(file).ok()?;
    let after = file_snapshot(file).ok()?;
    (before == after && actual_bytes == *expected_bytes).then_some(after)
}

fn evidence_matches(
    file: &File,
    expected_snapshot: FileSnapshot,
    expected_nlink: u64,
    expected_bytes: &[u8; EXTERNAL_FLOOR_REPLAY_RECORD_LEN],
) -> bool {
    refreshed_evidence(file, expected_snapshot, expected_nlink, expected_bytes).is_some_and(
        |actual| {
            expected_nlink != expected_snapshot.nlink
                || (actual.ctime == expected_snapshot.ctime
                    && actual.ctime_nsec == expected_snapshot.ctime_nsec)
        },
    )
}

fn read_record_bytes(file: &File) -> io::Result<[u8; EXTERNAL_FLOOR_REPLAY_RECORD_LEN]> {
    let mut record = [0_u8; EXTERNAL_FLOOR_REPLAY_RECORD_LEN];
    file.read_exact_at(&mut record, 0)?;
    let mut trailing = [0_u8; 1];
    if file.read_at(&mut trailing, record.len() as u64)? != 0 {
        return Err(invalid("replay record has trailing data"));
    }
    Ok(record)
}

fn validate_file_name(
    directory: &File,
    filename: &'static str,
    file: &File,
    description: &'static str,
) -> io::Result<()> {
    validate_file(file, description)?;
    let named = open_at(
        directory.as_raw_fd(),
        filename,
        libc::O_RDONLY | libc::O_NONBLOCK,
        0,
    )?;
    let opened = file.metadata()?;
    let named = named.metadata()?;
    if opened.dev() != named.dev() || opened.ino() != named.ino() {
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

fn open_state(
    directory: &File,
) -> io::Result<(
    ExternalFloorReplayCheckpoint,
    File,
    FileSnapshot,
    [u8; EXTERNAL_FLOOR_REPLAY_RECORD_LEN],
)> {
    let file = open_at(
        directory.as_raw_fd(),
        STATE_FILE,
        libc::O_RDONLY | libc::O_NONBLOCK,
        0,
    )?;
    validate_file_name(
        directory,
        STATE_FILE,
        &file,
        "replay state changed while it was opened",
    )?;
    let before = file_snapshot(&file)?;
    let record = read_record_bytes(&file)?;
    let after = file_snapshot(&file)?;
    if before != after {
        return Err(denied("replay state changed while it was read"));
    }
    Ok((decode(&record)?, file, after, record))
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

#[cfg(target_os = "linux")]
fn install_temp(directory: &File, create: bool) -> io::Result<()> {
    let flags = if create {
        libc::RENAME_NOREPLACE
    } else {
        libc::RENAME_EXCHANGE
    };
    // SAFETY: both names and the live directory descriptor are valid.
    let result = unsafe {
        libc::renameat2(
            directory.as_raw_fd(),
            name(TEMP_FILE).as_ptr(),
            directory.as_raw_fd(),
            name(STATE_FILE).as_ptr(),
            flags,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(Error::last_os_error())
    }
}

#[cfg(target_os = "macos")]
fn install_temp(directory: &File, create: bool) -> io::Result<()> {
    let flags = if create {
        libc::RENAME_EXCL
    } else {
        libc::RENAME_SWAP
    };
    // SAFETY: both names and the live directory descriptor are valid.
    let result = unsafe {
        libc::renameatx_np(
            directory.as_raw_fd(),
            name(TEMP_FILE).as_ptr(),
            directory.as_raw_fd(),
            name(STATE_FILE).as_ptr(),
            flags,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(Error::last_os_error())
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn install_temp(_directory: &File, _create: bool) -> io::Result<()> {
    Err(Error::new(
        ErrorKind::Unsupported,
        "atomic replay checkpoint install is unavailable on this platform",
    ))
}

#[cfg(target_os = "linux")]
fn publish_directory_noreplace(
    parent: &File,
    staging_name: &std::ffi::OsStr,
    target_name: &std::ffi::OsStr,
) -> io::Result<()> {
    // SAFETY: both names are NUL-checked and relative to the retained parent.
    let result = unsafe {
        libc::renameat2(
            parent.as_raw_fd(),
            path_name(staging_name)?.as_ptr(),
            parent.as_raw_fd(),
            path_name(target_name)?.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(Error::last_os_error())
    }
}

#[cfg(target_os = "macos")]
fn publish_directory_noreplace(
    parent: &File,
    staging_name: &std::ffi::OsStr,
    target_name: &std::ffi::OsStr,
) -> io::Result<()> {
    // SAFETY: both names are NUL-checked and relative to the retained parent.
    let result = unsafe {
        libc::renameatx_np(
            parent.as_raw_fd(),
            path_name(staging_name)?.as_ptr(),
            parent.as_raw_fd(),
            path_name(target_name)?.as_ptr(),
            libc::RENAME_EXCL,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(Error::last_os_error())
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn publish_directory_noreplace(
    _parent: &File,
    _staging_name: &std::ffi::OsStr,
    _target_name: &std::ffi::OsStr,
) -> io::Result<()> {
    Err(Error::new(
        ErrorKind::Unsupported,
        "atomic replay directory publication is unavailable on this platform",
    ))
}

fn write_temp(
    directory: &File,
    checkpoint: ExternalFloorReplayCheckpoint,
) -> io::Result<(File, FileSnapshot, [u8; EXTERNAL_FLOOR_REPLAY_RECORD_LEN])> {
    let encoded = encode(checkpoint);
    let mut temporary = open_at(
        directory.as_raw_fd(),
        TEMP_FILE,
        libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
        0o600,
    )?;
    validate_file(
        &temporary,
        "temporary replay state must be a private single-link regular file",
    )?;
    temporary.write_all(&encoded)?;
    temporary.sync_all()?;
    let snapshot = file_snapshot(&temporary)?;
    if read_record_bytes(&temporary)? != encoded {
        return Err(invalid("temporary replay checkpoint read-back mismatch"));
    }
    validate_file_name(
        directory,
        TEMP_FILE,
        &temporary,
        "temporary replay state changed before commit",
    )?;
    if file_snapshot(&temporary)? != snapshot {
        return Err(denied("temporary replay state changed before commit"));
    }
    Ok((temporary, snapshot, encoded))
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
        let acquired = Self(lock);
        acquired.validate_current(directory)?;
        Ok(acquired)
    }

    fn validate_current(&self, directory: &File) -> io::Result<()> {
        validate_directory(directory)?;
        validate_file(
            &self.0,
            "replay lock pathname no longer names the acquired private single-link file",
        )?;
        let named = open_at(directory.as_raw_fd(), LOCK_FILE, libc::O_RDWR, 0)?;
        validate_file(
            &named,
            "replay lock pathname no longer names the acquired private single-link file",
        )?;
        let acquired = self.0.metadata()?;
        let named = named.metadata()?;
        if acquired.dev() != named.dev() || acquired.ino() != named.ino() {
            return Err(denied(
                "replay lock pathname no longer names the acquired private single-link file",
            ));
        }
        Ok(())
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
    directory_path: PathBuf,
    directory: File,
    _lock: ExclusiveLock,
    #[cfg(test)]
    uncertain_after_rename: std::cell::Cell<bool>,
    #[cfg(test)]
    before_exchange: std::cell::Cell<Option<fn(&Path)>>,
    #[cfg(test)]
    before_cleanup: std::cell::Cell<Option<fn(&Path)>>,
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
        Self::provision_inner(path, initial, |_| {}, |_| {}, |_| {})
    }

    fn provision_inner<F, G, H>(
        path: &Path,
        initial: ExternalFloorReplayCheckpoint,
        before_open: F,
        before_install: G,
        before_publish: H,
    ) -> io::Result<()>
    where
        F: FnOnce(&Path),
        G: FnOnce(&Path),
        H: FnOnce(&Path),
    {
        if initial.session_nonce == [0; 32] {
            return Err(Error::new(ErrorKind::InvalidInput, "zero session nonce"));
        }
        if !path.is_absolute() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "replay directory must be absolute",
            ));
        }
        let parent_path = path
            .parent()
            .ok_or_else(|| invalid("replay directory has no parent"))?;
        let target_name = path
            .file_name()
            .ok_or_else(|| invalid("replay directory has no final name"))?;
        let parent = open_directory(parent_path)?;
        let (staging_path, staging_name) = loop {
            let staging_name = format!(
                ".external-floor-replay.provision.{}.{}",
                std::process::id(),
                NEXT_PROVISION_STAGING.fetch_add(1, Ordering::Relaxed),
            );
            let staging_path = parent_path.join(&staging_name);
            let mut builder = DirBuilder::new();
            builder.mode(0o700);
            match builder.create(&staging_path) {
                Ok(()) => break (staging_path, staging_name),
                Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        };
        let created = fs::symlink_metadata(&staging_path)?;
        if !created.is_dir() || created.file_type().is_symlink() {
            return Err(denied("new replay directory identity is invalid"));
        }
        let created = metadata_snapshot(&created);
        before_open(&staging_path);
        let directory = open_directory(&staging_path)?;
        if file_snapshot(&directory)? != created {
            return Err(denied(
                "new replay directory changed before its descriptor was retained",
            ));
        }
        let _lock = ExclusiveLock::acquire(&directory)?;
        reject_temporary_entry(&directory)?;
        let (temporary, snapshot, encoded) = write_temp(&directory, initial)?;
        before_install(&staging_path);
        validate_file_name(
            &directory,
            TEMP_FILE,
            &temporary,
            "initial temporary replay checkpoint changed before commit",
        )?;
        if !evidence_matches(&temporary, snapshot, 1, &encoded) {
            return Err(denied(
                "initial temporary replay checkpoint changed before commit",
            ));
        }
        validate_mutation_authority(&staging_path, &directory, &_lock)?;
        install_temp(&directory, true)?;
        validate_file_name(
            &directory,
            STATE_FILE,
            &temporary,
            "initial replay checkpoint changed during commit",
        )?;
        let committed_snapshot = refreshed_evidence(&temporary, snapshot, 1, &encoded)
            .ok_or_else(|| denied("initial replay checkpoint changed during commit"))?;
        directory.sync_all()?;
        validate_mutation_authority(&staging_path, &directory, &_lock)?;
        validate_file_name(
            &directory,
            STATE_FILE,
            &temporary,
            "initial replay checkpoint changed while commit was synced",
        )?;
        if !evidence_matches(&temporary, committed_snapshot, 1, &encoded) {
            return Err(invalid("initial replay checkpoint readback mismatch"));
        }
        before_publish(&staging_path);
        validate_directory_name(parent_path, &parent)?;
        validate_mutation_authority(&staging_path, &directory, &_lock)?;
        validate_file_name(
            &directory,
            STATE_FILE,
            &temporary,
            "staged replay checkpoint changed before directory publication",
        )?;
        if !evidence_matches(&temporary, committed_snapshot, 1, &encoded) {
            return Err(denied(
                "staged replay checkpoint changed before directory publication",
            ));
        }
        publish_directory_noreplace(&parent, std::ffi::OsStr::new(&staging_name), target_name)?;
        parent.sync_all()?;
        validate_directory_name(parent_path, &parent)?;
        validate_directory_name(path, &directory)?;
        _lock.validate_current(&directory)?;
        validate_file_name(
            &directory,
            STATE_FILE,
            &temporary,
            "published replay checkpoint does not match staged evidence",
        )?;
        if !evidence_matches(&temporary, committed_snapshot, 1, &encoded) {
            return Err(denied(
                "published replay checkpoint does not match staged evidence",
            ));
        }
        match fs::symlink_metadata(&staging_path) {
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Ok(_) => return Err(denied("published replay staging name still exists")),
            Err(error) => return Err(error),
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
        let (stored, state, snapshot, bytes) = open_state(&directory)?;
        validate_mutation_authority(path, &directory, &lock)?;
        reject_temporary_entry(&directory)?;
        validate_file_name(
            &directory,
            STATE_FILE,
            &state,
            "replay state changed while store was opened",
        )?;
        if file_snapshot(&state)? != snapshot || read_record_bytes(&state)? != bytes {
            return Err(denied("replay state changed while store was opened"));
        }
        if stored != trusted {
            return Err(invalid(
                "stored replay checkpoint does not equal the externally trusted checkpoint",
            ));
        }
        Ok(Self {
            directory_path: path.to_path_buf(),
            directory,
            _lock: lock,
            #[cfg(test)]
            uncertain_after_rename: std::cell::Cell::new(false),
            #[cfg(test)]
            before_exchange: std::cell::Cell::new(None),
            #[cfg(test)]
            before_cleanup: std::cell::Cell::new(None),
        })
    }
}

fn open_directory(path: &Path) -> io::Result<File> {
    if !path.is_absolute() {
        return Err(denied("replay directory must be absolute"));
    }
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

fn validate_directory_name(path: &Path, directory: &File) -> io::Result<()> {
    validate_directory(directory)?;
    let named = open_directory(path)?;
    let opened = directory.metadata()?;
    let named = named.metadata()?;
    if opened.dev() != named.dev() || opened.ino() != named.ino() {
        return Err(denied(
            "replay directory pathname no longer names the opened directory",
        ));
    }
    Ok(())
}

fn validate_mutation_authority(
    path: &Path,
    directory: &File,
    lock: &ExclusiveLock,
) -> io::Result<()> {
    validate_directory_name(path, directory)?;
    lock.validate_current(directory)
}

impl ExternalFloorReplayStore for UnixExternalFloorReplayStore {
    fn load(&self) -> io::Result<ExternalFloorReplayCheckpoint> {
        validate_mutation_authority(&self.directory_path, &self.directory, &self._lock)?;
        reject_temporary_entry(&self.directory)?;
        let (checkpoint, state, snapshot, bytes) = open_state(&self.directory)?;
        validate_mutation_authority(&self.directory_path, &self.directory, &self._lock)?;
        reject_temporary_entry(&self.directory)?;
        validate_file_name(
            &self.directory,
            STATE_FILE,
            &state,
            "replay state changed during load",
        )?;
        if file_snapshot(&state)? != snapshot || read_record_bytes(&state)? != bytes {
            return Err(denied("replay state changed during load"));
        }
        Ok(checkpoint)
    }

    fn compare_and_swap(
        &self,
        expected: ExternalFloorReplayCheckpoint,
        replacement: ExternalFloorReplayCheckpoint,
    ) -> io::Result<ExternalFloorReplayCasOutcome> {
        validate_mutation_authority(&self.directory_path, &self.directory, &self._lock)?;
        reject_temporary_entry(&self.directory)?;
        if replacement.session_nonce == [0; 32] {
            return Err(Error::new(ErrorKind::InvalidInput, "zero session nonce"));
        }
        let (current, previous, previous_snapshot, previous_bytes) = open_state(&self.directory)?;
        validate_mutation_authority(&self.directory_path, &self.directory, &self._lock)?;
        reject_temporary_entry(&self.directory)?;
        validate_file_name(
            &self.directory,
            STATE_FILE,
            &previous,
            "replay state changed before CAS comparison",
        )?;
        if file_snapshot(&previous)? != previous_snapshot
            || read_record_bytes(&previous)? != previous_bytes
        {
            return Err(denied("replay state changed before CAS comparison"));
        }
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
        let (temporary, temporary_snapshot, temporary_bytes) =
            write_temp(&self.directory, replacement)?;
        #[cfg(test)]
        if let Some(action) = self.before_exchange.take() {
            action(&self.directory_path);
        }
        validate_file_name(
            &self.directory,
            STATE_FILE,
            &previous,
            "previous replay state changed before commit",
        )?;
        if file_snapshot(&previous)? != previous_snapshot
            || read_record_bytes(&previous)? != previous_bytes
        {
            return Err(denied("previous replay state changed before commit"));
        }
        validate_file_name(
            &self.directory,
            TEMP_FILE,
            &temporary,
            "temporary replay state changed before commit",
        )?;
        if !evidence_matches(&temporary, temporary_snapshot, 1, &temporary_bytes) {
            return Err(denied("temporary replay state changed before commit"));
        }
        validate_mutation_authority(&self.directory_path, &self.directory, &self._lock)?;

        // From rename onward an error cannot safely distinguish an uncommitted
        // write from a committed-but-unacknowledged one.
        if install_temp(&self.directory, false).is_err() {
            return Ok(ExternalFloorReplayCasOutcome::Uncertain);
        }
        let names_valid = validate_file_name(
            &self.directory,
            STATE_FILE,
            &temporary,
            "replay state changed during commit",
        )
        .and_then(|()| {
            validate_file_name(
                &self.directory,
                TEMP_FILE,
                &previous,
                "previous replay state changed during exchange",
            )
        })
        .is_ok();
        let installed_snapshot =
            refreshed_evidence(&temporary, temporary_snapshot, 1, &temporary_bytes);
        let displaced_snapshot =
            refreshed_evidence(&previous, previous_snapshot, 1, &previous_bytes);
        let (Some(installed_snapshot), Some(displaced_snapshot)) =
            (installed_snapshot, displaced_snapshot)
        else {
            return Ok(ExternalFloorReplayCasOutcome::Uncertain);
        };
        if !names_valid || self.directory.sync_all().is_err() {
            return Ok(ExternalFloorReplayCasOutcome::Uncertain);
        }
        #[cfg(test)]
        if let Some(action) = self.before_cleanup.take() {
            action(&self.directory_path);
        }
        if validate_mutation_authority(&self.directory_path, &self.directory, &self._lock).is_err()
            || validate_file_name(
                &self.directory,
                STATE_FILE,
                &temporary,
                "replay state changed while commit was synced",
            )
            .is_err()
            || !evidence_matches(&temporary, installed_snapshot, 1, &temporary_bytes)
            || validate_file_name(
                &self.directory,
                TEMP_FILE,
                &previous,
                "previous replay state changed before cleanup",
            )
            .is_err()
            || !evidence_matches(&previous, displaced_snapshot, 1, &previous_bytes)
        {
            return Ok(ExternalFloorReplayCasOutcome::Uncertain);
        }
        // The old checkpoint is retained until both sides of the exchange
        // have been verified and synced. Removing it is part of the commit;
        // any failure after the exchange remains explicitly ambiguous.
        // SAFETY: the fixed name is valid relative to the retained directory.
        if unsafe { libc::unlinkat(self.directory.as_raw_fd(), name(TEMP_FILE).as_ptr(), 0) } != 0
            || !evidence_matches(&previous, displaced_snapshot, 0, &previous_bytes)
            || self.directory.sync_all().is_err()
            || validate_mutation_authority(&self.directory_path, &self.directory, &self._lock)
                .is_err()
        {
            return Ok(ExternalFloorReplayCasOutcome::Uncertain);
        }
        #[cfg(test)]
        if self.uncertain_after_rename.replace(false) {
            return Ok(ExternalFloorReplayCasOutcome::Uncertain);
        }
        match self.load() {
            Ok(readback) if readback == replacement => Ok(ExternalFloorReplayCasOutcome::Committed),
            _ => Ok(ExternalFloorReplayCasOutcome::Uncertain),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::os::unix::fs::OpenOptionsExt;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEST: AtomicU64 = AtomicU64::new(0);

    fn rewrite_same_inode_restoring_mtime(path: &Path) {
        let bytes = fs::read(path).unwrap();
        let file = OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .unwrap();
        let metadata = file.metadata().unwrap();
        file.write_all_at(&bytes, 0).unwrap();
        file.sync_all().unwrap();
        let times = [
            libc::timespec {
                tv_sec: metadata.atime(),
                tv_nsec: metadata.atime_nsec(),
            },
            libc::timespec {
                tv_sec: metadata.mtime(),
                tv_nsec: metadata.mtime_nsec(),
            },
        ];
        // SAFETY: `file` owns a live descriptor and `times` has the two
        // timespec entries required by futimens.
        assert_eq!(
            unsafe { libc::futimens(file.as_raw_fd(), times.as_ptr()) },
            0
        );
        file.sync_all().unwrap();
    }

    fn rewrite_state_restoring_mtime(path: &Path) {
        rewrite_same_inode_restoring_mtime(&path.join(STATE_FILE));
    }

    fn rewrite_temp_restoring_mtime(path: &Path) {
        rewrite_same_inode_restoring_mtime(&path.join(TEMP_FILE));
    }

    fn test_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "bloch-replay-{label}-{}-{}",
            std::process::id(),
            NEXT_TEST.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn checkpoint(revision: u64, next_sequence: u64) -> ExternalFloorReplayCheckpoint {
        ExternalFloorReplayCheckpoint {
            revision,
            session_nonce: [0x41; 32],
            next_sequence,
        }
    }

    #[test]
    fn provisioning_refuses_directory_replaced_before_first_open() {
        let path = test_path("provision-directory-race");
        let displaced = RefCell::new(None);
        let replacement = RefCell::new(None);
        let result = UnixExternalFloorReplayStore::provision_inner(
            &path,
            checkpoint(1, 1),
            |staging| {
                let moved = staging.with_extension("displaced");
                fs::rename(staging, &moved).unwrap();
                let mut builder = DirBuilder::new();
                builder.mode(0o700);
                builder.create(staging).unwrap();
                *displaced.borrow_mut() = Some(moved);
                *replacement.borrow_mut() = Some(staging.to_path_buf());
            },
            |_| {},
            |_| {},
        );
        assert!(result.is_err());
        assert!(!path.exists());
        let displaced = displaced.into_inner().unwrap();
        assert!(fs::read_dir(&displaced).unwrap().next().is_none());
        fs::remove_dir_all(displaced).unwrap();
        fs::remove_dir_all(replacement.into_inner().unwrap()).unwrap();
    }

    #[test]
    fn provisioning_detects_same_inode_candidate_rewrite_with_restored_mtime() {
        let path = test_path("provision-ctime-race");
        let retained_staging = RefCell::new(None);
        let result = UnixExternalFloorReplayStore::provision_inner(
            &path,
            checkpoint(1, 1),
            |_| {},
            |staging| {
                rewrite_temp_restoring_mtime(staging);
                *retained_staging.borrow_mut() = Some(staging.to_path_buf());
            },
            |_| {},
        );
        assert!(result.is_err());
        assert!(!path.exists());
        let staging = retained_staging.into_inner().unwrap();
        assert!(staging.join(TEMP_FILE).exists());
        assert!(!staging.join(STATE_FILE).exists());
        fs::remove_dir_all(staging).unwrap();
    }

    #[test]
    fn provisioning_never_adopts_a_target_raced_before_atomic_publication() {
        let path = test_path("provision-target-race");
        let retained_staging = RefCell::new(None);
        let result = UnixExternalFloorReplayStore::provision_inner(
            &path,
            checkpoint(1, 1),
            |_| {},
            |_| {},
            |staging| {
                *retained_staging.borrow_mut() = Some(staging.to_path_buf());
                let mut builder = DirBuilder::new();
                builder.mode(0o700);
                builder.create(&path).unwrap();
            },
        );
        assert_eq!(result.unwrap_err().kind(), ErrorKind::AlreadyExists);
        assert!(fs::read_dir(&path).unwrap().next().is_none());
        let staging = retained_staging.into_inner().unwrap();
        assert!(staging.join(STATE_FILE).exists());
        fs::remove_dir_all(staging).unwrap();
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn exchange_detects_same_inode_predecessor_rewrite_with_restored_mtime() {
        let path = test_path("exchange-ctime-race");
        let initial = checkpoint(1, 1);
        let replacement = checkpoint(2, 2);
        UnixExternalFloorReplayStore::provision(&path, initial).unwrap();
        let store = UnixExternalFloorReplayStore::open(&path, initial).unwrap();
        store
            .before_exchange
            .set(Some(rewrite_state_restoring_mtime));
        assert!(store.compare_and_swap(initial, replacement).is_err());
        assert_eq!(store.load().unwrap_err().kind(), ErrorKind::InvalidData);
        assert!(path.join(TEMP_FILE).exists());
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn cleanup_detects_same_inode_predecessor_rewrite_with_restored_mtime() {
        let path = test_path("cleanup-ctime-race");
        let initial = checkpoint(1, 1);
        let replacement = checkpoint(2, 2);
        UnixExternalFloorReplayStore::provision(&path, initial).unwrap();
        let store = UnixExternalFloorReplayStore::open(&path, initial).unwrap();
        store.before_cleanup.set(Some(rewrite_temp_restoring_mtime));
        assert_eq!(
            store.compare_and_swap(initial, replacement).unwrap(),
            ExternalFloorReplayCasOutcome::Uncertain
        );
        assert!(path.join(TEMP_FILE).exists());
        assert_eq!(open_state(&store.directory).unwrap().0, replacement);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn injected_post_rename_failure_reports_uncertain_even_when_visible() {
        let path = test_path("uncertain");
        let initial = checkpoint(1, 9);
        let replacement = checkpoint(2, 10);
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
