// SPDX-License-Identifier: MIT OR Apache-2.0
//! Durable local receipt for an accepted BXRC anchor-authority tuple.
//!
//! This store never discovers authority from disk. Every open requires the
//! exact checkpoint retained by the caller in another trust domain. The hash
//! chain and checksum detect damage and mismatched history, but ordinary disk
//! remains rollbackable unless the expected checkpoint is retained elsewhere.

use std::fs::{DirBuilder, File, OpenOptions};
use std::io::{self, Error, ErrorKind, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::fs::{DirBuilderExt, FileExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use tiny_keccak::{Hasher, Keccak};

use crate::{
    verify_external_floor_custodian_anchor_approval,
    verify_external_floor_custodian_anchor_continuity, ExternalFloorCustodianAnchorApproval,
    ExternalFloorCustodianAnchorContinuityApproval, ExternalFloorCustodianClientAnchor,
};

const STATE_FILE: &str = ".bxrc-accepted-authority";
const TEMP_FILE: &str = ".bxrc-accepted-authority.tmp";
const CLEANUP_FILE: &str = ".bxrc-accepted-authority.cleanup";
const LOCK_FILE: &str = ".bxrc-accepted-authority.lock";
const MAGIC: [u8; 4] = *b"BXAT";
const VERSION: u8 = 1;
const PREFIX_LEN: usize = 152;
const RECORD_DOMAIN: &[u8] = b"BLOCH-L2-BXRC-ACCEPTED-AUTHORITY-v1\0";

/// Exact canonical length of an accepted-authority checkpoint record.
pub const EXTERNAL_FLOOR_CUSTODIAN_AUTHORITY_RECORD_LEN: usize = PREFIX_LEN + 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CheckpointFileSnapshot {
    dev: u64,
    ino: u64,
    mode: u32,
    nlink: u64,
    uid: u32,
    gid: u32,
    size: u64,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
}

#[derive(Debug, Clone, Copy)]
struct CheckpointFileEvidence {
    encoded: [u8; EXTERNAL_FLOOR_CUSTODIAN_AUTHORITY_RECORD_LEN],
    snapshot: CheckpointFileSnapshot,
}

/// The complete authority state that must be retained together.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExternalFloorCustodianAuthorityTuple {
    pub deployment_id: [u8; 32],
    pub verifying_key: [u8; 32],
    pub anchor: ExternalFloorCustodianClientAnchor,
}

/// Receipt for one accepted tuple and its exact local history position.
///
/// Persist this value outside the store's rollback domain. In particular,
/// retaining it beside the record does not make either copy anti-rollback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExternalFloorCustodianAuthorityCheckpoint {
    pub transition_index: u64,
    pub authority: ExternalFloorCustodianAuthorityTuple,
    pub previous_record_hash: [u8; 32],
    pub record_hash: [u8; 32],
}

/// Exact result of reconciling one possibly ambiguous authority transition.
///
/// Both variants contain caller-derived checkpoints. The reconciliation never
/// returns or adopts an authority tuple merely because it was found on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalFloorCustodianAuthorityReconciliation {
    /// The local write did not commit; the prior externally retained receipt
    /// remains current.
    NotCommitted {
        current: ExternalFloorCustodianAuthorityCheckpoint,
    },
    /// The exact dual-signed transition committed locally and its receipt can
    /// now be exported to the independent trust domain.
    Committed {
        previous: ExternalFloorCustodianAuthorityCheckpoint,
        current: ExternalFloorCustodianAuthorityCheckpoint,
    },
}

/// Result of reconciling an interrupted initial authority provisioning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalFloorCustodianAuthorityProvisioningReconciliation {
    /// The exact caller-derived genesis record was already durable.
    Committed {
        current: ExternalFloorCustodianAuthorityCheckpoint,
    },
    /// The exact caller-derived temporary genesis record was installed and
    /// synced by explicit reconciliation.
    Recovered {
        current: ExternalFloorCustodianAuthorityCheckpoint,
    },
}

fn invalid(message: &'static str) -> Error {
    Error::new(ErrorKind::InvalidData, message)
}

fn denied(message: &'static str) -> Error {
    Error::new(ErrorKind::PermissionDenied, message)
}

fn c_name(value: &'static str) -> std::ffi::CString {
    std::ffi::CString::new(value).expect("fixed authority filename contains no NUL")
}

fn open_at(directory: RawFd, filename: &'static str, flags: i32, mode: u32) -> io::Result<File> {
    // The file type is necessarily checked only after open(2) gives us a
    // descriptor whose identity can be pinned. Refuse to let an unexpected
    // FIFO or terminal block that inspection or acquire a controlling TTY.
    // O_NONBLOCK/O_NOCTTY do not change regular-file I/O semantics.
    // SAFETY: the directory descriptor and fixed NUL-terminated name are valid.
    let descriptor = unsafe {
        libc::openat(
            directory,
            c_name(filename).as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY,
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

fn validate_directory(directory: &File) -> io::Result<()> {
    let metadata = directory.metadata()?;
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(denied(
            "BXRC authority directory must be private and owned by this user",
        ));
    }
    Ok(())
}

fn validate_file(file: &File, message: &'static str) -> io::Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(denied(message));
    }
    Ok(())
}

fn checkpoint_snapshot(file: &File) -> io::Result<CheckpointFileSnapshot> {
    let metadata = file.metadata()?;
    Ok(CheckpointFileSnapshot {
        dev: metadata.dev(),
        ino: metadata.ino(),
        mode: metadata.mode(),
        nlink: metadata.nlink(),
        uid: metadata.uid(),
        gid: metadata.gid(),
        size: metadata.size(),
        mtime: metadata.mtime(),
        mtime_nsec: metadata.mtime_nsec(),
        ctime: metadata.ctime(),
        ctime_nsec: metadata.ctime_nsec(),
    })
}

fn validate_checkpoint_snapshot(
    file: &File,
    expected: CheckpointFileSnapshot,
    expected_nlink: u64,
    message: &'static str,
) -> io::Result<()> {
    let mut actual = checkpoint_snapshot(file)?;
    let actual_nlink = actual.nlink;
    actual.nlink = expected.nlink;
    if actual_nlink != expected_nlink || actual != expected {
        return Err(denied(message));
    }
    Ok(())
}

fn read_checkpoint_bytes(
    file: &File,
) -> io::Result<[u8; EXTERNAL_FLOOR_CUSTODIAN_AUTHORITY_RECORD_LEN]> {
    let mut encoded = [0_u8; EXTERNAL_FLOOR_CUSTODIAN_AUTHORITY_RECORD_LEN];
    file.read_exact_at(&mut encoded, 0)?;
    let mut trailing = [0_u8; 1];
    if file.read_at(&mut trailing, encoded.len() as u64)? != 0 {
        return Err(invalid("BXRC authority record has trailing data"));
    }
    Ok(encoded)
}

fn exists_at(directory: &File, filename: &'static str) -> io::Result<bool> {
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: all pointers and the descriptor are valid.
    let result = unsafe {
        libc::fstatat(
            directory.as_raw_fd(),
            c_name(filename).as_ptr(),
            metadata.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result == 0 {
        Ok(true)
    } else {
        let error = Error::last_os_error();
        if error.kind() == ErrorKind::NotFound {
            Ok(false)
        } else {
            Err(error)
        }
    }
}

fn open_directory(path: &Path) -> io::Result<File> {
    if !path.is_absolute() {
        return Err(invalid("BXRC authority directory must be absolute"));
    }
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open(path)?;
    validate_directory(&directory)?;
    Ok(directory)
}

fn validate_directory_name(path: &Path, directory: &File) -> io::Result<()> {
    validate_directory(directory)?;
    let named = open_directory(path)?;
    let opened_metadata = directory.metadata()?;
    let named_metadata = named.metadata()?;
    if opened_metadata.dev() != named_metadata.dev()
        || opened_metadata.ino() != named_metadata.ino()
    {
        return Err(denied(
            "BXRC authority directory pathname no longer names the opened directory",
        ));
    }
    Ok(())
}

#[derive(Debug)]
struct Lock(File);

impl Lock {
    fn acquire(directory: &File) -> io::Result<Self> {
        let lock = match open_at(
            directory.as_raw_fd(),
            LOCK_FILE,
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
            0o600,
        ) {
            Ok(file) => {
                file.sync_all()?;
                directory.sync_all()?;
                file
            }
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {
                open_at(directory.as_raw_fd(), LOCK_FILE, libc::O_RDWR, 0)?
            }
            Err(error) => return Err(error),
        };
        validate_file(
            &lock,
            "BXRC authority lock is not a private single-link file",
        )?;
        // SAFETY: descriptor is live and flock constants are valid.
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(Error::last_os_error());
        }
        validate_file(&lock, "BXRC authority lock changed while acquired")?;
        let acquired = Self(lock);
        acquired.validate_current(directory)?;
        Ok(acquired)
    }

    fn validate_current(&self, directory: &File) -> io::Result<()> {
        validate_directory(directory)?;
        validate_file_name(
            directory,
            LOCK_FILE,
            &self.0,
            "BXRC authority lock pathname no longer names the acquired private single-link file",
        )
    }
}

impl Drop for Lock {
    fn drop(&mut self) {
        // The inode stays linked to prevent split-lock races.
        let _ = unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
    }
}

fn hash(prefix: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    hasher.update(RECORD_DOMAIN);
    hasher.update(prefix);
    let mut output = [0_u8; 32];
    hasher.finalize(&mut output);
    output
}

fn encode(
    transition_index: u64,
    authority: ExternalFloorCustodianAuthorityTuple,
    previous_record_hash: [u8; 32],
) -> io::Result<[u8; EXTERNAL_FLOOR_CUSTODIAN_AUTHORITY_RECORD_LEN]> {
    if authority.deployment_id == [0; 32]
        || authority.verifying_key == [0; 32]
        || authority.anchor.commitment == [0; 32]
        || (transition_index == 0) != (previous_record_hash == [0; 32])
    {
        return Err(invalid("invalid BXRC accepted-authority state"));
    }
    let mut encoded = [0_u8; EXTERNAL_FLOOR_CUSTODIAN_AUTHORITY_RECORD_LEN];
    encoded[..4].copy_from_slice(&MAGIC);
    encoded[4] = VERSION;
    encoded[8..16].copy_from_slice(&transition_index.to_be_bytes());
    encoded[16..48].copy_from_slice(&authority.deployment_id);
    encoded[48..80].copy_from_slice(&authority.verifying_key);
    encoded[80..88].copy_from_slice(&authority.anchor.revision.to_be_bytes());
    encoded[88..120].copy_from_slice(&authority.anchor.commitment);
    encoded[120..152].copy_from_slice(&previous_record_hash);
    let record_hash = hash(&encoded[..PREFIX_LEN]);
    encoded[PREFIX_LEN..].copy_from_slice(&record_hash);
    Ok(encoded)
}

fn decode(encoded: &[u8]) -> io::Result<ExternalFloorCustodianAuthorityCheckpoint> {
    if encoded.len() != EXTERNAL_FLOOR_CUSTODIAN_AUTHORITY_RECORD_LEN
        || encoded[..4] != MAGIC
        || encoded[4] != VERSION
        || encoded[5..8] != [0; 3]
        || encoded[PREFIX_LEN..] != hash(&encoded[..PREFIX_LEN])
    {
        return Err(invalid("invalid BXRC accepted-authority record"));
    }
    let checkpoint = ExternalFloorCustodianAuthorityCheckpoint {
        transition_index: u64::from_be_bytes(encoded[8..16].try_into().unwrap()),
        authority: ExternalFloorCustodianAuthorityTuple {
            deployment_id: encoded[16..48].try_into().unwrap(),
            verifying_key: encoded[48..80].try_into().unwrap(),
            anchor: ExternalFloorCustodianClientAnchor {
                revision: u64::from_be_bytes(encoded[80..88].try_into().unwrap()),
                commitment: encoded[88..120].try_into().unwrap(),
            },
        },
        previous_record_hash: encoded[120..152].try_into().unwrap(),
        record_hash: encoded[PREFIX_LEN..].try_into().unwrap(),
    };
    // Reuse all canonical identity and genesis/history invariants.
    encode(
        checkpoint.transition_index,
        checkpoint.authority,
        checkpoint.previous_record_hash,
    )?;
    Ok(checkpoint)
}

/// Encodes an authority checkpoint as the canonical portable receipt.
///
/// The returned bytes are identical to the durable on-disk record and include
/// its version, complete authority tuple, history link, and record hash. This
/// function validates the complete checkpoint instead of silently
/// canonicalizing inconsistent caller input.
pub fn encode_external_floor_custodian_authority_checkpoint(
    checkpoint: ExternalFloorCustodianAuthorityCheckpoint,
) -> io::Result<[u8; EXTERNAL_FLOOR_CUSTODIAN_AUTHORITY_RECORD_LEN]> {
    let encoded = encode(
        checkpoint.transition_index,
        checkpoint.authority,
        checkpoint.previous_record_hash,
    )?;
    if decode(&encoded)? != checkpoint {
        return Err(invalid("invalid BXRC authority checkpoint receipt"));
    }
    Ok(encoded)
}

/// Decodes and validates one canonical portable authority checkpoint receipt.
///
/// This enforces the exact versioned length, reserved bytes, tuple invariants,
/// history-link invariants, and record hash. Successful decoding establishes
/// internal integrity only; callers must still obtain these bytes from their
/// independently authenticated, rollback-detecting receipt channel.
pub fn decode_external_floor_custodian_authority_checkpoint(
    encoded: &[u8],
) -> io::Result<ExternalFloorCustodianAuthorityCheckpoint> {
    decode(encoded)
}

fn open_checkpoint_file(
    directory: &File,
    filename: &'static str,
    unsafe_file_message: &'static str,
) -> io::Result<(
    ExternalFloorCustodianAuthorityCheckpoint,
    File,
    CheckpointFileEvidence,
)> {
    let file = open_at(directory.as_raw_fd(), filename, libc::O_RDONLY, 0)?;
    validate_file(&file, unsafe_file_message)?;
    let before = checkpoint_snapshot(&file)?;
    let encoded = read_checkpoint_bytes(&file)?;
    // Revalidate after reading so a concurrent permission/link or pathname
    // change cannot turn bytes read from an obsolete descriptor into accepted
    // state.
    validate_file_name(directory, filename, &file, unsafe_file_message)?;
    let after = checkpoint_snapshot(&file)?;
    if after != before {
        return Err(denied(unsafe_file_message));
    }
    Ok((
        decode(&encoded)?,
        file,
        CheckpointFileEvidence {
            encoded,
            snapshot: after,
        },
    ))
}

fn read_checkpoint_file(
    directory: &File,
    filename: &'static str,
    unsafe_file_message: &'static str,
) -> io::Result<ExternalFloorCustodianAuthorityCheckpoint> {
    open_checkpoint_file(directory, filename, unsafe_file_message)
        .map(|(checkpoint, _file, _evidence)| checkpoint)
}

fn read_checkpoint(directory: &File) -> io::Result<ExternalFloorCustodianAuthorityCheckpoint> {
    open_checkpoint(directory).map(|(checkpoint, _file, _evidence)| checkpoint)
}

fn open_checkpoint(
    directory: &File,
) -> io::Result<(
    ExternalFloorCustodianAuthorityCheckpoint,
    File,
    CheckpointFileEvidence,
)> {
    if exists_at(directory, TEMP_FILE)? || exists_at(directory, CLEANUP_FILE)? {
        return Err(invalid(
            "temporary BXRC authority cleanup evidence exists; operator inspection required",
        ));
    }
    open_checkpoint_file(
        directory,
        STATE_FILE,
        "BXRC authority record must be private and single-link",
    )
}

fn validate_file_name(
    directory: &File,
    filename: &'static str,
    file: &File,
    unsafe_file_message: &'static str,
) -> io::Result<()> {
    validate_file(file, unsafe_file_message)?;
    let mut named = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: all pointers and the directory descriptor are valid.
    if unsafe {
        libc::fstatat(
            directory.as_raw_fd(),
            c_name(filename).as_ptr(),
            named.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(Error::last_os_error());
    }
    // SAFETY: successful `fstatat` initialized the structure.
    let named = unsafe { named.assume_init() };
    let opened = file.metadata()?;
    if opened.dev() != named.st_dev as u64 || opened.ino() != named.st_ino {
        return Err(denied(unsafe_file_message));
    }
    Ok(())
}

fn validate_checkpoint_evidence(
    file: &File,
    evidence: CheckpointFileEvidence,
    message: &'static str,
) -> io::Result<()> {
    validate_checkpoint_snapshot(file, evidence.snapshot, 1, message)?;
    if read_checkpoint_bytes(file)? != evidence.encoded {
        return Err(denied(message));
    }
    Ok(())
}

fn refresh_checkpoint_evidence_after_rename(
    file: &File,
    evidence: CheckpointFileEvidence,
    message: &'static str,
) -> io::Result<CheckpointFileEvidence> {
    let actual = checkpoint_snapshot(file)?;
    let mut comparable = actual;
    comparable.ctime = evidence.snapshot.ctime;
    comparable.ctime_nsec = evidence.snapshot.ctime_nsec;
    if comparable != evidence.snapshot || read_checkpoint_bytes(file)? != evidence.encoded {
        return Err(denied(message));
    }
    Ok(CheckpointFileEvidence {
        encoded: evidence.encoded,
        snapshot: actual,
    })
}

fn validate_newly_unlinked_checkpoint(
    file: &File,
    evidence: CheckpointFileEvidence,
    message: &'static str,
) -> io::Result<CheckpointFileSnapshot> {
    let actual = checkpoint_snapshot(file)?;
    let mut comparable = actual;
    comparable.nlink = evidence.snapshot.nlink;
    // Unlink necessarily changes ctime, so bind all other retained metadata
    // and use this post-unlink snapshot as the fsync comparison floor.
    comparable.ctime = evidence.snapshot.ctime;
    comparable.ctime_nsec = evidence.snapshot.ctime_nsec;
    if actual.nlink != 0
        || comparable != evidence.snapshot
        || read_checkpoint_bytes(file)? != evidence.encoded
    {
        return Err(denied(message));
    }
    Ok(actual)
}

fn remove_cleanup_checkpoint_inner<F, G>(
    directory_path: &Path,
    directory: &File,
    cleanup: &File,
    evidence: CheckpointFileEvidence,
    before_evidence_check: F,
    before_directory_check: G,
) -> io::Result<()>
where
    F: FnOnce(),
    G: FnOnce(),
{
    validate_file_name(
        directory,
        CLEANUP_FILE,
        cleanup,
        "BXRC authority cleanup tombstone changed before removal",
    )?;
    before_evidence_check();
    validate_file_name(
        directory,
        CLEANUP_FILE,
        cleanup,
        "BXRC authority cleanup tombstone changed before unlink",
    )?;
    validate_checkpoint_evidence(
        cleanup,
        evidence,
        "BXRC authority cleanup tombstone content or metadata changed before unlink",
    )?;
    before_directory_check();
    // Keep the configured pathname identity check as the final operation
    // before unlinkat. Moving the directory after evidence validation must not
    // let a live instance remove a tombstone from the displaced store.
    validate_directory_name(directory_path, directory)?;
    // SAFETY: the fixed name is valid and relative to the live directory fd.
    if unsafe { libc::unlinkat(directory.as_raw_fd(), c_name(CLEANUP_FILE).as_ptr(), 0) } != 0 {
        return Err(Error::last_os_error());
    }
    let unlinked = validate_newly_unlinked_checkpoint(
        cleanup,
        evidence,
        "validated BXRC authority cleanup tombstone was not removed",
    )?;
    directory.sync_all()?;
    validate_checkpoint_snapshot(
        cleanup,
        unlinked,
        0,
        "validated BXRC authority cleanup tombstone changed while removal was synced",
    )?;
    if read_checkpoint_bytes(cleanup)? != evidence.encoded {
        return Err(denied(
            "validated BXRC authority cleanup tombstone content changed while removal was synced",
        ));
    }
    Ok(())
}

fn remove_cleanup_checkpoint(
    directory_path: &Path,
    directory: &File,
    cleanup: &File,
    evidence: CheckpointFileEvidence,
) -> io::Result<()> {
    remove_cleanup_checkpoint_inner(directory_path, directory, cleanup, evidence, || {}, || {})
}

fn remove_temporary_checkpoint_inner<F>(
    directory_path: &Path,
    directory: &File,
    temporary: &File,
    evidence: CheckpointFileEvidence,
    before_stage: F,
) -> io::Result<()>
where
    F: FnOnce(),
{
    validate_file_name(
        directory,
        TEMP_FILE,
        temporary,
        "temporary BXRC authority record changed before cleanup",
    )?;
    validate_checkpoint_evidence(
        temporary,
        evidence,
        "temporary BXRC authority record content or metadata changed before cleanup",
    )?;
    before_stage();
    validate_directory_name(directory_path, directory)?;
    // Atomically move whatever occupies TEMP to a reserved tombstone without
    // overwriting prior crash evidence. The moved object must be the descriptor
    // pinned above before it can be unlinked.
    move_checkpoint_name_exclusive(directory, TEMP_FILE, CLEANUP_FILE)?;
    validate_file_name(
        directory,
        CLEANUP_FILE,
        temporary,
        "BXRC authority cleanup tombstone is not the validated temporary record",
    )?;
    let staged_evidence = refresh_checkpoint_evidence_after_rename(
        temporary,
        evidence,
        "BXRC authority cleanup tombstone content or metadata changed while staging",
    )?;
    directory.sync_all()?;
    validate_file_name(
        directory,
        CLEANUP_FILE,
        temporary,
        "BXRC authority cleanup tombstone changed while staging was synced",
    )?;
    validate_checkpoint_evidence(
        temporary,
        staged_evidence,
        "BXRC authority cleanup tombstone content or metadata changed while staging was synced",
    )?;
    remove_cleanup_checkpoint(directory_path, directory, temporary, staged_evidence)
}

fn remove_temporary_checkpoint(
    directory_path: &Path,
    directory: &File,
    temporary: &File,
    evidence: CheckpointFileEvidence,
) -> io::Result<()> {
    remove_temporary_checkpoint_inner(directory_path, directory, temporary, evidence, || {})
}

fn validate_replaced_checkpoint(
    previous: &File,
    evidence: CheckpointFileEvidence,
) -> io::Result<()> {
    validate_newly_unlinked_checkpoint(
        previous,
        evidence,
        "previous BXRC authority record was not atomically displaced during commit",
    )?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn exchange_checkpoint_names(directory: &File) -> io::Result<()> {
    // SAFETY: both fixed names and the live directory descriptor are valid.
    let result = unsafe {
        libc::renameat2(
            directory.as_raw_fd(),
            c_name(TEMP_FILE).as_ptr(),
            directory.as_raw_fd(),
            c_name(STATE_FILE).as_ptr(),
            libc::RENAME_EXCHANGE,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(Error::last_os_error())
    }
}

#[cfg(target_os = "macos")]
fn exchange_checkpoint_names(directory: &File) -> io::Result<()> {
    // SAFETY: both fixed names and the live directory descriptor are valid.
    let result = unsafe {
        libc::renameatx_np(
            directory.as_raw_fd(),
            c_name(TEMP_FILE).as_ptr(),
            directory.as_raw_fd(),
            c_name(STATE_FILE).as_ptr(),
            libc::RENAME_SWAP,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(Error::last_os_error())
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn exchange_checkpoint_names(_directory: &File) -> io::Result<()> {
    Err(Error::new(
        ErrorKind::Unsupported,
        "atomic BXRC authority checkpoint exchange is unavailable on this platform",
    ))
}

#[cfg(target_os = "linux")]
fn move_checkpoint_name_exclusive(
    directory: &File,
    source: &'static str,
    destination: &'static str,
) -> io::Result<()> {
    // SAFETY: both fixed names and the live directory descriptor are valid.
    let result = unsafe {
        libc::renameat2(
            directory.as_raw_fd(),
            c_name(source).as_ptr(),
            directory.as_raw_fd(),
            c_name(destination).as_ptr(),
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
fn move_checkpoint_name_exclusive(
    directory: &File,
    source: &'static str,
    destination: &'static str,
) -> io::Result<()> {
    // SAFETY: both fixed names and the live directory descriptor are valid.
    let result = unsafe {
        libc::renameatx_np(
            directory.as_raw_fd(),
            c_name(source).as_ptr(),
            directory.as_raw_fd(),
            c_name(destination).as_ptr(),
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
fn move_checkpoint_name_exclusive(
    _directory: &File,
    _source: &'static str,
    _destination: &'static str,
) -> io::Result<()> {
    Err(Error::new(
        ErrorKind::Unsupported,
        "atomic create-only BXRC authority checkpoint rename is unavailable on this platform",
    ))
}

fn install_checkpoint_name(directory: &File) -> io::Result<()> {
    move_checkpoint_name_exclusive(directory, TEMP_FILE, STATE_FILE)
}

fn commit_temporary_checkpoint_inner<F>(
    directory_path: &Path,
    directory: &File,
    temporary: &File,
    temporary_evidence: CheckpointFileEvidence,
    previous: Option<(&File, CheckpointFileEvidence)>,
    before_replace: F,
) -> io::Result<()>
where
    F: FnOnce(),
{
    if let Some((previous, previous_evidence)) = previous {
        validate_file_name(
            directory,
            STATE_FILE,
            previous,
            "previous BXRC authority record changed before commit",
        )?;
        validate_checkpoint_evidence(
            previous,
            previous_evidence,
            "previous BXRC authority record content or metadata changed before commit",
        )?;
    }
    validate_file_name(
        directory,
        TEMP_FILE,
        temporary,
        "temporary BXRC authority record changed before commit",
    )?;
    validate_checkpoint_evidence(
        temporary,
        temporary_evidence,
        "temporary BXRC authority record content or metadata changed before commit",
    )?;
    before_replace();
    validate_directory_name(directory_path, directory)?;
    let committed_evidence = if let Some((previous, previous_evidence)) = previous {
        // Atomically exchange both names. Whatever occupied STATE at this
        // instant is now inspectable at TEMP and must be the pinned predecessor.
        exchange_checkpoint_names(directory)?;
        validate_file_name(
            directory,
            STATE_FILE,
            temporary,
            "BXRC authority record changed during commit",
        )?;
        validate_file_name(
            directory,
            TEMP_FILE,
            previous,
            "BXRC authority predecessor changed during atomic exchange",
        )?;
        let committed = refresh_checkpoint_evidence_after_rename(
            temporary,
            temporary_evidence,
            "BXRC authority record content or metadata changed during commit",
        )?;
        let displaced = refresh_checkpoint_evidence_after_rename(
            previous,
            previous_evidence,
            "BXRC authority predecessor content or metadata changed during atomic exchange",
        )?;
        remove_temporary_checkpoint(directory_path, directory, previous, displaced)?;
        committed
    } else {
        // Fresh provisioning has no predecessor to exchange. Refuse rather
        // than overwrite any STATE raced into the newly created directory.
        install_checkpoint_name(directory)?;
        let committed = refresh_checkpoint_evidence_after_rename(
            temporary,
            temporary_evidence,
            "BXRC authority record content or metadata changed during install",
        )?;
        directory.sync_all()?;
        committed
    };
    // Keep the written descriptor live across rename and directory sync. A
    // pathname substitution is ambiguous, never a successful commit.
    validate_file_name(
        directory,
        STATE_FILE,
        temporary,
        "BXRC authority record changed during commit",
    )?;
    validate_checkpoint_evidence(
        temporary,
        committed_evidence,
        "BXRC authority record content or metadata changed while commit was synced",
    )?;
    if let Some((previous, previous_evidence)) = previous {
        validate_replaced_checkpoint(previous, previous_evidence)?;
    }
    Ok(())
}

fn commit_temporary_checkpoint(
    directory_path: &Path,
    directory: &File,
    temporary: &File,
    temporary_evidence: CheckpointFileEvidence,
    previous: Option<(&File, CheckpointFileEvidence)>,
) -> io::Result<()> {
    commit_temporary_checkpoint_inner(
        directory_path,
        directory,
        temporary,
        temporary_evidence,
        previous,
        || {},
    )
}

fn write_checkpoint(
    directory_path: &Path,
    directory: &File,
    transition_index: u64,
    authority: ExternalFloorCustodianAuthorityTuple,
    previous_record_hash: [u8; 32],
    create: bool,
    previous_file: Option<(&File, CheckpointFileEvidence)>,
) -> io::Result<ExternalFloorCustodianAuthorityCheckpoint> {
    if create == previous_file.is_some() {
        return Err(invalid("invalid BXRC authority commit predecessor"));
    }
    if exists_at(directory, TEMP_FILE)?
        || exists_at(directory, CLEANUP_FILE)?
        || (create && exists_at(directory, STATE_FILE)?)
    {
        return Err(Error::new(
            ErrorKind::AlreadyExists,
            "BXRC authority state already or ambiguously exists",
        ));
    }
    let encoded = encode(transition_index, authority, previous_record_hash)?;
    let expected = decode(&encoded)?;
    validate_directory_name(directory_path, directory)?;
    let mut temporary = open_at(
        directory.as_raw_fd(),
        TEMP_FILE,
        libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
        0o600,
    )?;
    validate_file(&temporary, "temporary BXRC authority record is unsafe")?;
    temporary.write_all(&encoded)?;
    temporary.sync_all()?;
    let temporary_evidence = CheckpointFileEvidence {
        encoded,
        snapshot: checkpoint_snapshot(&temporary)?,
    };
    commit_temporary_checkpoint(
        directory_path,
        directory,
        &temporary,
        temporary_evidence,
        previous_file,
    )?;
    if read_checkpoint(directory)? != expected {
        return Err(invalid("BXRC authority checkpoint read-back mismatch"));
    }
    Ok(expected)
}

/// Derives the only checkpoint a valid continuity approval may create.
///
/// This supports fail-closed recovery after an ambiguous local write: try
/// `open_expected` with the retained prior receipt and with this derived next
/// receipt, without trusting a tuple discovered on disk.
pub fn external_floor_custodian_expected_authority_checkpoint(
    previous: ExternalFloorCustodianAuthorityCheckpoint,
    approval: ExternalFloorCustodianAnchorContinuityApproval,
) -> io::Result<ExternalFloorCustodianAuthorityCheckpoint> {
    if decode(&encode(
        previous.transition_index,
        previous.authority,
        previous.previous_record_hash,
    )?)? != previous
    {
        return Err(invalid("invalid prior BXRC authority checkpoint"));
    }
    let (next_anchor, next_verifying_key) = verify_external_floor_custodian_anchor_continuity(
        previous.authority.deployment_id,
        previous.authority.verifying_key,
        previous.authority.anchor,
        approval,
    )?;
    let next_index = previous
        .transition_index
        .checked_add(1)
        .ok_or_else(|| invalid("BXRC authority transition index exhausted"))?;
    decode(&encode(
        next_index,
        ExternalFloorCustodianAuthorityTuple {
            deployment_id: previous.authority.deployment_id,
            verifying_key: next_verifying_key,
            anchor: next_anchor,
        },
        previous.record_hash,
    )?)
}

/// Derives the only genesis checkpoint authorized by an offline approval.
pub fn external_floor_custodian_expected_initial_authority_checkpoint(
    expected_deployment_id: [u8; 32],
    verifying_key: [u8; 32],
    approval: ExternalFloorCustodianAnchorApproval,
) -> io::Result<ExternalFloorCustodianAuthorityCheckpoint> {
    let anchor = verify_external_floor_custodian_anchor_approval(
        expected_deployment_id,
        verifying_key,
        approval,
    )?;
    decode(&encode(
        0,
        ExternalFloorCustodianAuthorityTuple {
            deployment_id: expected_deployment_id,
            verifying_key,
            anchor,
        },
        [0; 32],
    )?)
}

/// A durable, process-exclusive local receipt of accepted authority state.
///
/// This type intentionally has no unpinned `open`: callers must supply the
/// complete expected checkpoint or authenticated transition evidence.
pub struct UnixExternalFloorCustodianAuthorityStore {
    path: PathBuf,
    directory: File,
    _lock: Lock,
    expected: Mutex<ExternalFloorCustodianAuthorityCheckpoint>,
}

impl UnixExternalFloorCustodianAuthorityStore {
    /// Creates a fresh receipt only after validating an offline initial
    /// approval against separately supplied deployment and verifying key.
    pub fn provision_approved(
        path: &Path,
        expected_deployment_id: [u8; 32],
        verifying_key: [u8; 32],
        approval: ExternalFloorCustodianAnchorApproval,
    ) -> io::Result<(Self, ExternalFloorCustodianAuthorityCheckpoint)> {
        let expected = external_floor_custodian_expected_initial_authority_checkpoint(
            expected_deployment_id,
            verifying_key,
            approval,
        )?;
        if !path.is_absolute() {
            return Err(invalid("BXRC authority directory must be absolute"));
        }
        let mut builder = DirBuilder::new();
        builder.mode(0o700);
        builder.create(path)?;
        let directory = open_directory(path)?;
        let lock = Lock::acquire(&directory)?;
        let checkpoint = write_checkpoint(
            path,
            &directory,
            expected.transition_index,
            expected.authority,
            expected.previous_record_hash,
            true,
            None,
        )?;
        validate_directory_name(path, &directory)?;
        lock.validate_current(&directory)?;
        Ok((
            Self {
                path: path.to_path_buf(),
                directory,
                _lock: lock,
                expected: Mutex::new(checkpoint),
            },
            checkpoint,
        ))
    }

    /// Reconciles only exact artifacts from interrupted genesis provisioning.
    ///
    /// The admissible checkpoint is derived from the independently supplied
    /// deployment, key, and signed approval before disk inspection. An exact
    /// durable record is retained, an exact temporary-only candidate is
    /// installed with the create-only primitive, and an exact redundant
    /// temporary or cleanup-tombstone copy beside the durable record is
    /// removed. Missing artifacts, third states, simultaneous cleanup
    /// artifacts, corrupt records, and unsafe files fail closed without
    /// adopting or deleting disk evidence.
    pub fn reconcile_provisioning(
        path: &Path,
        expected_deployment_id: [u8; 32],
        verifying_key: [u8; 32],
        approval: ExternalFloorCustodianAnchorApproval,
    ) -> io::Result<(
        Self,
        ExternalFloorCustodianAuthorityProvisioningReconciliation,
    )> {
        let expected = external_floor_custodian_expected_initial_authority_checkpoint(
            expected_deployment_id,
            verifying_key,
            approval,
        )?;
        let directory = open_directory(path)?;
        let lock = Lock::acquire(&directory)?;
        validate_directory_name(path, &directory)?;
        let state_exists = exists_at(&directory, STATE_FILE)?;
        let temporary_exists = exists_at(&directory, TEMP_FILE)?;
        let cleanup_exists = exists_at(&directory, CLEANUP_FILE)?;
        if temporary_exists && cleanup_exists {
            return Err(denied(
                "BXRC authority provisioning found both temporary and cleanup evidence",
            ));
        }
        let recovered = match (state_exists, temporary_exists, cleanup_exists) {
            (true, false, false) => {
                if read_checkpoint_file(
                    &directory,
                    STATE_FILE,
                    "BXRC authority record must be private and single-link",
                )? != expected
                {
                    return Err(denied(
                        "BXRC authority provisioning found an unexpected durable checkpoint",
                    ));
                }
                false
            }
            (false, true, false) => {
                let (candidate, candidate_file, candidate_evidence) = open_checkpoint_file(
                    &directory,
                    TEMP_FILE,
                    "temporary BXRC authority record must be private and single-link",
                )?;
                if candidate != expected {
                    return Err(denied(
                        "BXRC authority provisioning found an unexpected temporary checkpoint",
                    ));
                }
                commit_temporary_checkpoint(
                    path,
                    &directory,
                    &candidate_file,
                    candidate_evidence,
                    None,
                )?;
                true
            }
            (true, true, false) | (true, false, true) => {
                let durable = read_checkpoint_file(
                    &directory,
                    STATE_FILE,
                    "BXRC authority record must be private and single-link",
                )?;
                let candidate_name = if temporary_exists {
                    TEMP_FILE
                } else {
                    CLEANUP_FILE
                };
                let (candidate, candidate_file, candidate_evidence) = open_checkpoint_file(
                    &directory,
                    candidate_name,
                    "BXRC authority cleanup candidate must be private and single-link",
                )?;
                if durable != expected || candidate != expected {
                    return Err(denied(
                        "BXRC authority provisioning found unexpected duplicate checkpoints",
                    ));
                }
                if temporary_exists {
                    remove_temporary_checkpoint(
                        path,
                        &directory,
                        &candidate_file,
                        candidate_evidence,
                    )?;
                } else {
                    remove_cleanup_checkpoint(
                        path,
                        &directory,
                        &candidate_file,
                        candidate_evidence,
                    )?;
                }
                false
            }
            (false, false, false) => {
                return Err(invalid(
                    "BXRC authority provisioning has no checkpoint evidence to reconcile",
                ));
            }
            (false, false, true) => {
                return Err(denied(
                    "BXRC authority provisioning found cleanup evidence without durable state",
                ));
            }
            (_, true, true) => unreachable!("both cleanup artifacts were rejected above"),
        };
        validate_directory_name(path, &directory)?;
        lock.validate_current(&directory)?;
        if read_checkpoint(&directory)? != expected {
            return Err(denied(
                "BXRC authority provisioning changed while it was reconciled",
            ));
        }
        let outcome = if recovered {
            ExternalFloorCustodianAuthorityProvisioningReconciliation::Recovered {
                current: expected,
            }
        } else {
            ExternalFloorCustodianAuthorityProvisioningReconciliation::Committed {
                current: expected,
            }
        };
        Ok((
            Self {
                path: path.to_path_buf(),
                directory,
                _lock: lock,
                expected: Mutex::new(expected),
            },
            outcome,
        ))
    }

    /// Opens only an exact checkpoint retained outside this rollback domain.
    pub fn open_expected(
        path: &Path,
        expected: ExternalFloorCustodianAuthorityCheckpoint,
    ) -> io::Result<Self> {
        let directory = open_directory(path)?;
        let lock = Lock::acquire(&directory)?;
        if read_checkpoint(&directory)? != expected {
            return Err(denied(
                "BXRC authority checkpoint does not match expected state",
            ));
        }
        validate_directory_name(path, &directory)?;
        lock.validate_current(&directory)?;
        Ok(Self {
            path: path.to_path_buf(),
            directory,
            _lock: lock,
            expected: Mutex::new(expected),
        })
    }

    /// Reconciles one possibly ambiguous continuity write without retrying it.
    ///
    /// The only admissible disk records are the exact externally retained
    /// prior checkpoint and the exact next checkpoint derived from the same
    /// dual-signed approval. If the durable record is still the exact prior
    /// checkpoint and an orphan temporary file is the exact derived next
    /// checkpoint, reconciliation durably removes that uncommitted candidate
    /// and returns `NotCommitted`. The inverse exact pair left after atomic
    /// exchange durably removes the displaced predecessor and returns
    /// `Committed`. An exact tombstone left after staging either cleanup is
    /// classified the same way. Any other record/artifact combination or
    /// unreadable store fails closed without cleanup. The returned store is
    /// pinned to the selected caller-derived checkpoint for restart checks.
    pub fn reconcile_continuity(
        path: &Path,
        previous: ExternalFloorCustodianAuthorityCheckpoint,
        approval: ExternalFloorCustodianAnchorContinuityApproval,
    ) -> io::Result<(Self, ExternalFloorCustodianAuthorityReconciliation)> {
        // Derive and authenticate both admissible states before consulting the
        // local rollbackable store. This prevents disk contents from becoming
        // an authority-selection input.
        let next = external_floor_custodian_expected_authority_checkpoint(previous, approval)?;
        let directory = open_directory(path)?;
        let lock = Lock::acquire(&directory)?;
        validate_directory_name(path, &directory)?;
        let temporary_exists = exists_at(&directory, TEMP_FILE)?;
        let cleanup_exists = exists_at(&directory, CLEANUP_FILE)?;
        if temporary_exists && cleanup_exists {
            return Err(denied(
                "BXRC authority reconciliation found both temporary and cleanup evidence",
            ));
        }
        let candidate_name = if temporary_exists {
            Some(TEMP_FILE)
        } else if cleanup_exists {
            Some(CLEANUP_FILE)
        } else {
            None
        };
        let current = if let Some(candidate_name) = candidate_name {
            let durable = read_checkpoint_file(
                &directory,
                STATE_FILE,
                "BXRC authority record must be private and single-link",
            )?;
            let (temporary, temporary_file, temporary_evidence) = open_checkpoint_file(
                &directory,
                candidate_name,
                "BXRC authority reconciliation candidate must be private and single-link",
            )?;
            let selected = if durable == previous && temporary == next {
                previous
            } else if durable == next && temporary == previous {
                next
            } else {
                return Err(denied(
                    "BXRC authority reconciliation found an unexpected temporary checkpoint",
                ));
            };
            if candidate_name == TEMP_FILE {
                remove_temporary_checkpoint(path, &directory, &temporary_file, temporary_evidence)?;
            } else {
                remove_cleanup_checkpoint(path, &directory, &temporary_file, temporary_evidence)?;
            }
            validate_directory_name(path, &directory)?;
            let reread = read_checkpoint(&directory)?;
            if reread != selected {
                return Err(denied(
                    "BXRC authority state changed while resolving an exchanged checkpoint",
                ));
            }
            reread
        } else {
            read_checkpoint(&directory)?
        };
        validate_directory_name(path, &directory)?;
        let (selected, reconciliation) = if current == previous {
            (
                previous,
                ExternalFloorCustodianAuthorityReconciliation::NotCommitted { current: previous },
            )
        } else if current == next {
            (
                next,
                ExternalFloorCustodianAuthorityReconciliation::Committed {
                    previous,
                    current: next,
                },
            )
        } else {
            return Err(denied(
                "BXRC authority reconciliation found neither exact prior nor derived next checkpoint",
            ));
        };
        lock.validate_current(&directory)?;
        Ok((
            Self {
                path: path.to_path_buf(),
                directory,
                _lock: lock,
                expected: Mutex::new(selected),
            },
            reconciliation,
        ))
    }

    fn expected(&self) -> io::Result<MutexGuard<'_, ExternalFloorCustodianAuthorityCheckpoint>> {
        self.expected
            .lock()
            .map_err(|_| Error::other("BXRC authority in-process lock is poisoned"))
    }

    /// Returns the exact currently pinned checkpoint; it never adopts another
    /// record because every instance was opened against an expected value.
    pub fn checkpoint(&self) -> io::Result<ExternalFloorCustodianAuthorityCheckpoint> {
        let expected = self.expected()?;
        validate_directory_name(&self.path, &self.directory)?;
        self._lock.validate_current(&self.directory)?;
        let actual = read_checkpoint(&self.directory)?;
        self._lock.validate_current(&self.directory)?;
        validate_directory_name(&self.path, &self.directory)?;
        if actual != *expected {
            return Err(denied("BXRC authority state changed behind live instance"));
        }
        Ok(*expected)
    }

    /// Atomically advances the local receipt after dual-signature continuity
    /// verification. A failed or ambiguous write must not be treated as an
    /// accepted transition; reopen using either exact expected checkpoint.
    pub fn accept_continuity(
        &self,
        approval: ExternalFloorCustodianAnchorContinuityApproval,
    ) -> io::Result<ExternalFloorCustodianAuthorityCheckpoint> {
        let mut expected = self.expected()?;
        validate_directory_name(&self.path, &self.directory)?;
        self._lock.validate_current(&self.directory)?;
        let (previous, previous_file, previous_evidence) = open_checkpoint(&self.directory)?;
        if previous != *expected {
            return Err(denied("BXRC authority state changed behind live instance"));
        }
        let derived = external_floor_custodian_expected_authority_checkpoint(previous, approval)?;
        let next = write_checkpoint(
            &self.path,
            &self.directory,
            derived.transition_index,
            derived.authority,
            derived.previous_record_hash,
            false,
            Some((&previous_file, previous_evidence)),
        )?;
        // If the lock pathname was replaced during the write, the transition
        // is deliberately ambiguous: leave the in-memory expectation at the
        // prior checkpoint and require explicit reconciliation.
        self._lock.validate_current(&self.directory)?;
        validate_directory_name(&self.path, &self.directory)?;
        *expected = next;
        Ok(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Read;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixStream;
    use std::os::unix::process::CommandExt;
    use std::process::{Child, Command, ExitStatus, Stdio};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::thread;
    use std::time::{Duration, Instant};

    static NEXT_PATH_IDENTITY_TEMP: AtomicU64 = AtomicU64::new(0);
    const FIFO_HELPER_ROOT_ENV: &str = "BLOCH_BXRC_FIFO_HELPER_ROOT";
    const FIFO_HELPER_TOKEN_ENV: &str = "BLOCH_BXRC_FIFO_HELPER_TOKEN";
    const FIFO_HELPER_FD_ENV: &str = "BLOCH_BXRC_FIFO_HELPER_FD";
    const FIFO_HELPER_TEST: &str = concat!(
        "external_floor_custodian_authority_file::tests::",
        "checkpoint_open_rejects_fifos_with_a_watchdog"
    );

    struct RemoveTestDirectory(PathBuf);

    impl Drop for RemoveTestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    struct ChildGuard(Option<Child>);

    impl ChildGuard {
        fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
            self.0.as_mut().unwrap().try_wait()
        }

        fn kill_and_reap(&mut self) -> (Option<ErrorKind>, io::Result<Option<ExitStatus>>) {
            let child = self.0.as_mut().unwrap();
            let kill_error = child.kill().err().map(|error| error.kind());
            let reap_result = if kill_error.is_none() {
                child.wait().map(Some)
            } else {
                child.try_wait()
            };
            if matches!(&reap_result, Ok(Some(_))) {
                self.0.take();
            }
            (kill_error, reap_result)
        }
    }

    impl Drop for ChildGuard {
        fn drop(&mut self) {
            if let Some(mut child) = self.0.take() {
                if !matches!(child.try_wait(), Ok(Some(_))) {
                    let _ = child.kill();
                    let _ = child.wait();
                }
            }
        }
    }

    fn fifo_helper_invocation() -> Option<(PathBuf, UnixStream, Vec<u8>)> {
        let root = PathBuf::from(std::env::var_os(FIFO_HELPER_ROOT_ENV)?);
        let token = std::env::var(FIFO_HELPER_TOKEN_ENV).ok()?.into_bytes();
        if token.len() != 64 || !token.iter().all(u8::is_ascii_hexdigit) {
            return None;
        }
        let inherited_fd = std::env::var(FIFO_HELPER_FD_ENV)
            .ok()?
            .parse::<RawFd>()
            .ok()?;
        if inherited_fd < 3 {
            return None;
        }
        // Duplicate the inherited descriptor so a fabricated environment can
        // never make this test close an unrelated descriptor owned by libtest.
        // SAFETY: fcntl validates inherited_fd and returns a new owned fd.
        let duplicated = unsafe { libc::fcntl(inherited_fd, libc::F_DUPFD_CLOEXEC, 3) };
        if duplicated < 0 {
            return None;
        }
        // SAFETY: duplicated is a new descriptor owned by this UnixStream.
        let mut channel = unsafe { UnixStream::from_raw_fd(duplicated) };
        let mut socket_type = 0_i32;
        let mut socket_type_len = std::mem::size_of::<i32>() as libc::socklen_t;
        // SAFETY: all pointers refer to initialized storage with the reported length.
        if unsafe {
            libc::getsockopt(
                channel.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_TYPE,
                (&mut socket_type as *mut i32).cast(),
                &mut socket_type_len,
            )
        } != 0
            || socket_type != libc::SOCK_STREAM
        {
            return None;
        }
        channel.set_nonblocking(true).ok()?;
        let mut received = vec![0_u8; token.len()];
        channel.read_exact(&mut received).ok()?;
        channel.set_nonblocking(false).ok()?;
        (received == token).then_some((root, channel, token))
    }

    fn random_fifo_helper_token() -> Vec<u8> {
        let mut random = [0_u8; 32];
        File::open("/dev/urandom")
            .unwrap()
            .read_exact(&mut random)
            .unwrap();
        random
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
            .into_bytes()
    }

    fn descriptor_flags(stream: &UnixStream) -> i32 {
        // SAFETY: stream owns a live descriptor and fcntl does not retain pointers.
        let flags = unsafe { libc::fcntl(stream.as_raw_fd(), libc::F_GETFD) };
        assert!(flags >= 0);
        flags
    }

    fn inherit_only_in_child(command: &mut Command, descriptor: RawFd) {
        // SAFETY: this callback runs after fork and before exec. It invokes
        // only async-signal-safe fcntl calls and changes the child's descriptor
        // table; the parent's copy remains CLOEXEC during concurrent tests.
        unsafe {
            command.pre_exec(move || {
                let flags = libc::fcntl(descriptor, libc::F_GETFD);
                if flags < 0 {
                    return Err(Error::last_os_error());
                }
                if libc::fcntl(descriptor, libc::F_SETFD, flags & !libc::FD_CLOEXEC) != 0 {
                    return Err(Error::last_os_error());
                }
                Ok(())
            });
        }
    }

    fn write_test_checkpoint(path: &Path, byte: u8) {
        fs::write(path, [byte; EXTERNAL_FLOOR_CUSTODIAN_AUTHORITY_RECORD_LEN]).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn test_evidence(file: &File) -> CheckpointFileEvidence {
        CheckpointFileEvidence {
            encoded: read_checkpoint_bytes(file).unwrap(),
            snapshot: checkpoint_snapshot(file).unwrap(),
        }
    }

    #[test]
    fn temporary_cleanup_rejects_pathname_substitution() {
        let root = std::env::temp_dir().join(format!(
            "bloch-bxrc-authority-path-identity-{}-{}",
            std::process::id(),
            NEXT_PATH_IDENTITY_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let temporary = root.join(TEMP_FILE);
        fs::write(&temporary, b"original").unwrap();
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600)).unwrap();

        let directory = open_directory(&root).unwrap();
        let opened = open_at(directory.as_raw_fd(), TEMP_FILE, libc::O_RDONLY, 0).unwrap();
        fs::rename(&temporary, root.join("displaced")).unwrap();
        fs::write(&temporary, b"replacement").unwrap();
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600)).unwrap();

        let error = validate_file_name(
            &directory,
            TEMP_FILE,
            &opened,
            "unsafe temporary checkpoint",
        )
        .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::PermissionDenied);
        assert!(temporary.exists());

        drop(opened);
        drop(directory);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn checkpoint_open_rejects_fifos_with_a_watchdog() {
        if let Some((root, mut channel, token)) = fifo_helper_invocation() {
            let directory = open_directory(&root).unwrap();
            for (filename, unsafe_file_message) in [
                (
                    STATE_FILE,
                    "BXRC authority record must be private and single-link",
                ),
                (
                    TEMP_FILE,
                    "temporary BXRC authority record must be private and single-link",
                ),
                (
                    CLEANUP_FILE,
                    "BXRC authority cleanup candidate must be private and single-link",
                ),
            ] {
                let error =
                    open_checkpoint_file(&directory, filename, unsafe_file_message).unwrap_err();
                assert_eq!(error.kind(), ErrorKind::PermissionDenied);
            }
            channel.write_all(&token).unwrap();
            return;
        }

        let path_identity = NEXT_PATH_IDENTITY_TEMP.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "bloch-bxrc-authority-fifo-{}-{}",
            std::process::id(),
            path_identity
        ));
        fs::create_dir(&root).unwrap();
        let _remove_root = RemoveTestDirectory(root.clone());
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let helper_token = random_fifo_helper_token();
        for filename in [STATE_FILE, TEMP_FILE, CLEANUP_FILE] {
            let path = root.join(filename);
            let path_name = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
            // SAFETY: path_name is a valid NUL-terminated pathname.
            assert_eq!(unsafe { libc::mkfifo(path_name.as_ptr(), 0o600) }, 0);
        }

        // Run the potentially blocking opens in a separate test process. If
        // O_NONBLOCK is ever removed, this watchdog kills the helper instead
        // of allowing the complete test suite to hang indefinitely.
        let (mut parent_channel, child_channel) = UnixStream::pair().unwrap();
        assert_ne!(descriptor_flags(&child_channel) & libc::FD_CLOEXEC, 0);
        parent_channel.write_all(&helper_token).unwrap();
        let child_descriptor = child_channel.as_raw_fd();
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .arg("--exact")
            .arg(FIFO_HELPER_TEST)
            .arg("--test-threads=1")
            .env(FIFO_HELPER_ROOT_ENV, &root)
            .env(
                FIFO_HELPER_TOKEN_ENV,
                std::str::from_utf8(&helper_token).unwrap(),
            )
            .env(FIFO_HELPER_FD_ENV, child_descriptor.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        inherit_only_in_child(&mut command, child_descriptor);
        let child = command.spawn().unwrap();
        assert_ne!(descriptor_flags(&child_channel) & libc::FD_CLOEXEC, 0);
        drop(child_channel);
        let mut child = ChildGuard(Some(child));
        let deadline = Instant::now() + Duration::from_secs(10);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= deadline {
                let (kill_error, reap_result) = child.kill_and_reap();
                panic!(
                    "checkpoint FIFO opens exceeded the ten-second watchdog; kill error: \
                     {kill_error:?}; reap result: {reap_result:?}"
                );
            }
            thread::sleep(Duration::from_millis(10));
        };

        let mut helper_completed = vec![0_u8; helper_token.len()];
        let helper_completion = parent_channel.read_exact(&mut helper_completed);
        let artifacts_preserved =
            [STATE_FILE, TEMP_FILE, CLEANUP_FILE].map(|filename| root.join(filename).exists());
        assert!(status.success(), "checkpoint FIFO helper failed: {status}");
        helper_completion.unwrap();
        assert_eq!(helper_completed, helper_token);
        assert_eq!(artifacts_preserved, [true; 3]);
    }

    #[test]
    fn fifo_helper_refuses_fabricated_environment_and_symlink_markers() {
        let path_identity = NEXT_PATH_IDENTITY_TEMP.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "bloch-bxrc-authority-fabricated-helper-{}-{}",
            std::process::id(),
            path_identity
        ));
        fs::create_dir(&root).unwrap();
        let _remove_root = RemoveTestDirectory(root.clone());
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        for filename in [STATE_FILE, TEMP_FILE, CLEANUP_FILE] {
            let path = root.join(filename);
            let path_name = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
            // SAFETY: path_name is a valid NUL-terminated pathname.
            assert_eq!(unsafe { libc::mkfifo(path_name.as_ptr(), 0o600) }, 0);
        }

        let token = "00".repeat(32);
        let invocation_target = root.join("fabricated-invocation-target");
        let completion_target = root.join("fabricated-completion-target");
        fs::write(&invocation_target, &token).unwrap();
        fs::write(&completion_target, b"must remain unchanged").unwrap();
        std::os::unix::fs::symlink(
            &invocation_target,
            root.join(".bxrc-test-fifo-helper-invocation"),
        )
        .unwrap();
        std::os::unix::fs::symlink(
            &completion_target,
            root.join(".bxrc-test-fifo-helper-complete"),
        )
        .unwrap();

        let status = Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg(FIFO_HELPER_TEST)
            .arg("--test-threads=1")
            .env(FIFO_HELPER_ROOT_ENV, &root)
            .env(FIFO_HELPER_TOKEN_ENV, &token)
            .env(FIFO_HELPER_FD_ENV, "0")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(
            status.success(),
            "watchdog parent subprocess failed: {status}"
        );
        assert_eq!(
            fs::read(completion_target).unwrap(),
            b"must remain unchanged"
        );
        assert_eq!(
            [STATE_FILE, TEMP_FILE, CLEANUP_FILE].map(|filename| root.join(filename).exists()),
            [true; 3]
        );
    }

    #[test]
    fn temporary_cleanup_detects_substitution_after_final_validation() {
        let root = std::env::temp_dir().join(format!(
            "bloch-bxrc-authority-cleanup-race-{}-{}",
            std::process::id(),
            NEXT_PATH_IDENTITY_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let temporary = root.join(TEMP_FILE);
        let cleanup = root.join(CLEANUP_FILE);
        write_test_checkpoint(&temporary, 0x41);

        let directory = open_directory(&root).unwrap();
        let opened = open_at(directory.as_raw_fd(), TEMP_FILE, libc::O_RDONLY, 0).unwrap();
        let evidence = test_evidence(&opened);
        let error = remove_temporary_checkpoint_inner(&root, &directory, &opened, evidence, || {
            // This runs after pathname validation and before the atomic move.
            // Model the exact unlink-and-replace race that used to delete the
            // replacement through a pathname-based unlinkat.
            fs::remove_file(&temporary).unwrap();
            write_test_checkpoint(&temporary, 0x42);
        })
        .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::PermissionDenied);

        // The raced third-party inode is atomically displaced to the reserved
        // tombstone and preserved when it does not match the pinned descriptor.
        assert!(!temporary.exists());
        assert_eq!(
            fs::read(&cleanup).unwrap(),
            [0x42; EXTERNAL_FLOOR_CUSTODIAN_AUTHORITY_RECORD_LEN]
        );
        assert_eq!(opened.metadata().unwrap().nlink(), 0);

        drop(opened);
        drop(directory);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn cleanup_tombstone_rejects_same_inode_rewrite_before_unlink() {
        let root = std::env::temp_dir().join(format!(
            "bloch-bxrc-authority-cleanup-rewrite-{}-{}",
            std::process::id(),
            NEXT_PATH_IDENTITY_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let cleanup = root.join(CLEANUP_FILE);
        write_test_checkpoint(&cleanup, 0x51);

        let directory = open_directory(&root).unwrap();
        let opened = open_at(directory.as_raw_fd(), CLEANUP_FILE, libc::O_RDONLY, 0).unwrap();
        let evidence = test_evidence(&opened);
        let original_inode = opened.metadata().unwrap().ino();
        let error = remove_cleanup_checkpoint_inner(
            &root,
            &directory,
            &opened,
            evidence,
            || {
                // Preserve the pathname and inode while changing authenticated
                // content in the last deterministic pre-unlink window.
                write_test_checkpoint(&cleanup, 0x52);
            },
            || {},
        )
        .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::PermissionDenied);
        assert_eq!(fs::metadata(&cleanup).unwrap().ino(), original_inode);
        assert_eq!(fs::read(&cleanup).unwrap()[0], 0x52);

        drop(opened);
        drop(directory);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn temporary_commit_rejects_pathname_substitution() {
        let root = std::env::temp_dir().join(format!(
            "bloch-bxrc-authority-commit-identity-{}-{}",
            std::process::id(),
            NEXT_PATH_IDENTITY_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let state = root.join(STATE_FILE);
        let temporary = root.join(TEMP_FILE);
        write_test_checkpoint(&state, 0x11);
        write_test_checkpoint(&temporary, 0x12);

        let directory = open_directory(&root).unwrap();
        let opened = open_at(directory.as_raw_fd(), TEMP_FILE, libc::O_RDONLY, 0).unwrap();
        let opened_evidence = test_evidence(&opened);
        fs::rename(&temporary, root.join("displaced-candidate")).unwrap();
        write_test_checkpoint(&temporary, 0x13);

        let error = commit_temporary_checkpoint(&root, &directory, &opened, opened_evidence, None)
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::PermissionDenied);
        assert_eq!(fs::read(&state).unwrap()[0], 0x11);
        assert_eq!(fs::read(&temporary).unwrap()[0], 0x13);

        drop(opened);
        drop(directory);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn temporary_commit_rejects_predecessor_substitution() {
        let root = std::env::temp_dir().join(format!(
            "bloch-bxrc-authority-predecessor-identity-{}-{}",
            std::process::id(),
            NEXT_PATH_IDENTITY_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let state = root.join(STATE_FILE);
        let temporary = root.join(TEMP_FILE);
        write_test_checkpoint(&state, 0x21);
        write_test_checkpoint(&temporary, 0x22);

        let directory = open_directory(&root).unwrap();
        let previous = open_at(directory.as_raw_fd(), STATE_FILE, libc::O_RDONLY, 0).unwrap();
        let candidate = open_at(directory.as_raw_fd(), TEMP_FILE, libc::O_RDONLY, 0).unwrap();
        let previous_evidence = test_evidence(&previous);
        let candidate_evidence = test_evidence(&candidate);
        fs::rename(&state, root.join("displaced-prior")).unwrap();
        write_test_checkpoint(&state, 0x23);

        let error = commit_temporary_checkpoint(
            &root,
            &directory,
            &candidate,
            candidate_evidence,
            Some((&previous, previous_evidence)),
        )
        .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::PermissionDenied);
        assert_eq!(fs::read(&state).unwrap()[0], 0x23);
        assert_eq!(fs::read(&temporary).unwrap()[0], 0x22);

        drop(candidate);
        drop(previous);
        drop(directory);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn atomic_exchange_detects_substitution_after_final_validation() {
        let root = std::env::temp_dir().join(format!(
            "bloch-bxrc-authority-exchange-race-{}-{}",
            std::process::id(),
            NEXT_PATH_IDENTITY_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let state = root.join(STATE_FILE);
        let temporary = root.join(TEMP_FILE);
        let displaced = root.join("displaced-prior");
        write_test_checkpoint(&state, 0x31);
        write_test_checkpoint(&temporary, 0x32);

        let directory = open_directory(&root).unwrap();
        let previous = open_at(directory.as_raw_fd(), STATE_FILE, libc::O_RDONLY, 0).unwrap();
        let candidate = open_at(directory.as_raw_fd(), TEMP_FILE, libc::O_RDONLY, 0).unwrap();
        let previous_evidence = test_evidence(&previous);
        let candidate_evidence = test_evidence(&candidate);
        let error = commit_temporary_checkpoint_inner(
            &root,
            &directory,
            &candidate,
            candidate_evidence,
            Some((&previous, previous_evidence)),
            || {
                // This runs after the last pre-exchange identity checks and
                // deterministically models a same-user writer in that window.
                fs::rename(&state, &displaced).unwrap();
                write_test_checkpoint(&state, 0x33);
            },
        )
        .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::PermissionDenied);

        // The approved candidate may now be visible, but the displaced object
        // at TEMP was not the pinned predecessor, so the outcome is ambiguous
        // and all evidence is retained for explicit reconciliation.
        assert_eq!(fs::read(&state).unwrap()[0], 0x32);
        assert_eq!(fs::read(&temporary).unwrap()[0], 0x33);
        assert_eq!(fs::read(&displaced).unwrap()[0], 0x31);

        drop(candidate);
        drop(previous);
        drop(directory);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn create_only_install_refuses_state_raced_after_final_validation() {
        let root = std::env::temp_dir().join(format!(
            "bloch-bxrc-authority-create-race-{}-{}",
            std::process::id(),
            NEXT_PATH_IDENTITY_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let state = root.join(STATE_FILE);
        let temporary = root.join(TEMP_FILE);
        write_test_checkpoint(&temporary, 0x41);

        let directory = open_directory(&root).unwrap();
        let candidate = open_at(directory.as_raw_fd(), TEMP_FILE, libc::O_RDONLY, 0).unwrap();
        let candidate_evidence = test_evidence(&candidate);
        let error = commit_temporary_checkpoint_inner(
            &root,
            &directory,
            &candidate,
            candidate_evidence,
            None,
            || {
                // This runs after TEMP's last identity check and models a STATE
                // raced into the fresh directory immediately before install.
                write_test_checkpoint(&state, 0x42);
            },
        )
        .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&state).unwrap()[0], 0x42);
        assert_eq!(fs::read(&temporary).unwrap()[0], 0x41);

        drop(candidate);
        drop(directory);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn atomic_exchange_refuses_displaced_directory_before_commit() {
        let root = std::env::temp_dir().join(format!(
            "bloch-bxrc-authority-directory-commit-race-{}-{}",
            std::process::id(),
            NEXT_PATH_IDENTITY_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let state = root.join(STATE_FILE);
        let temporary = root.join(TEMP_FILE);
        write_test_checkpoint(&state, 0x61);
        write_test_checkpoint(&temporary, 0x62);

        let directory = open_directory(&root).unwrap();
        let previous = open_at(directory.as_raw_fd(), STATE_FILE, libc::O_RDONLY, 0).unwrap();
        let candidate = open_at(directory.as_raw_fd(), TEMP_FILE, libc::O_RDONLY, 0).unwrap();
        let previous_evidence = test_evidence(&previous);
        let candidate_evidence = test_evidence(&candidate);
        let displaced = root.with_extension("displaced");
        let error = commit_temporary_checkpoint_inner(
            &root,
            &directory,
            &candidate,
            candidate_evidence,
            Some((&previous, previous_evidence)),
            || {
                fs::rename(&root, &displaced).unwrap();
                fs::create_dir(&root).unwrap();
                fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
            },
        )
        .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::PermissionDenied);
        assert_eq!(fs::read(displaced.join(STATE_FILE)).unwrap()[0], 0x61);
        assert_eq!(fs::read(displaced.join(TEMP_FILE)).unwrap()[0], 0x62);

        drop(candidate);
        drop(previous);
        drop(directory);
        fs::remove_dir(&root).unwrap();
        fs::remove_dir_all(displaced).unwrap();
    }

    #[test]
    fn cleanup_refuses_displaced_directory_before_unlink() {
        let root = std::env::temp_dir().join(format!(
            "bloch-bxrc-authority-directory-cleanup-race-{}-{}",
            std::process::id(),
            NEXT_PATH_IDENTITY_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let cleanup = root.join(CLEANUP_FILE);
        write_test_checkpoint(&cleanup, 0x71);

        let directory = open_directory(&root).unwrap();
        let opened = open_at(directory.as_raw_fd(), CLEANUP_FILE, libc::O_RDONLY, 0).unwrap();
        let evidence = test_evidence(&opened);
        let displaced = root.with_extension("displaced");
        let error = remove_cleanup_checkpoint_inner(
            &root,
            &directory,
            &opened,
            evidence,
            || {},
            || {
                // This hook runs after pathname and evidence validation, at
                // the final directory-identity boundary before unlinkat.
                fs::rename(&root, &displaced).unwrap();
                fs::create_dir(&root).unwrap();
                fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
            },
        )
        .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::PermissionDenied);
        assert_eq!(fs::read(displaced.join(CLEANUP_FILE)).unwrap()[0], 0x71);

        drop(opened);
        drop(directory);
        fs::remove_dir(&root).unwrap();
        fs::remove_dir_all(displaced).unwrap();
    }

    #[test]
    fn temporary_cleanup_refuses_displaced_directory_before_staging() {
        let root = std::env::temp_dir().join(format!(
            "bloch-bxrc-authority-directory-staging-race-{}-{}",
            std::process::id(),
            NEXT_PATH_IDENTITY_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let temporary = root.join(TEMP_FILE);
        write_test_checkpoint(&temporary, 0x81);

        let directory = open_directory(&root).unwrap();
        let opened = open_at(directory.as_raw_fd(), TEMP_FILE, libc::O_RDONLY, 0).unwrap();
        let evidence = test_evidence(&opened);
        let displaced = root.with_extension("displaced");
        let error = remove_temporary_checkpoint_inner(&root, &directory, &opened, evidence, || {
            fs::rename(&root, &displaced).unwrap();
            fs::create_dir(&root).unwrap();
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        })
        .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::PermissionDenied);
        assert_eq!(fs::read(displaced.join(TEMP_FILE)).unwrap()[0], 0x81);
        assert!(!displaced.join(CLEANUP_FILE).exists());

        drop(opened);
        drop(directory);
        fs::remove_dir(&root).unwrap();
        fs::remove_dir_all(displaced).unwrap();
    }
}
