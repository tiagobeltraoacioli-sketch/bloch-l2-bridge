// SPDX-License-Identifier: MIT OR Apache-2.0
//! Durable local receipt for an accepted BXRC anchor-authority tuple.
//!
//! This store never discovers authority from disk. Every open requires the
//! exact checkpoint retained by the caller in another trust domain. The hash
//! chain and checksum detect damage and mismatched history, but ordinary disk
//! remains rollbackable unless the expected checkpoint is retained elsewhere.

use std::fs::{DirBuilder, File, OpenOptions};
use std::io::{self, Error, ErrorKind, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
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
const LOCK_FILE: &str = ".bxrc-accepted-authority.lock";
const MAGIC: [u8; 4] = *b"BXAT";
const VERSION: u8 = 1;
const PREFIX_LEN: usize = 152;
const RECORD_DOMAIN: &[u8] = b"BLOCH-L2-BXRC-ACCEPTED-AUTHORITY-v1\0";

/// Exact canonical length of an accepted-authority checkpoint record.
pub const EXTERNAL_FLOOR_CUSTODIAN_AUTHORITY_RECORD_LEN: usize = PREFIX_LEN + 32;

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
    // SAFETY: the directory descriptor and fixed NUL-terminated name are valid.
    let descriptor = unsafe {
        libc::openat(
            directory,
            c_name(filename).as_ptr(),
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
) -> io::Result<(ExternalFloorCustodianAuthorityCheckpoint, File)> {
    let mut file = open_at(directory.as_raw_fd(), filename, libc::O_RDONLY, 0)?;
    validate_file(&file, unsafe_file_message)?;
    let mut encoded = [0_u8; EXTERNAL_FLOOR_CUSTODIAN_AUTHORITY_RECORD_LEN];
    file.read_exact(&mut encoded)?;
    let mut trailing = [0_u8; 1];
    if file.read(&mut trailing)? != 0 {
        return Err(invalid("BXRC authority record has trailing data"));
    }
    // Revalidate after reading so a concurrent permission/link or pathname
    // change cannot turn bytes read from an obsolete descriptor into accepted
    // state.
    validate_file_name(directory, filename, &file, unsafe_file_message)?;
    Ok((decode(&encoded)?, file))
}

fn read_checkpoint_file(
    directory: &File,
    filename: &'static str,
    unsafe_file_message: &'static str,
) -> io::Result<ExternalFloorCustodianAuthorityCheckpoint> {
    open_checkpoint_file(directory, filename, unsafe_file_message)
        .map(|(checkpoint, _file)| checkpoint)
}

fn read_checkpoint(directory: &File) -> io::Result<ExternalFloorCustodianAuthorityCheckpoint> {
    open_checkpoint(directory).map(|(checkpoint, _file)| checkpoint)
}

fn open_checkpoint(
    directory: &File,
) -> io::Result<(ExternalFloorCustodianAuthorityCheckpoint, File)> {
    if exists_at(directory, TEMP_FILE)? {
        return Err(invalid(
            "temporary BXRC authority record exists; operator inspection required",
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

fn remove_temporary_checkpoint(directory: &File, temporary: &File) -> io::Result<()> {
    validate_file_name(
        directory,
        TEMP_FILE,
        temporary,
        "temporary BXRC authority record changed before cleanup",
    )?;
    // SAFETY: the fixed name is valid and relative to the live directory fd.
    if unsafe { libc::unlinkat(directory.as_raw_fd(), c_name(TEMP_FILE).as_ptr(), 0) } != 0 {
        return Err(Error::last_os_error());
    }
    directory.sync_all()
}

fn validate_replaced_checkpoint(previous: &File) -> io::Result<()> {
    let metadata = previous.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.nlink() != 0
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(denied(
            "previous BXRC authority record was not atomically displaced during commit",
        ));
    }
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

fn commit_temporary_checkpoint_inner<F>(
    directory: &File,
    temporary: &File,
    previous: Option<&File>,
    before_replace: F,
) -> io::Result<()>
where
    F: FnOnce(),
{
    if let Some(previous) = previous {
        validate_file_name(
            directory,
            STATE_FILE,
            previous,
            "previous BXRC authority record changed before commit",
        )?;
    }
    validate_file_name(
        directory,
        TEMP_FILE,
        temporary,
        "temporary BXRC authority record changed before commit",
    )?;
    before_replace();
    if let Some(previous) = previous {
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
        remove_temporary_checkpoint(directory, previous)?;
    } else {
        // Fresh provisioning has no predecessor to exchange. The containing
        // directory is new and held under its exclusive process lock.
        // SAFETY: both fixed names are relative to the same live descriptor.
        if unsafe {
            libc::renameat(
                directory.as_raw_fd(),
                c_name(TEMP_FILE).as_ptr(),
                directory.as_raw_fd(),
                c_name(STATE_FILE).as_ptr(),
            )
        } != 0
        {
            return Err(Error::last_os_error());
        }
        directory.sync_all()?;
    }
    // Keep the written descriptor live across rename and directory sync. A
    // pathname substitution is ambiguous, never a successful commit.
    validate_file_name(
        directory,
        STATE_FILE,
        temporary,
        "BXRC authority record changed during commit",
    )?;
    if let Some(previous) = previous {
        validate_replaced_checkpoint(previous)?;
    }
    Ok(())
}

fn commit_temporary_checkpoint(
    directory: &File,
    temporary: &File,
    previous: Option<&File>,
) -> io::Result<()> {
    commit_temporary_checkpoint_inner(directory, temporary, previous, || {})
}

fn write_checkpoint(
    directory: &File,
    transition_index: u64,
    authority: ExternalFloorCustodianAuthorityTuple,
    previous_record_hash: [u8; 32],
    create: bool,
    previous_file: Option<&File>,
) -> io::Result<ExternalFloorCustodianAuthorityCheckpoint> {
    if create == previous_file.is_some() {
        return Err(invalid("invalid BXRC authority commit predecessor"));
    }
    if exists_at(directory, TEMP_FILE)? || (create && exists_at(directory, STATE_FILE)?) {
        return Err(Error::new(
            ErrorKind::AlreadyExists,
            "BXRC authority state already or ambiguously exists",
        ));
    }
    let encoded = encode(transition_index, authority, previous_record_hash)?;
    let expected = decode(&encoded)?;
    let mut temporary = open_at(
        directory.as_raw_fd(),
        TEMP_FILE,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        0o600,
    )?;
    validate_file(&temporary, "temporary BXRC authority record is unsafe")?;
    temporary.write_all(&encoded)?;
    temporary.sync_all()?;
    commit_temporary_checkpoint(directory, &temporary, previous_file)?;
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
        let anchor = verify_external_floor_custodian_anchor_approval(
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
            &directory,
            0,
            ExternalFloorCustodianAuthorityTuple {
                deployment_id: expected_deployment_id,
                verifying_key,
                anchor,
            },
            [0; 32],
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
    /// `Committed`. Any other record/temporary combination or unreadable store
    /// fails closed without cleanup. The returned store is pinned to the
    /// selected caller-derived checkpoint for restart checks.
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
        let current = if exists_at(&directory, TEMP_FILE)? {
            let durable = read_checkpoint_file(
                &directory,
                STATE_FILE,
                "BXRC authority record must be private and single-link",
            )?;
            let (temporary, temporary_file) = open_checkpoint_file(
                &directory,
                TEMP_FILE,
                "temporary BXRC authority record must be private and single-link",
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
            remove_temporary_checkpoint(&directory, &temporary_file)?;
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
        let (previous, previous_file) = open_checkpoint(&self.directory)?;
        if previous != *expected {
            return Err(denied("BXRC authority state changed behind live instance"));
        }
        let derived = external_floor_custodian_expected_authority_checkpoint(previous, approval)?;
        let next = write_checkpoint(
            &self.directory,
            derived.transition_index,
            derived.authority,
            derived.previous_record_hash,
            false,
            Some(&previous_file),
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
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_PATH_IDENTITY_TEMP: AtomicU64 = AtomicU64::new(0);

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
        fs::write(&state, b"prior").unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&temporary, b"candidate").unwrap();
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600)).unwrap();

        let directory = open_directory(&root).unwrap();
        let opened = open_at(directory.as_raw_fd(), TEMP_FILE, libc::O_RDONLY, 0).unwrap();
        fs::rename(&temporary, root.join("displaced-candidate")).unwrap();
        fs::write(&temporary, b"replacement").unwrap();
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600)).unwrap();

        let error = commit_temporary_checkpoint(&directory, &opened, None).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::PermissionDenied);
        assert_eq!(fs::read(&state).unwrap(), b"prior");
        assert_eq!(fs::read(&temporary).unwrap(), b"replacement");

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
        fs::write(&state, b"prior").unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&temporary, b"candidate").unwrap();
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600)).unwrap();

        let directory = open_directory(&root).unwrap();
        let previous = open_at(directory.as_raw_fd(), STATE_FILE, libc::O_RDONLY, 0).unwrap();
        let candidate = open_at(directory.as_raw_fd(), TEMP_FILE, libc::O_RDONLY, 0).unwrap();
        fs::rename(&state, root.join("displaced-prior")).unwrap();
        fs::write(&state, b"replacement").unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o600)).unwrap();

        let error =
            commit_temporary_checkpoint(&directory, &candidate, Some(&previous)).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::PermissionDenied);
        assert_eq!(fs::read(&state).unwrap(), b"replacement");
        assert_eq!(fs::read(&temporary).unwrap(), b"candidate");

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
        fs::write(&state, b"prior").unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&temporary, b"candidate").unwrap();
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600)).unwrap();

        let directory = open_directory(&root).unwrap();
        let previous = open_at(directory.as_raw_fd(), STATE_FILE, libc::O_RDONLY, 0).unwrap();
        let candidate = open_at(directory.as_raw_fd(), TEMP_FILE, libc::O_RDONLY, 0).unwrap();
        let error =
            commit_temporary_checkpoint_inner(&directory, &candidate, Some(&previous), || {
                // This runs after the last pre-exchange identity checks and
                // deterministically models a same-user writer in that window.
                fs::rename(&state, &displaced).unwrap();
                fs::write(&state, b"replacement").unwrap();
                fs::set_permissions(&state, fs::Permissions::from_mode(0o600)).unwrap();
            })
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::PermissionDenied);

        // The approved candidate may now be visible, but the displaced object
        // at TEMP was not the pinned predecessor, so the outcome is ambiguous
        // and all evidence is retained for explicit reconciliation.
        assert_eq!(fs::read(&state).unwrap(), b"candidate");
        assert_eq!(fs::read(&temporary).unwrap(), b"replacement");
        assert_eq!(fs::read(&displaced).unwrap(), b"prior");

        drop(candidate);
        drop(previous);
        drop(directory);
        fs::remove_dir_all(root).unwrap();
    }
}
