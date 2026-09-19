// SPDX-License-Identifier: MIT OR Apache-2.0
//! Crash-safe Unix checkpoint custody for the authenticated BXRC client.
//!
//! A reservation is durably committed before transport I/O. Transport or
//! process failure leaves a `Pending` record which cannot be opened for normal
//! traffic. Recovery is an explicit operator action and never retransmits the
//! consumed request.

use std::cell::Cell;
use std::fs::{DirBuilder, File, OpenOptions};
use std::io::{self, Error, ErrorKind, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use tiny_keccak::{Hasher, Kmac};
use zeroize::Zeroizing;

use crate::{
    AuthenticatedExternalFloorCustodian, ExternalFloorCustodianAuthentication,
    ExternalFloorCustodianTransport, ExternalFloorCustodianTransportCheckpoint,
    ExternalFloorReplayCasOutcome, ExternalFloorReplayCheckpoint, ExternalFloorReplayStore,
};

const STATE_FILE: &str = ".bxrc-client-checkpoint";
const TEMP_FILE: &str = ".bxrc-client-checkpoint.tmp";
const LOCK_FILE: &str = ".bxrc-client-checkpoint.lock";
const MAGIC: [u8; 4] = *b"BXCC";
const VERSION: u8 = 1;
const READY: u8 = 0;
const PENDING: u8 = 1;
const LOAD: u8 = 0;
const CAS: u8 = 1;
const PREFIX_LEN: usize = 176;
/// Exact length of a canonical BXRC client checkpoint record.
pub const EXTERNAL_FLOOR_CUSTODIAN_CLIENT_RECORD_LEN: usize = PREFIX_LEN + 32;
const AUTH_DOMAIN: &[u8] = b"BLOCH-L2-BXRC-CLIENT-CHECKPOINT-v1\0";
const OPERATION_DOMAIN: &[u8] = b"BLOCH-L2-BXRC-CLIENT-OPERATION-v1\0";

fn invalid(message: &'static str) -> Error {
    Error::new(ErrorKind::InvalidData, message)
}

fn denied(message: &'static str) -> Error {
    Error::new(ErrorKind::PermissionDenied, message)
}

fn c_name(value: &'static str) -> std::ffi::CString {
    std::ffi::CString::new(value).expect("fixed checkpoint filename contains no NUL")
}

fn open_at(directory: RawFd, filename: &'static str, flags: i32, mode: u32) -> io::Result<File> {
    // SAFETY: the directory descriptor is live, the name is NUL terminated,
    // and ownership of a successful descriptor is transferred exactly once.
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
            "BXRC checkpoint directory must be private and owned by this user",
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

fn reject_temp(directory: &File) -> io::Result<()> {
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: all pointers are valid for this call; the output is not read on
    // failure.
    let result = unsafe {
        libc::fstatat(
            directory.as_raw_fd(),
            c_name(TEMP_FILE).as_ptr(),
            metadata.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result == 0 {
        return Err(invalid(
            "temporary BXRC checkpoint exists; operator inspection is required",
        ));
    }
    let error = Error::last_os_error();
    if error.kind() == ErrorKind::NotFound {
        Ok(())
    } else {
        Err(error)
    }
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
            "BXRC checkpoint lock is not a private single-link file",
        )?;
        // SAFETY: the descriptor is live and the flock constants are supplied
        // by libc.
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(Error::last_os_error());
        }
        validate_file(&lock, "BXRC checkpoint lock changed while it was acquired")?;
        Ok(Self(lock))
    }
}

impl Drop for Lock {
    fn drop(&mut self) {
        // The inode is persistent: unlinking a lock permits split locking.
        let _ = unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
    }
}

/// Independently retained exact anchor for a client checkpoint revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExternalFloorCustodianClientAnchor {
    pub revision: u64,
    pub commitment: [u8; 32],
}

/// Outcome of an exact compare-and-swap in the independently retained anchor
/// store. An I/O error is always treated as ambiguous by the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalFloorCustodianAnchorCasOutcome {
    Committed,
    Conflict(ExternalFloorCustodianClientAnchor),
}

/// Independently administered, rollback-resistant custody for the current
/// client anchor. Implementations must provide a durable exact CAS and must
/// not derive their value from the checkpoint directory.
pub trait ExternalFloorCustodianAnchorStore {
    fn load(&self) -> io::Result<ExternalFloorCustodianClientAnchor>;

    fn compare_and_swap(
        &self,
        expected: ExternalFloorCustodianClientAnchor,
        replacement: ExternalFloorCustodianClientAnchor,
    ) -> io::Result<ExternalFloorCustodianAnchorCasOutcome>;
}

impl<S: ExternalFloorCustodianAnchorStore> ExternalFloorCustodianAnchorStore for &S {
    fn load(&self) -> io::Result<ExternalFloorCustodianClientAnchor> {
        <S as ExternalFloorCustodianAnchorStore>::load(*self)
    }

    fn compare_and_swap(
        &self,
        expected: ExternalFloorCustodianClientAnchor,
        replacement: ExternalFloorCustodianClientAnchor,
    ) -> io::Result<ExternalFloorCustodianAnchorCasOutcome> {
        <S as ExternalFloorCustodianAnchorStore>::compare_and_swap(*self, expected, replacement)
    }
}

/// A pending operation retained for operator inspection after ambiguity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExternalFloorCustodianPendingInspection {
    pub anchor: ExternalFloorCustodianClientAnchor,
    pub checkpoint: ExternalFloorCustodianTransportCheckpoint,
    pub operation_sequence: u64,
    pub operation_commitment: [u8; 32],
    pub compare_and_swap: bool,
}

/// Validated state returned by offline inspection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalFloorCustodianClientInspection {
    Ready {
        anchor: ExternalFloorCustodianClientAnchor,
        checkpoint: ExternalFloorCustodianTransportCheckpoint,
    },
    Pending(ExternalFloorCustodianPendingInspection),
}

#[derive(Clone, Copy)]
struct Record {
    revision: u64,
    phase: u8,
    operation: u8,
    checkpoint: ExternalFloorCustodianTransportCheckpoint,
    parent: ExternalFloorCustodianClientAnchor,
    operation_sequence: u64,
    operation_commitment: [u8; 32],
    recovery: ExternalFloorCustodianClientAnchor,
}

fn authenticate(key: &[u8; 32], prefix: &[u8]) -> [u8; 32] {
    let mut mac = Kmac::v256(key, AUTH_DOMAIN);
    mac.update(prefix);
    let mut output = [0_u8; 32];
    mac.finalize(&mut output);
    output
}

fn encode(record: Record, key: &[u8; 32]) -> [u8; EXTERNAL_FLOOR_CUSTODIAN_CLIENT_RECORD_LEN] {
    let mut encoded = [0_u8; EXTERNAL_FLOOR_CUSTODIAN_CLIENT_RECORD_LEN];
    encoded[..4].copy_from_slice(&MAGIC);
    encoded[4] = VERSION;
    encoded[5] = record.phase;
    encoded[6] = record.operation;
    // byte 7 is reserved and canonically zero.
    encoded[8..16].copy_from_slice(&record.revision.to_be_bytes());
    encoded[16..48].copy_from_slice(&record.checkpoint.session_nonce);
    encoded[48..56].copy_from_slice(&record.checkpoint.next_sequence.to_be_bytes());
    encoded[56..64].copy_from_slice(&record.parent.revision.to_be_bytes());
    encoded[64..96].copy_from_slice(&record.parent.commitment);
    encoded[96..104].copy_from_slice(&record.operation_sequence.to_be_bytes());
    encoded[104..136].copy_from_slice(&record.operation_commitment);
    encoded[136..144].copy_from_slice(&record.recovery.revision.to_be_bytes());
    encoded[144..176].copy_from_slice(&record.recovery.commitment);
    let commitment = authenticate(key, &encoded[..PREFIX_LEN]);
    encoded[PREFIX_LEN..].copy_from_slice(&commitment);
    encoded
}

fn decode(
    encoded: &[u8],
    key: &[u8; 32],
) -> io::Result<(Record, ExternalFloorCustodianClientAnchor)> {
    if encoded.len() != EXTERNAL_FLOOR_CUSTODIAN_CLIENT_RECORD_LEN {
        return Err(invalid("BXRC checkpoint record has invalid length"));
    }
    if encoded[..4] != MAGIC || encoded[4] != VERSION || encoded[7] != 0 {
        return Err(invalid("BXRC checkpoint record has a noncanonical header"));
    }
    let commitment = authenticate(key, &encoded[..PREFIX_LEN]);
    if encoded[PREFIX_LEN..] != commitment {
        return Err(invalid("BXRC checkpoint authentication failed"));
    }
    let phase = encoded[5];
    let operation = encoded[6];
    if !matches!(phase, READY | PENDING) || !matches!(operation, LOAD | CAS) {
        return Err(invalid("BXRC checkpoint state is invalid"));
    }
    let checkpoint = ExternalFloorCustodianTransportCheckpoint::new(
        encoded[16..48].try_into().expect("fixed session slice"),
        u64::from_be_bytes(encoded[48..56].try_into().expect("fixed sequence slice")),
    )
    .map_err(|_| invalid("BXRC checkpoint contains an invalid transport checkpoint"))?;
    let record = Record {
        revision: u64::from_be_bytes(encoded[8..16].try_into().expect("fixed revision slice")),
        phase,
        operation,
        checkpoint,
        parent: ExternalFloorCustodianClientAnchor {
            revision: u64::from_be_bytes(encoded[56..64].try_into().expect("fixed parent slice")),
            commitment: encoded[64..96].try_into().expect("fixed parent slice"),
        },
        operation_sequence: u64::from_be_bytes(
            encoded[96..104].try_into().expect("fixed operation slice"),
        ),
        operation_commitment: encoded[104..136].try_into().expect("fixed operation slice"),
        recovery: ExternalFloorCustodianClientAnchor {
            revision: u64::from_be_bytes(
                encoded[136..144].try_into().expect("fixed recovery slice"),
            ),
            commitment: encoded[144..176].try_into().expect("fixed recovery slice"),
        },
    };
    if phase == READY
        && (record.operation != LOAD
            || record.operation_sequence != 0
            || record.operation_commitment != [0; 32])
    {
        return Err(invalid("ready BXRC checkpoint has pending operation data"));
    }
    if phase == PENDING
        && (record.operation_sequence.checked_add(1) != Some(checkpoint.next_sequence)
            || record.operation_commitment == [0; 32])
    {
        return Err(invalid("pending BXRC checkpoint is inconsistent"));
    }
    Ok((
        record,
        ExternalFloorCustodianClientAnchor {
            revision: record.revision,
            commitment,
        },
    ))
}

fn read_record(
    directory: &File,
    key: &[u8; 32],
) -> io::Result<(Record, ExternalFloorCustodianClientAnchor)> {
    let mut file = open_at(directory.as_raw_fd(), STATE_FILE, libc::O_RDONLY, 0)?;
    validate_file(
        &file,
        "BXRC checkpoint must be a private single-link regular file",
    )?;
    let mut encoded = [0_u8; EXTERNAL_FLOOR_CUSTODIAN_CLIENT_RECORD_LEN];
    file.read_exact(&mut encoded)?;
    let mut trailing = [0_u8; 1];
    if file.read(&mut trailing)? != 0 {
        return Err(invalid("BXRC checkpoint has trailing data"));
    }
    decode(&encoded, key)
}

fn write_record(
    directory: &File,
    record: Record,
    key: &[u8; 32],
    expected: Option<ExternalFloorCustodianClientAnchor>,
) -> io::Result<ExternalFloorCustodianClientAnchor> {
    reject_temp(directory)?;
    match expected {
        Some(expected) => {
            let (_, actual) = read_record(directory, key)?;
            if actual != expected {
                return Err(denied("BXRC checkpoint CAS anchor mismatch"));
            }
        }
        None => {
            let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
            // SAFETY: the descriptor and fixed name are valid; output is not
            // read when `fstatat` fails.
            let result = unsafe {
                libc::fstatat(
                    directory.as_raw_fd(),
                    c_name(STATE_FILE).as_ptr(),
                    metadata.as_mut_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            };
            if result == 0 {
                return Err(Error::new(
                    ErrorKind::AlreadyExists,
                    "BXRC checkpoint already exists",
                ));
            }
            let error = Error::last_os_error();
            if error.kind() != ErrorKind::NotFound {
                return Err(error);
            }
        }
    }
    let encoded = encode(record, key);
    let anchor = ExternalFloorCustodianClientAnchor {
        revision: record.revision,
        commitment: encoded[PREFIX_LEN..]
            .try_into()
            .expect("fixed commitment slice"),
    };
    let mut temporary = open_at(
        directory.as_raw_fd(),
        TEMP_FILE,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        0o600,
    )?;
    validate_file(
        &temporary,
        "temporary BXRC checkpoint is not a private single-link file",
    )?;
    temporary.write_all(&encoded)?;
    temporary.sync_all()?;
    // SAFETY: both fixed names are valid and relative to the same live fd.
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
    let (_, observed) = read_record(directory, key)?;
    if observed != anchor {
        return Err(invalid("BXRC checkpoint read-back mismatch"));
    }
    Ok(anchor)
}

fn open_directory(path: &Path) -> io::Result<File> {
    if !path.is_absolute() {
        return Err(invalid("BXRC checkpoint directory must be absolute"));
    }
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open(path)?;
    validate_directory(&directory)?;
    Ok(directory)
}

fn operation_commitment(
    operation: u8,
    sequence: u64,
    expected: Option<ExternalFloorReplayCheckpoint>,
    replacement: Option<ExternalFloorReplayCheckpoint>,
) -> [u8; 32] {
    let mut hash = tiny_keccak::Keccak::v256();
    hash.update(OPERATION_DOMAIN);
    hash.update(&[operation]);
    hash.update(&sequence.to_be_bytes());
    for checkpoint in [expected, replacement].into_iter().flatten() {
        hash.update(&checkpoint.revision.to_be_bytes());
        hash.update(&checkpoint.session_nonce);
        hash.update(&checkpoint.next_sequence.to_be_bytes());
    }
    let mut output = [0_u8; 32];
    hash.finalize(&mut output);
    output
}

fn inspect_record(
    record: Record,
    anchor: ExternalFloorCustodianClientAnchor,
) -> ExternalFloorCustodianClientInspection {
    if record.phase == READY {
        ExternalFloorCustodianClientInspection::Ready {
            anchor,
            checkpoint: record.checkpoint,
        }
    } else {
        ExternalFloorCustodianClientInspection::Pending(ExternalFloorCustodianPendingInspection {
            anchor,
            checkpoint: record.checkpoint,
            operation_sequence: record.operation_sequence,
            operation_commitment: record.operation_commitment,
            compare_and_swap: record.operation == CAS,
        })
    }
}

fn trusted_or_recoverable(
    record: Record,
    actual: ExternalFloorCustodianClientAnchor,
    trusted: ExternalFloorCustodianClientAnchor,
) -> io::Result<()> {
    let direct_child =
        record.parent == trusted && trusted.revision.checked_add(1) == Some(record.revision);
    let completed_child =
        record.recovery == trusted && trusted.revision.checked_add(2) == Some(record.revision);
    if actual == trusted || direct_child || completed_child {
        Ok(())
    } else {
        Err(denied(
            "BXRC checkpoint does not descend from the trusted anchor",
        ))
    }
}

/// A filesystem-backed authenticated custodian client.
pub struct DurableAuthenticatedExternalFloorCustodian<T, A> {
    client: AuthenticatedExternalFloorCustodian<T>,
    anchor_store: A,
    directory: File,
    _lock: Lock,
    key: Zeroizing<[u8; 32]>,
    record: Cell<Record>,
    anchor: Cell<ExternalFloorCustodianClientAnchor>,
    poisoned: Cell<bool>,
}

impl<T, A> DurableAuthenticatedExternalFloorCustodian<T, A> {
    /// Explicitly creates a new store. Existing paths are never adopted.
    pub fn provision(
        path: &Path,
        checkpoint: ExternalFloorCustodianTransportCheckpoint,
        authentication_key: [u8; 32],
    ) -> io::Result<ExternalFloorCustodianClientAnchor> {
        let authentication_key = Zeroizing::new(authentication_key);
        if !path.is_absolute() || *authentication_key == [0; 32] {
            return Err(invalid(
                "invalid BXRC checkpoint provisioning configuration",
            ));
        }
        (|| {
            let mut builder = DirBuilder::new();
            builder.mode(0o700);
            builder.create(path)?;
            let directory = open_directory(path)?;
            let _lock = Lock::acquire(&directory)?;
            let record = Record {
                revision: 0,
                phase: READY,
                operation: LOAD,
                checkpoint,
                parent: ExternalFloorCustodianClientAnchor {
                    revision: 0,
                    commitment: [0; 32],
                },
                operation_sequence: 0,
                operation_commitment: [0; 32],
                recovery: ExternalFloorCustodianClientAnchor {
                    revision: 0,
                    commitment: [0; 32],
                },
            };
            write_record(&directory, record, &authentication_key, None)
        })()
    }

    /// Opens only an exact ready checkpoint anchored outside this directory.
    pub fn open(
        path: &Path,
        anchor_store: A,
        transport: T,
        authentication: ExternalFloorCustodianAuthentication,
        checkpoint_authentication_key: [u8; 32],
    ) -> io::Result<Self>
    where
        A: ExternalFloorCustodianAnchorStore,
    {
        let checkpoint_authentication_key = Zeroizing::new(checkpoint_authentication_key);
        if *checkpoint_authentication_key == [0; 32] {
            return Err(invalid("BXRC checkpoint authentication key is all zero"));
        }
        let directory = open_directory(path)?;
        let lock = Lock::acquire(&directory)?;
        reject_temp(&directory)?;
        let (record, anchor) = read_record(&directory, &checkpoint_authentication_key)?;
        let trusted_anchor = anchor_store.load()?;
        if anchor != trusted_anchor {
            return Err(denied("BXRC checkpoint does not match the trusted anchor"));
        }
        if record.phase != READY {
            return Err(Error::new(
                ErrorKind::WouldBlock,
                "BXRC checkpoint has a pending operation; inspect and reconcile explicitly",
            ));
        }
        Ok(Self {
            client: AuthenticatedExternalFloorCustodian::new(
                transport,
                authentication,
                record.checkpoint,
            ),
            anchor_store,
            directory,
            _lock: lock,
            key: checkpoint_authentication_key,
            record: Cell::new(record),
            anchor: Cell::new(anchor),
            poisoned: Cell::new(false),
        })
    }

    pub fn anchor(&self) -> ExternalFloorCustodianClientAnchor {
        self.anchor.get()
    }

    pub fn transport_checkpoint(&self) -> ExternalFloorCustodianTransportCheckpoint {
        self.record.get().checkpoint
    }

    fn reserve(
        &self,
        operation: u8,
        expected: Option<ExternalFloorReplayCheckpoint>,
        replacement: Option<ExternalFloorReplayCheckpoint>,
    ) -> io::Result<()>
    where
        A: ExternalFloorCustodianAnchorStore,
    {
        let current = self.record.get();
        if self.poisoned.get() || current.phase != READY {
            return Err(Error::new(
                ErrorKind::WouldBlock,
                "BXRC client has an unresolved pending operation",
            ));
        }
        let current_anchor = self.anchor.get();
        let sequence = current.checkpoint.next_sequence;
        let next_sequence = sequence
            .checked_add(1)
            .ok_or_else(|| invalid("BXRC client sequence is exhausted"))?;
        let revision = current
            .revision
            .checked_add(1)
            .ok_or_else(|| invalid("BXRC checkpoint revision is exhausted"))?;
        let pending = Record {
            revision,
            phase: PENDING,
            operation,
            checkpoint: ExternalFloorCustodianTransportCheckpoint {
                session_nonce: current.checkpoint.session_nonce,
                next_sequence,
            },
            parent: current_anchor,
            operation_sequence: sequence,
            operation_commitment: operation_commitment(operation, sequence, expected, replacement),
            recovery: current_anchor,
        };
        self.poisoned.set(true);
        let anchor = write_record(&self.directory, pending, &self.key, Some(current_anchor))?;
        self.record.set(pending);
        self.anchor.set(anchor);
        match self.anchor_store.compare_and_swap(current_anchor, anchor)? {
            ExternalFloorCustodianAnchorCasOutcome::Committed => {
                self.poisoned.set(false);
            }
            ExternalFloorCustodianAnchorCasOutcome::Conflict(_) => {
                return Err(denied("external BXRC anchor CAS conflict before transport"));
            }
        }
        Ok(())
    }

    fn finish(&self) -> io::Result<()>
    where
        A: ExternalFloorCustodianAnchorStore,
    {
        let pending = self.record.get();
        let pending_anchor = self.anchor.get();
        let revision = self
            .record
            .get()
            .revision
            .checked_add(1)
            .ok_or_else(|| invalid("BXRC checkpoint revision is exhausted"))?;
        let ready = Record {
            revision,
            phase: READY,
            operation: LOAD,
            checkpoint: pending.checkpoint,
            parent: pending_anchor,
            operation_sequence: 0,
            operation_commitment: [0; 32],
            recovery: pending.recovery,
        };
        let anchor = write_record(&self.directory, ready, &self.key, Some(pending_anchor))?;
        self.record.set(ready);
        self.anchor.set(anchor);
        self.poisoned.set(true);
        match self.anchor_store.compare_and_swap(pending_anchor, anchor) {
            Ok(ExternalFloorCustodianAnchorCasOutcome::Committed) => {
                self.poisoned.set(false);
                Ok(())
            }
            Ok(ExternalFloorCustodianAnchorCasOutcome::Conflict(_)) => {
                Err(denied("external BXRC anchor CAS conflict after transport"))
            }
            Err(error) => Err(error),
        }
    }

    /// Authenticated offline inspection. It accepts only the trusted record or
    /// a directly recoverable transition authenticated by the independent key.
    pub fn inspect<S: ExternalFloorCustodianAnchorStore>(
        path: &Path,
        anchor_store: &S,
        key: [u8; 32],
    ) -> io::Result<ExternalFloorCustodianClientInspection> {
        let key = Zeroizing::new(key);
        if *key == [0; 32] {
            return Err(invalid("BXRC checkpoint authentication key is all zero"));
        }
        (|| {
            let directory = open_directory(path)?;
            let _lock = Lock::acquire(&directory)?;
            reject_temp(&directory)?;
            let (record, actual) = read_record(&directory, &key)?;
            let trusted_anchor = anchor_store.load()?;
            trusted_or_recoverable(record, actual, trusted_anchor)?;
            Ok(inspect_record(record, actual))
        })()
    }

    /// Explicitly advances the independent anchor to an exact authenticated
    /// local descendant after inspection. This repairs a crash between the
    /// local durable write and the corresponding external CAS, performs no
    /// transport I/O, and never moves the anchor backwards.
    pub fn reconcile_external_anchor<S: ExternalFloorCustodianAnchorStore>(
        path: &Path,
        anchor_store: &S,
        expected_local_anchor: ExternalFloorCustodianClientAnchor,
        key: [u8; 32],
    ) -> io::Result<ExternalFloorCustodianClientAnchor> {
        let key = Zeroizing::new(key);
        if *key == [0; 32] {
            return Err(invalid("BXRC checkpoint authentication key is all zero"));
        }
        let directory = open_directory(path)?;
        let _lock = Lock::acquire(&directory)?;
        reject_temp(&directory)?;
        let (record, actual) = read_record(&directory, &key)?;
        if actual != expected_local_anchor {
            return Err(denied("local BXRC anchor reconciliation mismatch"));
        }
        let trusted = anchor_store.load()?;
        trusted_or_recoverable(record, actual, trusted)?;
        if trusted == actual {
            return Ok(actual);
        }
        match anchor_store.compare_and_swap(trusted, actual)? {
            ExternalFloorCustodianAnchorCasOutcome::Committed => Ok(actual),
            ExternalFloorCustodianAnchorCasOutcome::Conflict(_) => Err(denied(
                "external BXRC anchor CAS conflict during anchor reconciliation",
            )),
        }
    }

    /// Explicitly abandons one consumed pending request. It never performs I/O
    /// to the custodian; callers should next issue a fresh authenticated load.
    pub fn reconcile_pending<S: ExternalFloorCustodianAnchorStore>(
        path: &Path,
        anchor_store: &S,
        expected_operation_commitment: [u8; 32],
        key: [u8; 32],
    ) -> io::Result<ExternalFloorCustodianClientAnchor> {
        let key = Zeroizing::new(key);
        if *key == [0; 32] {
            return Err(invalid("BXRC checkpoint authentication key is all zero"));
        }
        (|| {
            let directory = open_directory(path)?;
            let _lock = Lock::acquire(&directory)?;
            reject_temp(&directory)?;
            let (record, actual) = read_record(&directory, &key)?;
            let pending_anchor = anchor_store.load()?;
            if actual != pending_anchor
                || record.phase != PENDING
                || record.operation_commitment != expected_operation_commitment
            {
                return Err(denied("pending BXRC reconciliation authorization mismatch"));
            }
            let ready = Record {
                revision: record
                    .revision
                    .checked_add(1)
                    .ok_or_else(|| invalid("BXRC checkpoint revision is exhausted"))?,
                phase: READY,
                operation: LOAD,
                checkpoint: record.checkpoint,
                parent: actual,
                operation_sequence: 0,
                operation_commitment: [0; 32],
                recovery: record.recovery,
            };
            let ready_anchor = write_record(&directory, ready, &key, Some(actual))?;
            match anchor_store.compare_and_swap(actual, ready_anchor)? {
                ExternalFloorCustodianAnchorCasOutcome::Committed => Ok(ready_anchor),
                ExternalFloorCustodianAnchorCasOutcome::Conflict(_) => Err(denied(
                    "external BXRC anchor CAS conflict during reconciliation",
                )),
            }
        })()
    }
}

impl<T: ExternalFloorCustodianTransport, A: ExternalFloorCustodianAnchorStore>
    ExternalFloorReplayStore for DurableAuthenticatedExternalFloorCustodian<T, A>
{
    fn load(&self) -> io::Result<ExternalFloorReplayCheckpoint> {
        self.reserve(LOAD, None, None)?;
        let result = self.client.load();
        if self.client.transport_checkpoint() != self.record.get().checkpoint {
            return Err(invalid("BXRC in-memory and durable checkpoints diverged"));
        }
        let value = result?;
        self.finish()?;
        Ok(value)
    }

    fn compare_and_swap(
        &self,
        expected: ExternalFloorReplayCheckpoint,
        replacement: ExternalFloorReplayCheckpoint,
    ) -> io::Result<ExternalFloorReplayCasOutcome> {
        if expected.session_nonce == [0; 32]
            || expected.session_nonce != replacement.session_nonce
            || expected.revision.checked_add(1) != Some(replacement.revision)
            || expected.next_sequence.checked_add(1) != Some(replacement.next_sequence)
        {
            return Err(invalid("invalid BXRC checkpoint CAS transition"));
        }
        self.reserve(CAS, Some(expected), Some(replacement))?;
        let result = self.client.compare_and_swap(expected, replacement);
        if self.client.transport_checkpoint() != self.record.get().checkpoint {
            return Err(invalid("BXRC in-memory and durable checkpoints diverged"));
        }
        let value = result?;
        self.finish()?;
        Ok(value)
    }
}
