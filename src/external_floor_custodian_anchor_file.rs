// SPDX-License-Identifier: MIT OR Apache-2.0
//! Durable Unix file backend for the independently administered BXRC client
//! anchor.
//!
//! This backend supplies atomic exact compare-and-swap and corruption
//! detection. Rollback resistance comes from placing its directory on
//! independently administered, non-rollbackable storage; a second directory
//! on the checkpoint filesystem is not an independent anchor.

use std::fs::{DirBuilder, File, OpenOptions};
use std::io::{self, Error, ErrorKind, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use tiny_keccak::{Hasher, Keccak};

use crate::{
    ExternalFloorCustodianAnchorCasOutcome, ExternalFloorCustodianAnchorStore,
    ExternalFloorCustodianClientAnchor,
};

const STATE_FILE: &str = ".bxrc-external-anchor";
const TEMP_FILE: &str = ".bxrc-external-anchor.tmp";
const LOCK_FILE: &str = ".bxrc-external-anchor.lock";
const MAGIC: [u8; 4] = *b"BXCA";
const VERSION: u8 = 1;
const PREFIX_LEN: usize = 48;
const SEAL_DOMAIN: &[u8] = b"BLOCH-L2-BXRC-EXTERNAL-ANCHOR-v1\0";

/// Exact canonical length of the external anchor record.
pub const EXTERNAL_FLOOR_CUSTODIAN_ANCHOR_RECORD_LEN: usize = PREFIX_LEN + 32;

fn invalid(message: &'static str) -> Error {
    Error::new(ErrorKind::InvalidData, message)
}

fn denied(message: &'static str) -> Error {
    Error::new(ErrorKind::PermissionDenied, message)
}

fn c_name(value: &'static str) -> std::ffi::CString {
    std::ffi::CString::new(value).expect("fixed anchor filename contains no NUL")
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
            "BXRC external anchor directory must be private and owned by this user",
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

fn path_exists_at(directory: &File, filename: &'static str) -> io::Result<bool> {
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: pointers and descriptor are valid; output is ignored on error.
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

fn reject_temp(directory: &File) -> io::Result<()> {
    if path_exists_at(directory, TEMP_FILE)? {
        Err(invalid(
            "temporary BXRC external anchor exists; operator inspection is required",
        ))
    } else {
        Ok(())
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
            "BXRC external anchor lock is not a private single-link file",
        )?;
        // SAFETY: descriptor is live and flock constants are valid.
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(Error::last_os_error());
        }
        validate_file(
            &lock,
            "BXRC external anchor lock changed while it was acquired",
        )?;
        Ok(Self(lock))
    }
}

impl Drop for Lock {
    fn drop(&mut self) {
        // The inode remains linked so a concurrent opener cannot split locks.
        let _ = unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
    }
}

fn open_directory(path: &Path) -> io::Result<File> {
    if !path.is_absolute() {
        return Err(invalid("BXRC external anchor directory must be absolute"));
    }
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open(path)?;
    validate_directory(&directory)?;
    Ok(directory)
}

fn seal(prefix: &[u8]) -> [u8; 32] {
    let mut hash = Keccak::v256();
    hash.update(SEAL_DOMAIN);
    hash.update(prefix);
    let mut output = [0_u8; 32];
    hash.finalize(&mut output);
    output
}

fn encode(
    anchor: ExternalFloorCustodianClientAnchor,
) -> [u8; EXTERNAL_FLOOR_CUSTODIAN_ANCHOR_RECORD_LEN] {
    let mut encoded = [0_u8; EXTERNAL_FLOOR_CUSTODIAN_ANCHOR_RECORD_LEN];
    encoded[..4].copy_from_slice(&MAGIC);
    encoded[4] = VERSION;
    // bytes 5..8 are reserved and canonically zero.
    encoded[8..16].copy_from_slice(&anchor.revision.to_be_bytes());
    encoded[16..48].copy_from_slice(&anchor.commitment);
    let checksum = seal(&encoded[..PREFIX_LEN]);
    encoded[PREFIX_LEN..].copy_from_slice(&checksum);
    encoded
}

fn decode(encoded: &[u8]) -> io::Result<ExternalFloorCustodianClientAnchor> {
    if encoded.len() != EXTERNAL_FLOOR_CUSTODIAN_ANCHOR_RECORD_LEN {
        return Err(invalid("BXRC external anchor record has invalid length"));
    }
    if encoded[..4] != MAGIC || encoded[4] != VERSION || encoded[5..8] != [0; 3] {
        return Err(invalid("BXRC external anchor has a noncanonical header"));
    }
    if encoded[PREFIX_LEN..] != seal(&encoded[..PREFIX_LEN]) {
        return Err(invalid("BXRC external anchor checksum failed"));
    }
    let anchor = ExternalFloorCustodianClientAnchor {
        revision: u64::from_be_bytes(encoded[8..16].try_into().expect("fixed revision slice")),
        commitment: encoded[16..48].try_into().expect("fixed commitment slice"),
    };
    if anchor.commitment == [0; 32] {
        return Err(invalid("BXRC external anchor commitment is all zero"));
    }
    Ok(anchor)
}

fn read_anchor(directory: &File) -> io::Result<ExternalFloorCustodianClientAnchor> {
    reject_temp(directory)?;
    let mut file = open_at(directory.as_raw_fd(), STATE_FILE, libc::O_RDONLY, 0)?;
    validate_file(
        &file,
        "BXRC external anchor must be a private single-link regular file",
    )?;
    let mut encoded = [0_u8; EXTERNAL_FLOOR_CUSTODIAN_ANCHOR_RECORD_LEN];
    file.read_exact(&mut encoded)?;
    let mut trailing = [0_u8; 1];
    if file.read(&mut trailing)? != 0 {
        return Err(invalid("BXRC external anchor has trailing data"));
    }
    decode(&encoded)
}

fn write_anchor(
    directory: &File,
    anchor: ExternalFloorCustodianClientAnchor,
    create: bool,
) -> io::Result<()> {
    reject_temp(directory)?;
    if anchor.commitment == [0; 32] {
        return Err(invalid("BXRC external anchor commitment is all zero"));
    }
    if create && path_exists_at(directory, STATE_FILE)? {
        return Err(Error::new(
            ErrorKind::AlreadyExists,
            "BXRC external anchor already exists",
        ));
    }
    let encoded = encode(anchor);
    let mut temporary = open_at(
        directory.as_raw_fd(),
        TEMP_FILE,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        0o600,
    )?;
    validate_file(
        &temporary,
        "temporary BXRC external anchor is not a private single-link file",
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
    if read_anchor(directory)? != anchor {
        return Err(invalid("BXRC external anchor read-back mismatch"));
    }
    Ok(())
}

/// A create-once, process-exclusive Unix implementation of the external BXRC
/// client anchor CAS.
///
/// Its directory must live in an independently administered rollback domain.
/// The checksum detects corruption, not malicious rewriting or rollback.
pub struct UnixExternalFloorCustodianAnchorStore {
    directory: File,
    _lock: Lock,
    gate: Mutex<()>,
}

impl UnixExternalFloorCustodianAnchorStore {
    /// Creates a new private directory and installs the externally approved
    /// initial anchor. Existing paths are never adopted.
    pub fn provision(path: &Path, initial: ExternalFloorCustodianClientAnchor) -> io::Result<Self> {
        if !path.is_absolute() || initial.commitment == [0; 32] {
            return Err(invalid(
                "invalid BXRC external anchor provisioning configuration",
            ));
        }
        let mut builder = DirBuilder::new();
        builder.mode(0o700);
        builder.create(path)?;
        let directory = open_directory(path)?;
        let lock = Lock::acquire(&directory)?;
        write_anchor(&directory, initial, true)?;
        Ok(Self {
            directory,
            _lock: lock,
            gate: Mutex::new(()),
        })
    }

    /// Opens an existing validated store and retains its exclusive process
    /// lock for this instance's lifetime.
    pub fn open(path: &Path) -> io::Result<Self> {
        let directory = open_directory(path)?;
        let lock = Lock::acquire(&directory)?;
        read_anchor(&directory)?;
        Ok(Self {
            directory,
            _lock: lock,
            gate: Mutex::new(()),
        })
    }

    fn gate(&self) -> io::Result<MutexGuard<'_, ()>> {
        self.gate
            .lock()
            .map_err(|_| Error::other("BXRC external anchor in-process lock is poisoned"))
    }
}

impl ExternalFloorCustodianAnchorStore for UnixExternalFloorCustodianAnchorStore {
    fn load(&self) -> io::Result<ExternalFloorCustodianClientAnchor> {
        let _gate = self.gate()?;
        read_anchor(&self.directory)
    }

    fn compare_and_swap(
        &self,
        expected: ExternalFloorCustodianClientAnchor,
        replacement: ExternalFloorCustodianClientAnchor,
    ) -> io::Result<ExternalFloorCustodianAnchorCasOutcome> {
        let _gate = self.gate()?;
        let actual = read_anchor(&self.directory)?;
        if actual != expected {
            return Ok(ExternalFloorCustodianAnchorCasOutcome::Conflict(actual));
        }
        let revision_delta = replacement.revision.checked_sub(expected.revision);
        if !matches!(revision_delta, Some(1 | 2))
            || replacement.commitment == [0; 32]
            || replacement.commitment == expected.commitment
        {
            return Err(invalid("invalid BXRC external anchor transition"));
        }
        write_anchor(&self.directory, replacement, false)?;
        Ok(ExternalFloorCustodianAnchorCasOutcome::Committed)
    }
}
