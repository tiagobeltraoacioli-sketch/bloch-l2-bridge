// SPDX-License-Identifier: MIT OR Apache-2.0
//! Durable Unix file backend for the independently administered BXRC client
//! anchor.
//!
//! This backend supplies atomic exact compare-and-swap and corruption
//! detection. Rollback resistance comes from placing its directory on
//! independently administered, non-rollbackable storage; a second directory
//! on the checkpoint filesystem is not an independent anchor.

#[cfg(target_os = "linux")]
use std::fs;
use std::fs::{File, OpenOptions};
#[cfg(target_os = "linux")]
use std::io::Read;
use std::io::{self, Error, ErrorKind, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
#[cfg(target_os = "linux")]
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};

use ring::signature::{UnparsedPublicKey, ED25519};
use tiny_keccak::{Hasher, Keccak};

use crate::{
    ExternalFloorCustodianAnchorCasOutcome, ExternalFloorCustodianAnchorStore,
    ExternalFloorCustodianClientAnchor,
};

const STATE_FILE: &str = ".bxrc-external-anchor";
const TEMP_FILE: &str = ".bxrc-external-anchor.tmp";
const LOCK_FILE: &str = ".bxrc-external-anchor.lock";
#[cfg(target_os = "linux")]
const QUARANTINE_PREFIX: &[u8] = b".bxrc-external-anchor.displaced.";
const MAGIC: [u8; 4] = *b"BXCA";
const VERSION: u8 = 1;
const PREFIX_LEN: usize = 48;
const SEAL_DOMAIN: &[u8] = b"BLOCH-L2-BXRC-EXTERNAL-ANCHOR-v1\0";
const APPROVAL_DOMAIN: &[u8; 48] = b"BLOCH-L2-BXRC-EXTERNAL-ANCHOR-APPROVAL-v1\0\0\0\0\0\0\0";
const CONTINUITY_AUTHORIZATION_DOMAIN: &[u8; 48] =
    b"BLOCH-L2-BXRC-ANCHOR-CONTINUITY-AUTH-v1\0\0\0\0\0\0\0\0\0";
const CONTINUITY_ACCEPTANCE_DOMAIN: &[u8; 48] =
    b"BLOCH-L2-BXRC-ANCHOR-CONTINUITY-ACCEPT-v1\0\0\0\0\0\0\0";
const QUARANTINE_INVENTORY_DOMAIN: &[u8] = b"BLOCH-L2-BXRC-ANCHOR-QUARANTINE-INVENTORY-v1\0";
const QUARANTINE_CHECKPOINT_DOMAIN: &[u8] = b"BLOCH-L2-BXRC-ANCHOR-QUARANTINE-CHECKPOINT-v1\0";
#[cfg(target_os = "linux")]
static NEXT_PROVISION_STAGING: AtomicU64 = AtomicU64::new(0);
static NEXT_QUARANTINE: AtomicU64 = AtomicU64::new(0);

#[cfg(target_os = "linux")]
const NOATIME: i32 = libc::O_NOATIME;
#[cfg(not(target_os = "linux"))]
const NOATIME: i32 = 0;

/// Exact canonical length of the external anchor record.
pub const EXTERNAL_FLOOR_CUSTODIAN_ANCHOR_RECORD_LEN: usize = PREFIX_LEN + 32;
/// Exact length of the domain-separated message signed by an offline anchor
/// approver.
pub const EXTERNAL_FLOOR_CUSTODIAN_ANCHOR_APPROVAL_MESSAGE_LEN: usize = 120;
/// Exact length of either role-separated anchor continuity message.
pub const EXTERNAL_FLOOR_CUSTODIAN_ANCHOR_CONTINUITY_MESSAGE_LEN: usize = 224;

/// An offline Ed25519 approval of one exact anchor in one deployment domain.
///
/// The signing key is never needed by this backend. Callers should pin the
/// verifying key and the deployment id through separate trusted channels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExternalFloorCustodianAnchorApproval {
    pub deployment_id: [u8; 32],
    pub anchor: ExternalFloorCustodianClientAnchor,
    pub signature: [u8; 64],
}

/// One expected quarantine anchor and its independently pinned offline
/// verifying key.
///
/// Supplying the key per record permits exact inventory inspection across
/// legitimate authority rotations without deriving any authority from disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExternalFloorCustodianAnchorQuarantineApproval {
    pub verifying_key: [u8; 32],
    pub approval: ExternalFloorCustodianAnchorApproval,
}

/// Exact offline-approved inventory of a live anchor and every retained
/// predecessor quarantine.
///
/// The inventory contains decoded anchors only. Quarantine pathnames remain
/// an internal implementation detail and are never returned as cleanup
/// authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalFloorCustodianAnchorQuarantineInspection {
    pub current: ExternalFloorCustodianClientAnchor,
    pub quarantined: Vec<ExternalFloorCustodianClientAnchor>,
}

/// Independently retained position in the offline quarantine-inspection
/// history.
///
/// The checkpoint is useful as an anti-rollback boundary only when the exact
/// value is retained outside the anchor store's rollback domain. It never
/// authorizes deletion, adoption, or mutation of any inspected pathname.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExternalFloorCustodianAnchorQuarantineCheckpoint {
    pub inspection_index: u64,
    pub deployment_id: [u8; 32],
    pub current_verifying_key: [u8; 32],
    pub current: ExternalFloorCustodianClientAnchor,
    pub quarantine_count: u64,
    pub quarantine_history_hash: [u8; 32],
    pub inventory_hash: [u8; 32],
    pub previous_checkpoint_hash: [u8; 32],
    pub checkpoint_hash: [u8; 32],
}

/// Exact inspected inventory paired with its caller-pinned history position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalFloorCustodianAnchorQuarantineReceipt {
    pub checkpoint: ExternalFloorCustodianAnchorQuarantineCheckpoint,
    pub inspection: ExternalFloorCustodianAnchorQuarantineInspection,
}

/// Offline, two-party continuity evidence for anchor reapproval or authority
/// rotation.
///
/// `authorization_signature` is made by the independently pinned current
/// key. `acceptance_signature` is made by `next_verifying_key`. The backend
/// accepts neither private key. Keeping the two role domains distinct proves
/// that both authorities approved their respective side of the transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExternalFloorCustodianAnchorContinuityApproval {
    pub deployment_id: [u8; 32],
    pub previous_anchor: ExternalFloorCustodianClientAnchor,
    pub next_anchor: ExternalFloorCustodianClientAnchor,
    pub next_verifying_key: [u8; 32],
    pub authorization_signature: [u8; 64],
    pub acceptance_signature: [u8; 64],
}

/// Builds the canonical message for an offline Ed25519 signer.
pub fn external_floor_custodian_anchor_approval_message(
    deployment_id: [u8; 32],
    anchor: ExternalFloorCustodianClientAnchor,
) -> [u8; EXTERNAL_FLOOR_CUSTODIAN_ANCHOR_APPROVAL_MESSAGE_LEN] {
    let mut message = [0_u8; EXTERNAL_FLOOR_CUSTODIAN_ANCHOR_APPROVAL_MESSAGE_LEN];
    message[..APPROVAL_DOMAIN.len()].copy_from_slice(APPROVAL_DOMAIN);
    message[48..80].copy_from_slice(&deployment_id);
    message[80..88].copy_from_slice(&anchor.revision.to_be_bytes());
    message[88..120].copy_from_slice(&anchor.commitment);
    message
}

/// Verifies an offline approval against independently pinned identity data.
pub fn verify_external_floor_custodian_anchor_approval(
    expected_deployment_id: [u8; 32],
    verifying_key: [u8; 32],
    approval: ExternalFloorCustodianAnchorApproval,
) -> io::Result<ExternalFloorCustodianClientAnchor> {
    if expected_deployment_id == [0; 32]
        || verifying_key == [0; 32]
        || approval.deployment_id != expected_deployment_id
        || approval.anchor.commitment == [0; 32]
    {
        return Err(denied("invalid BXRC external anchor approval identity"));
    }
    let message =
        external_floor_custodian_anchor_approval_message(approval.deployment_id, approval.anchor);
    UnparsedPublicKey::new(&ED25519, verifying_key)
        .verify(&message, &approval.signature)
        .map_err(|_| denied("BXRC external anchor approval signature failed"))?;
    Ok(approval.anchor)
}

fn keccak_parts(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hash = Keccak::v256();
    hash.update(domain);
    for part in parts {
        hash.update(part);
    }
    let mut output = [0_u8; 32];
    hash.finalize(&mut output);
    output
}

struct ApprovedQuarantineInventory {
    current: ExternalFloorCustodianClientAnchor,
    inventory_hash: [u8; 32],
    history_hash: [u8; 32],
    records: Vec<(ExternalFloorCustodianClientAnchor, [u8; 32])>,
}

fn approved_quarantine_inventory(
    deployment_id: [u8; 32],
    current_verifying_key: [u8; 32],
    current_approval: ExternalFloorCustodianAnchorApproval,
    quarantine_approvals: &[ExternalFloorCustodianAnchorQuarantineApproval],
) -> io::Result<ApprovedQuarantineInventory> {
    let current = verify_external_floor_custodian_anchor_approval(
        deployment_id,
        current_verifying_key,
        current_approval,
    )?;
    let mut records = Vec::with_capacity(quarantine_approvals.len());
    for expected in quarantine_approvals {
        records.push((
            verify_external_floor_custodian_anchor_approval(
                deployment_id,
                expected.verifying_key,
                expected.approval,
            )?,
            expected.verifying_key,
        ));
    }
    records.sort_by_key(|(anchor, key)| (anchor.revision, anchor.commitment, *key));
    if records
        .windows(2)
        .any(|pair| pair[0].0.revision >= pair[1].0.revision)
        || records
            .iter()
            .any(|(anchor, _)| anchor.revision >= current.revision)
    {
        return Err(invalid(
            "non-monotonic BXRC anchor offline approval in quarantine inventory",
        ));
    }
    let quarantine_history_hash = quarantine_history_hash(deployment_id, &records)?;
    let current_revision = current.revision.to_be_bytes();
    let inventory_hash = keccak_parts(
        QUARANTINE_INVENTORY_DOMAIN,
        &[
            &deployment_id,
            &current_verifying_key,
            &current_revision,
            &current.commitment,
            &quarantine_history_hash,
        ],
    );
    Ok(ApprovedQuarantineInventory {
        current,
        inventory_hash,
        history_hash: quarantine_history_hash,
        records,
    })
}

fn quarantine_history_hash(
    deployment_id: [u8; 32],
    records: &[(ExternalFloorCustodianClientAnchor, [u8; 32])],
) -> io::Result<[u8; 32]> {
    let count = u64::try_from(records.len())
        .map_err(|_| invalid("BXRC anchor quarantine approval count is invalid"))?
        .to_be_bytes();
    let mut hash = Keccak::v256();
    hash.update(QUARANTINE_INVENTORY_DOMAIN);
    hash.update(b"HISTORY\0");
    hash.update(&deployment_id);
    hash.update(&count);
    for (anchor, key) in records {
        hash.update(key);
        hash.update(&anchor.revision.to_be_bytes());
        hash.update(&anchor.commitment);
    }
    let mut output = [0; 32];
    hash.finalize(&mut output);
    Ok(output)
}

fn quarantine_checkpoint_hash(
    checkpoint: &ExternalFloorCustodianAnchorQuarantineCheckpoint,
) -> [u8; 32] {
    let index = checkpoint.inspection_index.to_be_bytes();
    let revision = checkpoint.current.revision.to_be_bytes();
    keccak_parts(
        QUARANTINE_CHECKPOINT_DOMAIN,
        &[
            &index,
            &checkpoint.deployment_id,
            &checkpoint.current_verifying_key,
            &revision,
            &checkpoint.current.commitment,
            &checkpoint.quarantine_count.to_be_bytes(),
            &checkpoint.quarantine_history_hash,
            &checkpoint.inventory_hash,
            &checkpoint.previous_checkpoint_hash,
        ],
    )
}

fn validate_quarantine_checkpoint(
    checkpoint: ExternalFloorCustodianAnchorQuarantineCheckpoint,
) -> io::Result<()> {
    if checkpoint.deployment_id == [0; 32]
        || checkpoint.current_verifying_key == [0; 32]
        || checkpoint.current.commitment == [0; 32]
        || checkpoint.quarantine_history_hash == [0; 32]
        || checkpoint.inventory_hash == [0; 32]
        || (checkpoint.inspection_index == 0) != (checkpoint.previous_checkpoint_hash == [0; 32])
        || checkpoint.checkpoint_hash != quarantine_checkpoint_hash(&checkpoint)
    {
        return Err(invalid("invalid BXRC anchor quarantine checkpoint"));
    }
    Ok(())
}

/// Verifies the canonical hash and structural invariants of an independently
/// retained quarantine checkpoint. Authenticity still comes from deriving the
/// checkpoint from the separately pinned approvals, not from this unkeyed
/// integrity check alone.
pub fn verify_external_floor_custodian_quarantine_checkpoint(
    checkpoint: ExternalFloorCustodianAnchorQuarantineCheckpoint,
) -> io::Result<()> {
    validate_quarantine_checkpoint(checkpoint)
}

/// Derives the genesis quarantine checkpoint exclusively from independently
/// supplied, signature-verified approvals. Retain the returned value outside
/// the anchor store before using it as an anti-rollback boundary.
pub fn external_floor_custodian_expected_initial_quarantine_checkpoint(
    deployment_id: [u8; 32],
    current_verifying_key: [u8; 32],
    current_approval: ExternalFloorCustodianAnchorApproval,
    quarantine_approvals: &[ExternalFloorCustodianAnchorQuarantineApproval],
) -> io::Result<ExternalFloorCustodianAnchorQuarantineCheckpoint> {
    let inventory = approved_quarantine_inventory(
        deployment_id,
        current_verifying_key,
        current_approval,
        quarantine_approvals,
    )?;
    let mut checkpoint = ExternalFloorCustodianAnchorQuarantineCheckpoint {
        inspection_index: 0,
        deployment_id,
        current_verifying_key,
        current: inventory.current,
        quarantine_count: inventory.records.len() as u64,
        quarantine_history_hash: inventory.history_hash,
        inventory_hash: inventory.inventory_hash,
        previous_checkpoint_hash: [0; 32],
        checkpoint_hash: [0; 32],
    };
    checkpoint.checkpoint_hash = quarantine_checkpoint_hash(&checkpoint);
    Ok(checkpoint)
}

/// Derives the only next checkpoint accepted after an independently retained
/// predecessor. Current-anchor revision cannot move backwards, and equal
/// revisions cannot change commitment.
pub fn external_floor_custodian_expected_next_quarantine_checkpoint(
    previous: ExternalFloorCustodianAnchorQuarantineCheckpoint,
    current_verifying_key: [u8; 32],
    current_approval: ExternalFloorCustodianAnchorApproval,
    quarantine_approvals: &[ExternalFloorCustodianAnchorQuarantineApproval],
) -> io::Result<ExternalFloorCustodianAnchorQuarantineCheckpoint> {
    validate_quarantine_checkpoint(previous)?;
    if current_verifying_key != previous.current_verifying_key {
        return Err(denied(
            "BXRC anchor quarantine checkpoint cannot rotate authority without dual-signed continuity",
        ));
    }
    let inventory = approved_quarantine_inventory(
        previous.deployment_id,
        current_verifying_key,
        current_approval,
        quarantine_approvals,
    )?;
    if inventory.current.revision < previous.current.revision
        || (inventory.current.revision == previous.current.revision
            && inventory.current != previous.current)
    {
        return Err(denied(
            "BXRC anchor quarantine checkpoint would roll back current authority",
        ));
    }
    let previous_count = usize::try_from(previous.quarantine_count)
        .map_err(|_| invalid("BXRC anchor quarantine checkpoint count is invalid"))?;
    if inventory.records.len() < previous_count
        || quarantine_history_hash(previous.deployment_id, &inventory.records[..previous_count])?
            != previous.quarantine_history_hash
        || (inventory.current == previous.current && inventory.records.len() != previous_count)
        || (inventory.current != previous.current
            && (inventory.records.len() == previous_count
                || inventory.records[previous_count]
                    != (previous.current, previous.current_verifying_key)))
    {
        return Err(denied(
            "BXRC anchor quarantine history does not extend retained checkpoint",
        ));
    }
    if inventory
        .records
        .iter()
        .skip(previous_count)
        .any(|(_, key)| *key != previous.current_verifying_key)
    {
        return Err(denied(
            "BXRC anchor quarantine history changes authority without dual-signed continuity",
        ));
    }
    if inventory.current != previous.current {
        let mut prior = previous.current;
        for (anchor, _) in inventory.records.iter().skip(previous_count + 1) {
            if !matches!(anchor.revision.checked_sub(prior.revision), Some(1 | 2)) {
                return Err(denied(
                    "BXRC anchor quarantine checkpoint has an invalid retained transition",
                ));
            }
            prior = *anchor;
        }
        if !matches!(
            inventory.current.revision.checked_sub(prior.revision),
            Some(1 | 2)
        ) {
            return Err(denied(
                "BXRC anchor quarantine checkpoint has an invalid current transition",
            ));
        }
    }
    let inspection_index = previous
        .inspection_index
        .checked_add(1)
        .ok_or_else(|| invalid("BXRC anchor quarantine checkpoint index overflow"))?;
    let mut checkpoint = ExternalFloorCustodianAnchorQuarantineCheckpoint {
        inspection_index,
        deployment_id: previous.deployment_id,
        current_verifying_key,
        current: inventory.current,
        quarantine_count: inventory.records.len() as u64,
        quarantine_history_hash: inventory.history_hash,
        inventory_hash: inventory.inventory_hash,
        previous_checkpoint_hash: previous.checkpoint_hash,
        checkpoint_hash: [0; 32],
    };
    checkpoint.checkpoint_hash = quarantine_checkpoint_hash(&checkpoint);
    Ok(checkpoint)
}

fn continuity_message(
    domain: &[u8; 48],
    deployment_id: [u8; 32],
    previous_verifying_key: [u8; 32],
    previous_anchor: ExternalFloorCustodianClientAnchor,
    next_verifying_key: [u8; 32],
    next_anchor: ExternalFloorCustodianClientAnchor,
) -> [u8; EXTERNAL_FLOOR_CUSTODIAN_ANCHOR_CONTINUITY_MESSAGE_LEN] {
    let mut message = [0_u8; EXTERNAL_FLOOR_CUSTODIAN_ANCHOR_CONTINUITY_MESSAGE_LEN];
    message[..48].copy_from_slice(domain);
    message[48..80].copy_from_slice(&deployment_id);
    message[80..112].copy_from_slice(&previous_verifying_key);
    message[112..120].copy_from_slice(&previous_anchor.revision.to_be_bytes());
    message[120..152].copy_from_slice(&previous_anchor.commitment);
    message[152..184].copy_from_slice(&next_verifying_key);
    message[184..192].copy_from_slice(&next_anchor.revision.to_be_bytes());
    message[192..224].copy_from_slice(&next_anchor.commitment);
    message
}

/// Builds the canonical message authorized by the currently pinned offline
/// authority.
pub fn external_floor_custodian_anchor_continuity_authorization_message(
    deployment_id: [u8; 32],
    previous_verifying_key: [u8; 32],
    previous_anchor: ExternalFloorCustodianClientAnchor,
    next_verifying_key: [u8; 32],
    next_anchor: ExternalFloorCustodianClientAnchor,
) -> [u8; EXTERNAL_FLOOR_CUSTODIAN_ANCHOR_CONTINUITY_MESSAGE_LEN] {
    continuity_message(
        CONTINUITY_AUTHORIZATION_DOMAIN,
        deployment_id,
        previous_verifying_key,
        previous_anchor,
        next_verifying_key,
        next_anchor,
    )
}

/// Builds the canonical, role-separated message accepted by the next offline
/// authority.
pub fn external_floor_custodian_anchor_continuity_acceptance_message(
    deployment_id: [u8; 32],
    previous_verifying_key: [u8; 32],
    previous_anchor: ExternalFloorCustodianClientAnchor,
    next_verifying_key: [u8; 32],
    next_anchor: ExternalFloorCustodianClientAnchor,
) -> [u8; EXTERNAL_FLOOR_CUSTODIAN_ANCHOR_CONTINUITY_MESSAGE_LEN] {
    continuity_message(
        CONTINUITY_ACCEPTANCE_DOMAIN,
        deployment_id,
        previous_verifying_key,
        previous_anchor,
        next_verifying_key,
        next_anchor,
    )
}

/// Verifies monotonic, two-party continuity from independently retained
/// authority state. The prior key and anchor are parameters rather than data
/// learned from the approval, preventing trust-on-first-use.
pub fn verify_external_floor_custodian_anchor_continuity(
    expected_deployment_id: [u8; 32],
    expected_previous_verifying_key: [u8; 32],
    expected_previous_anchor: ExternalFloorCustodianClientAnchor,
    approval: ExternalFloorCustodianAnchorContinuityApproval,
) -> io::Result<(ExternalFloorCustodianClientAnchor, [u8; 32])> {
    if expected_deployment_id == [0; 32]
        || expected_previous_verifying_key == [0; 32]
        || expected_previous_anchor.commitment == [0; 32]
        || approval.deployment_id != expected_deployment_id
        || approval.previous_anchor != expected_previous_anchor
        || approval.next_verifying_key == [0; 32]
        || approval.next_anchor.commitment == [0; 32]
    {
        return Err(denied("invalid BXRC anchor continuity identity"));
    }
    let same_anchor = approval.next_anchor == expected_previous_anchor;
    let same_key = approval.next_verifying_key == expected_previous_verifying_key;
    if (same_anchor && same_key)
        || (!same_anchor
            && (approval.next_anchor.revision <= expected_previous_anchor.revision
                || approval.next_anchor.commitment == expected_previous_anchor.commitment))
    {
        return Err(denied("non-monotonic BXRC anchor continuity transition"));
    }
    let authorization = external_floor_custodian_anchor_continuity_authorization_message(
        expected_deployment_id,
        expected_previous_verifying_key,
        expected_previous_anchor,
        approval.next_verifying_key,
        approval.next_anchor,
    );
    UnparsedPublicKey::new(&ED25519, expected_previous_verifying_key)
        .verify(&authorization, &approval.authorization_signature)
        .map_err(|_| denied("BXRC anchor continuity authorization failed"))?;
    let acceptance = external_floor_custodian_anchor_continuity_acceptance_message(
        expected_deployment_id,
        expected_previous_verifying_key,
        expected_previous_anchor,
        approval.next_verifying_key,
        approval.next_anchor,
    );
    UnparsedPublicKey::new(&ED25519, approval.next_verifying_key)
        .verify(&acceptance, &approval.acceptance_signature)
        .map_err(|_| denied("BXRC anchor continuity acceptance failed"))?;
    Ok((approval.next_anchor, approval.next_verifying_key))
}

fn invalid(message: &'static str) -> Error {
    Error::new(ErrorKind::InvalidData, message)
}

fn denied(message: &'static str) -> Error {
    Error::new(ErrorKind::PermissionDenied, message)
}

fn c_name(value: &'static str) -> std::ffi::CString {
    std::ffi::CString::new(value).expect("fixed anchor filename contains no NUL")
}

fn path_name(value: &std::ffi::OsStr) -> io::Result<std::ffi::CString> {
    std::ffi::CString::new(value.as_bytes())
        .map_err(|_| invalid("BXRC external anchor path contains NUL"))
}

#[cfg(target_os = "linux")]
fn random_staging_name() -> io::Result<String> {
    let mut random = [0_u8; 18];
    File::open("/dev/urandom")?.read_exact(&mut random)?;
    let mut encoded = String::with_capacity(random.len() * 2);
    for byte in random {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    Ok(format!(
        ".bxrc-external-anchor.provision.{encoded}.{}",
        NEXT_PROVISION_STAGING.fetch_add(1, Ordering::Relaxed),
    ))
}

#[cfg(target_os = "linux")]
fn mkdir_at(directory: &File, name: &std::ffi::OsStr, mode: u32) -> io::Result<()> {
    let name = path_name(name)?;
    let result =
        unsafe { libc::mkdirat(directory.as_raw_fd(), name.as_ptr(), mode as libc::mode_t) };
    if result == 0 {
        Ok(())
    } else {
        Err(Error::last_os_error())
    }
}

fn open_at(directory: RawFd, filename: &'static str, flags: i32, mode: u32) -> io::Result<File> {
    open_at_name(directory, std::ffi::OsStr::new(filename), flags, mode)
}

fn open_at_name(
    directory: RawFd,
    filename: &std::ffi::OsStr,
    flags: i32,
    mode: u32,
) -> io::Result<File> {
    let filename = path_name(filename)?;
    // SAFETY: the directory descriptor is live, the name is NUL terminated,
    // and ownership of a successful descriptor is transferred exactly once.
    let descriptor = unsafe {
        libc::openat(
            directory,
            filename.as_ptr(),
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

fn metadata_snapshot(metadata: &std::fs::Metadata) -> FileSnapshot {
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

fn same_directory_identity(left: FileSnapshot, right: FileSnapshot) -> bool {
    left.dev == right.dev
        && left.ino == right.ino
        && left.mode == right.mode
        && left.uid == right.uid
        && left.gid == right.gid
        && left.nlink == right.nlink
}

struct NamespaceGuard(File);

#[cfg(target_os = "linux")]
impl NamespaceGuard {
    fn arm(directory: &File) -> io::Result<Self> {
        let descriptor = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
        if descriptor < 0 {
            return Err(Error::last_os_error());
        }
        let guard = Self(unsafe { File::from_raw_fd(descriptor) });
        let proc_path = format!("/proc/self/fd/{}", directory.as_raw_fd());
        let proc_path = std::ffi::CString::new(proc_path).expect("fd path contains no NUL");
        let mask = libc::IN_CREATE
            | libc::IN_DELETE
            | libc::IN_MOVED_FROM
            | libc::IN_MOVED_TO
            | libc::IN_ATTRIB
            | libc::IN_MODIFY
            | libc::IN_DELETE_SELF
            | libc::IN_MOVE_SELF;
        if unsafe { libc::inotify_add_watch(guard.0.as_raw_fd(), proc_path.as_ptr(), mask) } < 0 {
            return Err(Error::last_os_error());
        }
        guard.assert_quiet()?;
        Ok(guard)
    }

    fn events(&self) -> io::Result<Vec<(u32, Vec<u8>)>> {
        let mut events = Vec::new();
        let mut buffer = [0_u8; 4096];
        loop {
            let length =
                unsafe { libc::read(self.0.as_raw_fd(), buffer.as_mut_ptr().cast(), buffer.len()) };
            if length < 0 {
                let error = Error::last_os_error();
                if error.kind() == ErrorKind::WouldBlock {
                    break;
                }
                return Err(error);
            }
            if length == 0 {
                break;
            }
            let mut offset = 0;
            while offset + std::mem::size_of::<libc::inotify_event>() <= length as usize {
                let event = unsafe {
                    buffer
                        .as_ptr()
                        .add(offset)
                        .cast::<libc::inotify_event>()
                        .read_unaligned()
                };
                let start = offset + std::mem::size_of::<libc::inotify_event>();
                let end = start + event.len as usize;
                if end > length as usize {
                    return Err(invalid("truncated BXRC namespace event"));
                }
                let name_end = buffer[start..end]
                    .iter()
                    .position(|byte| *byte == 0)
                    .map_or(end, |position| start + position);
                events.push((event.mask, buffer[start..name_end].to_vec()));
                offset = end;
            }
        }
        Ok(events)
    }

    fn assert_quiet(&self) -> io::Result<()> {
        if self.events()?.is_empty() {
            Ok(())
        } else {
            Err(denied("BXRC anchor namespace changed during validation"))
        }
    }

    fn assert_expected_directory_create(&self, name: &std::ffi::OsStr) -> io::Result<()> {
        let events = self.events()?;
        let expected = name.as_bytes();
        if events.len() == 1
            && events[0].0 == (libc::IN_CREATE | libc::IN_ISDIR)
            && events[0].1 == expected
        {
            Ok(())
        } else {
            Err(denied("unexpected BXRC staging namespace mutation"))
        }
    }
}

#[cfg(target_os = "macos")]
impl NamespaceGuard {
    fn arm(directory: &File) -> io::Result<Self> {
        let descriptor = unsafe { libc::kqueue() };
        if descriptor < 0 {
            return Err(Error::last_os_error());
        }
        let guard = Self(unsafe { File::from_raw_fd(descriptor) });
        let change = libc::kevent {
            ident: directory.as_raw_fd() as libc::uintptr_t,
            filter: libc::EVFILT_VNODE,
            flags: libc::EV_ADD | libc::EV_CLEAR,
            fflags: libc::NOTE_WRITE
                | libc::NOTE_EXTEND
                | libc::NOTE_ATTRIB
                | libc::NOTE_LINK
                | libc::NOTE_RENAME
                | libc::NOTE_DELETE
                | libc::NOTE_REVOKE,
            data: 0,
            udata: std::ptr::null_mut(),
        };
        if unsafe {
            libc::kevent(
                guard.0.as_raw_fd(),
                &change,
                1,
                std::ptr::null_mut(),
                0,
                std::ptr::null(),
            )
        } < 0
        {
            return Err(Error::last_os_error());
        }
        guard.assert_quiet()?;
        Ok(guard)
    }

    fn changed(&self) -> io::Result<bool> {
        let mut event = std::mem::MaybeUninit::<libc::kevent>::uninit();
        let timeout = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let result = unsafe {
            libc::kevent(
                self.0.as_raw_fd(),
                std::ptr::null(),
                0,
                event.as_mut_ptr(),
                1,
                &timeout,
            )
        };
        if result < 0 {
            Err(Error::last_os_error())
        } else {
            Ok(result != 0)
        }
    }

    fn assert_quiet(&self) -> io::Result<()> {
        if self.changed()? {
            Err(denied("BXRC anchor namespace changed during validation"))
        } else {
            Ok(())
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
impl NamespaceGuard {
    fn arm(_directory: &File) -> io::Result<Self> {
        Err(Error::new(
            ErrorKind::Unsupported,
            "kernel namespace guards are unavailable for BXRC anchors",
        ))
    }

    fn assert_quiet(&self) -> io::Result<()> {
        unreachable!()
    }
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

fn read_anchor_bytes(file: &File) -> io::Result<[u8; EXTERNAL_FLOOR_CUSTODIAN_ANCHOR_RECORD_LEN]> {
    let mut encoded = [0_u8; EXTERNAL_FLOOR_CUSTODIAN_ANCHOR_RECORD_LEN];
    file.read_exact_at(&mut encoded, 0)?;
    let mut trailing = [0_u8; 1];
    if file.read_at(&mut trailing, encoded.len() as u64)? != 0 {
        return Err(invalid("BXRC external anchor has trailing data"));
    }
    Ok(encoded)
}

fn refreshed_evidence(
    file: &File,
    expected_snapshot: FileSnapshot,
    expected_nlink: u64,
    expected_bytes: &[u8; EXTERNAL_FLOOR_CUSTODIAN_ANCHOR_RECORD_LEN],
) -> Option<FileSnapshot> {
    let before = file_snapshot(file).ok()?;
    if !same_stable_snapshot(before, expected_snapshot, expected_nlink) {
        return None;
    }
    let bytes = read_anchor_bytes(file).ok()?;
    let after = file_snapshot(file).ok()?;
    (before == after && bytes == *expected_bytes).then_some(after)
}

fn evidence_matches(
    file: &File,
    expected_snapshot: FileSnapshot,
    expected_nlink: u64,
    expected_bytes: &[u8; EXTERNAL_FLOOR_CUSTODIAN_ANCHOR_RECORD_LEN],
) -> bool {
    refreshed_evidence(file, expected_snapshot, expected_nlink, expected_bytes).is_some_and(
        |actual| {
            expected_nlink != expected_snapshot.nlink
                || (actual.ctime == expected_snapshot.ctime
                    && actual.ctime_nsec == expected_snapshot.ctime_nsec)
        },
    )
}

fn validate_file_name(
    directory: &File,
    filename: &'static str,
    file: &File,
    message: &'static str,
) -> io::Result<()> {
    validate_file_path_name(directory, std::ffi::OsStr::new(filename), file, message)
}

fn validate_file_path_name(
    directory: &File,
    filename: &std::ffi::OsStr,
    file: &File,
    message: &'static str,
) -> io::Result<()> {
    validate_file(file, message)?;
    let named = open_at_name(
        directory.as_raw_fd(),
        filename,
        libc::O_RDONLY | libc::O_NONBLOCK | NOATIME,
        0,
    )?;
    let retained = file.metadata()?;
    let named = named.metadata()?;
    if retained.dev() != named.dev() || retained.ino() != named.ino() {
        return Err(denied(message));
    }
    Ok(())
}

fn validate_named_evidence(
    directory: &File,
    filename: &'static str,
    file: &File,
    snapshot: FileSnapshot,
    bytes: &[u8; EXTERNAL_FLOOR_CUSTODIAN_ANCHOR_RECORD_LEN],
    message: &'static str,
) -> io::Result<()> {
    validate_file_name(directory, filename, file, message)?;
    let refreshed = refreshed_evidence(file, snapshot, 1, bytes).ok_or_else(|| denied(message))?;
    validate_file_name(directory, filename, file, message)?;
    if file_snapshot(file)? != refreshed {
        return Err(denied(message));
    }
    // End with a fresh pathname-to-retained-inode binding after the byte and
    // complete metadata proof, rather than merely trusting the earlier open.
    validate_file_name(directory, filename, file, message)
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

#[cfg(target_os = "linux")]
struct DirectoryStream(*mut libc::DIR);

#[cfg(target_os = "linux")]
impl Drop for DirectoryStream {
    fn drop(&mut self) {
        // SAFETY: `self.0` is owned by this wrapper and remains valid until
        // this single `closedir` call.
        let _ = unsafe { libc::closedir(self.0) };
    }
}

#[cfg(target_os = "linux")]
fn quarantine_names(
    directory: &File,
    expected_count: usize,
) -> io::Result<Vec<std::ffi::OsString>> {
    let duplicate = open_at_name(
        directory.as_raw_fd(),
        std::ffi::OsStr::new("."),
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOATIME,
        0,
    )?;
    use std::os::fd::IntoRawFd;
    let descriptor = duplicate.into_raw_fd();
    // SAFETY: `descriptor` is a newly owned directory descriptor. Ownership
    // transfers to the returned DIR stream on success.
    let stream = unsafe { libc::fdopendir(descriptor) };
    if stream.is_null() {
        let error = Error::last_os_error();
        // SAFETY: `fdopendir` failed and therefore did not take ownership.
        let _ = unsafe { libc::close(descriptor) };
        return Err(error);
    }
    let stream = DirectoryStream(stream);
    let mut names = Vec::with_capacity(expected_count);
    loop {
        // SAFETY: Linux exposes the thread-local errno pointer and assigning
        // zero distinguishes end-of-directory from a failed `readdir` call.
        unsafe { *libc::__errno_location() = 0 };
        // SAFETY: the owned DIR stream is valid and accessed by one thread.
        let entry = unsafe { libc::readdir(stream.0) };
        if entry.is_null() {
            let error = Error::last_os_error();
            if error.raw_os_error() == Some(0) {
                break;
            }
            return Err(error);
        }
        // SAFETY: `readdir` returned a live dirent whose d_name is NUL
        // terminated for the duration of this iteration.
        let bytes = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if bytes.starts_with(QUARANTINE_PREFIX) {
            if names.len() == expected_count {
                return Err(denied(
                    "BXRC anchor quarantine inventory exceeds offline approvals",
                ));
            }
            names.push(std::ffi::OsString::from_vec(bytes.to_vec()));
        }
    }
    names.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    Ok(names)
}

#[cfg(target_os = "linux")]
struct QuarantineEvidence {
    name: std::ffi::OsString,
    anchor: ExternalFloorCustodianClientAnchor,
    file: File,
    snapshot: FileSnapshot,
    bytes: [u8; EXTERNAL_FLOOR_CUSTODIAN_ANCHOR_RECORD_LEN],
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
        Self::acquire_file(directory, lock)
    }

    #[cfg(target_os = "linux")]
    fn acquire_existing(directory: &File) -> io::Result<Self> {
        let lock = open_at(
            directory.as_raw_fd(),
            LOCK_FILE,
            libc::O_RDWR | libc::O_NOATIME,
            0,
        )?;
        Self::acquire_file(directory, lock)
    }

    fn acquire_file(directory: &File, lock: File) -> io::Result<Self> {
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
        let acquired = Self(lock);
        acquired.validate_current(directory)?;
        Ok(acquired)
    }

    fn validate_current(&self, directory: &File) -> io::Result<()> {
        validate_directory(directory)?;
        validate_file(
            &self.0,
            "BXRC external anchor lock pathname no longer names the acquired private single-link file",
        )?;
        let named = open_at(directory.as_raw_fd(), LOCK_FILE, libc::O_RDWR | NOATIME, 0)?;
        validate_file(
            &named,
            "BXRC external anchor lock pathname no longer names the acquired private single-link file",
        )?;
        let acquired = self.0.metadata()?;
        let named = named.metadata()?;
        if acquired.dev() != named.dev() || acquired.ino() != named.ino() {
            return Err(denied(
                "BXRC external anchor lock pathname no longer names the acquired private single-link file",
            ));
        }
        Ok(())
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
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY | NOATIME)
        .open(path)?;
    validate_directory(&directory)?;
    Ok(directory)
}

fn validate_directory_name(path: &Path, directory: &File) -> io::Result<()> {
    validate_directory(directory)?;
    let named = open_directory(path)?;
    let retained = directory.metadata()?;
    let named = named.metadata()?;
    if retained.dev() != named.dev() || retained.ino() != named.ino() {
        return Err(denied(
            "BXRC external anchor directory pathname no longer names the retained directory",
        ));
    }
    Ok(())
}

fn validate_mutation_authority_inner<F>(
    path: &Path,
    directory: &File,
    lock: &Lock,
    after_lock: F,
) -> io::Result<()>
where
    F: FnOnce(),
{
    validate_directory_name(path, directory)?;
    lock.validate_current(directory)?;
    after_lock();
    validate_directory_name(path, directory)
}

fn validate_mutation_authority(path: &Path, directory: &File, lock: &Lock) -> io::Result<()> {
    validate_mutation_authority_inner(path, directory, lock, || {})
}

fn directory_seqlock_start(path: &Path, directory: &File) -> io::Result<FileSnapshot> {
    let retained = file_snapshot(directory)?;
    let named = open_directory(path)?;
    if !same_directory_identity(file_snapshot(&named)?, retained) {
        return Err(denied("BXRC external anchor directory authority changed"));
    }
    Ok(retained)
}

fn directory_seqlock_finish(
    path: &Path,
    directory: &File,
    expected: FileSnapshot,
) -> io::Result<()> {
    if !same_directory_identity(file_snapshot(directory)?, expected) {
        return Err(denied(
            "BXRC external anchor directory changed during validation",
        ));
    }
    let named = open_directory(path)?;
    if !same_directory_identity(file_snapshot(&named)?, expected) {
        return Err(denied(
            "BXRC external anchor directory pathname changed during validation",
        ));
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct RetainedEvidence<'a> {
    file: &'a File,
    snapshot: FileSnapshot,
    bytes: &'a [u8; EXTERNAL_FLOOR_CUSTODIAN_ANCHOR_RECORD_LEN],
}

fn validate_final_anchor_authority_inner<F>(
    path: &Path,
    directory: &File,
    lock: &Lock,
    state: RetainedEvidence<'_>,
    after_evidence: F,
) -> io::Result<()>
where
    F: FnOnce(),
{
    let namespace = NamespaceGuard::arm(directory)?;
    let directory_snapshot = directory_seqlock_start(path, directory)?;
    lock.validate_current(directory)?;
    validate_named_evidence(
        directory,
        STATE_FILE,
        state.file,
        state.snapshot,
        state.bytes,
        "BXRC external anchor final authority changed",
    )?;
    after_evidence();
    directory_seqlock_finish(path, directory, directory_snapshot)?;
    namespace.assert_quiet()
}

fn validate_final_anchor_authority(
    path: &Path,
    directory: &File,
    lock: &Lock,
    state: RetainedEvidence<'_>,
) -> io::Result<()> {
    validate_final_anchor_authority_inner(path, directory, lock, state, || {})
}

#[cfg(target_os = "linux")]
fn validate_final_published_authority_inner<F>(
    parent_path: &Path,
    parent: &File,
    path: &Path,
    directory: &File,
    lock: &Lock,
    state: RetainedEvidence<'_>,
    after_evidence: F,
) -> io::Result<()>
where
    F: FnOnce(),
{
    let parent_namespace = NamespaceGuard::arm(parent)?;
    let directory_namespace = NamespaceGuard::arm(directory)?;
    let parent_snapshot = directory_seqlock_start(parent_path, parent)?;
    let directory_snapshot = directory_seqlock_start(path, directory)?;
    lock.validate_current(directory)?;
    validate_named_evidence(
        directory,
        STATE_FILE,
        state.file,
        state.snapshot,
        state.bytes,
        "published BXRC external anchor final authority changed",
    )?;
    after_evidence();
    if !same_directory_identity(file_snapshot(parent)?, parent_snapshot)
        || !same_directory_identity(file_snapshot(directory)?, directory_snapshot)
    {
        return Err(denied(
            "published BXRC external anchor hierarchy changed during validation",
        ));
    }
    // Reopen the parent first and the complete public path last. A child-name
    // mutation also changes the retained parent's sequence metadata.
    directory_seqlock_finish(parent_path, parent, parent_snapshot)?;
    directory_seqlock_finish(path, directory, directory_snapshot)?;
    parent_namespace.assert_quiet()?;
    directory_namespace.assert_quiet()
}

#[cfg(target_os = "linux")]
fn validate_final_published_authority(
    parent_path: &Path,
    parent: &File,
    path: &Path,
    directory: &File,
    lock: &Lock,
    state: RetainedEvidence<'_>,
) -> io::Result<()> {
    validate_final_published_authority_inner(
        parent_path,
        parent,
        path,
        directory,
        lock,
        state,
        || {},
    )
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

fn open_anchor(
    directory: &File,
) -> io::Result<(
    ExternalFloorCustodianClientAnchor,
    File,
    FileSnapshot,
    [u8; EXTERNAL_FLOOR_CUSTODIAN_ANCHOR_RECORD_LEN],
)> {
    open_anchor_with_flags(directory, 0)
}

fn open_anchor_with_flags(
    directory: &File,
    additional_flags: i32,
) -> io::Result<(
    ExternalFloorCustodianClientAnchor,
    File,
    FileSnapshot,
    [u8; EXTERNAL_FLOOR_CUSTODIAN_ANCHOR_RECORD_LEN],
)> {
    reject_temp(directory)?;
    let file = open_at(
        directory.as_raw_fd(),
        STATE_FILE,
        libc::O_RDONLY | libc::O_NONBLOCK | additional_flags,
        0,
    )?;
    validate_file_name(
        directory,
        STATE_FILE,
        &file,
        "BXRC external anchor changed while it was opened",
    )?;
    let before = file_snapshot(&file)?;
    let encoded = read_anchor_bytes(&file)?;
    let after = file_snapshot(&file)?;
    if before != after {
        return Err(denied("BXRC external anchor changed while it was read"));
    }
    Ok((decode(&encoded)?, file, after, encoded))
}

struct ReadHooks<F, G> {
    after_read: F,
    after_evidence: G,
}

fn read_anchor_inner<F, G>(
    directory_path: &Path,
    directory: &File,
    lock: &Lock,
    hooks: ReadHooks<F, G>,
) -> io::Result<ExternalFloorCustodianClientAnchor>
where
    F: FnOnce(),
    G: FnOnce(),
{
    validate_mutation_authority(directory_path, directory, lock)?;
    let (anchor, state, snapshot, bytes) = open_anchor(directory)?;
    (hooks.after_read)();
    validate_mutation_authority(directory_path, directory, lock)?;
    reject_temp(directory)?;
    validate_named_evidence(
        directory,
        STATE_FILE,
        &state,
        snapshot,
        &bytes,
        "BXRC external anchor changed during load",
    )?;
    (hooks.after_evidence)();
    validate_final_anchor_authority(
        directory_path,
        directory,
        lock,
        RetainedEvidence {
            file: &state,
            snapshot,
            bytes: &bytes,
        },
    )?;
    Ok(anchor)
}

#[cfg(target_os = "linux")]
fn inspect_quarantines_inner<F>(
    directory_path: &Path,
    directory: &File,
    lock: &Lock,
    expected_current: ExternalFloorCustodianClientAnchor,
    expected_quarantined: &[ExternalFloorCustodianClientAnchor],
    after_inventory: F,
) -> io::Result<ExternalFloorCustodianAnchorQuarantineInspection>
where
    F: FnOnce(),
{
    let namespace = NamespaceGuard::arm(directory)?;
    let directory_snapshot = directory_seqlock_start(directory_path, directory)?;
    lock.validate_current(directory)?;
    let (current, state, state_snapshot, state_bytes) =
        open_anchor_with_flags(directory, libc::O_NOATIME)?;
    if current != expected_current {
        return Err(denied(
            "current BXRC anchor does not match its offline approval",
        ));
    }

    let names = quarantine_names(directory, expected_quarantined.len())?;
    if names.len() != expected_quarantined.len() {
        return Err(denied(
            "BXRC anchor quarantine inventory does not match offline approvals",
        ));
    }
    let mut evidence = Vec::with_capacity(names.len());
    for name in names {
        let file = open_at_name(
            directory.as_raw_fd(),
            &name,
            libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOATIME,
            0,
        )?;
        validate_file_path_name(
            directory,
            &name,
            &file,
            "BXRC anchor quarantine is not a private retained record",
        )?;
        let before = file_snapshot(&file)?;
        let bytes = read_anchor_bytes(&file)?;
        let after = file_snapshot(&file)?;
        if before != after {
            return Err(denied("BXRC anchor quarantine changed while read"));
        }
        let anchor = decode(&bytes)?;
        evidence.push(QuarantineEvidence {
            name,
            anchor,
            file,
            snapshot: after,
            bytes,
        });
    }
    after_inventory();

    let mut actual = evidence.iter().map(|item| item.anchor).collect::<Vec<_>>();
    actual.sort_by_key(|anchor| (anchor.revision, anchor.commitment));
    if actual != expected_quarantined {
        return Err(denied(
            "BXRC anchor quarantine inventory does not match offline approvals",
        ));
    }

    lock.validate_current(directory)?;
    validate_named_evidence(
        directory,
        STATE_FILE,
        &state,
        state_snapshot,
        &state_bytes,
        "current BXRC anchor changed during quarantine inspection",
    )?;
    for item in &evidence {
        validate_file_path_name(
            directory,
            &item.name,
            &item.file,
            "BXRC anchor quarantine changed during inspection",
        )?;
        if !evidence_matches(&item.file, item.snapshot, 1, &item.bytes) {
            return Err(denied("BXRC anchor quarantine changed during inspection"));
        }
        validate_file_path_name(
            directory,
            &item.name,
            &item.file,
            "BXRC anchor quarantine changed during inspection",
        )?;
    }
    reject_temp(directory)?;
    directory_seqlock_finish(directory_path, directory, directory_snapshot)?;
    namespace.assert_quiet()?;
    Ok(ExternalFloorCustodianAnchorQuarantineInspection {
        current,
        quarantined: actual,
    })
}

#[cfg(target_os = "linux")]
fn install_temp(directory: &File, create: bool) -> io::Result<()> {
    let flags = if create {
        libc::RENAME_NOREPLACE
    } else {
        libc::RENAME_EXCHANGE
    };
    let result = unsafe {
        libc::renameat2(
            directory.as_raw_fd(),
            c_name(TEMP_FILE).as_ptr(),
            directory.as_raw_fd(),
            c_name(STATE_FILE).as_ptr(),
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
    let result = unsafe {
        libc::renameatx_np(
            directory.as_raw_fd(),
            c_name(TEMP_FILE).as_ptr(),
            directory.as_raw_fd(),
            c_name(STATE_FILE).as_ptr(),
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
        "atomic BXRC anchor install unavailable",
    ))
}

#[cfg(target_os = "linux")]
fn publish_directory_noreplace(
    parent: &File,
    staging: &std::ffi::OsStr,
    target: &std::ffi::OsStr,
) -> io::Result<()> {
    let result = unsafe {
        libc::renameat2(
            parent.as_raw_fd(),
            path_name(staging)?.as_ptr(),
            parent.as_raw_fd(),
            path_name(target)?.as_ptr(),
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
    staging: &std::ffi::OsStr,
    target: &std::ffi::OsStr,
) -> io::Result<()> {
    let result = unsafe {
        libc::renameatx_np(
            parent.as_raw_fd(),
            path_name(staging)?.as_ptr(),
            parent.as_raw_fd(),
            path_name(target)?.as_ptr(),
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
    _staging: &std::ffi::OsStr,
    _target: &std::ffi::OsStr,
) -> io::Result<()> {
    Err(Error::new(
        ErrorKind::Unsupported,
        "atomic BXRC anchor directory publication unavailable",
    ))
}

struct WriteHooks<F, G, H> {
    before_install: F,
    before_quarantine: G,
    after_final_readback: H,
}

fn write_anchor_inner<F, G, H>(
    directory_path: &Path,
    directory: &File,
    lock: &Lock,
    anchor: ExternalFloorCustodianClientAnchor,
    expected: Option<ExternalFloorCustodianClientAnchor>,
    hooks: WriteHooks<F, G, H>,
) -> io::Result<()>
where
    F: FnOnce(),
    G: FnOnce(),
    H: FnOnce(),
{
    validate_mutation_authority(directory_path, directory, lock)?;
    reject_temp(directory)?;
    if anchor.commitment == [0; 32] {
        return Err(invalid("BXRC external anchor commitment is all zero"));
    }
    let previous = if let Some(expected) = expected {
        let evidence = open_anchor(directory)?;
        if evidence.0 != expected {
            return Err(denied("BXRC external anchor changed before CAS"));
        }
        Some(evidence)
    } else {
        None
    };
    let encoded = encode(anchor);
    let mut temporary = open_at(
        directory.as_raw_fd(),
        TEMP_FILE,
        libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
        0o600,
    )?;
    validate_file(
        &temporary,
        "temporary BXRC external anchor is not a private single-link file",
    )?;
    temporary.write_all(&encoded)?;
    temporary.sync_all()?;
    let temporary_snapshot = file_snapshot(&temporary)?;
    validate_file_name(
        directory,
        TEMP_FILE,
        &temporary,
        "temporary BXRC external anchor changed before commit",
    )?;
    if !evidence_matches(&temporary, temporary_snapshot, 1, &encoded) {
        return Err(denied(
            "temporary BXRC external anchor changed before commit",
        ));
    }
    (hooks.before_install)();
    if let Some((_, file, snapshot, bytes)) = &previous {
        validate_file_name(
            directory,
            STATE_FILE,
            file,
            "previous BXRC external anchor changed before commit",
        )?;
        if !evidence_matches(file, *snapshot, 1, bytes) {
            return Err(denied(
                "previous BXRC external anchor changed before commit",
            ));
        }
    } else if path_exists_at(directory, STATE_FILE)? {
        return Err(Error::new(
            ErrorKind::AlreadyExists,
            "BXRC external anchor already exists",
        ));
    }
    validate_file_name(
        directory,
        TEMP_FILE,
        &temporary,
        "temporary BXRC external anchor changed before commit",
    )?;
    if !evidence_matches(&temporary, temporary_snapshot, 1, &encoded) {
        return Err(denied(
            "temporary BXRC external anchor changed before commit",
        ));
    }
    validate_mutation_authority(directory_path, directory, lock)?;
    install_temp(directory, previous.is_none())?;
    validate_file_name(
        directory,
        STATE_FILE,
        &temporary,
        "BXRC external anchor changed during commit",
    )?;
    let installed_snapshot = refreshed_evidence(&temporary, temporary_snapshot, 1, &encoded)
        .ok_or_else(|| denied("BXRC external anchor changed during commit"))?;
    let displaced_snapshot = if let Some((_, file, snapshot, bytes)) = &previous {
        validate_file_name(
            directory,
            TEMP_FILE,
            file,
            "previous BXRC external anchor changed during exchange",
        )?;
        Some(
            refreshed_evidence(file, *snapshot, 1, bytes)
                .ok_or_else(|| denied("previous BXRC external anchor changed during exchange"))?,
        )
    } else {
        None
    };
    directory.sync_all()?;
    validate_mutation_authority(directory_path, directory, lock)?;
    validate_file_name(
        directory,
        STATE_FILE,
        &temporary,
        "BXRC external anchor changed before cleanup",
    )?;
    if !evidence_matches(&temporary, installed_snapshot, 1, &encoded) {
        return Err(denied("BXRC external anchor changed before cleanup"));
    }
    if let Some((_, file, _, bytes)) = &previous {
        let displaced_snapshot = displaced_snapshot.expect("snapshot exists with predecessor");
        validate_file_name(
            directory,
            TEMP_FILE,
            file,
            "previous BXRC external anchor changed before cleanup",
        )?;
        if !evidence_matches(file, displaced_snapshot, 1, bytes) {
            return Err(denied(
                "previous BXRC external anchor changed before cleanup",
            ));
        }
        (hooks.before_quarantine)();
        let quarantine_name = loop {
            let candidate = format!(
                ".bxrc-external-anchor.displaced.{}.{}",
                std::process::id(),
                NEXT_QUARANTINE.fetch_add(1, Ordering::Relaxed),
            );
            match publish_directory_noreplace(
                directory,
                std::ffi::OsStr::new(TEMP_FILE),
                std::ffi::OsStr::new(&candidate),
            ) {
                Ok(()) => break candidate,
                Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        };
        validate_file_path_name(
            directory,
            std::ffi::OsStr::new(&quarantine_name),
            file,
            "quarantined predecessor no longer names the displaced BXRC anchor",
        )?;
        let quarantined_snapshot = refreshed_evidence(file, displaced_snapshot, 1, bytes)
            .ok_or_else(|| denied("quarantined predecessor changed during publication"))?;
        directory.sync_all()?;
        validate_file_path_name(
            directory,
            std::ffi::OsStr::new(&quarantine_name),
            file,
            "quarantined predecessor changed while it was synced",
        )?;
        if !evidence_matches(file, quarantined_snapshot, 1, bytes) {
            return Err(denied(
                "quarantined predecessor changed while it was synced",
            ));
        }
    }
    validate_mutation_authority(directory_path, directory, lock)?;
    reject_temp(directory)?;
    validate_file_name(
        directory,
        STATE_FILE,
        &temporary,
        "BXRC external anchor changed during final readback",
    )?;
    if !evidence_matches(&temporary, installed_snapshot, 1, &encoded)
        || decode(&read_anchor_bytes(&temporary)?)? != anchor
    {
        return Err(invalid("BXRC external anchor read-back mismatch"));
    }
    (hooks.after_final_readback)();
    // This is deliberately the last fallible boundary before success and
    // includes the nominal STATE binding, complete snapshot and exact bytes.
    validate_final_anchor_authority(
        directory_path,
        directory,
        lock,
        RetainedEvidence {
            file: &temporary,
            snapshot: installed_snapshot,
            bytes: &encoded,
        },
    )?;
    Ok(())
}

/// A create-once, process-exclusive Unix implementation of the external BXRC
/// client anchor CAS.
///
/// Its directory must live in an independently administered rollback domain.
/// The checksum detects corruption, not malicious rewriting or rollback.
pub struct UnixExternalFloorCustodianAnchorStore {
    directory_path: PathBuf,
    directory: File,
    _lock: Lock,
    gate: Mutex<()>,
}

impl UnixExternalFloorCustodianAnchorStore {
    /// Creates a new private directory and installs the externally approved
    /// initial anchor. Existing paths are never adopted.
    ///
    /// Secure provisioning requires Linux `inotify`. On macOS and other
    /// non-Linux targets this fails with [`ErrorKind::Unsupported`] before
    /// creating the requested path.
    pub fn provision(path: &Path, initial: ExternalFloorCustodianClientAnchor) -> io::Result<Self> {
        #[cfg(target_os = "linux")]
        {
            Self::provision_inner(path, initial, |_| {}, |_| {}, |_| {})
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (path, initial);
            Err(Error::new(
                ErrorKind::Unsupported,
                "secure BXRC external anchor provisioning requires Linux inotify",
            ))
        }
    }

    #[cfg(target_os = "linux")]
    fn provision_inner<F, G, H>(
        path: &Path,
        initial: ExternalFloorCustodianClientAnchor,
        before_open: F,
        before_publish: G,
        after_readback: H,
    ) -> io::Result<Self>
    where
        F: FnOnce(&Path),
        G: FnOnce(&Path),
        H: FnOnce(&Path),
    {
        if !path.is_absolute() || initial.commitment == [0; 32] {
            return Err(invalid(
                "invalid BXRC external anchor provisioning configuration",
            ));
        }
        let parent_path = path
            .parent()
            .ok_or_else(|| invalid("BXRC external anchor directory has no parent"))?;
        let target_name = path
            .file_name()
            .ok_or_else(|| invalid("BXRC external anchor directory has no final name"))?;
        let parent = open_directory(parent_path)?;
        let (staging_path, staging_name, directory, created) = loop {
            let staging_name = random_staging_name()?;
            let staging_path = parent_path.join(&staging_name);
            let parent_namespace = NamespaceGuard::arm(&parent)?;
            match mkdir_at(&parent, std::ffi::OsStr::new(&staging_name), 0o700) {
                Ok(()) => {
                    // Capture the retained parent immediately after mkdirat.
                    // Any substitution before the child fd is opened mutates
                    // this sequence snapshot and is rejected below.
                    let parent_after_mkdir = file_snapshot(&parent)?;
                    before_open(&staging_path);
                    let directory = open_at_name(
                        parent.as_raw_fd(),
                        std::ffi::OsStr::new(&staging_name),
                        libc::O_RDONLY | libc::O_DIRECTORY,
                        0,
                    )?;
                    validate_directory(&directory)?;
                    let created = file_snapshot(&directory)?;
                    parent_namespace
                        .assert_expected_directory_create(std::ffi::OsStr::new(&staging_name))?;
                    if !same_directory_identity(file_snapshot(&parent)?, parent_after_mkdir) {
                        return Err(denied(
                            "new BXRC external anchor directory changed before retention",
                        ));
                    }
                    break (staging_path, staging_name, directory, created);
                }
                Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        };
        validate_directory_name(&staging_path, &directory)?;
        if file_snapshot(&directory)? != created {
            return Err(denied(
                "new BXRC external anchor directory changed before retention",
            ));
        }
        let lock = Lock::acquire(&directory)?;
        write_anchor_inner(
            &staging_path,
            &directory,
            &lock,
            initial,
            None,
            WriteHooks {
                before_install: || {},
                before_quarantine: || {},
                after_final_readback: || {},
            },
        )?;
        let (_, state, snapshot, bytes) = open_anchor(&directory)?;
        before_publish(&staging_path);
        validate_directory_name(parent_path, &parent)?;
        validate_mutation_authority(&staging_path, &directory, &lock)?;
        validate_file_name(
            &directory,
            STATE_FILE,
            &state,
            "staged BXRC external anchor changed before publication",
        )?;
        if !evidence_matches(&state, snapshot, 1, &bytes) {
            return Err(denied(
                "staged BXRC external anchor changed before publication",
            ));
        }
        publish_directory_noreplace(&parent, std::ffi::OsStr::new(&staging_name), target_name)?;
        parent.sync_all()?;
        validate_directory_name(parent_path, &parent)?;
        validate_directory_name(path, &directory)?;
        lock.validate_current(&directory)?;
        validate_file_name(
            &directory,
            STATE_FILE,
            &state,
            "published BXRC external anchor does not match staged evidence",
        )?;
        if !evidence_matches(&state, snapshot, 1, &bytes) {
            return Err(denied(
                "published BXRC external anchor does not match staged evidence",
            ));
        }
        match fs::symlink_metadata(&staging_path) {
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Ok(_) => {
                return Err(denied(
                    "published BXRC external anchor staging name still exists",
                ))
            }
            Err(error) => return Err(error),
        }
        after_readback(path);
        // Parent and public-name authority are the final provisioning boundary.
        validate_final_published_authority(
            parent_path,
            &parent,
            path,
            &directory,
            &lock,
            RetainedEvidence {
                file: &state,
                snapshot,
                bytes: &bytes,
            },
        )?;
        Ok(Self {
            directory_path: path.to_path_buf(),
            directory,
            _lock: lock,
            gate: Mutex::new(()),
        })
    }

    /// Verifies an offline approval before creating a store for its exact
    /// anchor. No signing key is loaded or accepted by this process.
    pub fn provision_approved(
        path: &Path,
        expected_deployment_id: [u8; 32],
        verifying_key: [u8; 32],
        approval: ExternalFloorCustodianAnchorApproval,
    ) -> io::Result<Self> {
        let initial = verify_external_floor_custodian_anchor_approval(
            expected_deployment_id,
            verifying_key,
            approval,
        )?;
        Self::provision(path, initial)
    }

    /// Opens an existing validated store and retains its exclusive process
    /// lock for this instance's lifetime.
    pub fn open(path: &Path) -> io::Result<Self> {
        let directory = open_directory(path)?;
        let lock = Lock::acquire(&directory)?;
        read_anchor_inner(
            path,
            &directory,
            &lock,
            ReadHooks {
                after_read: || {},
                after_evidence: || {},
            },
        )?;
        Ok(Self {
            directory_path: path.to_path_buf(),
            directory,
            _lock: lock,
            gate: Mutex::new(()),
        })
    }

    /// Opens a store only when its current value exactly matches a valid
    /// offline approval for the independently pinned deployment and key.
    /// This is intended for provisioning and operator inspection, not for
    /// silently adopting a value discovered on local disk.
    pub fn open_approved(
        path: &Path,
        expected_deployment_id: [u8; 32],
        verifying_key: [u8; 32],
        approval: ExternalFloorCustodianAnchorApproval,
    ) -> io::Result<Self> {
        let approved = verify_external_floor_custodian_anchor_approval(
            expected_deployment_id,
            verifying_key,
            approval,
        )?;
        let store = Self::open(path)?;
        if store.load()? != approved {
            return Err(denied(
                "BXRC external anchor does not match the offline approval",
            ));
        }
        Ok(store)
    }

    /// Inspects the exact current anchor and complete predecessor-quarantine
    /// inventory against independently supplied offline approvals.
    ///
    /// This operation is deliberately read-only: it never unlinks, renames,
    /// or treats a pathname discovered on disk as cleanup authority. It also
    /// requires the persistent lock to exist and be exclusively acquirable,
    /// so operators must stop every writer first. Linux `inotify` protects the
    /// complete enumeration and evidence-validation window; other platforms
    /// fail with [`ErrorKind::Unsupported`].
    pub fn inspect_quarantines_approved(
        path: &Path,
        expected_deployment_id: [u8; 32],
        verifying_key: [u8; 32],
        current_approval: ExternalFloorCustodianAnchorApproval,
        quarantine_approvals: &[ExternalFloorCustodianAnchorQuarantineApproval],
    ) -> io::Result<ExternalFloorCustodianAnchorQuarantineInspection> {
        let inventory = approved_quarantine_inventory(
            expected_deployment_id,
            verifying_key,
            current_approval,
            quarantine_approvals,
        )?;

        #[cfg(target_os = "linux")]
        {
            let quarantined = inventory
                .records
                .iter()
                .map(|(anchor, _)| *anchor)
                .collect::<Vec<_>>();
            let directory = open_directory(path)?;
            let lock = Lock::acquire_existing(&directory)?;
            inspect_quarantines_inner(
                path,
                &directory,
                &lock,
                inventory.current,
                &quarantined,
                || {},
            )
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (path, inventory);
            Err(Error::new(
                ErrorKind::Unsupported,
                "secure BXRC anchor quarantine inspection requires Linux inotify",
            ))
        }
    }

    /// Performs the same read-only Linux inspection while requiring an exact
    /// externally retained quarantine-history checkpoint.
    ///
    /// The checkpoint must first be derived from the supplied approvals with
    /// [`external_floor_custodian_expected_initial_quarantine_checkpoint`] or
    /// [`external_floor_custodian_expected_next_quarantine_checkpoint`]. This
    /// method never discovers a checkpoint from disk and never writes one into
    /// the inspected rollback domain.
    pub fn inspect_quarantines_checkpointed(
        path: &Path,
        expected_checkpoint: ExternalFloorCustodianAnchorQuarantineCheckpoint,
        current_approval: ExternalFloorCustodianAnchorApproval,
        quarantine_approvals: &[ExternalFloorCustodianAnchorQuarantineApproval],
    ) -> io::Result<ExternalFloorCustodianAnchorQuarantineReceipt> {
        validate_quarantine_checkpoint(expected_checkpoint)?;
        let inventory = approved_quarantine_inventory(
            expected_checkpoint.deployment_id,
            expected_checkpoint.current_verifying_key,
            current_approval,
            quarantine_approvals,
        )?;
        if inventory.current != expected_checkpoint.current
            || inventory.records.len() as u64 != expected_checkpoint.quarantine_count
            || inventory.history_hash != expected_checkpoint.quarantine_history_hash
            || inventory.inventory_hash != expected_checkpoint.inventory_hash
        {
            return Err(denied(
                "BXRC anchor quarantine inventory does not match retained checkpoint",
            ));
        }

        #[cfg(target_os = "linux")]
        {
            let quarantined = inventory
                .records
                .iter()
                .map(|(anchor, _)| *anchor)
                .collect::<Vec<_>>();
            let directory = open_directory(path)?;
            let lock = Lock::acquire_existing(&directory)?;
            let inspection = inspect_quarantines_inner(
                path,
                &directory,
                &lock,
                inventory.current,
                &quarantined,
                || {},
            )?;
            Ok(ExternalFloorCustodianAnchorQuarantineReceipt {
                checkpoint: expected_checkpoint,
                inspection,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (path, inventory);
            Err(Error::new(
                ErrorKind::Unsupported,
                "secure BXRC anchor quarantine inspection requires Linux inotify",
            ))
        }
    }

    /// Opens only the exact anchor named by a valid continuity transition.
    /// The returned public key is authenticated by both the independently
    /// pinned prior authority and the next authority, and can be retained out
    /// of band for the following transition. No private key enters runtime.
    pub fn open_continuity_approved(
        path: &Path,
        expected_deployment_id: [u8; 32],
        expected_previous_verifying_key: [u8; 32],
        expected_previous_anchor: ExternalFloorCustodianClientAnchor,
        approval: ExternalFloorCustodianAnchorContinuityApproval,
    ) -> io::Result<(Self, [u8; 32])> {
        let (approved_anchor, next_verifying_key) =
            verify_external_floor_custodian_anchor_continuity(
                expected_deployment_id,
                expected_previous_verifying_key,
                expected_previous_anchor,
                approval,
            )?;
        let store = Self::open(path)?;
        if store.load()? != approved_anchor {
            return Err(denied(
                "BXRC external anchor does not match the continuity approval",
            ));
        }
        Ok((store, next_verifying_key))
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
        read_anchor_inner(
            &self.directory_path,
            &self.directory,
            &self._lock,
            ReadHooks {
                after_read: || {},
                after_evidence: || {},
            },
        )
    }

    fn compare_and_swap(
        &self,
        expected: ExternalFloorCustodianClientAnchor,
        replacement: ExternalFloorCustodianClientAnchor,
    ) -> io::Result<ExternalFloorCustodianAnchorCasOutcome> {
        let _gate = self.gate()?;
        let actual = read_anchor_inner(
            &self.directory_path,
            &self.directory,
            &self._lock,
            ReadHooks {
                after_read: || {},
                after_evidence: || {},
            },
        )?;
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
        write_anchor_inner(
            &self.directory_path,
            &self.directory,
            &self._lock,
            replacement,
            Some(expected),
            WriteHooks {
                before_install: || {},
                before_quarantine: || {},
                after_final_readback: || {},
            },
        )?;
        Ok(ExternalFloorCustodianAnchorCasOutcome::Committed)
    }
}

#[cfg(test)]
mod quarantine_checkpoint_tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    fn signed(
        signer: &Ed25519KeyPair,
        deployment_id: [u8; 32],
        anchor: ExternalFloorCustodianClientAnchor,
    ) -> ExternalFloorCustodianAnchorApproval {
        let message = external_floor_custodian_anchor_approval_message(deployment_id, anchor);
        let mut signature = [0; 64];
        signature.copy_from_slice(signer.sign(&message).as_ref());
        ExternalFloorCustodianAnchorApproval {
            deployment_id,
            anchor,
            signature,
        }
    }

    #[test]
    fn checkpoint_chain_rejects_tampering_and_current_rollback() {
        let document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let signer = Ed25519KeyPair::from_pkcs8(document.as_ref()).unwrap();
        let key = signer.public_key().as_ref().try_into().unwrap();
        let deployment = [0x91; 32];
        let old = ExternalFloorCustodianClientAnchor {
            revision: 7,
            commitment: [0x71; 32],
        };
        let current = ExternalFloorCustodianClientAnchor {
            revision: 8,
            commitment: [0x72; 32],
        };
        let quarantine = ExternalFloorCustodianAnchorQuarantineApproval {
            verifying_key: key,
            approval: signed(&signer, deployment, old),
        };
        let initial = external_floor_custodian_expected_initial_quarantine_checkpoint(
            deployment,
            key,
            signed(&signer, deployment, current),
            &[quarantine],
        )
        .unwrap();
        verify_external_floor_custodian_quarantine_checkpoint(initial).unwrap();
        let next = external_floor_custodian_expected_next_quarantine_checkpoint(
            initial,
            key,
            signed(&signer, deployment, current),
            &[quarantine],
        )
        .unwrap();
        assert_eq!(next.previous_checkpoint_hash, initial.checkpoint_hash);
        assert!(
            external_floor_custodian_expected_next_quarantine_checkpoint(
                initial,
                key,
                signed(&signer, deployment, current),
                &[],
            )
            .is_err()
        );
        let advanced = ExternalFloorCustodianClientAnchor {
            revision: 9,
            commitment: [0x73; 32],
        };
        let other_document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let other_signer = Ed25519KeyPair::from_pkcs8(other_document.as_ref()).unwrap();
        let other_key = other_signer.public_key().as_ref().try_into().unwrap();
        assert!(
            external_floor_custodian_expected_next_quarantine_checkpoint(
                initial,
                other_key,
                signed(&other_signer, deployment, current),
                &[quarantine],
            )
            .is_err()
        );
        let current_only = ExternalFloorCustodianAnchorQuarantineApproval {
            verifying_key: key,
            approval: signed(&signer, deployment, current),
        };
        assert!(
            external_floor_custodian_expected_next_quarantine_checkpoint(
                initial,
                key,
                signed(&signer, deployment, advanced),
                &[current_only],
            )
            .is_err()
        );
        let wrong_authority_current = ExternalFloorCustodianAnchorQuarantineApproval {
            verifying_key: other_key,
            approval: signed(&other_signer, deployment, current),
        };
        assert!(
            external_floor_custodian_expected_next_quarantine_checkpoint(
                initial,
                key,
                signed(&signer, deployment, advanced),
                &[quarantine, wrong_authority_current],
            )
            .is_err()
        );
        let final_anchor = ExternalFloorCustodianClientAnchor {
            revision: 10,
            commitment: [0x74; 32],
        };
        let wrong_authority_intermediate = ExternalFloorCustodianAnchorQuarantineApproval {
            verifying_key: other_key,
            approval: signed(&other_signer, deployment, advanced),
        };
        assert!(
            external_floor_custodian_expected_next_quarantine_checkpoint(
                initial,
                key,
                signed(&signer, deployment, final_anchor),
                &[quarantine, current_only, wrong_authority_intermediate],
            )
            .is_err()
        );
        assert!(
            external_floor_custodian_expected_next_quarantine_checkpoint(
                next,
                key,
                signed(&signer, deployment, old),
                &[],
            )
            .is_err()
        );
        let mut forged = next;
        forged.inventory_hash[0] ^= 1;
        assert!(verify_external_floor_custodian_quarantine_checkpoint(forged).is_err());
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::fs::DirBuilder;
    use std::os::unix::fs::DirBuilderExt;

    static NEXT_TEST: AtomicU64 = AtomicU64::new(0);

    fn anchor(revision: u64) -> ExternalFloorCustodianClientAnchor {
        ExternalFloorCustodianClientAnchor {
            revision,
            commitment: [revision as u8; 32],
        }
    }

    fn test_path(label: &str) -> PathBuf {
        let parent = std::env::temp_dir().join(format!(
            "bloch-anchor-{label}-{}-{}",
            std::process::id(),
            NEXT_TEST.fetch_add(1, Ordering::Relaxed),
        ));
        let mut builder = DirBuilder::new();
        builder.mode(0o700);
        builder.create(&parent).unwrap();
        parent.join("store")
    }

    fn create_private_file(path: &Path, bytes: &[u8]) {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
    }

    fn set_old_atime(path: &Path, directory: bool) -> (i64, i64) {
        let flags =
            libc::O_NOFOLLOW | libc::O_NOATIME | if directory { libc::O_DIRECTORY } else { 0 };
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(flags)
            .open(path)
            .unwrap();
        let metadata = file.metadata().unwrap();
        let times = [
            libc::timespec {
                tv_sec: 946_684_800,
                tv_nsec: 123_456_789,
            },
            libc::timespec {
                tv_sec: metadata.mtime(),
                tv_nsec: metadata.mtime_nsec(),
            },
        ];
        // SAFETY: the descriptor and two-element timespec array are valid.
        assert_eq!(
            unsafe { libc::futimens(file.as_raw_fd(), times.as_ptr()) },
            0
        );
        let metadata = file.metadata().unwrap();
        (metadata.atime(), metadata.atime_nsec())
    }

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
        assert_eq!(
            unsafe { libc::futimens(file.as_raw_fd(), times.as_ptr()) },
            0
        );
        file.sync_all().unwrap();
    }

    #[test]
    fn load_rejects_state_path_replaced_after_bytes_are_read() {
        let path = test_path("load-state-race");
        let store = UnixExternalFloorCustodianAnchorStore::provision(&path, anchor(1)).unwrap();
        let state_path = path.join(STATE_FILE);
        let displaced = path.join("displaced-state");
        let result = read_anchor_inner(
            &path,
            &store.directory,
            &store._lock,
            ReadHooks {
                after_read: || {
                    let bytes = fs::read(&state_path).unwrap();
                    fs::rename(&state_path, &displaced).unwrap();
                    create_private_file(&state_path, &bytes);
                },
                after_evidence: || {},
            },
        );
        assert!(result.is_err());
        drop(store);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn load_rebinds_state_after_the_post_evidence_hook() {
        let path = test_path("load-post-evidence-state-race");
        let store = UnixExternalFloorCustodianAnchorStore::provision(&path, anchor(1)).unwrap();
        let state_path = path.join(STATE_FILE);
        let retained = path.join("race-retained-state");
        let result = read_anchor_inner(
            &path,
            &store.directory,
            &store._lock,
            ReadHooks {
                after_read: || {},
                after_evidence: || {
                    let bytes = fs::read(&state_path).unwrap();
                    fs::rename(&state_path, &retained).unwrap();
                    create_private_file(&state_path, &bytes);
                },
            },
        );
        assert!(result.is_err());
        assert!(retained.exists());
        drop(store);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn cas_never_clobbers_state_replaced_before_exchange() {
        let path = test_path("cas-state-race");
        let initial = anchor(1);
        let store = UnixExternalFloorCustodianAnchorStore::provision(&path, initial).unwrap();
        let state_path = path.join(STATE_FILE);
        let displaced = path.join("displaced-state");
        let replacement_inode = RefCell::new(None);
        let result = write_anchor_inner(
            &path,
            &store.directory,
            &store._lock,
            anchor(2),
            Some(initial),
            WriteHooks {
                before_install: || {
                    let bytes = fs::read(&state_path).unwrap();
                    fs::rename(&state_path, &displaced).unwrap();
                    create_private_file(&state_path, &bytes);
                    *replacement_inode.borrow_mut() =
                        Some(fs::metadata(&state_path).unwrap().ino());
                },
                before_quarantine: || {},
                after_final_readback: || {},
            },
        );
        assert!(result.is_err());
        assert_eq!(
            fs::metadata(&state_path).unwrap().ino(),
            replacement_inode.into_inner().unwrap()
        );
        assert!(path.join(TEMP_FILE).exists());
        drop(store);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn cas_detects_same_inode_predecessor_rewrite_with_restored_mtime() {
        let path = test_path("cas-ctime-race");
        let initial = anchor(1);
        let store = UnixExternalFloorCustodianAnchorStore::provision(&path, initial).unwrap();
        let result = write_anchor_inner(
            &path,
            &store.directory,
            &store._lock,
            anchor(2),
            Some(initial),
            WriteHooks {
                before_install: || rewrite_same_inode_restoring_mtime(&path.join(STATE_FILE)),
                before_quarantine: || {},
                after_final_readback: || {},
            },
        );
        assert!(result.is_err());
        assert!(path.join(TEMP_FILE).exists());
        drop(store);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn write_revalidates_directory_authority_as_last_success_boundary() {
        let path = test_path("final-authority-race");
        let initial = anchor(1);
        let store = UnixExternalFloorCustodianAnchorStore::provision(&path, initial).unwrap();
        let displaced = path.with_extension("displaced");
        let result = write_anchor_inner(
            &path,
            &store.directory,
            &store._lock,
            anchor(2),
            Some(initial),
            WriteHooks {
                before_install: || {},
                before_quarantine: || {},
                after_final_readback: || {
                    fs::rename(&path, &displaced).unwrap();
                    let mut builder = DirBuilder::new();
                    builder.mode(0o700);
                    builder.create(&path).unwrap();
                },
            },
        );
        assert!(result.is_err());
        drop(store);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn cas_rebinds_state_after_the_final_readback_hook() {
        let path = test_path("final-state-race");
        let initial = anchor(1);
        let store = UnixExternalFloorCustodianAnchorStore::provision(&path, initial).unwrap();
        let state_path = path.join(STATE_FILE);
        let retained_candidate = path.join("race-retained-candidate");
        let result = write_anchor_inner(
            &path,
            &store.directory,
            &store._lock,
            anchor(2),
            Some(initial),
            WriteHooks {
                before_install: || {},
                before_quarantine: || {},
                after_final_readback: || {
                    let bytes = fs::read(&state_path).unwrap();
                    fs::rename(&state_path, &retained_candidate).unwrap();
                    create_private_file(&state_path, &bytes);
                },
            },
        );
        assert!(result.is_err());
        assert!(retained_candidate.exists());
        drop(store);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn mutation_authority_rechecks_directory_after_lock_validation() {
        let path = test_path("post-lock-directory-race");
        let store = UnixExternalFloorCustodianAnchorStore::provision(&path, anchor(1)).unwrap();
        let displaced = path.with_extension("displaced");
        let result =
            validate_mutation_authority_inner(&path, &store.directory, &store._lock, || {
                fs::rename(&path, &displaced).unwrap();
                let mut builder = DirBuilder::new();
                builder.mode(0o700);
                builder.create(&path).unwrap();
            });
        assert!(result.is_err());
        drop(store);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn kernel_guard_detects_state_swap_even_when_directory_mtime_is_restored() {
        let path = test_path("seqlock-state-race");
        let store = UnixExternalFloorCustodianAnchorStore::provision(&path, anchor(1)).unwrap();
        let (_, state, snapshot, bytes) = open_anchor(&store.directory).unwrap();
        let directory_metadata = store.directory.metadata().unwrap();
        let state_path = path.join(STATE_FILE);
        let retained = path.join("race-retained-state");
        let result = validate_final_anchor_authority_inner(
            &path,
            &store.directory,
            &store._lock,
            RetainedEvidence {
                file: &state,
                snapshot,
                bytes: &bytes,
            },
            || {
                fs::rename(&state_path, &retained).unwrap();
                create_private_file(&state_path, &bytes);
                let times = [
                    libc::timespec {
                        tv_sec: directory_metadata.atime(),
                        tv_nsec: directory_metadata.atime_nsec(),
                    },
                    libc::timespec {
                        tv_sec: directory_metadata.mtime(),
                        tv_nsec: directory_metadata.mtime_nsec(),
                    },
                ];
                assert_eq!(
                    unsafe { libc::futimens(store.directory.as_raw_fd(), times.as_ptr()) },
                    0
                );
            },
        );
        assert!(result.is_err());
        assert!(retained.exists());
        drop(store);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn published_seqlock_detects_state_swap_after_internal_evidence() {
        let path = test_path("published-seqlock-state-race");
        let parent_path = path.parent().unwrap();
        let store = UnixExternalFloorCustodianAnchorStore::provision(&path, anchor(1)).unwrap();
        let parent = open_directory(parent_path).unwrap();
        let (_, state, snapshot, bytes) = open_anchor(&store.directory).unwrap();
        let state_path = path.join(STATE_FILE);
        let retained = path.join("race-retained-state");
        let result = validate_final_published_authority_inner(
            parent_path,
            &parent,
            &path,
            &store.directory,
            &store._lock,
            RetainedEvidence {
                file: &state,
                snapshot,
                bytes: &bytes,
            },
            || {
                fs::rename(&state_path, &retained).unwrap();
                create_private_file(&state_path, &bytes);
            },
        );
        assert!(result.is_err());
        assert!(retained.exists());
        drop(store);
        fs::remove_dir_all(parent_path).unwrap();
    }

    #[test]
    fn cas_quarantines_without_unlinking_a_substituted_temp_path() {
        let path = test_path("quarantine-substitution");
        let initial = anchor(1);
        let store = UnixExternalFloorCustodianAnchorStore::provision(&path, initial).unwrap();
        let retained_predecessor = path.join("race-retained-predecessor");
        let result = write_anchor_inner(
            &path,
            &store.directory,
            &store._lock,
            anchor(2),
            Some(initial),
            WriteHooks {
                before_install: || {},
                before_quarantine: || {
                    let temporary = path.join(TEMP_FILE);
                    let bytes = fs::read(&temporary).unwrap();
                    fs::rename(&temporary, &retained_predecessor).unwrap();
                    create_private_file(&temporary, &bytes);
                },
                after_final_readback: || {},
            },
        );
        assert!(result.is_err());
        assert!(retained_predecessor.exists());
        assert!(fs::read_dir(&path).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".bxrc-external-anchor.displaced.")
        }));
        drop(store);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn successful_cas_retains_each_predecessor_in_offline_quarantine() {
        let path = test_path("successful-quarantine");
        let store = UnixExternalFloorCustodianAnchorStore::provision(&path, anchor(1)).unwrap();
        assert_eq!(
            store.compare_and_swap(anchor(1), anchor(2)).unwrap(),
            ExternalFloorCustodianAnchorCasOutcome::Committed
        );
        assert_eq!(
            store.compare_and_swap(anchor(2), anchor(3)).unwrap(),
            ExternalFloorCustodianAnchorCasOutcome::Committed
        );
        let mut quarantined = fs::read_dir(&path)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".bxrc-external-anchor.displaced.")
            })
            .map(|entry| decode(&fs::read(entry.path()).unwrap()).unwrap())
            .collect::<Vec<_>>();
        quarantined.sort_by_key(|value| value.revision);
        assert_eq!(quarantined, vec![anchor(1), anchor(2)]);
        drop(store);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn quarantine_inspection_rejects_same_bytes_path_replacement() {
        let path = test_path("quarantine-inspection-race");
        let store = UnixExternalFloorCustodianAnchorStore::provision(&path, anchor(1)).unwrap();
        assert_eq!(
            store.compare_and_swap(anchor(1), anchor(2)).unwrap(),
            ExternalFloorCustodianAnchorCasOutcome::Committed
        );
        let quarantine = fs::read_dir(&path)
            .unwrap()
            .filter_map(Result::ok)
            .find(|entry| entry.file_name().as_bytes().starts_with(QUARANTINE_PREFIX))
            .unwrap()
            .path();
        let retained = path.join("retained-quarantine-race");
        let result = inspect_quarantines_inner(
            &path,
            &store.directory,
            &store._lock,
            anchor(2),
            &[anchor(1)],
            || {
                let bytes = fs::read(&quarantine).unwrap();
                fs::rename(&quarantine, &retained).unwrap();
                create_private_file(&quarantine, &bytes);
            },
        );
        assert!(result.is_err());
        assert!(retained.exists());
        drop(store);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn quarantine_inspection_preserves_all_record_and_directory_atimes() {
        let path = test_path("quarantine-inspection-atime");
        let store = UnixExternalFloorCustodianAnchorStore::provision(&path, anchor(1)).unwrap();
        assert_eq!(
            store.compare_and_swap(anchor(1), anchor(2)).unwrap(),
            ExternalFloorCustodianAnchorCasOutcome::Committed
        );
        let quarantine = fs::read_dir(&path)
            .unwrap()
            .filter_map(Result::ok)
            .find(|entry| entry.file_name().as_bytes().starts_with(QUARANTINE_PREFIX))
            .unwrap()
            .path();
        let state = path.join(STATE_FILE);
        let state_atime = set_old_atime(&state, false);
        let quarantine_atime = set_old_atime(&quarantine, false);
        // Set the directory last because discovering the records reads it.
        let directory_atime = set_old_atime(&path, true);

        let inspected = inspect_quarantines_inner(
            &path,
            &store.directory,
            &store._lock,
            anchor(2),
            &[anchor(1)],
            || {},
        )
        .unwrap();
        assert_eq!(inspected.current, anchor(2));
        assert_eq!(inspected.quarantined, vec![anchor(1)]);
        let atime = |target: &Path| {
            let metadata = fs::metadata(target).unwrap();
            (metadata.atime(), metadata.atime_nsec())
        };
        assert_eq!(atime(&state), state_atime);
        assert_eq!(atime(&quarantine), quarantine_atime);
        assert_eq!(atime(&path), directory_atime);
        drop(store);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn provisioning_never_adopts_target_raced_before_publication() {
        let path = test_path("provision-target-race");
        let staging = RefCell::new(None);
        let result = UnixExternalFloorCustodianAnchorStore::provision_inner(
            &path,
            anchor(1),
            |_| {},
            |candidate| {
                *staging.borrow_mut() = Some(candidate.to_path_buf());
                let mut builder = DirBuilder::new();
                builder.mode(0o700);
                builder.create(&path).unwrap();
            },
            |_| {},
        );
        assert!(matches!(result, Err(ref error) if error.kind() == ErrorKind::AlreadyExists));
        assert!(fs::read_dir(&path).unwrap().next().is_none());
        assert!(staging.into_inner().unwrap().join(STATE_FILE).exists());
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn provisioning_rejects_staging_directory_replaced_before_open() {
        let path = test_path("provision-open-race");
        let displaced = RefCell::new(None);
        let replacement = RefCell::new(None);
        let result = UnixExternalFloorCustodianAnchorStore::provision_inner(
            &path,
            anchor(1),
            |candidate| {
                let moved = candidate.with_extension("displaced");
                fs::rename(candidate, &moved).unwrap();
                let mut builder = DirBuilder::new();
                builder.mode(0o700);
                builder.create(candidate).unwrap();
                *displaced.borrow_mut() = Some(moved);
                *replacement.borrow_mut() = Some(candidate.to_path_buf());
            },
            |_| {},
            |_| {},
        );
        assert!(result.is_err());
        assert!(!path.exists());
        fs::remove_dir_all(displaced.into_inner().unwrap()).unwrap();
        fs::remove_dir_all(replacement.into_inner().unwrap()).unwrap();
        fs::remove_dir(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn provisioning_revalidates_public_name_after_all_readbacks() {
        let path = test_path("provision-final-public-race");
        let displaced = path.with_extension("displaced");
        let result = UnixExternalFloorCustodianAnchorStore::provision_inner(
            &path,
            anchor(1),
            |_| {},
            |_| {},
            |_| {
                fs::rename(&path, &displaced).unwrap();
                let mut builder = DirBuilder::new();
                builder.mode(0o700);
                builder.create(&path).unwrap();
            },
        );
        assert!(result.is_err());
        assert!(displaced.join(STATE_FILE).exists());
        assert!(fs::read_dir(&path).unwrap().next().is_none());
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn provisioning_rebinds_state_after_the_final_readback_hook() {
        let path = test_path("provision-final-state-race");
        let retained_candidate = path.join("race-retained-candidate");
        let result = UnixExternalFloorCustodianAnchorStore::provision_inner(
            &path,
            anchor(1),
            |_| {},
            |_| {},
            |_| {
                let state_path = path.join(STATE_FILE);
                let bytes = fs::read(&state_path).unwrap();
                fs::rename(&state_path, &retained_candidate).unwrap();
                create_private_file(&state_path, &bytes);
            },
        );
        assert!(result.is_err());
        assert!(retained_candidate.exists());
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
}

#[cfg(all(test, not(target_os = "linux")))]
mod unsupported_provision_tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    #[test]
    fn provisioning_fails_unsupported_before_creating_any_path() {
        let path =
            std::env::temp_dir().join(format!("bloch-anchor-unsupported-{}", std::process::id()));
        let result = UnixExternalFloorCustodianAnchorStore::provision(
            &path,
            ExternalFloorCustodianClientAnchor {
                revision: 1,
                commitment: [0x41; 32],
            },
        );
        assert!(matches!(result, Err(ref error) if error.kind() == ErrorKind::Unsupported));
        assert!(!path.exists());
    }

    #[test]
    fn quarantine_inspection_fails_unsupported_before_opening_any_path() {
        let path = std::env::temp_dir().join(format!(
            "bloch-anchor-inspection-unsupported-{}",
            std::process::id()
        ));
        let deployment_id = [0x51; 32];
        let anchor = ExternalFloorCustodianClientAnchor {
            revision: 1,
            commitment: [0x52; 32],
        };
        let document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let signer = Ed25519KeyPair::from_pkcs8(document.as_ref()).unwrap();
        let message = external_floor_custodian_anchor_approval_message(deployment_id, anchor);
        let mut signature = [0_u8; 64];
        signature.copy_from_slice(signer.sign(&message).as_ref());
        let result = UnixExternalFloorCustodianAnchorStore::inspect_quarantines_approved(
            &path,
            deployment_id,
            signer.public_key().as_ref().try_into().unwrap(),
            ExternalFloorCustodianAnchorApproval {
                deployment_id,
                anchor,
                signature,
            },
            &[],
        );
        assert!(matches!(result, Err(ref error) if error.kind() == ErrorKind::Unsupported));
        assert!(!path.exists());
    }
}
