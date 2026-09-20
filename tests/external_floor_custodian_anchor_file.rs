// SPDX-License-Identifier: MIT OR Apache-2.0
#![cfg(target_os = "linux")]

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{symlink, OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use bloch_l2_bridge::{
    external_floor_custodian_anchor_approval_message,
    external_floor_custodian_anchor_continuity_acceptance_message,
    external_floor_custodian_anchor_continuity_authorization_message,
    external_floor_custodian_expected_initial_quarantine_checkpoint,
    external_floor_custodian_expected_next_quarantine_checkpoint,
    verify_external_floor_custodian_anchor_approval,
    verify_external_floor_custodian_anchor_continuity, ExternalFloorCustodianAnchorApproval,
    ExternalFloorCustodianAnchorCasOutcome, ExternalFloorCustodianAnchorContinuityApproval,
    ExternalFloorCustodianAnchorQuarantineApproval, ExternalFloorCustodianAnchorStore,
    ExternalFloorCustodianClientAnchor, UnixExternalFloorCustodianAnchorStore,
    EXTERNAL_FLOOR_CUSTODIAN_ANCHOR_RECORD_LEN,
};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct Temp {
    root: PathBuf,
    store: PathBuf,
}

impl Temp {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "bloch-bxrc-anchor-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        Self {
            store: root.join("external"),
            root,
        }
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}

fn anchor(revision: u64, byte: u8) -> ExternalFloorCustodianClientAnchor {
    ExternalFloorCustodianClientAnchor {
        revision,
        commitment: [byte; 32],
    }
}

fn signer() -> Ed25519KeyPair {
    let document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    Ed25519KeyPair::from_pkcs8(document.as_ref()).unwrap()
}

fn verifying_key(signer: &Ed25519KeyPair) -> [u8; 32] {
    signer.public_key().as_ref().try_into().unwrap()
}

fn approval(
    signer: &Ed25519KeyPair,
    deployment_id: [u8; 32],
    anchor: ExternalFloorCustodianClientAnchor,
) -> ExternalFloorCustodianAnchorApproval {
    let message = external_floor_custodian_anchor_approval_message(deployment_id, anchor);
    let mut signature = [0_u8; 64];
    signature.copy_from_slice(signer.sign(&message).as_ref());
    ExternalFloorCustodianAnchorApproval {
        deployment_id,
        anchor,
        signature,
    }
}

fn quarantine_approval(
    signer: &Ed25519KeyPair,
    deployment_id: [u8; 32],
    anchor: ExternalFloorCustodianClientAnchor,
) -> ExternalFloorCustodianAnchorQuarantineApproval {
    ExternalFloorCustodianAnchorQuarantineApproval {
        verifying_key: verifying_key(signer),
        approval: approval(signer, deployment_id, anchor),
    }
}

fn continuity_approval(
    previous_signer: &Ed25519KeyPair,
    next_signer: &Ed25519KeyPair,
    deployment_id: [u8; 32],
    previous_anchor: ExternalFloorCustodianClientAnchor,
    next_anchor: ExternalFloorCustodianClientAnchor,
) -> ExternalFloorCustodianAnchorContinuityApproval {
    let previous_verifying_key = verifying_key(previous_signer);
    let next_verifying_key = verifying_key(next_signer);
    let authorization = external_floor_custodian_anchor_continuity_authorization_message(
        deployment_id,
        previous_verifying_key,
        previous_anchor,
        next_verifying_key,
        next_anchor,
    );
    let acceptance = external_floor_custodian_anchor_continuity_acceptance_message(
        deployment_id,
        previous_verifying_key,
        previous_anchor,
        next_verifying_key,
        next_anchor,
    );
    let mut authorization_signature = [0_u8; 64];
    authorization_signature.copy_from_slice(previous_signer.sign(&authorization).as_ref());
    let mut acceptance_signature = [0_u8; 64];
    acceptance_signature.copy_from_slice(next_signer.sign(&acceptance).as_ref());
    ExternalFloorCustodianAnchorContinuityApproval {
        deployment_id,
        previous_anchor,
        next_anchor,
        next_verifying_key,
        authorization_signature,
        acceptance_signature,
    }
}

#[test]
fn offline_approval_binds_deployment_anchor_and_verifying_key() {
    let deployment = [0x44; 32];
    let approved_anchor = anchor(7, 0x55);
    let signer = signer();
    let verifying_key = verifying_key(&signer);
    let approved = approval(&signer, deployment, approved_anchor);
    assert_eq!(
        verify_external_floor_custodian_anchor_approval(deployment, verifying_key, approved)
            .unwrap(),
        approved_anchor
    );

    assert!(
        verify_external_floor_custodian_anchor_approval([0x45; 32], verifying_key, approved)
            .is_err()
    );
    assert!(
        verify_external_floor_custodian_anchor_approval(deployment, [0x99; 32], approved).is_err()
    );
    let mut tampered = approved;
    tampered.anchor.revision += 1;
    assert!(
        verify_external_floor_custodian_anchor_approval(deployment, verifying_key, tampered)
            .is_err()
    );
}

#[test]
fn approved_provisioning_and_inspection_refuse_unapproved_disk_state() {
    let temp = Temp::new();
    let deployment = [0x66; 32];
    let initial = anchor(0, 0x11);
    let next = anchor(1, 0x22);
    let signer = signer();
    let verifying_key = verifying_key(&signer);
    let initial_approval = approval(&signer, deployment, initial);
    let store = UnixExternalFloorCustodianAnchorStore::provision_approved(
        &temp.store,
        deployment,
        verifying_key,
        initial_approval,
    )
    .unwrap();
    assert_eq!(store.load().unwrap(), initial);
    assert_eq!(
        store.compare_and_swap(initial, next).unwrap(),
        ExternalFloorCustodianAnchorCasOutcome::Committed
    );
    drop(store);

    assert!(UnixExternalFloorCustodianAnchorStore::open_approved(
        &temp.store,
        deployment,
        verifying_key,
        initial_approval,
    )
    .is_err());
    let next_approval = approval(&signer, deployment, next);
    let inspected = UnixExternalFloorCustodianAnchorStore::open_approved(
        &temp.store,
        deployment,
        verifying_key,
        next_approval,
    )
    .unwrap();
    assert_eq!(inspected.load().unwrap(), next);
}

#[test]
fn offline_quarantine_inspection_requires_the_exact_approved_inventory() {
    let temp = Temp::new();
    let deployment = [0x68; 32];
    let first = anchor(1, 0x11);
    let second = anchor(2, 0x22);
    let current = anchor(3, 0x33);
    let signer = signer();
    let key = verifying_key(&signer);
    let store = UnixExternalFloorCustodianAnchorStore::provision_approved(
        &temp.store,
        deployment,
        key,
        approval(&signer, deployment, first),
    )
    .unwrap();
    assert_eq!(
        store.compare_and_swap(first, second).unwrap(),
        ExternalFloorCustodianAnchorCasOutcome::Committed
    );
    assert_eq!(
        store.compare_and_swap(second, current).unwrap(),
        ExternalFloorCustodianAnchorCasOutcome::Committed
    );
    drop(store);

    let mut before = fs::read_dir(&temp.store)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with(".bxrc-external-anchor.displaced.")
        })
        .map(|entry| (entry.file_name(), fs::read(entry.path()).unwrap()))
        .collect::<Vec<_>>();
    before.sort_by(|left, right| left.0.cmp(&right.0));
    let current_approval = approval(&signer, deployment, current);
    let first_approval = quarantine_approval(&signer, deployment, first);
    let second_approval = quarantine_approval(&signer, deployment, second);

    assert!(
        UnixExternalFloorCustodianAnchorStore::inspect_quarantines_approved(
            &temp.store,
            deployment,
            key,
            current_approval,
            &[first_approval],
        )
        .is_err()
    );
    assert!(
        UnixExternalFloorCustodianAnchorStore::inspect_quarantines_approved(
            &temp.store,
            deployment,
            key,
            current_approval,
            &[
                first_approval,
                quarantine_approval(&signer, deployment, anchor(9, 0x99))
            ],
        )
        .is_err()
    );

    let inspected = UnixExternalFloorCustodianAnchorStore::inspect_quarantines_approved(
        &temp.store,
        deployment,
        key,
        current_approval,
        &[second_approval, first_approval],
    )
    .unwrap();
    assert_eq!(inspected.current, current);
    assert_eq!(inspected.quarantined, vec![first, second]);
    let mut after = fs::read_dir(&temp.store)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with(".bxrc-external-anchor.displaced.")
        })
        .map(|entry| (entry.file_name(), fs::read(entry.path()).unwrap()))
        .collect::<Vec<_>>();
    after.sort_by(|left, right| left.0.cmp(&right.0));
    assert_eq!(after, before, "inspection must not mutate quarantines");
}

#[test]
fn offline_quarantine_inspection_never_creates_a_missing_lock() {
    let temp = Temp::new();
    let deployment = [0x69; 32];
    let current = anchor(1, 0x41);
    let signer = signer();
    let key = verifying_key(&signer);
    drop(
        UnixExternalFloorCustodianAnchorStore::provision_approved(
            &temp.store,
            deployment,
            key,
            approval(&signer, deployment, current),
        )
        .unwrap(),
    );
    let lock = temp.store.join(".bxrc-external-anchor.lock");
    fs::remove_file(&lock).unwrap();
    assert!(
        UnixExternalFloorCustodianAnchorStore::inspect_quarantines_approved(
            &temp.store,
            deployment,
            key,
            approval(&signer, deployment, current),
            &[],
        )
        .is_err()
    );
    assert!(
        !lock.exists(),
        "offline inspection must not create authority"
    );
}

#[test]
fn checkpointed_quarantine_receipts_are_exact_and_anti_rollback() {
    let temp = Temp::new();
    let deployment = [0x6a; 32];
    let first = anchor(1, 0x51);
    let second = anchor(2, 0x52);
    let third = anchor(3, 0x53);
    let signer = signer();
    let key = verifying_key(&signer);
    let store = UnixExternalFloorCustodianAnchorStore::provision_approved(
        &temp.store,
        deployment,
        key,
        approval(&signer, deployment, first),
    )
    .unwrap();
    assert_eq!(
        store.compare_and_swap(first, second).unwrap(),
        ExternalFloorCustodianAnchorCasOutcome::Committed
    );
    drop(store);

    let first_quarantine = quarantine_approval(&signer, deployment, first);
    let initial = external_floor_custodian_expected_initial_quarantine_checkpoint(
        deployment,
        key,
        approval(&signer, deployment, second),
        &[first_quarantine],
    )
    .unwrap();
    let receipt = UnixExternalFloorCustodianAnchorStore::inspect_quarantines_checkpointed(
        &temp.store,
        initial,
        approval(&signer, deployment, second),
        &[first_quarantine],
    )
    .unwrap();
    assert_eq!(receipt.checkpoint, initial);
    assert_eq!(receipt.inspection.current, second);
    assert_eq!(receipt.inspection.quarantined, vec![first]);

    let store = UnixExternalFloorCustodianAnchorStore::open_approved(
        &temp.store,
        deployment,
        key,
        approval(&signer, deployment, second),
    )
    .unwrap();
    assert_eq!(
        store.compare_and_swap(second, third).unwrap(),
        ExternalFloorCustodianAnchorCasOutcome::Committed
    );
    drop(store);
    let second_quarantine = quarantine_approval(&signer, deployment, second);
    let next = external_floor_custodian_expected_next_quarantine_checkpoint(
        initial,
        key,
        approval(&signer, deployment, third),
        &[first_quarantine, second_quarantine],
    )
    .unwrap();
    assert_eq!(next.inspection_index, 1);
    assert_eq!(next.previous_checkpoint_hash, initial.checkpoint_hash);
    UnixExternalFloorCustodianAnchorStore::inspect_quarantines_checkpointed(
        &temp.store,
        next,
        approval(&signer, deployment, third),
        &[second_quarantine, first_quarantine],
    )
    .unwrap();

    assert!(
        UnixExternalFloorCustodianAnchorStore::inspect_quarantines_checkpointed(
            &temp.store,
            initial,
            approval(&signer, deployment, third),
            &[first_quarantine, second_quarantine],
        )
        .is_err()
    );
    assert!(
        external_floor_custodian_expected_next_quarantine_checkpoint(
            next,
            key,
            approval(&signer, deployment, second),
            &[first_quarantine],
        )
        .is_err()
    );

    let mut forged = next;
    forged.previous_checkpoint_hash = [0x99; 32];
    assert!(
        UnixExternalFloorCustodianAnchorStore::inspect_quarantines_checkpointed(
            &temp.store,
            forged,
            approval(&signer, deployment, third),
            &[first_quarantine, second_quarantine],
        )
        .is_err()
    );
}

#[test]
fn continuity_reapproval_and_key_rotation_require_both_offline_authorities() {
    let deployment = [0x71; 32];
    let previous_anchor = anchor(7, 0x41);
    let next_anchor = anchor(11, 0x42);
    let previous_signer = signer();
    let next_signer = signer();
    let previous_key = verifying_key(&previous_signer);
    let next_key = verifying_key(&next_signer);
    assert_ne!(
        external_floor_custodian_anchor_continuity_authorization_message(
            deployment,
            previous_key,
            previous_anchor,
            next_key,
            next_anchor,
        ),
        external_floor_custodian_anchor_continuity_acceptance_message(
            deployment,
            previous_key,
            previous_anchor,
            next_key,
            next_anchor,
        ),
        "authorization and acceptance signatures must be role separated"
    );
    let approved = continuity_approval(
        &previous_signer,
        &next_signer,
        deployment,
        previous_anchor,
        next_anchor,
    );
    assert_eq!(
        verify_external_floor_custodian_anchor_continuity(
            deployment,
            previous_key,
            previous_anchor,
            approved,
        )
        .unwrap(),
        (next_anchor, next_key)
    );

    let mut missing_acceptance = approved;
    missing_acceptance.acceptance_signature = [0; 64];
    assert!(verify_external_floor_custodian_anchor_continuity(
        deployment,
        previous_key,
        previous_anchor,
        missing_acceptance,
    )
    .is_err());
    let mut missing_authorization = approved;
    missing_authorization.authorization_signature = [0; 64];
    assert!(verify_external_floor_custodian_anchor_continuity(
        deployment,
        previous_key,
        previous_anchor,
        missing_authorization,
    )
    .is_err());
    assert!(verify_external_floor_custodian_anchor_continuity(
        deployment,
        verifying_key(&signer()),
        previous_anchor,
        approved,
    )
    .is_err());

    // Reapproval under the same authority remains possible, but still uses
    // distinct authorization and acceptance domains.
    let reapproved = continuity_approval(
        &previous_signer,
        &previous_signer,
        deployment,
        previous_anchor,
        next_anchor,
    );
    assert_eq!(
        verify_external_floor_custodian_anchor_continuity(
            deployment,
            previous_key,
            previous_anchor,
            reapproved,
        )
        .unwrap(),
        (next_anchor, previous_key)
    );
}

#[test]
fn continuity_refuses_rollback_noop_tampering_and_unapproved_disk_state() {
    let temp = Temp::new();
    let deployment = [0x72; 32];
    let previous_anchor = anchor(8, 0x51);
    let next_anchor = anchor(12, 0x52);
    let previous_signer = signer();
    let next_signer = signer();
    let previous_key = verifying_key(&previous_signer);
    let next_key = verifying_key(&next_signer);
    let approved = continuity_approval(
        &previous_signer,
        &next_signer,
        deployment,
        previous_anchor,
        next_anchor,
    );

    let store = UnixExternalFloorCustodianAnchorStore::provision(&temp.store, next_anchor).unwrap();
    drop(store);
    let (opened, authenticated_next_key) =
        UnixExternalFloorCustodianAnchorStore::open_continuity_approved(
            &temp.store,
            deployment,
            previous_key,
            previous_anchor,
            approved,
        )
        .unwrap();
    assert_eq!(authenticated_next_key, next_key);
    assert_eq!(opened.load().unwrap(), next_anchor);
    drop(opened);

    let wrong_disk = anchor(13, 0x53);
    let store = UnixExternalFloorCustodianAnchorStore::open(&temp.store).unwrap();
    assert_eq!(
        store.compare_and_swap(next_anchor, wrong_disk).unwrap(),
        ExternalFloorCustodianAnchorCasOutcome::Committed
    );
    drop(store);
    assert!(
        UnixExternalFloorCustodianAnchorStore::open_continuity_approved(
            &temp.store,
            deployment,
            previous_key,
            previous_anchor,
            approved,
        )
        .is_err()
    );

    let rollback = continuity_approval(
        &previous_signer,
        &next_signer,
        deployment,
        previous_anchor,
        anchor(7, 0x50),
    );
    assert!(verify_external_floor_custodian_anchor_continuity(
        deployment,
        previous_key,
        previous_anchor,
        rollback,
    )
    .is_err());
    let no_op = continuity_approval(
        &previous_signer,
        &previous_signer,
        deployment,
        previous_anchor,
        previous_anchor,
    );
    assert!(verify_external_floor_custodian_anchor_continuity(
        deployment,
        previous_key,
        previous_anchor,
        no_op,
    )
    .is_err());
    let mut tampered_next_key = approved;
    tampered_next_key.next_verifying_key = [0x99; 32];
    assert!(verify_external_floor_custodian_anchor_continuity(
        deployment,
        previous_key,
        previous_anchor,
        tampered_next_key,
    )
    .is_err());
}

#[test]
fn authority_rotation_can_reapprove_the_same_exact_anchor() {
    let deployment = [0x73; 32];
    let current_anchor = anchor(9, 0x61);
    let previous_signer = signer();
    let next_signer = signer();
    let previous_key = verifying_key(&previous_signer);
    let next_key = verifying_key(&next_signer);
    let approved = continuity_approval(
        &previous_signer,
        &next_signer,
        deployment,
        current_anchor,
        current_anchor,
    );
    assert_eq!(
        verify_external_floor_custodian_anchor_continuity(
            deployment,
            previous_key,
            current_anchor,
            approved,
        )
        .unwrap(),
        (current_anchor, next_key)
    );
}

#[test]
fn create_once_exact_cas_is_durable_and_conflicts_are_non_mutating() {
    let temp = Temp::new();
    let initial = anchor(0, 0x11);
    let next = anchor(1, 0x22);
    let store = UnixExternalFloorCustodianAnchorStore::provision(&temp.store, initial).unwrap();
    assert_eq!(store.load().unwrap(), initial);
    assert_eq!(
        store.compare_and_swap(anchor(0, 0x99), next).unwrap(),
        ExternalFloorCustodianAnchorCasOutcome::Conflict(initial)
    );
    assert_eq!(store.load().unwrap(), initial);
    assert!(store.compare_and_swap(initial, initial).is_err());
    assert!(store.compare_and_swap(initial, anchor(3, 0x33)).is_err());
    assert!(store
        .compare_and_swap(
            initial,
            ExternalFloorCustodianClientAnchor {
                revision: 1,
                commitment: initial.commitment,
            },
        )
        .is_err());
    assert_eq!(
        store.compare_and_swap(initial, next).unwrap(),
        ExternalFloorCustodianAnchorCasOutcome::Committed
    );
    assert_eq!(store.load().unwrap(), next);
    let reconciled_descendant = anchor(3, 0x33);
    assert_eq!(
        store.compare_and_swap(next, reconciled_descendant).unwrap(),
        ExternalFloorCustodianAnchorCasOutcome::Committed
    );
    assert!(UnixExternalFloorCustodianAnchorStore::open(&temp.store).is_err());
    drop(store);

    let reopened = UnixExternalFloorCustodianAnchorStore::open(&temp.store).unwrap();
    assert_eq!(reopened.load().unwrap(), reconciled_descendant);
    assert!(UnixExternalFloorCustodianAnchorStore::provision(&temp.store, initial).is_err());

    let bytes = fs::read(temp.store.join(".bxrc-external-anchor")).unwrap();
    assert_eq!(bytes.len(), EXTERNAL_FLOOR_CUSTODIAN_ANCHOR_RECORD_LEN);
}

#[test]
fn live_store_refuses_replaced_lock_before_load_or_cas() {
    let temp = Temp::new();
    let initial = anchor(2, 0x31);
    let replacement = anchor(3, 0x32);
    let store = UnixExternalFloorCustodianAnchorStore::provision(&temp.store, initial).unwrap();
    let state = temp.store.join(".bxrc-external-anchor");
    let lock = temp.store.join(".bxrc-external-anchor.lock");
    let displaced = temp.root.join("displaced-anchor-lock");
    let before = fs::read(&state).unwrap();

    fs::rename(&lock, &displaced).unwrap();
    let replacement_lock = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&lock)
        .unwrap();
    replacement_lock.sync_all().unwrap();

    assert!(store.load().is_err());
    assert!(store.compare_and_swap(initial, replacement).is_err());
    assert_eq!(fs::read(state).unwrap(), before);
    assert!(!temp.store.join(".bxrc-external-anchor.tmp").exists());
}

#[test]
fn live_store_refuses_displaced_directory_before_load_or_cas() {
    let temp = Temp::new();
    let initial = anchor(4, 0x41);
    let replacement = anchor(5, 0x42);
    let store = UnixExternalFloorCustodianAnchorStore::provision(&temp.store, initial).unwrap();
    let displaced = temp.root.join("displaced-anchor-store");
    let before = fs::read(temp.store.join(".bxrc-external-anchor")).unwrap();

    fs::rename(&temp.store, &displaced).unwrap();
    fs::create_dir(&temp.store).unwrap();
    fs::set_permissions(&temp.store, fs::Permissions::from_mode(0o700)).unwrap();

    assert!(store.load().is_err());
    assert!(store.compare_and_swap(initial, replacement).is_err());
    assert_eq!(
        fs::read(displaced.join(".bxrc-external-anchor")).unwrap(),
        before
    );
    assert!(!displaced.join(".bxrc-external-anchor.tmp").exists());
}

#[test]
fn zero_commitments_relative_paths_and_relaxed_permissions_fail_closed() {
    let temp = Temp::new();
    assert!(UnixExternalFloorCustodianAnchorStore::provision(
        PathBuf::from("relative-anchor").as_path(),
        anchor(0, 1),
    )
    .is_err());
    assert!(UnixExternalFloorCustodianAnchorStore::provision(
        &temp.store,
        ExternalFloorCustodianClientAnchor {
            revision: 0,
            commitment: [0; 32],
        },
    )
    .is_err());

    let store =
        UnixExternalFloorCustodianAnchorStore::provision(&temp.store, anchor(0, 1)).unwrap();
    assert!(store
        .compare_and_swap(
            anchor(0, 1),
            ExternalFloorCustodianClientAnchor {
                revision: 1,
                commitment: [0; 32],
            },
        )
        .is_err());
    drop(store);
    fs::set_permissions(&temp.store, fs::Permissions::from_mode(0o750)).unwrap();
    assert!(UnixExternalFloorCustodianAnchorStore::open(&temp.store).is_err());
}

#[test]
fn corruption_hardlinks_symlinks_and_orphan_temporary_files_are_rejected() {
    let temp = Temp::new();
    let store =
        UnixExternalFloorCustodianAnchorStore::provision(&temp.store, anchor(0, 1)).unwrap();
    drop(store);
    let state = temp.store.join(".bxrc-external-anchor");
    let original = fs::read(&state).unwrap();

    let mut corrupted = original.clone();
    corrupted[20] ^= 1;
    fs::write(&state, &corrupted).unwrap();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(UnixExternalFloorCustodianAnchorStore::open(&temp.store).is_err());
    fs::write(&state, &original).unwrap();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o600)).unwrap();

    let alias = temp.root.join("hardlink");
    fs::hard_link(&state, &alias).unwrap();
    assert!(UnixExternalFloorCustodianAnchorStore::open(&temp.store).is_err());
    fs::remove_file(alias).unwrap();

    let temporary = temp.store.join(".bxrc-external-anchor.tmp");
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .unwrap()
        .write_all(b"orphan")
        .unwrap();
    assert!(UnixExternalFloorCustodianAnchorStore::open(&temp.store).is_err());
    fs::remove_file(temporary).unwrap();

    let moved = temp.root.join("moved-anchor");
    fs::rename(&state, &moved).unwrap();
    symlink(&moved, &state).unwrap();
    assert!(UnixExternalFloorCustodianAnchorStore::open(&temp.store).is_err());
}

#[test]
fn directory_symlink_and_unsafe_lock_are_rejected() {
    let temp = Temp::new();
    let store =
        UnixExternalFloorCustodianAnchorStore::provision(&temp.store, anchor(0, 1)).unwrap();
    drop(store);

    let alias = temp.root.join("external-link");
    symlink(&temp.store, &alias).unwrap();
    assert!(UnixExternalFloorCustodianAnchorStore::open(&alias).is_err());

    let lock = temp.store.join(".bxrc-external-anchor.lock");
    fs::set_permissions(&lock, fs::Permissions::from_mode(0o640)).unwrap();
    assert!(UnixExternalFloorCustodianAnchorStore::open(&temp.store).is_err());
}
