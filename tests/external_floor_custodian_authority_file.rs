// SPDX-License-Identifier: MIT OR Apache-2.0
#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use bloch_l2_bridge::{
    external_floor_custodian_anchor_approval_message,
    external_floor_custodian_anchor_continuity_acceptance_message,
    external_floor_custodian_anchor_continuity_authorization_message,
    external_floor_custodian_expected_authority_checkpoint, ExternalFloorCustodianAnchorApproval,
    ExternalFloorCustodianAnchorContinuityApproval, ExternalFloorCustodianClientAnchor,
    UnixExternalFloorCustodianAuthorityStore, EXTERNAL_FLOOR_CUSTODIAN_AUTHORITY_RECORD_LEN,
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
            "bloch-bxrc-authority-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        Self {
            store: root.join("authority"),
            root,
        }
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}

fn signer() -> Ed25519KeyPair {
    let document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    Ed25519KeyPair::from_pkcs8(document.as_ref()).unwrap()
}

fn key(signer: &Ed25519KeyPair) -> [u8; 32] {
    signer.public_key().as_ref().try_into().unwrap()
}

fn anchor(revision: u64, byte: u8) -> ExternalFloorCustodianClientAnchor {
    ExternalFloorCustodianClientAnchor {
        revision,
        commitment: [byte; 32],
    }
}

fn initial_approval(
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

fn continuity(
    previous: &Ed25519KeyPair,
    next: &Ed25519KeyPair,
    deployment_id: [u8; 32],
    previous_anchor: ExternalFloorCustodianClientAnchor,
    next_anchor: ExternalFloorCustodianClientAnchor,
) -> ExternalFloorCustodianAnchorContinuityApproval {
    let authorization = external_floor_custodian_anchor_continuity_authorization_message(
        deployment_id,
        key(previous),
        previous_anchor,
        key(next),
        next_anchor,
    );
    let acceptance = external_floor_custodian_anchor_continuity_acceptance_message(
        deployment_id,
        key(previous),
        previous_anchor,
        key(next),
        next_anchor,
    );
    let mut authorization_signature = [0; 64];
    authorization_signature.copy_from_slice(previous.sign(&authorization).as_ref());
    let mut acceptance_signature = [0; 64];
    acceptance_signature.copy_from_slice(next.sign(&acceptance).as_ref());
    ExternalFloorCustodianAnchorContinuityApproval {
        deployment_id,
        previous_anchor,
        next_anchor,
        next_verifying_key: key(next),
        authorization_signature,
        acceptance_signature,
    }
}

#[test]
fn persists_complete_tuple_and_dual_signed_history() {
    let temp = Temp::new();
    let deployment = [0x31; 32];
    let first = signer();
    let second = signer();
    let initial = anchor(4, 0x41);
    let next = anchor(8, 0x42);
    let (store, checkpoint0) = UnixExternalFloorCustodianAuthorityStore::provision_approved(
        &temp.store,
        deployment,
        key(&first),
        initial_approval(&first, deployment, initial),
    )
    .unwrap();
    assert_eq!(checkpoint0.transition_index, 0);
    assert_eq!(checkpoint0.authority.deployment_id, deployment);
    assert_eq!(checkpoint0.authority.verifying_key, key(&first));
    assert_eq!(checkpoint0.authority.anchor, initial);

    let approval = continuity(&first, &second, deployment, initial, next);
    let expected1 =
        external_floor_custodian_expected_authority_checkpoint(checkpoint0, approval).unwrap();
    let checkpoint1 = store.accept_continuity(approval).unwrap();
    assert_eq!(checkpoint1, expected1);
    assert_eq!(checkpoint1.transition_index, 1);
    assert_eq!(checkpoint1.previous_record_hash, checkpoint0.record_hash);
    assert_eq!(checkpoint1.authority.verifying_key, key(&second));
    assert_eq!(checkpoint1.authority.anchor, next);
    drop(store);

    let reopened =
        UnixExternalFloorCustodianAuthorityStore::open_expected(&temp.store, checkpoint1).unwrap();
    assert_eq!(reopened.checkpoint().unwrap(), checkpoint1);
    assert_eq!(
        fs::read(temp.store.join(".bxrc-accepted-authority"))
            .unwrap()
            .len(),
        EXTERNAL_FLOOR_CUSTODIAN_AUTHORITY_RECORD_LEN
    );
}

#[test]
fn rollback_requires_an_externally_retained_new_checkpoint_to_detect() {
    let temp = Temp::new();
    let deployment = [0x51; 32];
    let first = signer();
    let second = signer();
    let initial = anchor(1, 0x61);
    let next = anchor(2, 0x62);
    let (store, checkpoint0) = UnixExternalFloorCustodianAuthorityStore::provision_approved(
        &temp.store,
        deployment,
        key(&first),
        initial_approval(&first, deployment, initial),
    )
    .unwrap();
    let state = temp.store.join(".bxrc-accepted-authority");
    let old_bytes = fs::read(&state).unwrap();
    let checkpoint1 = store
        .accept_continuity(continuity(&first, &second, deployment, initial, next))
        .unwrap();
    drop(store);

    fs::write(&state, old_bytes).unwrap();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(
        UnixExternalFloorCustodianAuthorityStore::open_expected(&temp.store, checkpoint1).is_err()
    );
    // Honest limitation: restoring the old receipt with the old disk snapshot
    // is coherent. The latest receipt must therefore be retained elsewhere.
    assert!(
        UnixExternalFloorCustodianAuthorityStore::open_expected(&temp.store, checkpoint0).is_ok()
    );
}

#[test]
fn unilateral_transition_and_live_rewrite_fail_closed() {
    let temp = Temp::new();
    let deployment = [0x71; 32];
    let first = signer();
    let second = signer();
    let initial = anchor(7, 0x21);
    let next = anchor(9, 0x22);
    let (store, checkpoint0) = UnixExternalFloorCustodianAuthorityStore::provision_approved(
        &temp.store,
        deployment,
        key(&first),
        initial_approval(&first, deployment, initial),
    )
    .unwrap();
    let mut unsigned = continuity(&first, &second, deployment, initial, next);
    unsigned.acceptance_signature = [0; 64];
    assert!(store.accept_continuity(unsigned).is_err());
    assert_eq!(store.checkpoint().unwrap(), checkpoint0);

    let state = temp.store.join(".bxrc-accepted-authority");
    let mut bytes = fs::read(&state).unwrap();
    bytes[90] ^= 1;
    fs::write(&state, bytes).unwrap();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(store.checkpoint().is_err());
    assert!(store
        .accept_continuity(continuity(&first, &second, deployment, initial, next))
        .is_err());
}

#[test]
fn wrong_expected_receipt_and_orphan_temp_are_rejected() {
    let temp = Temp::new();
    let deployment = [0x81; 32];
    let first = signer();
    let initial = anchor(3, 0x31);
    let (store, checkpoint) = UnixExternalFloorCustodianAuthorityStore::provision_approved(
        &temp.store,
        deployment,
        key(&first),
        initial_approval(&first, deployment, initial),
    )
    .unwrap();
    drop(store);
    let mut wrong = checkpoint;
    wrong.transition_index += 1;
    assert!(UnixExternalFloorCustodianAuthorityStore::open_expected(&temp.store, wrong).is_err());

    let temporary = temp.store.join(".bxrc-accepted-authority.tmp");
    fs::write(&temporary, b"orphan").unwrap();
    fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(
        UnixExternalFloorCustodianAuthorityStore::open_expected(&temp.store, checkpoint).is_err()
    );
}
