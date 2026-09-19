// SPDX-License-Identifier: MIT OR Apache-2.0
#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use bloch_l2_bridge::{
    decode_external_floor_custodian_authority_checkpoint,
    encode_external_floor_custodian_authority_checkpoint,
    external_floor_custodian_anchor_approval_message,
    external_floor_custodian_anchor_continuity_acceptance_message,
    external_floor_custodian_anchor_continuity_authorization_message,
    external_floor_custodian_expected_authority_checkpoint, ExternalFloorCustodianAnchorApproval,
    ExternalFloorCustodianAnchorContinuityApproval, ExternalFloorCustodianAuthorityReconciliation,
    ExternalFloorCustodianClientAnchor, UnixExternalFloorCustodianAuthorityStore,
    EXTERNAL_FLOOR_CUSTODIAN_AUTHORITY_RECORD_LEN,
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

#[test]
fn portable_receipt_round_trips_exact_durable_record() {
    let temp = Temp::new();
    let deployment = [0x89; 32];
    let first = signer();
    let second = signer();
    let initial = anchor(4, 0x41);
    let next = anchor(5, 0x42);
    let (store, checkpoint0) = UnixExternalFloorCustodianAuthorityStore::provision_approved(
        &temp.store,
        deployment,
        key(&first),
        initial_approval(&first, deployment, initial),
    )
    .unwrap();

    let encoded0 = encode_external_floor_custodian_authority_checkpoint(checkpoint0).unwrap();
    assert_eq!(
        encoded0.as_slice(),
        fs::read(temp.store.join(".bxrc-accepted-authority"))
            .unwrap()
            .as_slice()
    );
    assert_eq!(
        decode_external_floor_custodian_authority_checkpoint(&encoded0).unwrap(),
        checkpoint0
    );

    let checkpoint1 = store
        .accept_continuity(continuity(&first, &second, deployment, initial, next))
        .unwrap();
    let encoded1 = encode_external_floor_custodian_authority_checkpoint(checkpoint1).unwrap();
    assert_eq!(
        decode_external_floor_custodian_authority_checkpoint(&encoded1).unwrap(),
        checkpoint1
    );
    assert_ne!(encoded0, encoded1);
}

#[test]
fn portable_receipt_rejects_noncanonical_or_tampered_input() {
    let temp = Temp::new();
    let deployment = [0x8a; 32];
    let first = signer();
    let initial = anchor(6, 0x43);
    let (store, checkpoint) = UnixExternalFloorCustodianAuthorityStore::provision_approved(
        &temp.store,
        deployment,
        key(&first),
        initial_approval(&first, deployment, initial),
    )
    .unwrap();
    drop(store);
    let encoded = encode_external_floor_custodian_authority_checkpoint(checkpoint).unwrap();

    let mut tampered = encoded;
    tampered[88] ^= 1;
    assert!(decode_external_floor_custodian_authority_checkpoint(&tampered).is_err());

    let mut reserved = encoded;
    reserved[5] = 1;
    assert!(decode_external_floor_custodian_authority_checkpoint(&reserved).is_err());

    let mut trailing = encoded.to_vec();
    trailing.push(0);
    assert!(decode_external_floor_custodian_authority_checkpoint(&trailing).is_err());
    assert!(
        decode_external_floor_custodian_authority_checkpoint(&encoded[..encoded.len() - 1])
            .is_err()
    );

    let mut inconsistent = checkpoint;
    inconsistent.record_hash[0] ^= 1;
    assert!(encode_external_floor_custodian_authority_checkpoint(inconsistent).is_err());
}

#[test]
fn reconciliation_accepts_only_exact_prior_or_derived_next_across_restart() {
    let temp = Temp::new();
    let deployment = [0x91; 32];
    let first = signer();
    let second = signer();
    let initial = anchor(5, 0x51);
    let next = anchor(6, 0x52);
    let (store, checkpoint0) = UnixExternalFloorCustodianAuthorityStore::provision_approved(
        &temp.store,
        deployment,
        key(&first),
        initial_approval(&first, deployment, initial),
    )
    .unwrap();
    drop(store);
    let approval = continuity(&first, &second, deployment, initial, next);
    let checkpoint1 =
        external_floor_custodian_expected_authority_checkpoint(checkpoint0, approval).unwrap();

    let (prior, outcome) = UnixExternalFloorCustodianAuthorityStore::reconcile_continuity(
        &temp.store,
        checkpoint0,
        approval,
    )
    .unwrap();
    assert_eq!(
        outcome,
        ExternalFloorCustodianAuthorityReconciliation::NotCommitted {
            current: checkpoint0
        }
    );
    assert_eq!(prior.checkpoint().unwrap(), checkpoint0);
    assert_eq!(prior.accept_continuity(approval).unwrap(), checkpoint1);
    drop(prior);

    // A new process can resolve an incomplete export using only the retained
    // prior receipt and the same signed artifact.
    let (restarted, outcome) = UnixExternalFloorCustodianAuthorityStore::reconcile_continuity(
        &temp.store,
        checkpoint0,
        approval,
    )
    .unwrap();
    assert_eq!(
        outcome,
        ExternalFloorCustodianAuthorityReconciliation::Committed {
            previous: checkpoint0,
            current: checkpoint1
        }
    );
    assert_eq!(restarted.checkpoint().unwrap(), checkpoint1);
}

#[test]
fn reconciliation_durably_aborts_only_an_exact_uncommitted_candidate() {
    let temp = Temp::new();
    let deployment = [0x99; 32];
    let first = signer();
    let second = signer();
    let initial = anchor(20, 0x71);
    let next = anchor(21, 0x72);
    let approval = continuity(&first, &second, deployment, initial, next);

    // Produce the exact bytes that the interrupted transition would have
    // synced before its atomic rename.
    let candidate_directory = temp.root.join("candidate");
    let (candidate_store, _) = UnixExternalFloorCustodianAuthorityStore::provision_approved(
        &candidate_directory,
        deployment,
        key(&first),
        initial_approval(&first, deployment, initial),
    )
    .unwrap();
    let checkpoint1 = candidate_store.accept_continuity(approval).unwrap();
    drop(candidate_store);
    let candidate = fs::read(candidate_directory.join(".bxrc-accepted-authority")).unwrap();

    let (store, checkpoint0) = UnixExternalFloorCustodianAuthorityStore::provision_approved(
        &temp.store,
        deployment,
        key(&first),
        initial_approval(&first, deployment, initial),
    )
    .unwrap();
    drop(store);
    let temporary = temp.store.join(".bxrc-accepted-authority.tmp");
    fs::write(&temporary, candidate).unwrap();
    fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600)).unwrap();

    let (reconciled, outcome) = UnixExternalFloorCustodianAuthorityStore::reconcile_continuity(
        &temp.store,
        checkpoint0,
        approval,
    )
    .unwrap();
    assert_eq!(
        outcome,
        ExternalFloorCustodianAuthorityReconciliation::NotCommitted {
            current: checkpoint0
        }
    );
    assert!(!temporary.exists());
    assert_eq!(reconciled.checkpoint().unwrap(), checkpoint0);
    assert_eq!(reconciled.accept_continuity(approval).unwrap(), checkpoint1);
}

#[test]
fn reconciliation_preserves_unexpected_or_unsafe_temporary_records() {
    let temp = Temp::new();
    let deployment = [0x9a; 32];
    let first = signer();
    let second = signer();
    let initial = anchor(30, 0x73);
    let next = anchor(31, 0x74);
    let approval = continuity(&first, &second, deployment, initial, next);
    let (store, checkpoint0) = UnixExternalFloorCustodianAuthorityStore::provision_approved(
        &temp.store,
        deployment,
        key(&first),
        initial_approval(&first, deployment, initial),
    )
    .unwrap();
    drop(store);
    let state = temp.store.join(".bxrc-accepted-authority");
    let temporary = temp.store.join(".bxrc-accepted-authority.tmp");

    // A valid but unexpected candidate is evidence, not safe garbage.
    fs::copy(&state, &temporary).unwrap();
    assert!(
        UnixExternalFloorCustodianAuthorityStore::reconcile_continuity(
            &temp.store,
            checkpoint0,
            approval,
        )
        .is_err()
    );
    assert!(temporary.exists());
    fs::remove_file(&temporary).unwrap();

    // Even exact bytes are not cleaned up when the candidate has another
    // filesystem name and could therefore be modified through that alias.
    let candidate_directory = temp.root.join("hardlink-candidate");
    let (candidate_store, _) = UnixExternalFloorCustodianAuthorityStore::provision_approved(
        &candidate_directory,
        deployment,
        key(&first),
        initial_approval(&first, deployment, initial),
    )
    .unwrap();
    candidate_store.accept_continuity(approval).unwrap();
    drop(candidate_store);
    fs::hard_link(
        candidate_directory.join(".bxrc-accepted-authority"),
        &temporary,
    )
    .unwrap();
    assert!(
        UnixExternalFloorCustodianAuthorityStore::reconcile_continuity(
            &temp.store,
            checkpoint0,
            approval,
        )
        .is_err()
    );
    assert!(temporary.exists());
}

#[test]
fn reconciliation_rejects_third_state_and_never_adopts_it() {
    let temp = Temp::new();
    let deployment = [0xa1; 32];
    let first = signer();
    let second = signer();
    let third = signer();
    let initial = anchor(10, 0x61);
    let next = anchor(11, 0x62);
    let later = anchor(12, 0x63);
    let (store, checkpoint0) = UnixExternalFloorCustodianAuthorityStore::provision_approved(
        &temp.store,
        deployment,
        key(&first),
        initial_approval(&first, deployment, initial),
    )
    .unwrap();
    let first_approval = continuity(&first, &second, deployment, initial, next);
    let checkpoint1 = store.accept_continuity(first_approval).unwrap();
    let checkpoint2 = store
        .accept_continuity(continuity(&second, &third, deployment, next, later))
        .unwrap();
    drop(store);

    let error = match UnixExternalFloorCustodianAuthorityStore::reconcile_continuity(
        &temp.store,
        checkpoint0,
        first_approval,
    ) {
        Ok(_) => panic!("third authority state must fail closed"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    // The public receipt for the actual later state is still required to open;
    // reconciliation did not expose or bless it.
    assert!(
        UnixExternalFloorCustodianAuthorityStore::open_expected(&temp.store, checkpoint1).is_err()
    );
    assert_eq!(
        UnixExternalFloorCustodianAuthorityStore::open_expected(&temp.store, checkpoint2)
            .unwrap()
            .checkpoint()
            .unwrap(),
        checkpoint2
    );
}

#[test]
fn live_store_fails_closed_when_lock_path_is_replaced() {
    let temp = Temp::new();
    let deployment = [0xb1; 32];
    let first = signer();
    let second = signer();
    let initial = anchor(20, 0x71);
    let next = anchor(21, 0x72);
    let (store, checkpoint0) = UnixExternalFloorCustodianAuthorityStore::provision_approved(
        &temp.store,
        deployment,
        key(&first),
        initial_approval(&first, deployment, initial),
    )
    .unwrap();

    let lock = temp.store.join(".bxrc-accepted-authority.lock");
    let displaced = temp.store.join("displaced-lock");
    fs::rename(&lock, &displaced).unwrap();
    fs::write(&lock, []).unwrap();
    fs::set_permissions(&lock, fs::Permissions::from_mode(0o600)).unwrap();

    let error = store.checkpoint().unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    let error = store
        .accept_continuity(continuity(&first, &second, deployment, initial, next))
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);

    // Losing lock identity must not advance the durable authority state.
    fs::remove_file(&lock).unwrap();
    fs::rename(&displaced, &lock).unwrap();
    assert_eq!(store.checkpoint().unwrap(), checkpoint0);
}

#[test]
fn live_store_fails_closed_when_directory_becomes_public() {
    let temp = Temp::new();
    let deployment = [0xb2; 32];
    let first = signer();
    let second = signer();
    let initial = anchor(30, 0x81);
    let next = anchor(31, 0x82);
    let (store, checkpoint0) = UnixExternalFloorCustodianAuthorityStore::provision_approved(
        &temp.store,
        deployment,
        key(&first),
        initial_approval(&first, deployment, initial),
    )
    .unwrap();

    fs::set_permissions(&temp.store, fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(
        store.checkpoint().unwrap_err().kind(),
        std::io::ErrorKind::PermissionDenied
    );
    assert_eq!(
        store
            .accept_continuity(continuity(&first, &second, deployment, initial, next))
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::PermissionDenied
    );

    fs::set_permissions(&temp.store, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(store.checkpoint().unwrap(), checkpoint0);
}
