// SPDX-License-Identifier: MIT OR Apache-2.0
#![cfg(target_os = "linux")]

use std::cell::{Cell, RefCell};
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};

use bloch_l2_bridge::{
    encode_authenticated_external_floor_request, external_floor_custodian_anchor_approval_message,
    external_floor_custodian_anchor_continuity_acceptance_message,
    external_floor_custodian_anchor_continuity_authorization_message,
    AuthenticatedExternalFloorCustodianServer, DurableAuthenticatedExternalFloorCustodian,
    ExternalFloorBoundary, ExternalFloorCustodianAnchorApproval,
    ExternalFloorCustodianAnchorContinuityApproval, ExternalFloorCustodianAuthentication,
    ExternalFloorCustodianClientAnchor, ExternalFloorCustodianTransportCheckpoint,
    ExternalFloorOutcome, ExternalFloorPeerAuthentication, ExternalFloorReplayCasOutcome,
    ExternalFloorReplayCheckpoint, ExternalFloorReplayStore, ExternalFloorRequest,
    ExternalFloorResponse, ExternalGenerationFloor, SourceFloorState, SourceGenerationFloor,
    UnixExternalFloorCustodianAnchorStore, UnixExternalFloorCustodianAuthorityStore,
    UnixExternalFloorCustodianRuntimeConfig, UnixExternalFloorReplayStore,
    UnixExternalFloorServerConfig,
};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};

const CHECKPOINT_KEY: [u8; 32] = [0x11; 32];
const CUSTODIAN_KEY: [u8; 32] = [0x22; 32];
const CUSTODIAN_CLIENT: [u8; 32] = [0x33; 32];
const CUSTODIAN_SERVER: [u8; 32] = [0x44; 32];
const CUSTODIAN_SESSION: [u8; 32] = [0x55; 32];
const SERVER_KEY: [u8; 32] = [0x66; 32];
const SERVER_CLIENT: [u8; 32] = [0x77; 32];
const SERVER_BOUNDARY: [u8; 32] = [0x88; 32];
const REQUEST_SESSION: [u8; 32] = [0x99; 32];
static NEXT: AtomicU64 = AtomicU64::new(0);

struct Temp {
    root: PathBuf,
}

impl Temp {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "bloch-bxrc-runtime-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let root = root.canonicalize().unwrap();
        Self { root }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}

#[derive(Clone)]
struct RemoteStore {
    state: Rc<RefCell<ExternalFloorReplayCheckpoint>>,
    loads: Rc<Cell<usize>>,
}

impl ExternalFloorReplayStore for RemoteStore {
    fn load(&self) -> io::Result<ExternalFloorReplayCheckpoint> {
        self.loads.set(self.loads.get() + 1);
        Ok(*self.state.borrow())
    }

    fn compare_and_swap(
        &self,
        expected: ExternalFloorReplayCheckpoint,
        replacement: ExternalFloorReplayCheckpoint,
    ) -> io::Result<ExternalFloorReplayCasOutcome> {
        let mut state = self.state.borrow_mut();
        if *state == expected {
            *state = replacement;
            Ok(ExternalFloorReplayCasOutcome::Committed)
        } else {
            Ok(ExternalFloorReplayCasOutcome::Conflict(*state))
        }
    }
}

fn signer() -> Ed25519KeyPair {
    let document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    Ed25519KeyPair::from_pkcs8(document.as_ref()).unwrap()
}

fn key(signer: &Ed25519KeyPair) -> [u8; 32] {
    signer.public_key().as_ref().try_into().unwrap()
}

fn approval(
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

fn custodian_authentication() -> ExternalFloorCustodianAuthentication {
    ExternalFloorCustodianAuthentication::new(CUSTODIAN_KEY, CUSTODIAN_CLIENT, CUSTODIAN_SERVER)
        .unwrap()
}

fn provision(
    temp: &Temp,
    initial: ExternalFloorReplayCheckpoint,
) -> (
    bloch_l2_bridge::ExternalFloorCustodianAuthorityCheckpoint,
    RemoteStore,
    Ed25519KeyPair,
) {
    let checkpoint = temp.path("checkpoint");
    let anchor = DurableAuthenticatedExternalFloorCustodian::<(), ()>::provision(
        &checkpoint,
        ExternalFloorCustodianTransportCheckpoint::new(CUSTODIAN_SESSION, 0).unwrap(),
        CHECKPOINT_KEY,
    )
    .unwrap();
    let deployment = [0xa1; 32];
    let signer = signer();
    let signed = approval(&signer, deployment, anchor);
    drop(
        UnixExternalFloorCustodianAnchorStore::provision_approved(
            &temp.path("anchor"),
            deployment,
            key(&signer),
            signed,
        )
        .unwrap(),
    );
    let (authority, receipt) = UnixExternalFloorCustodianAuthorityStore::provision_approved(
        &temp.path("authority"),
        deployment,
        key(&signer),
        signed,
    )
    .unwrap();
    drop(authority);
    (
        receipt,
        RemoteStore {
            state: Rc::new(RefCell::new(initial)),
            loads: Rc::new(Cell::new(0)),
        },
        signer,
    )
}

fn runtime_config(
    temp: &Temp,
    receipt: bloch_l2_bridge::ExternalFloorCustodianAuthorityCheckpoint,
) -> UnixExternalFloorCustodianRuntimeConfig {
    UnixExternalFloorCustodianRuntimeConfig::new(
        temp.path("checkpoint"),
        temp.path("anchor"),
        temp.path("authority"),
        receipt,
        custodian_authentication(),
        CHECKPOINT_KEY,
    )
    .unwrap()
}

fn request() -> ExternalFloorRequest {
    struct Capture(RefCell<Option<ExternalFloorRequest>>);
    impl ExternalFloorBoundary for &Capture {
        fn transact(&self, request: ExternalFloorRequest) -> io::Result<ExternalFloorResponse> {
            *self.0.borrow_mut() = Some(request);
            Ok(ExternalFloorResponse {
                request_binding: request.binding,
                outcome: ExternalFloorOutcome::Current(SourceFloorState {
                    generation: 0,
                    snapshot_commitment: None,
                }),
            })
        }
    }
    let capture = Capture(RefCell::new(None));
    ExternalGenerationFloor::new(&capture, [0xb1; 32], REQUEST_SESSION)
        .unwrap()
        .current()
        .unwrap();
    capture.0.into_inner().unwrap()
}

#[test]
fn authority_pinned_runtime_composes_with_production_coordinator() {
    let temp = Temp::new();
    let initial = ExternalFloorReplayCheckpoint::new(7, REQUEST_SESSION, 0).unwrap();
    let (receipt, remote, _) = provision(&temp, initial);
    let remote_server =
        AuthenticatedExternalFloorCustodianServer::new(remote.clone(), custodian_authentication());
    let runtime = runtime_config(&temp, receipt).open(&remote_server).unwrap();
    assert_eq!(runtime.anchor(), receipt.authority.anchor);
    assert_eq!(runtime.anchor_store().accepted_authority(), receipt,);

    UnixExternalFloorReplayStore::provision(&temp.path("replay"), initial).unwrap();
    struct Boundary;
    impl ExternalFloorBoundary for Boundary {
        fn transact(&self, request: ExternalFloorRequest) -> io::Result<ExternalFloorResponse> {
            Ok(ExternalFloorResponse {
                request_binding: request.binding,
                outcome: ExternalFloorOutcome::Current(SourceFloorState {
                    generation: 0,
                    snapshot_commitment: None,
                }),
            })
        }
    }
    let coordinator = UnixExternalFloorServerConfig::new(
        temp.path("replay"),
        initial,
        SERVER_KEY,
        SERVER_CLIENT,
        SERVER_BOUNDARY,
    )
    .unwrap()
    .open(&runtime, Boundary)
    .unwrap();
    let request = request();
    let wire = encode_authenticated_external_floor_request(
        &request,
        &ExternalFloorPeerAuthentication::new(SERVER_KEY, SERVER_CLIENT, SERVER_BOUNDARY).unwrap(),
    )
    .unwrap();
    coordinator.handle(&wire).unwrap();
    assert_eq!(*remote.state.borrow(), coordinator.checkpoint());
    assert_eq!(runtime.anchor_store().accepted_authority(), receipt);
    assert!(runtime.anchor().revision > receipt.authority.anchor.revision);
    let advanced_anchor = runtime.anchor();
    drop(coordinator);
    drop(runtime);

    // The offline receipt is an authority floor, not a mirror of the mutable
    // operational head. A clean restart after committed work must succeed.
    let restarted = runtime_config(&temp, receipt).open(&remote_server).unwrap();
    assert_eq!(restarted.anchor(), advanced_anchor);
    assert_eq!(restarted.load().unwrap(), *remote.state.borrow());
}

#[test]
fn live_dual_signed_transition_checkpoints_exact_head_and_controls_restart() {
    let temp = Temp::new();
    let initial = ExternalFloorReplayCheckpoint::new(8, REQUEST_SESSION, 0).unwrap();
    let (receipt, remote, first) = provision(&temp, initial);
    let server =
        AuthenticatedExternalFloorCustodianServer::new(remote.clone(), custodian_authentication());
    let old_anchor_record = fs::read(temp.path("anchor").join(".bxrc-external-anchor")).unwrap();
    let runtime = runtime_config(&temp, receipt).open(&server).unwrap();

    runtime.load().unwrap();
    let operational_head = runtime.anchor();
    assert!(operational_head.revision > receipt.authority.anchor.revision);
    let next_signer = signer();
    let signed = continuity(
        &first,
        &next_signer,
        receipt.authority.deployment_id,
        receipt.authority.anchor,
        operational_head,
    );
    let next_receipt = runtime
        .anchor_store()
        .accept_authority_continuity(signed)
        .unwrap();
    assert_eq!(next_receipt.transition_index, receipt.transition_index + 1);
    assert_eq!(next_receipt.previous_record_hash, receipt.record_hash);
    assert_eq!(next_receipt.authority.anchor, operational_head);
    assert_eq!(next_receipt.authority.verifying_key, key(&next_signer));
    assert_eq!(runtime.anchor_store().accepted_authority(), next_receipt);
    drop(runtime);

    assert!(runtime_config(&temp, receipt).open(&server).is_err());
    let restarted = runtime_config(&temp, next_receipt).open(&server).unwrap();
    assert_eq!(restarted.anchor(), operational_head);
    drop(restarted);

    // Rolling the operational file back below the newly exported floor is
    // rejected when the independently retained next receipt is supplied.
    let anchor_path = temp.path("anchor").join(".bxrc-external-anchor");
    fs::write(&anchor_path, old_anchor_record).unwrap();
    fs::set_permissions(&anchor_path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(runtime_config(&temp, next_receipt).open(&server).is_err());
}

#[test]
fn live_transition_refuses_to_bless_a_floor_other_than_exact_head() {
    let temp = Temp::new();
    let initial = ExternalFloorReplayCheckpoint::new(9, REQUEST_SESSION, 0).unwrap();
    let (receipt, remote, first) = provision(&temp, initial);
    let server = AuthenticatedExternalFloorCustodianServer::new(remote, custodian_authentication());
    let runtime = runtime_config(&temp, receipt).open(&server).unwrap();
    runtime.load().unwrap();
    let operational_head = runtime.anchor();
    let mismatched = ExternalFloorCustodianClientAnchor {
        revision: operational_head.revision + 1,
        commitment: [0xd1; 32],
    };
    let next_signer = signer();
    let signed = continuity(
        &first,
        &next_signer,
        receipt.authority.deployment_id,
        receipt.authority.anchor,
        mismatched,
    );

    assert!(runtime
        .anchor_store()
        .accept_authority_continuity(signed)
        .is_err());
    assert_eq!(runtime.anchor_store().accepted_authority(), receipt);
    assert_eq!(runtime.anchor(), operational_head);
}

#[test]
fn startup_rejects_anchor_not_named_by_authority_before_transport() {
    let temp = Temp::new();
    let initial = ExternalFloorReplayCheckpoint::new(1, REQUEST_SESSION, 0).unwrap();
    let approved_anchor = DurableAuthenticatedExternalFloorCustodian::<(), ()>::provision(
        &temp.path("checkpoint"),
        ExternalFloorCustodianTransportCheckpoint::new(CUSTODIAN_SESSION, 0).unwrap(),
        CHECKPOINT_KEY,
    )
    .unwrap();
    let deployment = [0xa1; 32];
    let signer = signer();
    let signed = approval(&signer, deployment, approved_anchor);
    let (authority, receipt) = UnixExternalFloorCustodianAuthorityStore::provision_approved(
        &temp.path("authority"),
        deployment,
        key(&signer),
        signed,
    )
    .unwrap();
    drop(authority);
    let conflicting_anchor = ExternalFloorCustodianClientAnchor {
        revision: approved_anchor.revision,
        commitment: [0xc1; 32],
    };
    drop(
        UnixExternalFloorCustodianAnchorStore::provision(&temp.path("anchor"), conflicting_anchor)
            .unwrap(),
    );
    let remote = RemoteStore {
        state: Rc::new(RefCell::new(initial)),
        loads: Rc::new(Cell::new(0)),
    };
    let server =
        AuthenticatedExternalFloorCustodianServer::new(remote.clone(), custodian_authentication());
    assert!(runtime_config(&temp, receipt).open(&server).is_err());
    assert_eq!(remote.loads.get(), 0);
}

#[test]
fn wrong_receipt_and_live_authority_replacement_fail_closed() {
    let temp = Temp::new();
    let initial = ExternalFloorReplayCheckpoint::new(2, REQUEST_SESSION, 0).unwrap();
    let (receipt, remote, _) = provision(&temp, initial);
    let mut wrong = receipt;
    wrong.record_hash[0] ^= 1;
    let server =
        AuthenticatedExternalFloorCustodianServer::new(remote.clone(), custodian_authentication());
    assert!(runtime_config(&temp, wrong).open(&server).is_err());
    assert_eq!(remote.loads.get(), 0);

    let runtime = runtime_config(&temp, receipt).open(&server).unwrap();
    let authority_path = temp.path("authority").join(".bxrc-accepted-authority");
    let mut encoded = fs::read(&authority_path).unwrap();
    encoded[20] ^= 1;
    fs::write(&authority_path, encoded).unwrap();
    fs::set_permissions(&authority_path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(runtime.load().is_err());
    assert_eq!(remote.loads.get(), 0);
}

#[test]
fn runtime_config_has_no_relative_or_shared_paths_and_redacts_keys() {
    let temp = Temp::new();
    let initial = ExternalFloorReplayCheckpoint::new(3, REQUEST_SESSION, 0).unwrap();
    let (receipt, _, _) = provision(&temp, initial);
    assert!(UnixExternalFloorCustodianRuntimeConfig::new(
        PathBuf::from("relative"),
        temp.path("anchor"),
        temp.path("authority"),
        receipt,
        custodian_authentication(),
        CHECKPOINT_KEY,
    )
    .is_err());
    assert!(UnixExternalFloorCustodianRuntimeConfig::new(
        temp.path("checkpoint"),
        temp.path("anchor"),
        temp.path("anchor"),
        receipt,
        custodian_authentication(),
        CHECKPOINT_KEY,
    )
    .is_err());
    let debug = format!("{:?}", runtime_config(&temp, receipt));
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains("17, 17"));
    assert!(!debug.contains("34, 34"));
}
