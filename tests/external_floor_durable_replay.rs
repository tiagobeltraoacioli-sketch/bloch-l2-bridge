// SPDX-License-Identifier: MIT OR Apache-2.0
#![cfg(unix)]

use std::cell::{Cell, RefCell};
use std::io;
use std::rc::Rc;

use bloch_l2_bridge::{
    decode_authenticated_external_floor_response, encode_authenticated_external_floor_request,
    DurableAuthenticatedExternalFloorServer, DurableExternalFloorReplayGuard,
    ExternalFloorBoundary, ExternalFloorDurableReplayError, ExternalFloorOutcome,
    ExternalFloorPeerAuthentication, ExternalFloorReplayCasOutcome, ExternalFloorReplayCheckpoint,
    ExternalFloorReplayStore, ExternalFloorRequest, ExternalFloorResponse, ExternalGenerationFloor,
    SourceFloorState, SourceGenerationFloor,
};

const KEY: [u8; 32] = [0x31; 32];
const CLIENT: [u8; 32] = [0xc1; 32];
const BOUNDARY: [u8; 32] = [0xb2; 32];
const SESSION: [u8; 32] = [0x5a; 32];

fn authentication() -> ExternalFloorPeerAuthentication {
    ExternalFloorPeerAuthentication::new(KEY, CLIENT, BOUNDARY).unwrap()
}

fn checkpoint(next_sequence: u64) -> ExternalFloorReplayCheckpoint {
    ExternalFloorReplayCheckpoint::new(17 + next_sequence, SESSION, next_sequence).unwrap()
}

fn fresh() -> SourceFloorState {
    SourceFloorState {
        generation: 0,
        snapshot_commitment: None,
    }
}

struct Capture(RefCell<Vec<ExternalFloorRequest>>);

impl ExternalFloorBoundary for &Capture {
    fn transact(&self, request: ExternalFloorRequest) -> io::Result<ExternalFloorResponse> {
        self.0.borrow_mut().push(request);
        Ok(ExternalFloorResponse {
            request_binding: request.binding,
            outcome: ExternalFloorOutcome::Current(fresh()),
        })
    }
}

fn requests() -> Vec<ExternalFloorRequest> {
    let capture = Capture(RefCell::new(Vec::new()));
    let floor = ExternalGenerationFloor::new(&capture, [0xd0; 32], SESSION).unwrap();
    floor.current().unwrap();
    floor.current().unwrap();
    capture.0.into_inner()
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum StoreMode {
    Normal,
    Conflict,
    UncertainCommitted,
    IoError,
}

#[derive(Clone)]
struct TestStore {
    state: Rc<RefCell<ExternalFloorReplayCheckpoint>>,
    mode: Rc<Cell<StoreMode>>,
    cas_calls: Rc<Cell<usize>>,
}

impl TestStore {
    fn new(state: ExternalFloorReplayCheckpoint) -> Self {
        Self {
            state: Rc::new(RefCell::new(state)),
            mode: Rc::new(Cell::new(StoreMode::Normal)),
            cas_calls: Rc::new(Cell::new(0)),
        }
    }
}

impl ExternalFloorReplayStore for TestStore {
    fn load(&self) -> io::Result<ExternalFloorReplayCheckpoint> {
        Ok(*self.state.borrow())
    }

    fn compare_and_swap(
        &self,
        expected: ExternalFloorReplayCheckpoint,
        replacement: ExternalFloorReplayCheckpoint,
    ) -> io::Result<ExternalFloorReplayCasOutcome> {
        self.cas_calls.set(self.cas_calls.get() + 1);
        match self.mode.get() {
            StoreMode::IoError => Err(io::Error::new(io::ErrorKind::TimedOut, "ambiguous")),
            StoreMode::Conflict => Ok(ExternalFloorReplayCasOutcome::Conflict(
                *self.state.borrow(),
            )),
            StoreMode::UncertainCommitted => {
                *self.state.borrow_mut() = replacement;
                Ok(ExternalFloorReplayCasOutcome::Uncertain)
            }
            StoreMode::Normal if *self.state.borrow() == expected => {
                *self.state.borrow_mut() = replacement;
                Ok(ExternalFloorReplayCasOutcome::Committed)
            }
            StoreMode::Normal => Ok(ExternalFloorReplayCasOutcome::Conflict(
                *self.state.borrow(),
            )),
        }
    }
}

#[derive(Clone)]
struct Boundary {
    calls: Rc<Cell<usize>>,
    stored: Rc<RefCell<ExternalFloorReplayCheckpoint>>,
    fail: bool,
}

impl ExternalFloorBoundary for Boundary {
    fn transact(&self, request: ExternalFloorRequest) -> io::Result<ExternalFloorResponse> {
        assert_eq!(self.stored.borrow().next_sequence, request.sequence + 1);
        self.calls.set(self.calls.get() + 1);
        if self.fail {
            return Err(io::Error::other("external outcome unknown"));
        }
        Ok(ExternalFloorResponse {
            request_binding: request.binding,
            outcome: ExternalFloorOutcome::Current(fresh()),
        })
    }
}

fn server(
    store: TestStore,
    trusted: ExternalFloorReplayCheckpoint,
    fail: bool,
    calls: Rc<Cell<usize>>,
) -> DurableAuthenticatedExternalFloorServer<TestStore, Boundary> {
    let boundary = Boundary {
        calls,
        stored: store.state.clone(),
        fail,
    };
    DurableAuthenticatedExternalFloorServer::open(store, trusted, boundary, authentication())
        .unwrap()
}

#[test]
fn server_consumes_durable_sequence_before_external_effect_and_survives_restart() {
    let initial = checkpoint(0);
    let store = TestStore::new(initial);
    let calls = Rc::new(Cell::new(0));
    let request = requests()[0];
    let wire = encode_authenticated_external_floor_request(&request, &authentication()).unwrap();
    let first = server(store.clone(), initial, false, calls.clone());
    let response = first.handle(&wire).unwrap();
    decode_authenticated_external_floor_response(&response, &request, &authentication()).unwrap();
    assert_eq!(calls.get(), 1);
    let committed = first.checkpoint();
    assert_eq!(committed.next_sequence, 1);

    let restarted = server(store.clone(), committed, false, calls.clone());
    assert!(restarted.handle(&wire).is_err());
    assert_eq!(calls.get(), 1);
    let second_request = requests()[1];
    let second_wire =
        encode_authenticated_external_floor_request(&second_request, &authentication()).unwrap();
    restarted.handle(&second_wire).unwrap();
    assert_eq!(calls.get(), 2);
}

#[test]
fn unauthorized_session_gaps_and_reordering_never_reach_store_or_boundary() {
    let initial = checkpoint(0);
    let store = TestStore::new(initial);
    let calls = Rc::new(Cell::new(0));
    let server = server(store.clone(), initial, false, calls.clone());
    let second = requests()[1];
    let wire = encode_authenticated_external_floor_request(&second, &authentication()).unwrap();
    assert!(server.handle(&wire).is_err());

    let capture = Capture(RefCell::new(Vec::new()));
    let floor = ExternalGenerationFloor::new(&capture, [0xd0; 32], [0x77; 32]).unwrap();
    floor.current().unwrap();
    let unauthorized = capture.0.into_inner()[0];
    let wire =
        encode_authenticated_external_floor_request(&unauthorized, &authentication()).unwrap();
    assert!(server.handle(&wire).is_err());
    assert_eq!(store.cas_calls.get(), 0);
    assert_eq!(calls.get(), 0);
}

#[test]
fn stale_or_rolled_back_store_cannot_open_against_trusted_checkpoint() {
    let store = TestStore::new(checkpoint(0));
    let trusted = checkpoint(1);
    let error = match DurableExternalFloorReplayGuard::open(store, trusted) {
        Ok(_) => panic!("rollback was accepted"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        ExternalFloorDurableReplayError::CheckpointMismatch { .. }
    ));
}

#[test]
fn cas_conflict_uncertainty_and_io_error_close_before_external_effect() {
    for mode in [
        StoreMode::Conflict,
        StoreMode::UncertainCommitted,
        StoreMode::IoError,
    ] {
        let initial = checkpoint(0);
        let store = TestStore::new(initial);
        store.mode.set(mode);
        let calls = Rc::new(Cell::new(0));
        let server = server(store.clone(), initial, false, calls.clone());
        let request = requests()[0];
        let wire =
            encode_authenticated_external_floor_request(&request, &authentication()).unwrap();
        assert!(server.handle(&wire).is_err());
        assert!(server.is_closed());
        assert!(server.handle(&wire).is_err());
        assert_eq!(store.cas_calls.get(), 1);
        assert_eq!(calls.get(), 0);
    }
}

#[test]
fn ambiguous_commit_requires_reconciliation_and_rejects_old_checkpoint() {
    let initial = checkpoint(0);
    let store = TestStore::new(initial);
    store.mode.set(StoreMode::UncertainCommitted);
    let calls = Rc::new(Cell::new(0));
    let server = server(store.clone(), initial, false, calls);
    let request = requests()[0];
    let wire = encode_authenticated_external_floor_request(&request, &authentication()).unwrap();
    assert!(server.handle(&wire).is_err());
    assert!(matches!(
        DurableExternalFloorReplayGuard::open(store.clone(), initial),
        Err(ExternalFloorDurableReplayError::CheckpointMismatch { .. })
    ));
    let reconciled = *store.state.borrow();
    let reopened = DurableExternalFloorReplayGuard::open(store, reconciled).unwrap();
    assert_eq!(reopened.checkpoint().next_sequence, 1);
}

#[test]
fn external_failure_after_reservation_cannot_be_replayed() {
    let initial = checkpoint(0);
    let store = TestStore::new(initial);
    let calls = Rc::new(Cell::new(0));
    let server = server(store.clone(), initial, true, calls.clone());
    let request = requests()[0];
    let wire = encode_authenticated_external_floor_request(&request, &authentication()).unwrap();
    assert!(server.handle(&wire).is_err());
    assert_eq!(calls.get(), 1);
    assert_eq!(store.state.borrow().next_sequence, 1);
    assert!(server.is_closed());
    assert!(server.handle(&wire).is_err());
    assert_eq!(calls.get(), 1);
}

#[test]
fn malformed_or_unauthenticated_input_never_reaches_store_or_boundary() {
    let initial = checkpoint(0);
    let store = TestStore::new(initial);
    let calls = Rc::new(Cell::new(0));
    let server = server(store.clone(), initial, false, calls.clone());
    let request = requests()[0];
    let mut wire =
        encode_authenticated_external_floor_request(&request, &authentication()).unwrap();
    wire[144] ^= 1;
    assert!(server.handle(&wire).is_err());
    assert_eq!(store.cas_calls.get(), 0);
    assert_eq!(calls.get(), 0);
    assert!(!server.is_closed());
}

#[test]
fn sequence_and_revision_exhaustion_fail_without_touching_store() {
    let sequence_max = ExternalFloorReplayCheckpoint::new(1, SESSION, u64::MAX).unwrap();
    let store = TestStore::new(sequence_max);
    let mut guard = DurableExternalFloorReplayGuard::open(store.clone(), sequence_max).unwrap();
    assert!(matches!(
        guard.reserve(SESSION, u64::MAX),
        Err(ExternalFloorDurableReplayError::SequenceExhausted)
    ));
    assert_eq!(store.cas_calls.get(), 0);

    let revision_max = ExternalFloorReplayCheckpoint::new(u64::MAX, SESSION, 0).unwrap();
    let store = TestStore::new(revision_max);
    let mut guard = DurableExternalFloorReplayGuard::open(store.clone(), revision_max).unwrap();
    assert!(matches!(
        guard.reserve(SESSION, 0),
        Err(ExternalFloorDurableReplayError::RevisionExhausted)
    ));
    assert_eq!(store.cas_calls.get(), 0);
}
