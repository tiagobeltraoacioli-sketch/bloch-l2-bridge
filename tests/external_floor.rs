// SPDX-License-Identifier: MIT OR Apache-2.0
#![cfg(unix)]

use std::cell::{Cell, RefCell};
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};

use bloch_l2_bridge::watcher::MemorySource;
use bloch_l2_bridge::{
    persist_versioned_source, ExternalFloorBoundary, ExternalFloorOperation, ExternalFloorOutcome,
    ExternalFloorRequest, ExternalFloorResponse, ExternalGenerationFloor, L1Block,
    SourceFloorState, SourceGenerationFloor, VersionedMemorySource,
};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "bloch-external-floor-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn fresh() -> SourceFloorState {
    SourceFloorState {
        generation: 0,
        snapshot_commitment: None,
    }
}

fn bound(generation: u64, byte: u8) -> SourceFloorState {
    SourceFloorState {
        generation,
        snapshot_commitment: Some([byte; 32]),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Normal,
    ConflictOnCas,
    FailAfterCas,
    WrongCasAcknowledgement,
    ImpossibleConflict,
}

struct Shared {
    state: Cell<SourceFloorState>,
    mode: Cell<Mode>,
    requests: RefCell<Vec<ExternalFloorRequest>>,
    replay: Cell<Option<ExternalFloorResponse>>,
}

#[derive(Clone)]
struct Boundary(Rc<Shared>);

impl Boundary {
    fn new() -> (Self, Rc<Shared>) {
        let shared = Rc::new(Shared {
            state: Cell::new(fresh()),
            mode: Cell::new(Mode::Normal),
            requests: RefCell::new(Vec::new()),
            replay: Cell::new(None),
        });
        (Self(Rc::clone(&shared)), shared)
    }
}

impl ExternalFloorBoundary for Boundary {
    fn transact(&self, request: ExternalFloorRequest) -> io::Result<ExternalFloorResponse> {
        self.0.requests.borrow_mut().push(request);
        if let Some(response) = self.0.replay.get() {
            return Ok(response);
        }
        let response = match request.operation {
            ExternalFloorOperation::Read => ExternalFloorResponse {
                request_binding: request.binding,
                outcome: ExternalFloorOutcome::Current(self.0.state.get()),
            },
            ExternalFloorOperation::CompareAndSwap {
                expected,
                requested,
            } => {
                if self.0.mode.get() == Mode::ImpossibleConflict {
                    return Ok(ExternalFloorResponse {
                        request_binding: request.binding,
                        outcome: ExternalFloorOutcome::Conflict { current: expected },
                    });
                }
                if self.0.mode.get() == Mode::ConflictOnCas {
                    self.0.state.set(bound(expected.generation + 1, 0xcc));
                }
                if self.0.state.get() != expected {
                    ExternalFloorResponse {
                        request_binding: request.binding,
                        outcome: ExternalFloorOutcome::Conflict {
                            current: self.0.state.get(),
                        },
                    }
                } else {
                    self.0.state.set(requested);
                    if self.0.mode.get() == Mode::FailAfterCas {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "acknowledgement lost",
                        ));
                    }
                    let current = if self.0.mode.get() == Mode::WrongCasAcknowledgement {
                        bound(requested.generation + 1, 0xdd)
                    } else {
                        requested
                    };
                    ExternalFloorResponse {
                        request_binding: request.binding,
                        outcome: ExternalFloorOutcome::Advanced {
                            previous: expected,
                            current,
                        },
                    }
                }
            }
        };
        Ok(response)
    }
}

fn adapter(boundary: Boundary, nonce: u8) -> ExternalGenerationFloor<Boundary> {
    ExternalGenerationFloor::new(boundary, [0xa5; 32], [nonce; 32]).unwrap()
}

fn source() -> VersionedMemorySource {
    let mut source = MemorySource::new();
    source
        .push(L1Block {
            height: 0,
            hash: [1; 32],
            parent_hash: [0; 32],
            txs: Vec::new(),
        })
        .unwrap();
    VersionedMemorySource::new(source)
}

#[test]
fn cas_binds_exact_state_and_requests_are_uniquely_bound() {
    let (boundary, shared) = Boundary::new();
    let floor = adapter(boundary, 1);
    let requested = bound(0, 0x11);

    floor.advance(requested).unwrap();
    assert_eq!(floor.current().unwrap(), requested);
    assert!(!floor.is_uncertain());

    let requests = shared.requests.borrow();
    assert_eq!(requests.len(), 3);
    assert_eq!(requests[0].sequence, 0);
    assert_eq!(requests[1].sequence, 1);
    assert_eq!(requests[2].sequence, 2);
    assert_ne!(requests[0].binding, requests[1].binding);
    assert_ne!(requests[1].binding, requests[2].binding);
    assert_eq!(
        requests[1].operation,
        ExternalFloorOperation::CompareAndSwap {
            expected: fresh(),
            requested,
        }
    );
}

#[test]
fn stale_response_replay_is_rejected_by_request_binding() {
    let (boundary, shared) = Boundary::new();
    let floor = adapter(boundary, 2);
    floor.current().unwrap();
    let first = shared.requests.borrow()[0];
    shared.replay.set(Some(ExternalFloorResponse {
        request_binding: first.binding,
        outcome: ExternalFloorOutcome::Current(fresh()),
    }));

    let error = floor.current().unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert!(error.to_string().contains("replayed or misbound"));
}

#[test]
fn transactional_conflict_never_overwrites_concurrent_state() {
    let (boundary, shared) = Boundary::new();
    shared.mode.set(Mode::ConflictOnCas);
    let floor = adapter(boundary, 3);

    let error = floor.advance(bound(1, 0x22)).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
    assert_eq!(shared.state.get(), bound(1, 0xcc));
    assert!(!floor.is_uncertain());
}

#[test]
fn lost_cas_acknowledgement_poisoning_blocks_every_retry() {
    let (boundary, shared) = Boundary::new();
    shared.mode.set(Mode::FailAfterCas);
    let floor = adapter(boundary, 4);
    let requested = bound(1, 0x33);

    let error = floor.advance(requested).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(error.to_string().contains("outcome is uncertain"));
    assert_eq!(
        shared.state.get(),
        requested,
        "CAS really committed remotely"
    );
    assert!(floor.is_uncertain());
    let request_count = shared.requests.borrow().len();

    assert!(floor.advance(requested).is_err());
    assert!(floor.current().is_err());
    assert_eq!(shared.requests.borrow().len(), request_count);

    shared.mode.set(Mode::Normal);
    let boundary = floor.into_boundary();
    let reconciled = adapter(boundary, 5);
    assert_eq!(reconciled.current().unwrap(), requested);
}

#[test]
fn ambiguous_external_advance_never_publishes_local_snapshot() {
    let directory = TestDirectory::new();
    let path = directory.0.join("source.json");
    let (boundary, shared) = Boundary::new();
    shared.mode.set(Mode::FailAfterCas);
    let floor = adapter(boundary, 11);

    assert!(persist_versioned_source(&path, &source(), &floor, 16 * 1024).is_err());
    assert!(floor.is_uncertain());
    assert!(shared.state.get().snapshot_commitment.is_some());
    assert!(!path.exists());
    assert!(!PathBuf::from(format!("{}.tmp", path.display())).exists());
}

#[test]
fn false_or_malformed_cas_acknowledgement_is_ambiguous_and_poisoning() {
    let (boundary, shared) = Boundary::new();
    shared.mode.set(Mode::WrongCasAcknowledgement);
    let floor = adapter(boundary, 6);

    let error = floor.advance(bound(1, 0x44)).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert!(floor.is_uncertain());
    let requests = shared.requests.borrow().len();
    assert!(floor.current().is_err());
    assert_eq!(shared.requests.borrow().len(), requests);
}

#[test]
fn impossible_conflict_is_ambiguous_and_poisoning() {
    let (boundary, shared) = Boundary::new();
    shared.mode.set(Mode::ImpossibleConflict);
    let floor = adapter(boundary, 10);

    let error = floor.advance(bound(1, 0x45)).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert!(error.to_string().contains("impossible CAS conflict"));
    assert!(floor.is_uncertain());
}

#[test]
fn rollback_rebinding_and_unbound_advances_fail_before_cas() {
    let (boundary, shared) = Boundary::new();
    shared.state.set(bound(3, 0x55));
    let floor = adapter(boundary, 7);

    assert_eq!(
        floor.advance(bound(2, 0x55)).unwrap_err().kind(),
        io::ErrorKind::InvalidInput
    );
    assert_eq!(
        floor.advance(bound(3, 0x66)).unwrap_err().kind(),
        io::ErrorKind::AlreadyExists
    );
    assert_eq!(
        floor
            .advance(SourceFloorState {
                generation: 4,
                snapshot_commitment: None,
            })
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidInput
    );
    assert!(shared
        .requests
        .borrow()
        .iter()
        .all(|request| matches!(request.operation, ExternalFloorOperation::Read)));
}

#[test]
fn deployment_and_session_identifiers_are_mandatory_and_separate_bindings() {
    let (boundary, _) = Boundary::new();
    assert!(ExternalGenerationFloor::new(boundary.clone(), [0; 32], [1; 32]).is_err());
    assert!(ExternalGenerationFloor::new(boundary.clone(), [1; 32], [0; 32]).is_err());

    let first = adapter(boundary.clone(), 8);
    first.current().unwrap();
    let second = adapter(boundary, 9);
    second.current().unwrap();
    let requests = first.into_boundary().0.requests.borrow().clone();
    assert_ne!(requests[0].binding, requests[1].binding);
}
