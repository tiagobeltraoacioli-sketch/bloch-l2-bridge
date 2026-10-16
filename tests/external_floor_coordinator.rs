// SPDX-License-Identifier: MIT OR Apache-2.0
#![cfg(unix)]

use std::cell::{Cell, RefCell};
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};

use bloch_l2_bridge::{
    decode_authenticated_external_floor_response, encode_authenticated_external_floor_request,
    AuthenticatedExternalFloorCustodian, AuthenticatedExternalFloorCustodianServer,
    ExternalFloorBoundary, ExternalFloorCustodianAuthentication,
    ExternalFloorCustodianTransportCheckpoint, ExternalFloorOutcome,
    ExternalFloorPeerAuthentication, ExternalFloorReplayCasOutcome, ExternalFloorReplayCheckpoint,
    ExternalFloorReplayStore, ExternalFloorRequest, ExternalFloorResponse, ExternalGenerationFloor,
    SourceFloorState, SourceGenerationFloor, UnixExternalFloorReplayStore,
    UnixExternalFloorServerConfig,
};

const KEY: [u8; 32] = [0x31; 32];
const CLIENT: [u8; 32] = [0xc1; 32];
const BOUNDARY: [u8; 32] = [0xb2; 32];
const SESSION: [u8; 32] = [0x5a; 32];
const CUSTODIAN_KEY: [u8; 32] = [0x73; 32];
const CUSTODIAN_CLIENT: [u8; 32] = [0x84; 32];
const CUSTODIAN_SERVER: [u8; 32] = [0x95; 32];
const CUSTODIAN_SESSION: [u8; 32] = [0xa6; 32];
static NEXT: AtomicU64 = AtomicU64::new(0);

struct TemporaryDirectory(PathBuf);

impl TemporaryDirectory {
    fn new() -> Self {
        let base = std::env::temp_dir().canonicalize().unwrap();
        let path = base.join(format!(
            "bloch-external-coordinator-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }

    fn replay(&self) -> PathBuf {
        self.0.join("replay")
    }
}

impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn checkpoint(revision: u64, sequence: u64) -> ExternalFloorReplayCheckpoint {
    ExternalFloorReplayCheckpoint::new(revision, SESSION, sequence).unwrap()
}

fn authentication() -> ExternalFloorPeerAuthentication {
    ExternalFloorPeerAuthentication::new(KEY, CLIENT, BOUNDARY).unwrap()
}

fn custodian_authentication() -> ExternalFloorCustodianAuthentication {
    ExternalFloorCustodianAuthentication::new(CUSTODIAN_KEY, CUSTODIAN_CLIENT, CUSTODIAN_SERVER)
        .unwrap()
}

fn config(path: PathBuf, trusted: ExternalFloorReplayCheckpoint) -> UnixExternalFloorServerConfig {
    UnixExternalFloorServerConfig::new(path, trusted, KEY, CLIENT, BOUNDARY).unwrap()
}

fn requests() -> Vec<ExternalFloorRequest> {
    struct Capture(RefCell<Vec<ExternalFloorRequest>>);
    impl ExternalFloorBoundary for &Capture {
        fn transact(&self, request: ExternalFloorRequest) -> io::Result<ExternalFloorResponse> {
            self.0.borrow_mut().push(request);
            Ok(ExternalFloorResponse {
                request_binding: request.binding,
                outcome: ExternalFloorOutcome::Current(SourceFloorState {
                    generation: 0,
                    snapshot_commitment: None,
                }),
            })
        }
    }
    let capture = Capture(RefCell::new(Vec::new()));
    let floor = ExternalGenerationFloor::new(&capture, [0xd0; 32], SESSION).unwrap();
    floor.current().unwrap();
    floor.current().unwrap();
    capture.0.into_inner()
}

#[derive(Clone, Copy)]
enum Mode {
    Normal,
    Conflict,
    Uncertain,
    Error,
    FalseCommit,
}

#[derive(Clone)]
struct Custodian {
    state: Rc<RefCell<ExternalFloorReplayCheckpoint>>,
    mode: Rc<Cell<Mode>>,
}

impl Custodian {
    fn new(initial: ExternalFloorReplayCheckpoint) -> Self {
        Self {
            state: Rc::new(RefCell::new(initial)),
            mode: Rc::new(Cell::new(Mode::Normal)),
        }
    }
}

impl ExternalFloorReplayStore for Custodian {
    fn load(&self) -> io::Result<ExternalFloorReplayCheckpoint> {
        Ok(*self.state.borrow())
    }

    fn compare_and_swap(
        &self,
        expected: ExternalFloorReplayCheckpoint,
        replacement: ExternalFloorReplayCheckpoint,
    ) -> io::Result<ExternalFloorReplayCasOutcome> {
        match self.mode.get() {
            Mode::Conflict => Ok(ExternalFloorReplayCasOutcome::Conflict(
                *self.state.borrow(),
            )),
            Mode::Uncertain => Ok(ExternalFloorReplayCasOutcome::Uncertain),
            Mode::Error => Err(io::Error::other("custodian unavailable")),
            Mode::FalseCommit => Ok(ExternalFloorReplayCasOutcome::Committed),
            Mode::Normal if *self.state.borrow() == expected => {
                *self.state.borrow_mut() = replacement;
                Ok(ExternalFloorReplayCasOutcome::Committed)
            }
            Mode::Normal => Ok(ExternalFloorReplayCasOutcome::Conflict(
                *self.state.borrow(),
            )),
        }
    }
}

#[derive(Clone)]
struct Boundary {
    calls: Rc<Cell<usize>>,
    custodian: Custodian,
}

impl ExternalFloorBoundary for Boundary {
    fn transact(&self, request: ExternalFloorRequest) -> io::Result<ExternalFloorResponse> {
        assert_eq!(
            self.custodian.state.borrow().next_sequence,
            request.sequence + 1,
            "custodian must commit before the boundary is called"
        );
        self.calls.set(self.calls.get() + 1);
        Ok(ExternalFloorResponse {
            request_binding: request.binding,
            outcome: ExternalFloorOutcome::Current(SourceFloorState {
                generation: 0,
                snapshot_commitment: None,
            }),
        })
    }
}

#[test]
fn concrete_coordinator_advances_both_stores_before_effect_and_survives_restart() {
    let temporary = TemporaryDirectory::new();
    let initial = checkpoint(4, 0);
    UnixExternalFloorReplayStore::provision(&temporary.replay(), initial).unwrap();
    let custodian = Custodian::new(initial);
    let calls = Rc::new(Cell::new(0));
    let boundary = Boundary {
        calls: calls.clone(),
        custodian: custodian.clone(),
    };
    let server = config(temporary.replay(), initial)
        .open(custodian.clone(), boundary.clone())
        .unwrap();
    let request = requests()[0];
    let wire = encode_authenticated_external_floor_request(&request, &authentication()).unwrap();
    let response = server.handle(&wire).unwrap();
    decode_authenticated_external_floor_response(&response, &request, &authentication()).unwrap();
    assert_eq!(calls.get(), 1);
    let committed = server.checkpoint();
    assert_eq!(*custodian.state.borrow(), committed);
    drop(server);

    let restarted = config(temporary.replay(), committed)
        .open(custodian.clone(), boundary)
        .unwrap();
    assert!(restarted.handle(&wire).is_err());
    let next = requests()[1];
    let next_wire = encode_authenticated_external_floor_request(&next, &authentication()).unwrap();
    restarted.handle(&next_wire).unwrap();
    assert_eq!(calls.get(), 2);
}

#[test]
fn production_coordinator_accepts_the_authenticated_transport_custodian() {
    let temporary = TemporaryDirectory::new();
    let initial = checkpoint(12, 0);
    UnixExternalFloorReplayStore::provision(&temporary.replay(), initial).unwrap();
    let remote_store = Custodian::new(initial);
    let remote_server = AuthenticatedExternalFloorCustodianServer::new(
        remote_store.clone(),
        custodian_authentication(),
    );
    let remote_client = AuthenticatedExternalFloorCustodian::new(
        &remote_server,
        custodian_authentication(),
        ExternalFloorCustodianTransportCheckpoint::new(CUSTODIAN_SESSION, 0).unwrap(),
    );
    let calls = Rc::new(Cell::new(0));
    let boundary = Boundary {
        calls: calls.clone(),
        custodian: remote_store.clone(),
    };
    let coordinator = config(temporary.replay(), initial)
        .open(&remote_client, boundary)
        .unwrap();
    let request = requests()[0];
    let wire = encode_authenticated_external_floor_request(&request, &authentication()).unwrap();
    coordinator.handle(&wire).unwrap();
    assert_eq!(calls.get(), 1);
    assert_eq!(*remote_store.state.borrow(), coordinator.checkpoint());
    assert_eq!(
        coordinator.custodian().transport_checkpoint().next_sequence,
        3
    );
}

#[test]
fn custodian_must_exactly_match_before_primary_store_is_accepted() {
    let temporary = TemporaryDirectory::new();
    let initial = checkpoint(4, 0);
    UnixExternalFloorReplayStore::provision(&temporary.replay(), initial).unwrap();
    let stale = Custodian::new(checkpoint(3, 0));
    let boundary = Boundary {
        calls: Rc::new(Cell::new(0)),
        custodian: stale.clone(),
    };
    assert!(config(temporary.replay(), initial)
        .open(stale, boundary)
        .is_err());
}

#[test]
fn every_custodian_failure_closes_after_primary_reservation_and_before_effect() {
    for (label, mode) in [
        ("conflict", Mode::Conflict),
        ("uncertain", Mode::Uncertain),
        ("error", Mode::Error),
        ("false-commit", Mode::FalseCommit),
    ] {
        let temporary = TemporaryDirectory::new();
        let initial = checkpoint(9, 0);
        UnixExternalFloorReplayStore::provision(&temporary.replay(), initial).unwrap();
        let custodian = Custodian::new(initial);
        custodian.mode.set(mode);
        let calls = Rc::new(Cell::new(0));
        let boundary = Boundary {
            calls: calls.clone(),
            custodian: custodian.clone(),
        };
        let server = config(temporary.replay(), initial)
            .open(custodian, boundary)
            .unwrap();
        let request = requests()[0];
        let wire =
            encode_authenticated_external_floor_request(&request, &authentication()).unwrap();
        assert!(server.handle(&wire).is_err(), "{label}");
        assert!(server.is_closed(), "{label}");
        assert_eq!(calls.get(), 0, "{label}");
        assert_eq!(server.checkpoint().next_sequence, 1, "{label}");
        assert!(server.handle(&wire).is_err(), "{label}");
        assert_eq!(calls.get(), 0, "{label}");
    }
}

#[test]
fn production_config_has_no_defaults_rejects_relative_paths_and_redacts_key() {
    let initial = checkpoint(1, 0);
    assert!(UnixExternalFloorServerConfig::new(
        PathBuf::from("relative/replay"),
        initial,
        KEY,
        CLIENT,
        BOUNDARY,
    )
    .is_err());
    assert!(UnixExternalFloorServerConfig::new(
        PathBuf::from("/absolute/replay"),
        initial,
        [0; 32],
        CLIENT,
        BOUNDARY,
    )
    .is_err());
    let configured = UnixExternalFloorServerConfig::new(
        PathBuf::from("/absolute/replay"),
        initial,
        [0x99; 32],
        CLIENT,
        BOUNDARY,
    )
    .unwrap();
    let debug = format!("{configured:?}");
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains("153, 153"));
}
