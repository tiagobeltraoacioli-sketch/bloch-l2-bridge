// SPDX-License-Identifier: MIT OR Apache-2.0
#![cfg(unix)]

use std::cell::{Cell, RefCell};
use std::io;
use std::rc::Rc;

use bloch_l2_bridge::{
    AuthenticatedExternalFloorCustodian, AuthenticatedExternalFloorCustodianServer,
    ExternalFloorCustodianAuthentication, ExternalFloorCustodianTransport,
    ExternalFloorCustodianTransportCheckpoint, ExternalFloorReplayCasOutcome,
    ExternalFloorReplayCheckpoint, ExternalFloorReplayStore, EXTERNAL_FLOOR_CUSTODIAN_MAX_LEN,
};

const KEY: [u8; 32] = [0x71; 32];
const CLIENT: [u8; 32] = [0xc1; 32];
const CUSTODIAN: [u8; 32] = [0xd2; 32];
const TRANSPORT_SESSION: [u8; 32] = [0x83; 32];
const CHECKPOINT_SESSION: [u8; 32] = [0x54; 32];

fn authentication() -> ExternalFloorCustodianAuthentication {
    ExternalFloorCustodianAuthentication::new(KEY, CLIENT, CUSTODIAN).unwrap()
}

fn checkpoint(revision: u64, next_sequence: u64) -> ExternalFloorReplayCheckpoint {
    ExternalFloorReplayCheckpoint::new(revision, CHECKPOINT_SESSION, next_sequence).unwrap()
}

fn transport_checkpoint(next_sequence: u64) -> ExternalFloorCustodianTransportCheckpoint {
    ExternalFloorCustodianTransportCheckpoint::new(TRANSPORT_SESSION, next_sequence).unwrap()
}

#[derive(Clone, Copy)]
enum Mode {
    Normal,
    Uncertain,
}

#[derive(Clone)]
struct MemoryStore {
    state: Rc<RefCell<ExternalFloorReplayCheckpoint>>,
    cas_calls: Rc<Cell<usize>>,
    load_calls: Rc<Cell<usize>>,
    mode: Rc<Cell<Mode>>,
}

impl MemoryStore {
    fn new(initial: ExternalFloorReplayCheckpoint) -> Self {
        Self {
            state: Rc::new(RefCell::new(initial)),
            cas_calls: Rc::new(Cell::new(0)),
            load_calls: Rc::new(Cell::new(0)),
            mode: Rc::new(Cell::new(Mode::Normal)),
        }
    }
}

impl ExternalFloorReplayStore for MemoryStore {
    fn load(&self) -> io::Result<ExternalFloorReplayCheckpoint> {
        self.load_calls.set(self.load_calls.get() + 1);
        Ok(*self.state.borrow())
    }

    fn compare_and_swap(
        &self,
        expected: ExternalFloorReplayCheckpoint,
        replacement: ExternalFloorReplayCheckpoint,
    ) -> io::Result<ExternalFloorReplayCasOutcome> {
        self.cas_calls.set(self.cas_calls.get() + 1);
        match self.mode.get() {
            Mode::Uncertain => Ok(ExternalFloorReplayCasOutcome::Uncertain),
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

#[test]
fn authenticated_remote_store_round_trips_load_commit_and_conflict() {
    let initial = checkpoint(7, 11);
    let replacement = checkpoint(8, 12);
    let underlying = MemoryStore::new(initial);
    let server =
        AuthenticatedExternalFloorCustodianServer::new(underlying.clone(), authentication());
    let client = AuthenticatedExternalFloorCustodian::new(
        &server,
        authentication(),
        transport_checkpoint(0),
    );
    assert_eq!(client.load().unwrap(), initial);
    assert_eq!(
        client.compare_and_swap(initial, replacement).unwrap(),
        ExternalFloorReplayCasOutcome::Committed
    );
    assert_eq!(client.load().unwrap(), replacement);
    assert_eq!(
        client.compare_and_swap(checkpoint(6, 10), initial).unwrap(),
        ExternalFloorReplayCasOutcome::Conflict(replacement)
    );
    assert_eq!(client.transport_checkpoint().next_sequence, 4);
}

struct DuplicateTransport<'a> {
    server: &'a AuthenticatedExternalFloorCustodianServer<MemoryStore>,
}

impl ExternalFloorCustodianTransport for DuplicateTransport<'_> {
    fn exchange(&self, request: &[u8]) -> io::Result<Vec<u8>> {
        let _lost = self.server.handle(request)?;
        self.server.handle(request)
    }
}

#[test]
fn exact_duplicate_after_lost_response_is_idempotently_committed_once() {
    let initial = checkpoint(2, 3);
    let replacement = checkpoint(3, 4);
    let underlying = MemoryStore::new(initial);
    let server =
        AuthenticatedExternalFloorCustodianServer::new(underlying.clone(), authentication());
    let client = AuthenticatedExternalFloorCustodian::new(
        DuplicateTransport { server: &server },
        authentication(),
        transport_checkpoint(0),
    );
    assert_eq!(
        client.compare_and_swap(initial, replacement).unwrap(),
        ExternalFloorReplayCasOutcome::Committed
    );
    assert_eq!(*underlying.state.borrow(), replacement);
    assert_eq!(underlying.cas_calls.get(), 1);
}

struct FailingTransport(Cell<usize>);

impl ExternalFloorCustodianTransport for FailingTransport {
    fn exchange(&self, _request: &[u8]) -> io::Result<Vec<u8>> {
        self.0.set(self.0.get() + 1);
        Err(io::Error::new(io::ErrorKind::TimedOut, "outcome unknown"))
    }
}

#[test]
fn ambiguous_transport_failure_consumes_sequence_without_automatic_retry() {
    let client = AuthenticatedExternalFloorCustodian::new(
        FailingTransport(Cell::new(0)),
        authentication(),
        transport_checkpoint(9),
    );
    assert!(client.load().is_err());
    assert_eq!(client.transport_checkpoint().next_sequence, 10);
    assert_eq!(client.load().unwrap_err().kind(), io::ErrorKind::TimedOut);
    assert_eq!(client.transport_checkpoint().next_sequence, 11);
}

struct TamperTransport<'a> {
    server: &'a AuthenticatedExternalFloorCustodianServer<MemoryStore>,
}

impl ExternalFloorCustodianTransport for TamperTransport<'_> {
    fn exchange(&self, request: &[u8]) -> io::Result<Vec<u8>> {
        let mut response = self.server.handle(request)?;
        let index = response.len() - 1;
        response[index] ^= 1;
        Ok(response)
    }
}

struct ReplayResponseTransport<'a> {
    server: &'a AuthenticatedExternalFloorCustodianServer<MemoryStore>,
    cached: RefCell<Option<Vec<u8>>>,
}

impl ExternalFloorCustodianTransport for ReplayResponseTransport<'_> {
    fn exchange(&self, request: &[u8]) -> io::Result<Vec<u8>> {
        if let Some(cached) = self.cached.borrow().as_ref() {
            return Ok(cached.clone());
        }
        let response = self.server.handle(request)?;
        *self.cached.borrow_mut() = Some(response.clone());
        Ok(response)
    }
}

#[test]
fn tampered_or_replayed_response_is_rejected_and_sequence_stays_consumed() {
    let initial = checkpoint(1, 0);
    let store = MemoryStore::new(initial);
    let server = AuthenticatedExternalFloorCustodianServer::new(store, authentication());
    let tampered = AuthenticatedExternalFloorCustodian::new(
        TamperTransport { server: &server },
        authentication(),
        transport_checkpoint(0),
    );
    assert!(tampered.load().is_err());
    assert_eq!(tampered.transport_checkpoint().next_sequence, 1);

    let replayed = AuthenticatedExternalFloorCustodian::new(
        ReplayResponseTransport {
            server: &server,
            cached: RefCell::new(None),
        },
        authentication(),
        transport_checkpoint(20),
    );
    assert_eq!(replayed.load().unwrap(), initial);
    assert!(replayed.load().is_err());
    assert_eq!(replayed.transport_checkpoint().next_sequence, 22);
}

#[test]
fn uncertain_store_result_is_authenticated_and_preserved() {
    let initial = checkpoint(4, 8);
    let replacement = checkpoint(5, 9);
    let underlying = MemoryStore::new(initial);
    underlying.mode.set(Mode::Uncertain);
    let server = AuthenticatedExternalFloorCustodianServer::new(underlying, authentication());
    let client = AuthenticatedExternalFloorCustodian::new(
        &server,
        authentication(),
        transport_checkpoint(0),
    );
    assert_eq!(
        client.compare_and_swap(initial, replacement).unwrap(),
        ExternalFloorReplayCasOutcome::Uncertain
    );
}

#[test]
fn malformed_bounded_inputs_never_reach_the_store_or_panic() {
    let initial = checkpoint(1, 0);
    let underlying = MemoryStore::new(initial);
    let server =
        AuthenticatedExternalFloorCustodianServer::new(underlying.clone(), authentication());
    for length in 0..=EXTERNAL_FLOOR_CUSTODIAN_MAX_LEN + 1 {
        let bytes = vec![(length & 0xff) as u8; length];
        assert!(server.handle(&bytes).is_err());
    }
    assert_eq!(underlying.load_calls.get(), 0);
    assert_eq!(underlying.cas_calls.get(), 0);
}

#[test]
fn invalid_configuration_and_transition_fail_before_transport() {
    assert!(ExternalFloorCustodianAuthentication::new([0; 32], CLIENT, CUSTODIAN).is_err());
    let debug_authentication = authentication();
    let debug = format!("{debug_authentication:?}");
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains("113, 113"));
    assert!(ExternalFloorCustodianTransportCheckpoint::new([0; 32], 0).is_err());
    let transport = FailingTransport(Cell::new(0));
    let client = AuthenticatedExternalFloorCustodian::new(
        transport,
        authentication(),
        transport_checkpoint(0),
    );
    assert!(client
        .compare_and_swap(checkpoint(1, 1), checkpoint(3, 2))
        .is_err());
    assert_eq!(client.transport_checkpoint().next_sequence, 0);

    let initial = checkpoint(1, 0);
    let underlying = MemoryStore::new(initial);
    let server =
        AuthenticatedExternalFloorCustodianServer::new(underlying.clone(), authentication());
    let wrong_key =
        ExternalFloorCustodianAuthentication::new([0x72; 32], CLIENT, CUSTODIAN).unwrap();
    let unauthorized =
        AuthenticatedExternalFloorCustodian::new(&server, wrong_key, transport_checkpoint(0));
    assert!(unauthorized.load().is_err());
    assert_eq!(underlying.load_calls.get(), 0);
}
