// SPDX-License-Identifier: MIT OR Apache-2.0
#![cfg(unix)]

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{symlink, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use bloch_l2_bridge::{
    AuthenticatedExternalFloorCustodianServer, DurableAuthenticatedExternalFloorCustodian,
    ExternalFloorCustodianAnchorCasOutcome, ExternalFloorCustodianAnchorStore,
    ExternalFloorCustodianAuthentication, ExternalFloorCustodianClientAnchor,
    ExternalFloorCustodianClientInspection, ExternalFloorCustodianTransport,
    ExternalFloorCustodianTransportCheckpoint, ExternalFloorReplayCasOutcome,
    ExternalFloorReplayCheckpoint, ExternalFloorReplayStore,
};

const KEY: [u8; 32] = [0x41; 32];
const CHECKPOINT_KEY: [u8; 32] = [0x52; 32];
const CLIENT: [u8; 32] = [0x63; 32];
const SERVER: [u8; 32] = [0x74; 32];
const SESSION: [u8; 32] = [0x85; 32];
static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct Temp {
    root: PathBuf,
    store: PathBuf,
}

impl Temp {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "bloch-bxrc-client-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        Self {
            store: root.join("checkpoint"),
            root,
        }
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}

#[derive(Clone)]
struct Store(Arc<Mutex<ExternalFloorReplayCheckpoint>>);

impl ExternalFloorReplayStore for Store {
    fn load(&self) -> io::Result<ExternalFloorReplayCheckpoint> {
        Ok(*self.0.lock().unwrap())
    }

    fn compare_and_swap(
        &self,
        expected: ExternalFloorReplayCheckpoint,
        replacement: ExternalFloorReplayCheckpoint,
    ) -> io::Result<ExternalFloorReplayCasOutcome> {
        let mut current = self.0.lock().unwrap();
        if *current == expected {
            *current = replacement;
            Ok(ExternalFloorReplayCasOutcome::Committed)
        } else {
            Ok(ExternalFloorReplayCasOutcome::Conflict(*current))
        }
    }
}

struct FailingTransport(Arc<AtomicUsize>);

impl ExternalFloorCustodianTransport for FailingTransport {
    fn exchange(&self, _request: &[u8]) -> io::Result<Vec<u8>> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(io::Error::new(io::ErrorKind::TimedOut, "ambiguous"))
    }
}

#[derive(Clone)]
struct AnchorStore {
    state: Arc<Mutex<ExternalFloorCustodianClientAnchor>>,
    fail_after_commit: Arc<AtomicUsize>,
}

impl AnchorStore {
    fn new(anchor: ExternalFloorCustodianClientAnchor) -> Self {
        Self {
            state: Arc::new(Mutex::new(anchor)),
            fail_after_commit: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn fail_next_after_commit(&self) {
        self.fail_after_commit.store(1, Ordering::SeqCst);
    }
}

impl ExternalFloorCustodianAnchorStore for AnchorStore {
    fn load(&self) -> io::Result<ExternalFloorCustodianClientAnchor> {
        Ok(*self.state.lock().unwrap())
    }

    fn compare_and_swap(
        &self,
        expected: ExternalFloorCustodianClientAnchor,
        replacement: ExternalFloorCustodianClientAnchor,
    ) -> io::Result<ExternalFloorCustodianAnchorCasOutcome> {
        let mut state = self.state.lock().unwrap();
        if *state == expected {
            *state = replacement;
            if self.fail_after_commit.swap(0, Ordering::SeqCst) == 1 {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "ambiguous external anchor CAS",
                ));
            }
            Ok(ExternalFloorCustodianAnchorCasOutcome::Committed)
        } else {
            Ok(ExternalFloorCustodianAnchorCasOutcome::Conflict(*state))
        }
    }
}

struct ObservingTransport<'a, S> {
    server: &'a AuthenticatedExternalFloorCustodianServer<S>,
    anchors: AnchorStore,
    calls: Arc<AtomicUsize>,
    fail_finish_anchor: bool,
}

impl<S: ExternalFloorReplayStore> ExternalFloorCustodianTransport for ObservingTransport<'_, S> {
    fn exchange(&self, request: &[u8]) -> io::Result<Vec<u8>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(self.anchors.load()?.revision, 1);
        if self.fail_finish_anchor {
            self.anchors.fail_next_after_commit();
        }
        self.server.handle(request)
    }
}

fn authentication() -> ExternalFloorCustodianAuthentication {
    ExternalFloorCustodianAuthentication::new(KEY, CLIENT, SERVER).unwrap()
}

fn transport_checkpoint(sequence: u64) -> ExternalFloorCustodianTransportCheckpoint {
    ExternalFloorCustodianTransportCheckpoint::new(SESSION, sequence).unwrap()
}

fn replay(revision: u64, sequence: u64) -> ExternalFloorReplayCheckpoint {
    ExternalFloorReplayCheckpoint::new(revision, [0x96; 32], sequence).unwrap()
}

fn provision(path: &Path) -> ExternalFloorCustodianClientAnchor {
    DurableAuthenticatedExternalFloorCustodian::<FailingTransport, AnchorStore>::provision(
        path,
        transport_checkpoint(0),
        CHECKPOINT_KEY,
    )
    .unwrap()
}

#[test]
fn successful_exchange_is_reserved_then_finalized_and_reopens_exactly() {
    let temp = Temp::new();
    let initial_anchor = provision(&temp.store);
    let anchor_store = AnchorStore::new(initial_anchor);
    let remote = replay(7, 11);
    let server = AuthenticatedExternalFloorCustodianServer::new(
        Store(Arc::new(Mutex::new(remote))),
        authentication(),
    );
    let client = DurableAuthenticatedExternalFloorCustodian::open(
        &temp.store,
        anchor_store.clone(),
        &server,
        authentication(),
        CHECKPOINT_KEY,
    )
    .unwrap();
    assert_eq!(client.load().unwrap(), remote);
    assert_eq!(client.transport_checkpoint(), transport_checkpoint(1));
    let committed_anchor = client.anchor();
    assert_ne!(committed_anchor, initial_anchor);
    drop(client);

    assert_eq!(
        DurableAuthenticatedExternalFloorCustodian::<FailingTransport, AnchorStore>::inspect(
            &temp.store,
            &anchor_store,
            CHECKPOINT_KEY,
        )
        .unwrap(),
        ExternalFloorCustodianClientInspection::Ready {
            anchor: committed_anchor,
            checkpoint: transport_checkpoint(1),
        }
    );

    let reopened = DurableAuthenticatedExternalFloorCustodian::open(
        &temp.store,
        anchor_store,
        &server,
        authentication(),
        CHECKPOINT_KEY,
    )
    .unwrap();
    assert_eq!(reopened.transport_checkpoint(), transport_checkpoint(1));
}

#[test]
fn ambiguous_io_blocks_retry_across_restart_until_exact_reconciliation() {
    let temp = Temp::new();
    let initial_anchor = provision(&temp.store);
    let anchor_store = AnchorStore::new(initial_anchor);
    let attempts = Arc::new(AtomicUsize::new(0));
    let client = DurableAuthenticatedExternalFloorCustodian::open(
        &temp.store,
        anchor_store.clone(),
        FailingTransport(Arc::clone(&attempts)),
        authentication(),
        CHECKPOINT_KEY,
    )
    .unwrap();
    assert_eq!(client.load().unwrap_err().kind(), io::ErrorKind::TimedOut);
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
    assert_eq!(client.load().unwrap_err().kind(), io::ErrorKind::WouldBlock);
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
    drop(client);

    let pending =
        match DurableAuthenticatedExternalFloorCustodian::<FailingTransport, AnchorStore>::inspect(
            &temp.store,
            &anchor_store,
            CHECKPOINT_KEY,
        )
        .unwrap()
        {
            ExternalFloorCustodianClientInspection::Pending(pending) => pending,
            _ => panic!("expected a pending operation"),
        };
    assert_eq!(pending.operation_sequence, 0);
    assert_eq!(pending.checkpoint, transport_checkpoint(1));
    assert!(!pending.compare_and_swap);
    assert!(DurableAuthenticatedExternalFloorCustodian::open(
        &temp.store,
        anchor_store.clone(),
        FailingTransport(Arc::clone(&attempts)),
        authentication(),
        CHECKPOINT_KEY,
    )
    .is_err());
    let mut wrong = pending.operation_commitment;
    wrong[0] ^= 1;
    assert!(
        DurableAuthenticatedExternalFloorCustodian::<FailingTransport, AnchorStore>::reconcile_pending(
            &temp.store,
            &anchor_store,
            wrong,
            CHECKPOINT_KEY,
        )
        .is_err()
    );
    let ready = DurableAuthenticatedExternalFloorCustodian::<FailingTransport, AnchorStore>::reconcile_pending(
        &temp.store,
        &anchor_store,
        pending.operation_commitment,
        CHECKPOINT_KEY,
    )
    .unwrap();
    assert_eq!(anchor_store.load().unwrap(), ready);
    let reopened = DurableAuthenticatedExternalFloorCustodian::open(
        &temp.store,
        anchor_store,
        FailingTransport(Arc::clone(&attempts)),
        authentication(),
        CHECKPOINT_KEY,
    )
    .unwrap();
    assert_eq!(reopened.transport_checkpoint(), transport_checkpoint(1));
}

#[test]
fn invalid_cas_does_not_consume_or_reserve_a_sequence() {
    let temp = Temp::new();
    let anchor = provision(&temp.store);
    let anchor_store = AnchorStore::new(anchor);
    let attempts = Arc::new(AtomicUsize::new(0));
    let client = DurableAuthenticatedExternalFloorCustodian::open(
        &temp.store,
        anchor_store,
        FailingTransport(Arc::clone(&attempts)),
        authentication(),
        CHECKPOINT_KEY,
    )
    .unwrap();
    assert!(client.compare_and_swap(replay(1, 1), replay(3, 2)).is_err());
    assert_eq!(attempts.load(Ordering::SeqCst), 0);
    assert_eq!(client.anchor(), anchor);
    assert_eq!(client.transport_checkpoint(), transport_checkpoint(0));
}

#[test]
fn wrong_key_tamper_rollback_temp_and_concurrent_open_fail_closed() {
    let temp = Temp::new();
    let anchor = provision(&temp.store);
    let anchor_store = AnchorStore::new(anchor);
    assert!(
        DurableAuthenticatedExternalFloorCustodian::<FailingTransport, AnchorStore>::inspect(
            &temp.store,
            &anchor_store,
            [0x11; 32],
        )
        .is_err()
    );

    let attempts = Arc::new(AtomicUsize::new(0));
    let client = DurableAuthenticatedExternalFloorCustodian::open(
        &temp.store,
        anchor_store.clone(),
        FailingTransport(Arc::clone(&attempts)),
        authentication(),
        CHECKPOINT_KEY,
    )
    .unwrap();
    assert!(DurableAuthenticatedExternalFloorCustodian::open(
        &temp.store,
        anchor_store.clone(),
        FailingTransport(attempts),
        authentication(),
        CHECKPOINT_KEY,
    )
    .is_err());
    drop(client);

    let state = temp.store.join(".bxrc-client-checkpoint");
    let mut bytes = fs::read(&state).unwrap();
    bytes[24] ^= 1;
    fs::write(&state, bytes).unwrap();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(
        DurableAuthenticatedExternalFloorCustodian::<FailingTransport, AnchorStore>::inspect(
            &temp.store,
            &anchor_store,
            CHECKPOINT_KEY,
        )
        .is_err()
    );
}

#[test]
fn unsafe_filesystem_objects_are_rejected() {
    let temp = Temp::new();
    let anchor = provision(&temp.store);
    let anchor_store = AnchorStore::new(anchor);
    let state = temp.store.join(".bxrc-client-checkpoint");
    let alias = temp.root.join("alias");
    fs::hard_link(&state, &alias).unwrap();
    assert!(
        DurableAuthenticatedExternalFloorCustodian::<FailingTransport, AnchorStore>::inspect(
            &temp.store,
            &anchor_store,
            CHECKPOINT_KEY,
        )
        .is_err()
    );
    fs::remove_file(alias).unwrap();

    let temporary = temp.store.join(".bxrc-client-checkpoint.tmp");
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .unwrap()
        .write_all(b"orphan")
        .unwrap();
    assert!(
        DurableAuthenticatedExternalFloorCustodian::<FailingTransport, AnchorStore>::inspect(
            &temp.store,
            &anchor_store,
            CHECKPOINT_KEY,
        )
        .is_err()
    );
    fs::remove_file(temporary).unwrap();

    let moved = temp.root.join("moved");
    fs::rename(&state, &moved).unwrap();
    symlink(&moved, &state).unwrap();
    assert!(
        DurableAuthenticatedExternalFloorCustodian::<FailingTransport, AnchorStore>::inspect(
            &temp.store,
            &anchor_store,
            CHECKPOINT_KEY,
        )
        .is_err()
    );
}

#[test]
fn authenticated_rollback_is_rejected_by_the_newer_independent_anchor() {
    let temp = Temp::new();
    let initial_anchor = provision(&temp.store);
    let anchor_store = AnchorStore::new(initial_anchor);
    let state_path = temp.store.join(".bxrc-client-checkpoint");
    let old_record = fs::read(&state_path).unwrap();
    let remote = replay(2, 4);
    let server = AuthenticatedExternalFloorCustodianServer::new(
        Store(Arc::new(Mutex::new(remote))),
        authentication(),
    );
    let client = DurableAuthenticatedExternalFloorCustodian::open(
        &temp.store,
        anchor_store.clone(),
        &server,
        authentication(),
        CHECKPOINT_KEY,
    )
    .unwrap();
    assert_eq!(client.load().unwrap(), remote);
    let newer_anchor = client.anchor();
    assert_eq!(anchor_store.load().unwrap(), newer_anchor);
    drop(client);

    fs::write(&state_path, old_record).unwrap();
    fs::set_permissions(&state_path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(
        DurableAuthenticatedExternalFloorCustodian::<FailingTransport, AnchorStore>::inspect(
            &temp.store,
            &anchor_store,
            CHECKPOINT_KEY,
        )
        .is_err()
    );
}

#[test]
fn directory_symlink_and_relaxed_directory_permissions_are_rejected() {
    let temp = Temp::new();
    let anchor = provision(&temp.store);
    let anchor_store = AnchorStore::new(anchor);
    let alias = temp.root.join("checkpoint-link");
    symlink(&temp.store, &alias).unwrap();
    assert!(
        DurableAuthenticatedExternalFloorCustodian::<FailingTransport, AnchorStore>::inspect(
            &alias,
            &anchor_store,
            CHECKPOINT_KEY,
        )
        .is_err()
    );

    fs::set_permissions(&temp.store, fs::Permissions::from_mode(0o750)).unwrap();
    assert!(
        DurableAuthenticatedExternalFloorCustodian::<FailingTransport, AnchorStore>::inspect(
            &temp.store,
            &anchor_store,
            CHECKPOINT_KEY,
        )
        .is_err()
    );
    fs::set_permissions(&temp.store, fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn external_anchor_is_pending_during_transport_and_finish_ambiguity_poisons_client() {
    let temp = Temp::new();
    let initial_anchor = provision(&temp.store);
    let anchor_store = AnchorStore::new(initial_anchor);
    let remote = replay(5, 9);
    let server = AuthenticatedExternalFloorCustodianServer::new(
        Store(Arc::new(Mutex::new(remote))),
        authentication(),
    );
    let calls = Arc::new(AtomicUsize::new(0));
    let transport = ObservingTransport {
        server: &server,
        anchors: anchor_store.clone(),
        calls: Arc::clone(&calls),
        fail_finish_anchor: true,
    };
    let client = DurableAuthenticatedExternalFloorCustodian::open(
        &temp.store,
        anchor_store.clone(),
        transport,
        authentication(),
        CHECKPOINT_KEY,
    )
    .unwrap();

    assert_eq!(client.load().unwrap_err().kind(), io::ErrorKind::TimedOut);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(anchor_store.load().unwrap().revision, 2);
    assert_eq!(client.load().unwrap_err().kind(), io::ErrorKind::WouldBlock);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn ambiguous_pending_anchor_failure_prevents_transport_and_rollback_reopen() {
    let temp = Temp::new();
    let initial_anchor = provision(&temp.store);
    let state_path = temp.store.join(".bxrc-client-checkpoint");
    let ready_record = fs::read(&state_path).unwrap();
    let anchor_store = AnchorStore::new(initial_anchor);
    anchor_store.fail_next_after_commit();
    let calls = Arc::new(AtomicUsize::new(0));
    let client = DurableAuthenticatedExternalFloorCustodian::open(
        &temp.store,
        anchor_store.clone(),
        FailingTransport(Arc::clone(&calls)),
        authentication(),
        CHECKPOINT_KEY,
    )
    .unwrap();

    assert_eq!(client.load().unwrap_err().kind(), io::ErrorKind::TimedOut);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(anchor_store.load().unwrap().revision, 1);
    assert_eq!(client.load().unwrap_err().kind(), io::ErrorKind::WouldBlock);
    drop(client);

    fs::write(&state_path, ready_record).unwrap();
    fs::set_permissions(&state_path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(DurableAuthenticatedExternalFloorCustodian::open(
        &temp.store,
        anchor_store,
        FailingTransport(Arc::clone(&calls)),
        authentication(),
        CHECKPOINT_KEY,
    )
    .is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}
