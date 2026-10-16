// SPDX-License-Identifier: MIT OR Apache-2.0
#![cfg(unix)]

use std::cell::RefCell;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use bloch_l2_bridge::{
    handle_external_floor_custodian_tcp_connection, AuthenticatedExternalFloorCustodian,
    AuthenticatedExternalFloorCustodianServer, ExternalFloorCustodianAuthentication,
    ExternalFloorCustodianTcpClientConfig, ExternalFloorCustodianTcpServerPolicy,
    ExternalFloorCustodianTransport, ExternalFloorCustodianTransportCheckpoint,
    ExternalFloorReplayCasOutcome, ExternalFloorReplayCheckpoint, ExternalFloorReplayStore,
    TcpExternalFloorCustodianTransport, EXTERNAL_FLOOR_CUSTODIAN_MAX_LEN,
};

const KEY: [u8; 32] = [0x61; 32];
const CLIENT: [u8; 32] = [0x72; 32];
const SERVER: [u8; 32] = [0x83; 32];
const TRANSPORT_SESSION: [u8; 32] = [0x94; 32];
const CHECKPOINT_SESSION: [u8; 32] = [0xa5; 32];
const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

fn authentication() -> ExternalFloorCustodianAuthentication {
    ExternalFloorCustodianAuthentication::new(KEY, CLIENT, SERVER).unwrap()
}

fn checkpoint(revision: u64, next_sequence: u64) -> ExternalFloorReplayCheckpoint {
    ExternalFloorReplayCheckpoint::new(revision, CHECKPOINT_SESSION, next_sequence).unwrap()
}

fn transport_checkpoint() -> ExternalFloorCustodianTransportCheckpoint {
    ExternalFloorCustodianTransportCheckpoint::new(TRANSPORT_SESSION, 0).unwrap()
}

#[derive(Clone)]
struct ThreadStore {
    state: Arc<Mutex<ExternalFloorReplayCheckpoint>>,
    loads: Arc<AtomicUsize>,
    swaps: Arc<AtomicUsize>,
}

impl ThreadStore {
    fn new(initial: ExternalFloorReplayCheckpoint) -> Self {
        Self {
            state: Arc::new(Mutex::new(initial)),
            loads: Arc::new(AtomicUsize::new(0)),
            swaps: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl ExternalFloorReplayStore for ThreadStore {
    fn load(&self) -> io::Result<ExternalFloorReplayCheckpoint> {
        self.loads.fetch_add(1, Ordering::SeqCst);
        Ok(*self.state.lock().unwrap())
    }

    fn compare_and_swap(
        &self,
        expected: ExternalFloorReplayCheckpoint,
        replacement: ExternalFloorReplayCheckpoint,
    ) -> io::Result<ExternalFloorReplayCasOutcome> {
        self.swaps.fetch_add(1, Ordering::SeqCst);
        let mut current = self.state.lock().unwrap();
        if *current == expected {
            *current = replacement;
            Ok(ExternalFloorReplayCasOutcome::Committed)
        } else {
            Ok(ExternalFloorReplayCasOutcome::Conflict(*current))
        }
    }
}

fn listener() -> (TcpListener, SocketAddr) {
    let listener = TcpListener::bind(SocketAddr::new(LOOPBACK, 0)).unwrap();
    let address = listener.local_addr().unwrap();
    (listener, address)
}

fn client_config(address: SocketAddr, timeout: Duration) -> ExternalFloorCustodianTcpClientConfig {
    ExternalFloorCustodianTcpClientConfig::new(address, timeout, Some(LOOPBACK)).unwrap()
}

#[test]
fn strict_tcp_transport_round_trips_without_reconnect_or_retry() {
    let initial = checkpoint(5, 9);
    let replacement = checkpoint(6, 10);
    let store = ThreadStore::new(initial);
    let observed = store.clone();
    let (listener, address) = listener();
    let server_store = store.clone();
    let server_thread = thread::spawn(move || {
        let server = AuthenticatedExternalFloorCustodianServer::new(server_store, authentication());
        let policy =
            ExternalFloorCustodianTcpServerPolicy::new(LOOPBACK, Duration::from_secs(2)).unwrap();
        for _ in 0..3 {
            let (stream, _) = listener.accept().unwrap();
            handle_external_floor_custodian_tcp_connection(stream, &server, policy).unwrap();
        }
    });
    let transport =
        TcpExternalFloorCustodianTransport::new(client_config(address, Duration::from_secs(2)));
    let client = AuthenticatedExternalFloorCustodian::new(
        transport,
        authentication(),
        transport_checkpoint(),
    );
    assert_eq!(client.load().unwrap(), initial);
    assert_eq!(
        client.compare_and_swap(initial, replacement).unwrap(),
        ExternalFloorReplayCasOutcome::Committed
    );
    assert_eq!(client.load().unwrap(), replacement);
    server_thread.join().unwrap();
    assert_eq!(observed.swaps.load(Ordering::SeqCst), 1);
    assert_eq!(client.transport_checkpoint().next_sequence, 3);
}

#[test]
fn read_timeout_is_ambiguous_consumes_sequence_and_never_reconnects() {
    let (listener, address) = listener();
    let accepted = Arc::new(AtomicUsize::new(0));
    let accepted_by_server = accepted.clone();
    let server_thread = thread::spawn(move || {
        let (_stream, _) = listener.accept().unwrap();
        accepted_by_server.fetch_add(1, Ordering::SeqCst);
        thread::sleep(Duration::from_millis(120));
    });
    let transport =
        TcpExternalFloorCustodianTransport::new(client_config(address, Duration::from_millis(30)));
    let client = AuthenticatedExternalFloorCustodian::new(
        transport,
        authentication(),
        transport_checkpoint(),
    );
    assert!(client.load().is_err());
    assert_eq!(client.transport_checkpoint().next_sequence, 1);
    server_thread.join().unwrap();
    assert_eq!(accepted.load(Ordering::SeqCst), 1);
}

#[test]
fn oversized_response_prefix_is_rejected_before_allocation() {
    let (listener, address) = listener();
    let server_thread = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut prefix = [0_u8; 2];
        stream.read_exact(&mut prefix).unwrap();
        let mut request = vec![0_u8; u16::from_be_bytes(prefix) as usize];
        stream.read_exact(&mut request).unwrap();
        assert_eq!(stream.read(&mut [0_u8; 1]).unwrap(), 0);
        let oversized = u16::try_from(EXTERNAL_FLOOR_CUSTODIAN_MAX_LEN + 1).unwrap();
        stream.write_all(&oversized.to_be_bytes()).unwrap();
        stream.shutdown(Shutdown::Write).unwrap();
    });
    let transport =
        TcpExternalFloorCustodianTransport::new(client_config(address, Duration::from_secs(2)));
    let client = AuthenticatedExternalFloorCustodian::new(
        transport,
        authentication(),
        transport_checkpoint(),
    );
    assert!(client.load().is_err());
    assert_eq!(client.transport_checkpoint().next_sequence, 1);
    server_thread.join().unwrap();
}

#[test]
fn authenticated_response_with_trailing_bytes_is_still_rejected() {
    let initial = checkpoint(3, 7);
    let request = captured_request();
    let response_server =
        AuthenticatedExternalFloorCustodianServer::new(ThreadStore::new(initial), authentication());
    let response = response_server.handle(&request).unwrap();
    let (listener, address) = listener();
    let server_thread = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut prefix = [0_u8; 2];
        stream.read_exact(&mut prefix).unwrap();
        let mut received = vec![0_u8; u16::from_be_bytes(prefix) as usize];
        stream.read_exact(&mut received).unwrap();
        assert_eq!(stream.read(&mut [0_u8; 1]).unwrap(), 0);
        stream
            .write_all(&u16::try_from(response.len()).unwrap().to_be_bytes())
            .unwrap();
        stream.write_all(&response).unwrap();
        stream.write_all(&[0xee]).unwrap();
        stream.shutdown(Shutdown::Write).unwrap();
    });
    let transport =
        TcpExternalFloorCustodianTransport::new(client_config(address, Duration::from_secs(2)));
    let client = AuthenticatedExternalFloorCustodian::new(
        transport,
        authentication(),
        transport_checkpoint(),
    );
    assert!(client.load().is_err());
    assert_eq!(client.transport_checkpoint().next_sequence, 1);
    server_thread.join().unwrap();
}

struct CaptureTransport(RefCell<Option<Vec<u8>>>);

impl ExternalFloorCustodianTransport for CaptureTransport {
    fn exchange(&self, request: &[u8]) -> io::Result<Vec<u8>> {
        *self.0.borrow_mut() = Some(request.to_vec());
        Err(io::Error::other("captured"))
    }
}

fn captured_request() -> Vec<u8> {
    let transport = CaptureTransport(RefCell::new(None));
    let client = AuthenticatedExternalFloorCustodian::new(
        &transport,
        authentication(),
        transport_checkpoint(),
    );
    assert!(client.load().is_err());
    transport.0.into_inner().unwrap()
}

impl ExternalFloorCustodianTransport for &CaptureTransport {
    fn exchange(&self, request: &[u8]) -> io::Result<Vec<u8>> {
        (*self).exchange(request)
    }
}

#[test]
fn server_rejects_trailing_smuggled_bytes_before_store_access() {
    let request = captured_request();
    let store = ThreadStore::new(checkpoint(1, 0));
    let observed = store.clone();
    let (listener, address) = listener();
    let server_thread = thread::spawn(move || {
        let server = AuthenticatedExternalFloorCustodianServer::new(store, authentication());
        let policy =
            ExternalFloorCustodianTcpServerPolicy::new(LOOPBACK, Duration::from_secs(2)).unwrap();
        let (stream, _) = listener.accept().unwrap();
        assert!(handle_external_floor_custodian_tcp_connection(stream, &server, policy).is_err());
    });
    let mut stream = TcpStream::connect(address).unwrap();
    stream
        .write_all(&u16::try_from(request.len()).unwrap().to_be_bytes())
        .unwrap();
    stream.write_all(&request).unwrap();
    stream.write_all(&[0xff]).unwrap();
    stream.shutdown(Shutdown::Write).unwrap();
    server_thread.join().unwrap();
    assert_eq!(observed.loads.load(Ordering::SeqCst), 0);
    assert_eq!(observed.swaps.load(Ordering::SeqCst), 0);
}

#[test]
fn pinned_client_ip_is_checked_before_reading_or_store_access() {
    let store = ThreadStore::new(checkpoint(1, 0));
    let observed = store.clone();
    let (listener, address) = listener();
    let server_thread = thread::spawn(move || {
        let server = AuthenticatedExternalFloorCustodianServer::new(store, authentication());
        let policy = ExternalFloorCustodianTcpServerPolicy::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            Duration::from_secs(2),
        )
        .unwrap();
        let (stream, _) = listener.accept().unwrap();
        assert!(handle_external_floor_custodian_tcp_connection(stream, &server, policy).is_err());
    });
    let transport =
        TcpExternalFloorCustodianTransport::new(client_config(address, Duration::from_secs(2)));
    let client = AuthenticatedExternalFloorCustodian::new(
        transport,
        authentication(),
        transport_checkpoint(),
    );
    assert!(client.load().is_err());
    server_thread.join().unwrap();
    assert_eq!(observed.loads.load(Ordering::SeqCst), 0);
    assert_eq!(observed.swaps.load(Ordering::SeqCst), 0);
}

#[test]
fn unsafe_or_unbounded_connection_configuration_is_rejected() {
    assert!(ExternalFloorCustodianTcpClientConfig::new(
        SocketAddr::new(LOOPBACK, 0),
        Duration::from_secs(1),
        None,
    )
    .is_err());
    assert!(ExternalFloorCustodianTcpClientConfig::new(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 1234),
        Duration::from_secs(1),
        None,
    )
    .is_err());
    assert!(ExternalFloorCustodianTcpClientConfig::new(
        SocketAddr::new(LOOPBACK, 1234),
        Duration::ZERO,
        None,
    )
    .is_err());
    assert!(
        ExternalFloorCustodianTcpServerPolicy::new(LOOPBACK, Duration::from_secs(31),).is_err()
    );
}
