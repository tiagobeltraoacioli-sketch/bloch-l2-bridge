// SPDX-License-Identifier: MIT OR Apache-2.0
#![cfg(unix)]

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use bloch_l2_bridge::{
    handle_external_floor_custodian_mtls_connection, AuthenticatedExternalFloorCustodian,
    AuthenticatedExternalFloorCustodianServer, ExternalFloorCustodianAuthentication,
    ExternalFloorCustodianMtlsClientConfig, ExternalFloorCustodianMtlsServerPolicy,
    ExternalFloorCustodianTcpClientConfig, ExternalFloorCustodianTcpServerPolicy,
    ExternalFloorCustodianTransportCheckpoint, ExternalFloorReplayCasOutcome,
    ExternalFloorReplayCheckpoint, ExternalFloorReplayStore, MtlsExternalFloorCustodianTransport,
};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use sha2::{Digest, Sha256};

const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const KEY: [u8; 32] = [0x31; 32];
const CLIENT_ID: [u8; 32] = [0x42; 32];
const SERVER_ID: [u8; 32] = [0x53; 32];

#[derive(Clone)]
struct Store {
    state: Arc<Mutex<ExternalFloorReplayCheckpoint>>,
    loads: Arc<AtomicUsize>,
    swaps: Arc<AtomicUsize>,
}

impl Store {
    fn new(state: ExternalFloorReplayCheckpoint) -> Self {
        Self {
            state: Arc::new(Mutex::new(state)),
            loads: Arc::new(AtomicUsize::new(0)),
            swaps: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl ExternalFloorReplayStore for Store {
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
        let mut state = self.state.lock().unwrap();
        if *state == expected {
            *state = replacement;
            Ok(ExternalFloorReplayCasOutcome::Committed)
        } else {
            Ok(ExternalFloorReplayCasOutcome::Conflict(*state))
        }
    }
}

struct Identity {
    cert: CertificateDer<'static>,
    key: Vec<u8>,
    pin: [u8; 32],
}

struct TestPki {
    root: CertificateDer<'static>,
    server: Identity,
    client: Identity,
    other_client: Identity,
}

fn identity(
    ca: &Certificate,
    ca_key: &KeyPair,
    name: &str,
    usage: ExtendedKeyUsagePurpose,
) -> Identity {
    let mut params = CertificateParams::new(vec![name.to_owned()]).unwrap();
    params.extended_key_usages.push(usage);
    params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    let key = KeyPair::generate().unwrap();
    let cert = params.signed_by(&key, ca, ca_key).unwrap().der().clone();
    let pin = Sha256::digest(cert.as_ref()).into();
    Identity {
        cert,
        key: key.serialize_der(),
        pin,
    }
}

fn test_pki() -> TestPki {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages.push(KeyUsagePurpose::KeyCertSign);
    params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    let ca_key = KeyPair::generate().unwrap();
    let ca = params.self_signed(&ca_key).unwrap();
    TestPki {
        root: ca.der().clone(),
        server: identity(
            &ca,
            &ca_key,
            "custodian.test",
            ExtendedKeyUsagePurpose::ServerAuth,
        ),
        client: identity(
            &ca,
            &ca_key,
            "coordinator.test",
            ExtendedKeyUsagePurpose::ClientAuth,
        ),
        other_client: identity(
            &ca,
            &ca_key,
            "other.test",
            ExtendedKeyUsagePurpose::ClientAuth,
        ),
    }
}

fn private_key(bytes: &[u8]) -> PrivateKeyDer<'static> {
    PrivatePkcs8KeyDer::from(bytes.to_vec()).into()
}

fn listener() -> (TcpListener, SocketAddr) {
    let listener = TcpListener::bind(SocketAddr::new(LOOPBACK, 0)).unwrap();
    let address = listener.local_addr().unwrap();
    (listener, address)
}

fn auth() -> ExternalFloorCustodianAuthentication {
    ExternalFloorCustodianAuthentication::new(KEY, CLIENT_ID, SERVER_ID).unwrap()
}

fn replay_checkpoint(revision: u64, sequence: u64) -> ExternalFloorReplayCheckpoint {
    ExternalFloorReplayCheckpoint::new(revision, [0x64; 32], sequence).unwrap()
}

fn client_config(
    address: SocketAddr,
    pki: &TestPki,
    server_pin: [u8; 32],
) -> ExternalFloorCustodianMtlsClientConfig {
    let tcp =
        ExternalFloorCustodianTcpClientConfig::new(address, Duration::from_secs(2), Some(LOOPBACK))
            .unwrap();
    ExternalFloorCustodianMtlsClientConfig::new(
        tcp,
        ServerName::try_from("custodian.test").unwrap().to_owned(),
        vec![pki.root.clone()],
        vec![pki.client.cert.clone()],
        private_key(&pki.client.key),
        server_pin,
    )
    .unwrap()
}

fn server_policy(pki: &TestPki, client_pin: [u8; 32]) -> ExternalFloorCustodianMtlsServerPolicy {
    ExternalFloorCustodianMtlsServerPolicy::new(
        ExternalFloorCustodianTcpServerPolicy::new(LOOPBACK, Duration::from_secs(2)).unwrap(),
        vec![pki.root.clone()],
        vec![pki.server.cert.clone()],
        private_key(&pki.server.key),
        client_pin,
    )
    .unwrap()
}

#[test]
fn pinned_mutual_tls_round_trip_preserves_bxrc_cas_semantics() {
    let pki = test_pki();
    let initial = replay_checkpoint(7, 11);
    let replacement = replay_checkpoint(8, 12);
    let store = Store::new(initial);
    let observed = store.clone();
    let policy = server_policy(&pki, pki.client.pin);
    let (listener, address) = listener();
    let server = thread::spawn(move || {
        let service = AuthenticatedExternalFloorCustodianServer::new(store, auth());
        for _ in 0..2 {
            let (stream, _) = listener.accept().unwrap();
            handle_external_floor_custodian_mtls_connection(stream, &service, &policy).unwrap();
        }
    });
    let transport =
        MtlsExternalFloorCustodianTransport::new(client_config(address, &pki, pki.server.pin));
    let client = AuthenticatedExternalFloorCustodian::new(
        transport,
        auth(),
        ExternalFloorCustodianTransportCheckpoint::new([0x75; 32], 0).unwrap(),
    );
    assert_eq!(client.load().unwrap(), initial);
    assert_eq!(
        client.compare_and_swap(initial, replacement).unwrap(),
        ExternalFloorReplayCasOutcome::Committed
    );
    server.join().unwrap();
    assert_eq!(observed.loads.load(Ordering::SeqCst), 2);
    assert_eq!(observed.swaps.load(Ordering::SeqCst), 1);
    assert_eq!(client.transport_checkpoint().next_sequence, 2);
}

#[test]
fn wrong_server_leaf_pin_fails_closed_and_consumes_sequence() {
    let pki = test_pki();
    let store = Store::new(replay_checkpoint(1, 0));
    let observed = store.clone();
    let policy = server_policy(&pki, pki.client.pin);
    let (listener, address) = listener();
    let server = thread::spawn(move || {
        let service = AuthenticatedExternalFloorCustodianServer::new(store, auth());
        let (stream, _) = listener.accept().unwrap();
        assert!(
            handle_external_floor_custodian_mtls_connection(stream, &service, &policy).is_err()
        );
    });
    let mut wrong = pki.server.pin;
    wrong[0] ^= 1;
    let client = AuthenticatedExternalFloorCustodian::new(
        MtlsExternalFloorCustodianTransport::new(client_config(address, &pki, wrong)),
        auth(),
        ExternalFloorCustodianTransportCheckpoint::new([0x86; 32], 0).unwrap(),
    );
    assert!(client.load().is_err());
    assert_eq!(client.transport_checkpoint().next_sequence, 1);
    server.join().unwrap();
    assert_eq!(observed.loads.load(Ordering::SeqCst), 0);
}

#[test]
fn valid_ca_but_wrong_client_leaf_pin_is_rejected_before_store_access() {
    let pki = test_pki();
    let store = Store::new(replay_checkpoint(1, 0));
    let observed = store.clone();
    let policy = server_policy(&pki, pki.other_client.pin);
    let (listener, address) = listener();
    let server = thread::spawn(move || {
        let service = AuthenticatedExternalFloorCustodianServer::new(store, auth());
        let (stream, _) = listener.accept().unwrap();
        assert!(
            handle_external_floor_custodian_mtls_connection(stream, &service, &policy).is_err()
        );
    });
    let client = AuthenticatedExternalFloorCustodian::new(
        MtlsExternalFloorCustodianTransport::new(client_config(address, &pki, pki.server.pin)),
        auth(),
        ExternalFloorCustodianTransportCheckpoint::new([0x97; 32], 0).unwrap(),
    );
    assert!(client.load().is_err());
    assert_eq!(client.transport_checkpoint().next_sequence, 1);
    server.join().unwrap();
    assert_eq!(observed.loads.load(Ordering::SeqCst), 0);
}

#[test]
fn empty_roots_and_zero_pins_are_never_implicit_defaults() {
    let pki = test_pki();
    let tcp = ExternalFloorCustodianTcpClientConfig::new(
        SocketAddr::new(LOOPBACK, 443),
        Duration::from_secs(1),
        None,
    )
    .unwrap();
    assert!(ExternalFloorCustodianMtlsClientConfig::new(
        tcp,
        ServerName::try_from("custodian.test").unwrap().to_owned(),
        Vec::new(),
        vec![pki.client.cert.clone()],
        private_key(&pki.client.key),
        pki.server.pin,
    )
    .is_err());

    let tcp = ExternalFloorCustodianTcpClientConfig::new(
        SocketAddr::new(LOOPBACK, 443),
        Duration::from_secs(1),
        None,
    )
    .unwrap();
    assert!(ExternalFloorCustodianMtlsClientConfig::new(
        tcp,
        ServerName::try_from("custodian.test").unwrap().to_owned(),
        vec![pki.root],
        vec![pki.client.cert],
        private_key(&pki.client.key),
        [0_u8; 32],
    )
    .is_err());
}
