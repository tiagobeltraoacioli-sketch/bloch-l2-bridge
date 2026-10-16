// SPDX-License-Identifier: MIT OR Apache-2.0
//! TLS 1.3 mutual-authentication carrier for one bounded `BXRC` exchange.
//!
//! The caller supplies every trust anchor, identity, private key, DNS identity,
//! leaf-certificate pin and numeric TCP endpoint.  No platform roots,
//! environment lookup, DNS resolution, fallback endpoint, reconnect or retry is
//! used here.

use std::io::{self, Error, ErrorKind, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection};
use sha2::{Digest, Sha256};

use crate::{
    AuthenticatedExternalFloorCustodianServer, ExternalFloorCustodianTcpClientConfig,
    ExternalFloorCustodianTcpServerPolicy, ExternalFloorCustodianTransport,
    ExternalFloorReplayStore, EXTERNAL_FLOOR_CUSTODIAN_MAGIC, EXTERNAL_FLOOR_CUSTODIAN_MAX_LEN,
    EXTERNAL_FLOOR_CUSTODIAN_MIN_LEN, EXTERNAL_FLOOR_CUSTODIAN_VERSION,
};

const LENGTH_PREFIX_LEN: usize = 2;
const TLS_BUFFER_LIMIT: usize = EXTERNAL_FLOOR_CUSTODIAN_MAX_LEN + LENGTH_PREFIX_LEN + 1024;

fn invalid(message: &'static str) -> Error {
    Error::new(ErrorKind::InvalidData, message)
}

fn tls_error(error: rustls::Error) -> Error {
    Error::new(ErrorKind::InvalidData, error)
}

fn at_stage(stage: &'static str, error: Error) -> Error {
    Error::new(error.kind(), format!("custodian mTLS {stage}: {error}"))
}

fn root_store(roots: Vec<CertificateDer<'static>>) -> io::Result<RootCertStore> {
    if roots.is_empty() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "custodian mTLS trust anchors must not be empty",
        ));
    }
    let mut store = RootCertStore::empty();
    for root in roots {
        store
            .add(root)
            .map_err(|error| Error::new(ErrorKind::InvalidInput, error))?;
    }
    Ok(store)
}

fn validate_identity(chain: &[CertificateDer<'static>], pin: &[u8; 32]) -> io::Result<()> {
    if chain.is_empty() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "custodian mTLS certificate chain must not be empty",
        ));
    }
    if *pin == [0_u8; 32] {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "custodian mTLS leaf certificate pin must not be all zero",
        ));
    }
    Ok(())
}

/// Complete client policy. TLS is restricted to 1.3 and uses explicit roots,
/// an explicit client identity and an independent SHA-256 server leaf pin.
pub struct ExternalFloorCustodianMtlsClientConfig {
    tcp: ExternalFloorCustodianTcpClientConfig,
    server_name: ServerName<'static>,
    tls: Arc<ClientConfig>,
    expected_server_leaf_sha256: [u8; 32],
}

impl ExternalFloorCustodianMtlsClientConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tcp: ExternalFloorCustodianTcpClientConfig,
        server_name: ServerName<'static>,
        trust_anchors: Vec<CertificateDer<'static>>,
        client_chain: Vec<CertificateDer<'static>>,
        client_key: PrivateKeyDer<'static>,
        expected_server_leaf_sha256: [u8; 32],
    ) -> io::Result<Self> {
        validate_identity(&client_chain, &expected_server_leaf_sha256)?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let tls = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(tls_error)?
            .with_root_certificates(root_store(trust_anchors)?)
            .with_client_auth_cert(client_chain, client_key)
            .map_err(tls_error)?;
        Ok(Self {
            tcp,
            server_name,
            tls: Arc::new(tls),
            expected_server_leaf_sha256,
        })
    }
}

/// Complete server policy. Client certificates are mandatory, chain-checked
/// against explicit roots, and independently checked against a SHA-256 leaf pin.
pub struct ExternalFloorCustodianMtlsServerPolicy {
    tcp: ExternalFloorCustodianTcpServerPolicy,
    tls: Arc<ServerConfig>,
    expected_client_leaf_sha256: [u8; 32],
}

impl ExternalFloorCustodianMtlsServerPolicy {
    pub fn new(
        tcp: ExternalFloorCustodianTcpServerPolicy,
        trust_anchors: Vec<CertificateDer<'static>>,
        server_chain: Vec<CertificateDer<'static>>,
        server_key: PrivateKeyDer<'static>,
        expected_client_leaf_sha256: [u8; 32],
    ) -> io::Result<Self> {
        validate_identity(&server_chain, &expected_client_leaf_sha256)?;
        let verifier =
            rustls::server::WebPkiClientVerifier::builder(Arc::new(root_store(trust_anchors)?))
                .build()
                .map_err(|error| Error::new(ErrorKind::InvalidInput, error))?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let tls = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(tls_error)?
            .with_client_cert_verifier(verifier)
            .with_single_cert(server_chain, server_key)
            .map_err(tls_error)?;
        Ok(Self {
            tcp,
            tls: Arc::new(tls),
            expected_client_leaf_sha256,
        })
    }
}

/// One-connect, one-exchange mTLS carrier. Any error after connecting is an
/// ambiguous transport result to the BXRC caller and is never retried here.
pub struct MtlsExternalFloorCustodianTransport {
    config: ExternalFloorCustodianMtlsClientConfig,
}

impl MtlsExternalFloorCustodianTransport {
    pub fn new(config: ExternalFloorCustodianMtlsClientConfig) -> Self {
        Self { config }
    }
}

impl ExternalFloorCustodianTransport for MtlsExternalFloorCustodianTransport {
    fn exchange(&self, request: &[u8]) -> io::Result<Vec<u8>> {
        validate_bxrc_frame(request)?;
        let mut socket = self
            .config
            .tcp
            .connect()
            .map_err(|error| at_stage("TCP connect failed", error))?;
        let deadline = deadline(self.config.tcp.timeout())?;
        let mut connection = ClientConnection::new(
            Arc::clone(&self.config.tls),
            self.config.server_name.clone(),
        )
        .map_err(tls_error)?;
        connection.set_buffer_limit(Some(TLS_BUFFER_LIMIT));
        complete_client_handshake(&mut connection, &mut socket, deadline)
            .map_err(|error| at_stage("client handshake failed", error))?;
        verify_leaf_pin(
            connection.peer_certificates(),
            self.config.expected_server_leaf_sha256,
        )?;
        write_frame_client(&mut connection, &mut socket, request, deadline)
            .map_err(|error| at_stage("request write failed", error))?;
        connection.send_close_notify();
        flush_client(&mut connection, &mut socket, deadline)
            .map_err(|error| at_stage("client close_notify failed", error))?;
        // TLS close_notify is the authenticated end-of-request marker. Keep
        // the TCP write half open until the response is consumed because some
        // platforms reject subsequent timeout updates after shutdown(Write).
        let response = read_frame_client(&mut connection, &mut socket, deadline)
            .map_err(|error| at_stage("response read failed", error))?;
        require_client_tls_eof(&mut connection, &mut socket, deadline)
            .map_err(|error| at_stage("response EOF check failed", error))?;
        validate_bxrc_frame(&response)?;
        Ok(response)
    }
}

fn deadline(timeout: Duration) -> io::Result<Instant> {
    Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "invalid custodian mTLS deadline"))
}

fn remaining(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or_else(|| {
            Error::new(
                ErrorKind::TimedOut,
                "custodian mTLS absolute deadline elapsed",
            )
        })
}

fn prepare_read(socket: &TcpStream, deadline: Instant) -> io::Result<()> {
    let remaining = remaining(deadline)?;
    socket.set_read_timeout(Some(remaining))
}

fn prepare_write(socket: &TcpStream, deadline: Instant) -> io::Result<()> {
    let remaining = remaining(deadline)?;
    socket.set_write_timeout(Some(remaining))
}

fn complete_client_handshake(
    connection: &mut ClientConnection,
    socket: &mut TcpStream,
    deadline: Instant,
) -> io::Result<()> {
    while connection.is_handshaking() {
        while connection.wants_write() {
            prepare_write(socket, deadline)?;
            connection.write_tls(socket)?;
        }
        if connection.wants_read() {
            prepare_read(socket, deadline)?;
            if connection.read_tls(socket)? == 0 {
                return Err(Error::new(
                    ErrorKind::UnexpectedEof,
                    "custodian mTLS peer closed during handshake",
                ));
            }
            connection.process_new_packets().map_err(tls_error)?;
        }
    }
    flush_client(connection, socket, deadline)
}

fn complete_server_handshake(
    connection: &mut ServerConnection,
    socket: &mut TcpStream,
    deadline: Instant,
) -> io::Result<()> {
    while connection.is_handshaking() {
        while connection.wants_write() {
            prepare_write(socket, deadline)?;
            connection.write_tls(socket)?;
        }
        if connection.wants_read() {
            prepare_read(socket, deadline)?;
            if connection.read_tls(socket)? == 0 {
                return Err(Error::new(
                    ErrorKind::UnexpectedEof,
                    "custodian mTLS peer closed during handshake",
                ));
            }
            connection.process_new_packets().map_err(tls_error)?;
        }
    }
    flush_server(connection, socket, deadline)
}

fn verify_leaf_pin(certs: Option<&[CertificateDer<'_>]>, expected: [u8; 32]) -> io::Result<()> {
    let leaf = certs
        .and_then(|certs| certs.first())
        .ok_or_else(|| Error::new(ErrorKind::PermissionDenied, "mTLS peer sent no certificate"))?;
    let actual: [u8; 32] = Sha256::digest(leaf.as_ref()).into();
    if actual != expected {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            "mTLS peer leaf certificate does not match the pinned SHA-256 digest",
        ));
    }
    Ok(())
}

fn validate_bxrc_frame(frame: &[u8]) -> io::Result<()> {
    if !(EXTERNAL_FLOOR_CUSTODIAN_MIN_LEN..=EXTERNAL_FLOOR_CUSTODIAN_MAX_LEN).contains(&frame.len())
    {
        return Err(invalid(
            "custodian mTLS BXRC frame length is outside bounds",
        ));
    }
    if frame[..4] != EXTERNAL_FLOOR_CUSTODIAN_MAGIC || frame[4] != EXTERNAL_FLOOR_CUSTODIAN_VERSION
    {
        return Err(invalid("custodian mTLS frame has invalid BXRC preamble"));
    }
    Ok(())
}

macro_rules! tls_io {
    ($write_frame:ident, $read_frame:ident, $read_exact:ident, $flush:ident, $require_eof:ident, $connection:ty) => {
        fn $write_frame(
            connection: &mut $connection,
            socket: &mut TcpStream,
            frame: &[u8],
            deadline: Instant,
        ) -> io::Result<()> {
            let length = u16::try_from(frame.len())
                .map_err(|_| invalid("invalid custodian mTLS BXRC frame length"))?;
            connection.writer().write_all(&length.to_be_bytes())?;
            connection.writer().write_all(frame)?;
            $flush(connection, socket, deadline)
        }

        fn $flush(
            connection: &mut $connection,
            socket: &mut TcpStream,
            deadline: Instant,
        ) -> io::Result<()> {
            while connection.wants_write() {
                prepare_write(socket, deadline)?;
                connection.write_tls(socket)?;
            }
            socket.flush()
        }

        fn $read_frame(
            connection: &mut $connection,
            socket: &mut TcpStream,
            deadline: Instant,
        ) -> io::Result<Vec<u8>> {
            let mut prefix = [0_u8; LENGTH_PREFIX_LEN];
            $read_exact(connection, socket, &mut prefix, deadline)?;
            let length = u16::from_be_bytes(prefix) as usize;
            if !(EXTERNAL_FLOOR_CUSTODIAN_MIN_LEN..=EXTERNAL_FLOOR_CUSTODIAN_MAX_LEN)
                .contains(&length)
            {
                return Err(invalid(
                    "custodian mTLS length prefix is outside BXRC bounds",
                ));
            }
            let mut frame = vec![0_u8; length];
            $read_exact(connection, socket, &mut frame, deadline)?;
            Ok(frame)
        }

        fn $read_exact(
            connection: &mut $connection,
            socket: &mut TcpStream,
            mut output: &mut [u8],
            deadline: Instant,
        ) -> io::Result<()> {
            while !output.is_empty() {
                match connection.reader().read(output) {
                    Ok(0) => {
                        return Err(Error::new(
                            ErrorKind::UnexpectedEof,
                            "truncated custodian mTLS frame",
                        ))
                    }
                    Ok(read) => output = &mut output[read..],
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {
                        prepare_read(socket, deadline)?;
                        let read = connection.read_tls(socket)?;
                        if read == 0 {
                            return Err(Error::new(
                                ErrorKind::UnexpectedEof,
                                "custodian mTLS peer closed during frame",
                            ));
                        }
                        connection.process_new_packets().map_err(tls_error)?;
                    }
                    Err(error) => return Err(error),
                }
            }
            Ok(())
        }

        fn $require_eof(
            connection: &mut $connection,
            socket: &mut TcpStream,
            deadline: Instant,
        ) -> io::Result<()> {
            let mut trailing = [0_u8; 1];
            loop {
                match connection.reader().read(&mut trailing) {
                    // rustls returns zero only after the authenticated peer's
                    // close_notify. Requiring a second raw TCP EOF is both
                    // redundant and non-portable after a local half-close.
                    Ok(0) => return Ok(()),
                    Ok(_) => return Err(invalid("custodian mTLS stream has trailing plaintext")),
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {
                        prepare_read(socket, deadline)
                            .map_err(|error| at_stage("EOF read deadline failed", error))?;
                        let read = connection
                            .read_tls(socket)
                            .map_err(|error| at_stage("EOF TLS record read failed", error))?;
                        if read == 0 {
                            return Err(Error::new(
                                ErrorKind::UnexpectedEof,
                                "custodian mTLS peer omitted close_notify",
                            ));
                        }
                        connection
                            .process_new_packets()
                            .map_err(tls_error)
                            .map_err(|error| at_stage("EOF TLS record processing failed", error))?;
                    }
                    Err(error) => {
                        return Err(at_stage("EOF plaintext read failed", error));
                    }
                }
            }
        }
    };
}

tls_io!(
    write_frame_client,
    read_frame_client,
    read_exact_client,
    flush_client,
    require_client_tls_eof,
    ClientConnection
);
tls_io!(
    write_frame_server,
    read_frame_server,
    read_exact_server,
    flush_server,
    require_server_tls_eof,
    ServerConnection
);

/// Handle one mTLS-protected exchange on an already accepted TCP stream.
/// Peer IP, TLS chain, leaf pin, complete bounded frame and close-notify are
/// verified before the authenticated BXRC server can touch its durable store.
pub fn handle_external_floor_custodian_mtls_connection<S: ExternalFloorReplayStore>(
    mut socket: TcpStream,
    server: &AuthenticatedExternalFloorCustodianServer<S>,
    policy: &ExternalFloorCustodianMtlsServerPolicy,
) -> io::Result<()> {
    policy.tcp.validate_stream(&socket)?;
    let deadline = deadline(policy.tcp.timeout())?;
    let mut connection = ServerConnection::new(Arc::clone(&policy.tls)).map_err(tls_error)?;
    connection.set_buffer_limit(Some(TLS_BUFFER_LIMIT));
    complete_server_handshake(&mut connection, &mut socket, deadline)?;
    verify_leaf_pin(
        connection.peer_certificates(),
        policy.expected_client_leaf_sha256,
    )?;
    let request = read_frame_server(&mut connection, &mut socket, deadline)?;
    require_server_tls_eof(&mut connection, &mut socket, deadline)?;
    validate_bxrc_frame(&request)?;
    let response = server.handle(&request)?;
    validate_bxrc_frame(&response)?;
    write_frame_server(&mut connection, &mut socket, &response, deadline)?;
    connection.send_close_notify();
    flush_server(&mut connection, &mut socket, deadline)?;
    socket.shutdown(Shutdown::Write)
}
