// SPDX-License-Identifier: MIT OR Apache-2.0
//! Strict one-exchange-per-connection TCP carrier for authenticated `BXRC`.
//!
//! TCP supplies neither confidentiality nor cryptographic channel identity.
//! The inner BXRC KMAC authenticates peers and content; production should run
//! this carrier inside a mutually authenticated, pinned secure channel.

use std::io::{self, Error, ErrorKind, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpStream};
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};

use crate::{
    AuthenticatedExternalFloorCustodianServer, ExternalFloorCustodianTransport,
    ExternalFloorReplayStore, EXTERNAL_FLOOR_CUSTODIAN_MAGIC, EXTERNAL_FLOOR_CUSTODIAN_MAX_LEN,
    EXTERNAL_FLOOR_CUSTODIAN_MIN_LEN, EXTERNAL_FLOOR_CUSTODIAN_VERSION,
};

const LENGTH_PREFIX_LEN: usize = 2;
const MAX_TIMEOUT: Duration = Duration::from_secs(30);

fn invalid(message: &'static str) -> Error {
    Error::new(ErrorKind::InvalidData, message)
}

fn validate_timeout(timeout: Duration) -> io::Result<()> {
    if timeout.is_zero() || timeout > MAX_TIMEOUT {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "custodian TCP timeout must be between 1ns and 30s",
        ));
    }
    Ok(())
}

fn validate_ip(ip: IpAddr) -> io::Result<()> {
    if ip.is_unspecified() || ip.is_multicast() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "custodian TCP peer address must be a concrete unicast address",
        ));
    }
    Ok(())
}

/// Client-side connection policy with no DNS resolution or implicit defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExternalFloorCustodianTcpClientConfig {
    remote: SocketAddr,
    timeout: Duration,
    expected_local_ip: Option<IpAddr>,
}

impl ExternalFloorCustodianTcpClientConfig {
    pub fn new(
        remote: SocketAddr,
        timeout: Duration,
        expected_local_ip: Option<IpAddr>,
    ) -> io::Result<Self> {
        validate_timeout(timeout)?;
        validate_ip(remote.ip())?;
        if remote.port() == 0 {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "custodian TCP remote port must not be zero",
            ));
        }
        if let Some(local_ip) = expected_local_ip {
            validate_ip(local_ip)?;
        }
        Ok(Self {
            remote,
            timeout,
            expected_local_ip,
        })
    }
}

/// Server-side policy for a stream already accepted by an application-owned
/// listener. This module never creates a listener or starts a runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExternalFloorCustodianTcpServerPolicy {
    allowed_client_ip: IpAddr,
    timeout: Duration,
}

impl ExternalFloorCustodianTcpServerPolicy {
    pub fn new(allowed_client_ip: IpAddr, timeout: Duration) -> io::Result<Self> {
        validate_ip(allowed_client_ip)?;
        validate_timeout(timeout)?;
        Ok(Self {
            allowed_client_ip,
            timeout,
        })
    }
}

/// Concrete synchronous TCP client. Each `exchange` performs exactly one
/// connect/write/read and never reconnects or retransmits.
#[derive(Debug, Clone, Copy)]
pub struct TcpExternalFloorCustodianTransport {
    config: ExternalFloorCustodianTcpClientConfig,
}

impl TcpExternalFloorCustodianTransport {
    pub fn new(config: ExternalFloorCustodianTcpClientConfig) -> Self {
        Self { config }
    }

    fn connect(&self) -> io::Result<TcpStream> {
        let stream = TcpStream::connect_timeout(&self.config.remote, self.config.timeout)?;
        configure_stream(&stream, self.config.timeout)?;
        if stream.peer_addr()? != self.config.remote {
            return Err(Error::new(
                ErrorKind::PermissionDenied,
                "custodian TCP peer address does not match the pinned endpoint",
            ));
        }
        if let Some(expected) = self.config.expected_local_ip {
            if stream.local_addr()?.ip() != expected {
                return Err(Error::new(
                    ErrorKind::PermissionDenied,
                    "custodian TCP local address does not match the pinned egress address",
                ));
            }
        }
        Ok(stream)
    }
}

impl ExternalFloorCustodianTransport for TcpExternalFloorCustodianTransport {
    fn exchange(&self, request: &[u8]) -> io::Result<Vec<u8>> {
        validate_bxrc_frame(request)?;
        let mut stream = self.connect()?;
        write_frame(&mut stream, request)?;
        // The server requires EOF before touching its store, preventing a
        // valid request followed by smuggled bytes on the same connection.
        stream.shutdown(Shutdown::Write)?;
        let response = read_frame(&mut stream, self.config.timeout)?;
        require_eof(&mut stream, self.config.timeout)?;
        validate_bxrc_frame(&response)?;
        Ok(response)
    }
}

fn configure_stream(stream: &TcpStream, timeout: Duration) -> io::Result<()> {
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    stream.set_nodelay(true)
}

fn validate_bxrc_frame(frame: &[u8]) -> io::Result<()> {
    if frame.len() < EXTERNAL_FLOOR_CUSTODIAN_MIN_LEN {
        return Err(invalid("custodian TCP frame is shorter than BXRC minimum"));
    }
    if frame.len() > EXTERNAL_FLOOR_CUSTODIAN_MAX_LEN {
        return Err(invalid("custodian TCP frame exceeds BXRC maximum"));
    }
    if frame[..4] != EXTERNAL_FLOOR_CUSTODIAN_MAGIC {
        return Err(invalid("custodian TCP frame has wrong BXRC magic"));
    }
    if frame[4] != EXTERNAL_FLOOR_CUSTODIAN_VERSION {
        return Err(invalid("custodian TCP frame has unsupported BXRC version"));
    }
    Ok(())
}

fn write_frame(stream: &mut TcpStream, frame: &[u8]) -> io::Result<()> {
    let length = u16::try_from(frame.len()).map_err(|_| invalid("invalid BXRC frame length"))?;
    stream.write_all(&length.to_be_bytes())?;
    stream.write_all(frame)?;
    stream.flush()
}

fn read_frame(stream: &mut TcpStream, timeout: Duration) -> io::Result<Vec<u8>> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "invalid TCP read deadline"))?;
    let mut prefix = [0_u8; LENGTH_PREFIX_LEN];
    read_exact_before(stream, &mut prefix, deadline)?;
    let length = u16::from_be_bytes(prefix) as usize;
    if !(EXTERNAL_FLOOR_CUSTODIAN_MIN_LEN..=EXTERNAL_FLOOR_CUSTODIAN_MAX_LEN).contains(&length) {
        return Err(invalid(
            "custodian TCP length prefix is outside BXRC bounds",
        ));
    }
    let mut frame = vec![0_u8; length];
    read_exact_before(stream, &mut frame, deadline)?;
    Ok(frame)
}

fn read_exact_before(
    stream: &mut TcpStream,
    mut output: &mut [u8],
    deadline: Instant,
) -> io::Result<()> {
    while !output.is_empty() {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| {
                Error::new(ErrorKind::TimedOut, "custodian TCP frame deadline elapsed")
            })?;
        if remaining.is_zero() {
            return Err(Error::new(
                ErrorKind::TimedOut,
                "custodian TCP frame deadline elapsed",
            ));
        }
        wait_until_readable(stream, deadline)?;
        match stream.read(output) {
            Ok(0) => return Err(Error::new(ErrorKind::UnexpectedEof, "truncated TCP frame")),
            Ok(read) => output = &mut output[read..],
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn wait_until_readable(stream: &TcpStream, deadline: Instant) -> io::Result<()> {
    let mut descriptor = libc::pollfd {
        fd: stream.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| {
                Error::new(ErrorKind::TimedOut, "custodian TCP frame deadline elapsed")
            })?;
        let rounded_up_millis = remaining.as_millis().saturating_add(1);
        let timeout = i32::try_from(rounded_up_millis).unwrap_or(i32::MAX);
        // SAFETY: `descriptor` points to one initialized pollfd containing a
        // live descriptor borrowed for the duration of this call.
        let result = unsafe { libc::poll(&mut descriptor, 1, timeout) };
        if result > 0 {
            return Ok(());
        }
        if result == 0 {
            return Err(Error::new(
                ErrorKind::TimedOut,
                "custodian TCP frame deadline elapsed",
            ));
        }
        let error = Error::last_os_error();
        if error.kind() != ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

fn require_eof(stream: &mut TcpStream, timeout: Duration) -> io::Result<()> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "invalid TCP EOF deadline"))?;
    wait_until_readable(stream, deadline)?;
    let mut trailing = [0_u8; 1];
    match stream.read(&mut trailing) {
        Ok(0) => Ok(()),
        Ok(_) => Err(invalid("custodian TCP connection has trailing data")),
        Err(error) => Err(error),
    }
}

/// Handle exactly one strict framed BXRC request on an already accepted TCP
/// stream. Authentication and store access occur only after pinned-source,
/// bounds, exact-frame and EOF checks pass.
pub fn handle_external_floor_custodian_tcp_connection<S: ExternalFloorReplayStore>(
    mut stream: TcpStream,
    server: &AuthenticatedExternalFloorCustodianServer<S>,
    policy: ExternalFloorCustodianTcpServerPolicy,
) -> io::Result<()> {
    configure_stream(&stream, policy.timeout)?;
    if stream.peer_addr()?.ip() != policy.allowed_client_ip {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            "custodian TCP client IP does not match the pinned source",
        ));
    }
    let request = read_frame(&mut stream, policy.timeout)?;
    require_eof(&mut stream, policy.timeout)?;
    validate_bxrc_frame(&request)?;
    let response = server.handle(&request)?;
    validate_bxrc_frame(&response)?;
    write_frame(&mut stream, &response)?;
    stream.shutdown(Shutdown::Write)
}
