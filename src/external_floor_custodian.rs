// SPDX-License-Identifier: MIT OR Apache-2.0
//! Authenticated transport protocol for an independent replay custodian.
//!
//! This module supplies canonical bounded framing, peer/session/request
//! binding, and exact-CAS idempotence. It deliberately supplies no socket,
//! retry loop, key loading, or claim that the custodian is in an independent
//! failure domain.

use core::fmt;
use std::cell::Cell;
use std::io;

use tiny_keccak::{Hasher, Keccak, Kmac};
use zeroize::Zeroize;

use crate::{
    ExternalFloorReplayCasOutcome, ExternalFloorReplayCheckpoint, ExternalFloorReplayStore,
};

pub const EXTERNAL_FLOOR_CUSTODIAN_MAGIC: [u8; 4] = *b"BXRC";
pub const EXTERNAL_FLOOR_CUSTODIAN_VERSION: u8 = 1;
pub const EXTERNAL_FLOOR_CUSTODIAN_MAX_LEN: usize = 274;

const HEADER_LEN: usize = 114;
const CHECKPOINT_LEN: usize = 48;
const CAS_PAYLOAD_LEN: usize = CHECKPOINT_LEN * 2;
const BINDING_LEN: usize = 32;
const TAG_LEN: usize = 32;
const MIN_LEN: usize = HEADER_LEN + BINDING_LEN + TAG_LEN;
const REQUEST: u8 = 0;
const RESPONSE: u8 = 1;
const LOAD: u8 = 0;
const CAS: u8 = 1;
const REQUEST_STATUS: u8 = 0;
const CURRENT: u8 = 1;
const COMMITTED: u8 = 2;
const CONFLICT: u8 = 3;
const UNCERTAIN: u8 = 4;
const BINDING_DOMAIN: &[u8] = b"BLOCH-L2-REPLAY-CUSTODIAN-BINDING-v1\0";
const AUTH_DOMAIN: &[u8] = b"BLOCH-L2-REPLAY-CUSTODIAN-AUTH-v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalFloorCustodianProtocolError {
    InvalidConfiguration(&'static str),
    TooShort(usize),
    TooLong(usize),
    BadMagic,
    UnsupportedVersion(u8),
    WrongDirection,
    WrongOperation,
    InvalidStatus,
    IdentityMismatch,
    SessionMismatch,
    SequenceMismatch,
    InvalidLength,
    AuthenticationFailed,
    RequestBindingMismatch,
    InvalidCheckpoint(&'static str),
    InvalidTransition,
    SequenceExhausted,
}

impl fmt::Display for ExternalFloorCustodianProtocolError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            output,
            "external replay custodian protocol rejected: {self:?}"
        )
    }
}

impl std::error::Error for ExternalFloorCustodianProtocolError {}

/// Symmetric authentication and fixed peer identities for one custodian link.
pub struct ExternalFloorCustodianAuthentication {
    key: [u8; 32],
    client_peer: [u8; 32],
    custodian_peer: [u8; 32],
}

impl ExternalFloorCustodianAuthentication {
    pub fn new(
        mut key: [u8; 32],
        client_peer: [u8; 32],
        custodian_peer: [u8; 32],
    ) -> Result<Self, ExternalFloorCustodianProtocolError> {
        if key == [0; 32] {
            key.zeroize();
            return Err(ExternalFloorCustodianProtocolError::InvalidConfiguration(
                "authentication key is all zero",
            ));
        }
        if client_peer == [0; 32] || custodian_peer == [0; 32] {
            key.zeroize();
            return Err(ExternalFloorCustodianProtocolError::InvalidConfiguration(
                "peer identity is all zero",
            ));
        }
        if client_peer == custodian_peer {
            key.zeroize();
            return Err(ExternalFloorCustodianProtocolError::InvalidConfiguration(
                "peer identities are equal",
            ));
        }
        Ok(Self {
            key,
            client_peer,
            custodian_peer,
        })
    }
}

impl fmt::Debug for ExternalFloorCustodianAuthentication {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output
            .debug_struct("ExternalFloorCustodianAuthentication")
            .field("key", &"[REDACTED]")
            .field("client_peer", &self.client_peer)
            .field("custodian_peer", &self.custodian_peer)
            .finish()
    }
}

impl Drop for ExternalFloorCustodianAuthentication {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

/// One synchronous byte exchange. Implementations must not retry an ambiguous
/// exchange under a newly generated request identity.
pub trait ExternalFloorCustodianTransport {
    fn exchange(&self, request: &[u8]) -> io::Result<Vec<u8>>;
}

/// Independently retained request identity for the custodian client.
///
/// After every attempted exchange callers must retain the value returned by
/// [`AuthenticatedExternalFloorCustodian::transport_checkpoint`] outside the
/// rollback domain of the client. After a crash, either restore that exact
/// next sequence or authorize a fresh unpredictable session. Reusing an old
/// `(session_nonce, next_sequence)` can make a recorded `load` response valid
/// again and is therefore forbidden.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExternalFloorCustodianTransportCheckpoint {
    pub session_nonce: [u8; 32],
    pub next_sequence: u64,
}

impl ExternalFloorCustodianTransportCheckpoint {
    pub fn new(
        session_nonce: [u8; 32],
        next_sequence: u64,
    ) -> Result<Self, ExternalFloorCustodianProtocolError> {
        if session_nonce == [0; 32] {
            return Err(ExternalFloorCustodianProtocolError::InvalidConfiguration(
                "transport session is all zero",
            ));
        }
        Ok(Self {
            session_nonce,
            next_sequence,
        })
    }
}

#[derive(Clone, Copy)]
enum Operation {
    Load,
    CompareAndSwap {
        expected: ExternalFloorReplayCheckpoint,
        replacement: ExternalFloorReplayCheckpoint,
    },
}

struct Request {
    session: [u8; 32],
    sequence: u64,
    binding: [u8; 32],
    operation: Operation,
}

enum Response {
    Current(ExternalFloorReplayCheckpoint),
    Committed,
    Conflict(ExternalFloorReplayCheckpoint),
    Uncertain,
}

fn encode_checkpoint(checkpoint: ExternalFloorReplayCheckpoint) -> [u8; CHECKPOINT_LEN] {
    let mut encoded = [0_u8; CHECKPOINT_LEN];
    encoded[..8].copy_from_slice(&checkpoint.revision.to_be_bytes());
    encoded[8..40].copy_from_slice(&checkpoint.session_nonce);
    encoded[40..].copy_from_slice(&checkpoint.next_sequence.to_be_bytes());
    encoded
}

fn decode_checkpoint(
    encoded: &[u8],
) -> Result<ExternalFloorReplayCheckpoint, ExternalFloorCustodianProtocolError> {
    if encoded.len() != CHECKPOINT_LEN {
        return Err(ExternalFloorCustodianProtocolError::InvalidLength);
    }
    let checkpoint = ExternalFloorReplayCheckpoint {
        revision: u64::from_be_bytes(encoded[..8].try_into().expect("fixed checkpoint slice")),
        session_nonce: encoded[8..40].try_into().expect("fixed checkpoint slice"),
        next_sequence: u64::from_be_bytes(
            encoded[40..48].try_into().expect("fixed checkpoint slice"),
        ),
    };
    if checkpoint.session_nonce == [0; 32] {
        return Err(ExternalFloorCustodianProtocolError::InvalidCheckpoint(
            "session nonce is all zero",
        ));
    }
    Ok(checkpoint)
}

fn validate_transition(
    expected: ExternalFloorReplayCheckpoint,
    replacement: ExternalFloorReplayCheckpoint,
) -> Result<(), ExternalFloorCustodianProtocolError> {
    if expected.session_nonce == [0; 32] || replacement.session_nonce == [0; 32] {
        return Err(ExternalFloorCustodianProtocolError::InvalidCheckpoint(
            "session nonce is all zero",
        ));
    }
    if expected.session_nonce != replacement.session_nonce
        || expected.revision.checked_add(1) != Some(replacement.revision)
        || expected.next_sequence.checked_add(1) != Some(replacement.next_sequence)
    {
        return Err(ExternalFloorCustodianProtocolError::InvalidTransition);
    }
    Ok(())
}

fn operation_tag(operation: Operation) -> u8 {
    match operation {
        Operation::Load => LOAD,
        Operation::CompareAndSwap { .. } => CAS,
    }
}

fn binding(prefix: &[u8]) -> [u8; 32] {
    let mut hash = Keccak::v256();
    hash.update(BINDING_DOMAIN);
    hash.update(prefix);
    let mut result = [0_u8; 32];
    hash.finalize(&mut result);
    result
}

fn tag(authentication: &ExternalFloorCustodianAuthentication, authenticated: &[u8]) -> [u8; 32] {
    let mut mac = Kmac::v256(&authentication.key, AUTH_DOMAIN);
    mac.update(authenticated);
    let mut result = [0_u8; 32];
    mac.finalize(&mut result);
    result
}

fn equal(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .fold(0_u8, |difference, (left, right)| {
                difference | (left ^ right)
            })
            == 0
}

#[allow(clippy::too_many_arguments)]
fn encode_frame(
    direction: u8,
    operation: u8,
    status: u8,
    sender: [u8; 32],
    receiver: [u8; 32],
    session: [u8; 32],
    sequence: u64,
    payload: &[u8],
    request_binding: Option<[u8; 32]>,
    authentication: &ExternalFloorCustodianAuthentication,
) -> Result<Vec<u8>, ExternalFloorCustodianProtocolError> {
    let payload_len = u16::try_from(payload.len())
        .map_err(|_| ExternalFloorCustodianProtocolError::InvalidLength)?;
    let mut encoded = Vec::with_capacity(HEADER_LEN + payload.len() + BINDING_LEN + TAG_LEN);
    encoded.extend_from_slice(&EXTERNAL_FLOOR_CUSTODIAN_MAGIC);
    encoded.push(EXTERNAL_FLOOR_CUSTODIAN_VERSION);
    encoded.push(direction);
    encoded.push(operation);
    encoded.push(status);
    encoded.extend_from_slice(&sender);
    encoded.extend_from_slice(&receiver);
    encoded.extend_from_slice(&session);
    encoded.extend_from_slice(&sequence.to_be_bytes());
    encoded.extend_from_slice(&payload_len.to_be_bytes());
    debug_assert_eq!(encoded.len(), HEADER_LEN);
    encoded.extend_from_slice(payload);
    let request_binding = request_binding.unwrap_or_else(|| binding(&encoded));
    encoded.extend_from_slice(&request_binding);
    let authentication_tag = tag(authentication, &encoded);
    encoded.extend_from_slice(&authentication_tag);
    if encoded.len() > EXTERNAL_FLOOR_CUSTODIAN_MAX_LEN {
        return Err(ExternalFloorCustodianProtocolError::TooLong(encoded.len()));
    }
    Ok(encoded)
}

struct Frame<'a> {
    operation: u8,
    status: u8,
    session: [u8; 32],
    sequence: u64,
    payload: &'a [u8],
    request_binding: [u8; 32],
}

fn decode_frame<'a>(
    encoded: &'a [u8],
    direction: u8,
    sender: [u8; 32],
    receiver: [u8; 32],
    authentication: &ExternalFloorCustodianAuthentication,
) -> Result<Frame<'a>, ExternalFloorCustodianProtocolError> {
    if encoded.len() < MIN_LEN {
        return Err(ExternalFloorCustodianProtocolError::TooShort(encoded.len()));
    }
    if encoded.len() > EXTERNAL_FLOOR_CUSTODIAN_MAX_LEN {
        return Err(ExternalFloorCustodianProtocolError::TooLong(encoded.len()));
    }
    if encoded[..4] != EXTERNAL_FLOOR_CUSTODIAN_MAGIC {
        return Err(ExternalFloorCustodianProtocolError::BadMagic);
    }
    if encoded[4] != EXTERNAL_FLOOR_CUSTODIAN_VERSION {
        return Err(ExternalFloorCustodianProtocolError::UnsupportedVersion(
            encoded[4],
        ));
    }
    let payload_len = u16::from_be_bytes([encoded[112], encoded[113]]) as usize;
    let expected_len = HEADER_LEN
        .checked_add(payload_len)
        .and_then(|length| length.checked_add(BINDING_LEN + TAG_LEN))
        .ok_or(ExternalFloorCustodianProtocolError::InvalidLength)?;
    if encoded.len() != expected_len {
        return Err(ExternalFloorCustodianProtocolError::InvalidLength);
    }
    let tag_start = encoded.len() - TAG_LEN;
    let expected_tag = tag(authentication, &encoded[..tag_start]);
    if !equal(&encoded[tag_start..], &expected_tag) {
        return Err(ExternalFloorCustodianProtocolError::AuthenticationFailed);
    }
    if encoded[5] != direction {
        return Err(ExternalFloorCustodianProtocolError::WrongDirection);
    }
    if encoded[8..40] != sender || encoded[40..72] != receiver {
        return Err(ExternalFloorCustodianProtocolError::IdentityMismatch);
    }
    let payload_end = HEADER_LEN + payload_len;
    Ok(Frame {
        operation: encoded[6],
        status: encoded[7],
        session: encoded[72..104].try_into().expect("fixed session slice"),
        sequence: u64::from_be_bytes(encoded[104..112].try_into().expect("fixed sequence slice")),
        payload: &encoded[HEADER_LEN..payload_end],
        request_binding: encoded[payload_end..payload_end + BINDING_LEN]
            .try_into()
            .expect("fixed binding slice"),
    })
}

fn encode_request(
    session: [u8; 32],
    sequence: u64,
    operation: Operation,
    authentication: &ExternalFloorCustodianAuthentication,
) -> Result<Vec<u8>, ExternalFloorCustodianProtocolError> {
    let payload = match operation {
        Operation::Load => Vec::new(),
        Operation::CompareAndSwap {
            expected,
            replacement,
        } => {
            validate_transition(expected, replacement)?;
            let mut payload = Vec::with_capacity(CAS_PAYLOAD_LEN);
            payload.extend_from_slice(&encode_checkpoint(expected));
            payload.extend_from_slice(&encode_checkpoint(replacement));
            payload
        }
    };
    encode_frame(
        REQUEST,
        operation_tag(operation),
        REQUEST_STATUS,
        authentication.client_peer,
        authentication.custodian_peer,
        session,
        sequence,
        &payload,
        None,
        authentication,
    )
}

fn decode_request(
    encoded: &[u8],
    authentication: &ExternalFloorCustodianAuthentication,
) -> Result<Request, ExternalFloorCustodianProtocolError> {
    let frame = decode_frame(
        encoded,
        REQUEST,
        authentication.client_peer,
        authentication.custodian_peer,
        authentication,
    )?;
    if frame.status != REQUEST_STATUS {
        return Err(ExternalFloorCustodianProtocolError::InvalidStatus);
    }
    if frame.session == [0; 32] {
        return Err(ExternalFloorCustodianProtocolError::InvalidConfiguration(
            "transport session is all zero",
        ));
    }
    let binding_start = encoded.len() - TAG_LEN - BINDING_LEN;
    if binding(&encoded[..binding_start]) != frame.request_binding {
        return Err(ExternalFloorCustodianProtocolError::RequestBindingMismatch);
    }
    let operation = match frame.operation {
        LOAD if frame.payload.is_empty() => Operation::Load,
        CAS if frame.payload.len() == CAS_PAYLOAD_LEN => {
            let expected = decode_checkpoint(&frame.payload[..CHECKPOINT_LEN])?;
            let replacement = decode_checkpoint(&frame.payload[CHECKPOINT_LEN..])?;
            validate_transition(expected, replacement)?;
            Operation::CompareAndSwap {
                expected,
                replacement,
            }
        }
        LOAD | CAS => return Err(ExternalFloorCustodianProtocolError::InvalidLength),
        _ => return Err(ExternalFloorCustodianProtocolError::WrongOperation),
    };
    Ok(Request {
        session: frame.session,
        sequence: frame.sequence,
        binding: frame.request_binding,
        operation,
    })
}

fn encode_response(
    request: &Request,
    response: Response,
    authentication: &ExternalFloorCustodianAuthentication,
) -> Result<Vec<u8>, ExternalFloorCustodianProtocolError> {
    let (status, payload) = match response {
        Response::Current(current) => (CURRENT, encode_checkpoint(current).to_vec()),
        Response::Committed => (COMMITTED, Vec::new()),
        Response::Conflict(current) => (CONFLICT, encode_checkpoint(current).to_vec()),
        Response::Uncertain => (UNCERTAIN, Vec::new()),
    };
    encode_frame(
        RESPONSE,
        operation_tag(request.operation),
        status,
        authentication.custodian_peer,
        authentication.client_peer,
        request.session,
        request.sequence,
        &payload,
        Some(request.binding),
        authentication,
    )
}

fn decode_response(
    encoded: &[u8],
    request: &Request,
    authentication: &ExternalFloorCustodianAuthentication,
) -> Result<Response, ExternalFloorCustodianProtocolError> {
    let frame = decode_frame(
        encoded,
        RESPONSE,
        authentication.custodian_peer,
        authentication.client_peer,
        authentication,
    )?;
    if frame.operation != operation_tag(request.operation) {
        return Err(ExternalFloorCustodianProtocolError::WrongOperation);
    }
    if frame.session != request.session {
        return Err(ExternalFloorCustodianProtocolError::SessionMismatch);
    }
    if frame.sequence != request.sequence {
        return Err(ExternalFloorCustodianProtocolError::SequenceMismatch);
    }
    if frame.request_binding != request.binding {
        return Err(ExternalFloorCustodianProtocolError::RequestBindingMismatch);
    }
    match (request.operation, frame.status, frame.payload.len()) {
        (Operation::Load, CURRENT, CHECKPOINT_LEN) => {
            Ok(Response::Current(decode_checkpoint(frame.payload)?))
        }
        (Operation::CompareAndSwap { .. }, COMMITTED, 0) => Ok(Response::Committed),
        (Operation::CompareAndSwap { .. }, CONFLICT, CHECKPOINT_LEN) => {
            Ok(Response::Conflict(decode_checkpoint(frame.payload)?))
        }
        (Operation::CompareAndSwap { .. }, UNCERTAIN, 0) => Ok(Response::Uncertain),
        _ => Err(ExternalFloorCustodianProtocolError::InvalidStatus),
    }
}

fn protocol_io(error: ExternalFloorCustodianProtocolError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

/// Client-side authenticated remote custodian implementing the exact replay
/// store contract. Every attempted exchange consumes a transport sequence;
/// errors are returned without retry.
pub struct AuthenticatedExternalFloorCustodian<T> {
    transport: T,
    authentication: ExternalFloorCustodianAuthentication,
    session: [u8; 32],
    next_sequence: Cell<u64>,
}

impl<T> AuthenticatedExternalFloorCustodian<T> {
    pub fn new(
        transport: T,
        authentication: ExternalFloorCustodianAuthentication,
        checkpoint: ExternalFloorCustodianTransportCheckpoint,
    ) -> Self {
        Self {
            transport,
            authentication,
            session: checkpoint.session_nonce,
            next_sequence: Cell::new(checkpoint.next_sequence),
        }
    }

    pub fn transport_checkpoint(&self) -> ExternalFloorCustodianTransportCheckpoint {
        ExternalFloorCustodianTransportCheckpoint {
            session_nonce: self.session,
            next_sequence: self.next_sequence.get(),
        }
    }

    fn exchange(&self, operation: Operation) -> io::Result<Response>
    where
        T: ExternalFloorCustodianTransport,
    {
        let sequence = self.next_sequence.get();
        let next = sequence
            .checked_add(1)
            .ok_or_else(|| protocol_io(ExternalFloorCustodianProtocolError::SequenceExhausted))?;
        let encoded = encode_request(self.session, sequence, operation, &self.authentication)
            .map_err(protocol_io)?;
        // Consume before I/O. Reusing a sequence after an ambiguous exchange
        // would let a delayed response satisfy a later operation.
        self.next_sequence.set(next);
        let response = self.transport.exchange(&encoded)?;
        let request = decode_request(&encoded, &self.authentication).map_err(protocol_io)?;
        decode_response(&response, &request, &self.authentication).map_err(protocol_io)
    }
}

impl<T: ExternalFloorCustodianTransport> ExternalFloorReplayStore
    for AuthenticatedExternalFloorCustodian<T>
{
    fn load(&self) -> io::Result<ExternalFloorReplayCheckpoint> {
        match self.exchange(Operation::Load)? {
            Response::Current(current) => Ok(current),
            _ => Err(protocol_io(
                ExternalFloorCustodianProtocolError::InvalidStatus,
            )),
        }
    }

    fn compare_and_swap(
        &self,
        expected: ExternalFloorReplayCheckpoint,
        replacement: ExternalFloorReplayCheckpoint,
    ) -> io::Result<ExternalFloorReplayCasOutcome> {
        validate_transition(expected, replacement).map_err(protocol_io)?;
        match self.exchange(Operation::CompareAndSwap {
            expected,
            replacement,
        })? {
            Response::Committed => Ok(ExternalFloorReplayCasOutcome::Committed),
            Response::Conflict(current) => Ok(ExternalFloorReplayCasOutcome::Conflict(current)),
            Response::Uncertain => Ok(ExternalFloorReplayCasOutcome::Uncertain),
            Response::Current(_) => Err(protocol_io(
                ExternalFloorCustodianProtocolError::InvalidStatus,
            )),
        }
    }
}

impl<T: ExternalFloorCustodianTransport> ExternalFloorReplayStore
    for &AuthenticatedExternalFloorCustodian<T>
{
    fn load(&self) -> io::Result<ExternalFloorReplayCheckpoint> {
        <AuthenticatedExternalFloorCustodian<T> as ExternalFloorReplayStore>::load(*self)
    }

    fn compare_and_swap(
        &self,
        expected: ExternalFloorReplayCheckpoint,
        replacement: ExternalFloorReplayCheckpoint,
    ) -> io::Result<ExternalFloorReplayCasOutcome> {
        <AuthenticatedExternalFloorCustodian<T> as ExternalFloorReplayStore>::compare_and_swap(
            *self,
            expected,
            replacement,
        )
    }
}

/// Server-side authenticated adapter around a durable independent store.
pub struct AuthenticatedExternalFloorCustodianServer<S> {
    store: S,
    authentication: ExternalFloorCustodianAuthentication,
}

impl<S: ExternalFloorReplayStore> AuthenticatedExternalFloorCustodianServer<S> {
    pub fn new(store: S, authentication: ExternalFloorCustodianAuthentication) -> Self {
        Self {
            store,
            authentication,
        }
    }

    pub fn handle(&self, encoded: &[u8]) -> io::Result<Vec<u8>> {
        let request = decode_request(encoded, &self.authentication).map_err(protocol_io)?;
        let response = match request.operation {
            Operation::Load => Response::Current(self.store.load()?),
            Operation::CompareAndSwap {
                expected,
                replacement,
            } => {
                let current = self.store.load()?;
                if current == replacement {
                    // An exact duplicate after a lost response is semantically
                    // committed without executing another CAS.
                    Response::Committed
                } else if current != expected {
                    Response::Conflict(current)
                } else {
                    match self.store.compare_and_swap(expected, replacement)? {
                        ExternalFloorReplayCasOutcome::Committed => Response::Committed,
                        ExternalFloorReplayCasOutcome::Conflict(current) => {
                            Response::Conflict(current)
                        }
                        ExternalFloorReplayCasOutcome::Uncertain => Response::Uncertain,
                    }
                }
            }
        };
        encode_response(&request, response, &self.authentication).map_err(protocol_io)
    }
}

impl<S: ExternalFloorReplayStore> ExternalFloorCustodianTransport
    for &AuthenticatedExternalFloorCustodianServer<S>
{
    fn exchange(&self, request: &[u8]) -> io::Result<Vec<u8>> {
        self.handle(request)
    }
}
