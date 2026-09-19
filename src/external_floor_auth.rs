// SPDX-License-Identifier: MIT OR Apache-2.0
//! Authenticated, role-bound framing for canonical `BXFL` records.
//!
//! This module supplies message authentication plus an interface for durable,
//! linearizable replay-state CAS. It supplies no network transport,
//! confidentiality, storage backend, key isolation, or physical anti-rollback
//! boundary. Production deployments still need mTLS (or an equivalent
//! authenticated channel), HSM-backed key custody, and an independently
//! retained replay checkpoint.

use core::fmt;
use std::cell::RefCell;
use std::io;

use tiny_keccak::{Hasher, Kmac};
use zeroize::Zeroize;

use crate::external_floor::{ExternalFloorBoundary, ExternalFloorRequest, ExternalFloorResponse};
use crate::external_floor_codec::{
    decode_external_floor_request, decode_external_floor_response, encode_external_floor_request,
    encode_external_floor_response, ExternalFloorCodecError, EXTERNAL_FLOOR_CODEC_MAX_LEN,
};

/// Magic prefix for authenticated external-floor envelopes.
pub const EXTERNAL_FLOOR_AUTH_MAGIC: [u8; 4] = *b"BXFA";
/// Authenticated-envelope version.
pub const EXTERNAL_FLOOR_AUTH_VERSION: u8 = 1;
/// Largest accepted authenticated envelope.
pub const EXTERNAL_FLOOR_AUTH_MAX_LEN: usize = 369;

const HEADER_LEN: usize = 144;
const TAG_LEN: usize = 32;
const MIN_LEN: usize = HEADER_LEN + TAG_LEN;
const REQUEST_DIRECTION: u8 = 0;
const RESPONSE_DIRECTION: u8 = 1;
const KMAC_CUSTOMIZATION: &[u8] = b"BLOCH-L2-EXTERNAL-FLOOR-AUTH-v1\0";

/// Secret and fixed peer identities for one client↔boundary relationship.
///
/// The symmetric key authenticates membership in the configured peer pair;
/// it does not provide asymmetric attribution or non-repudiation. The key is
/// redacted from `Debug` and zeroized on drop.
pub struct ExternalFloorPeerAuthentication {
    key: [u8; 32],
    client_peer: [u8; 32],
    boundary_peer: [u8; 32],
}

impl ExternalFloorPeerAuthentication {
    pub fn new(
        mut key: [u8; 32],
        client_peer: [u8; 32],
        boundary_peer: [u8; 32],
    ) -> Result<Self, ExternalFloorAuthError> {
        if key == [0; 32] {
            return Err(ExternalFloorAuthError::InvalidConfiguration(
                "authentication key is all zero",
            ));
        }
        if client_peer == [0; 32] || boundary_peer == [0; 32] {
            key.zeroize();
            return Err(ExternalFloorAuthError::InvalidConfiguration(
                "peer identity is all zero",
            ));
        }
        if client_peer == boundary_peer {
            key.zeroize();
            return Err(ExternalFloorAuthError::InvalidConfiguration(
                "client and boundary peer identities are equal",
            ));
        }
        Ok(Self {
            key,
            client_peer,
            boundary_peer,
        })
    }
}

impl fmt::Debug for ExternalFloorPeerAuthentication {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output
            .debug_struct("ExternalFloorPeerAuthentication")
            .field("key", &"[REDACTED]")
            .field("client_peer", &self.client_peer)
            .field("boundary_peer", &self.boundary_peer)
            .finish()
    }
}

impl Drop for ExternalFloorPeerAuthentication {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

/// In-memory, exact-next-sequence replay guard for one pre-authorized session.
///
/// A production boundary must persist equivalent state outside the rollbackable
/// bridge host. A new session requires a newly constructed guard after the
/// session nonce has been authorized by that durable registry.
#[derive(Debug)]
pub struct ExternalFloorReplayGuard {
    session_nonce: [u8; 32],
    next_sequence: u64,
}

/// Independently retained checkpoint for one authorized server session.
///
/// Production callers must retain this value outside the rollback domain of
/// the replay store and supply it again after restart. Equality with the
/// store's value is required before traffic is accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExternalFloorReplayCheckpoint {
    pub revision: u64,
    pub session_nonce: [u8; 32],
    pub next_sequence: u64,
}

impl ExternalFloorReplayCheckpoint {
    pub fn new(
        revision: u64,
        session_nonce: [u8; 32],
        next_sequence: u64,
    ) -> Result<Self, ExternalFloorDurableReplayError> {
        if session_nonce == [0; 32] {
            return Err(ExternalFloorDurableReplayError::InvalidCheckpoint(
                "authorized session nonce is all zero",
            ));
        }
        Ok(Self {
            revision,
            session_nonce,
            next_sequence,
        })
    }
}

/// Result of an atomic replay-checkpoint compare-and-swap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalFloorReplayCasOutcome {
    /// The replacement is durably committed and visible to later loads.
    Committed,
    /// The expected checkpoint did not match the current durable checkpoint.
    Conflict(ExternalFloorReplayCheckpoint),
    /// The caller cannot determine whether the replacement committed.
    Uncertain,
}

/// Durable, linearizable storage used by the authenticated server path.
///
/// `compare_and_swap` must compare the complete checkpoint, durably commit the
/// complete replacement atomically, and be linearizable with `load`. An I/O
/// error or [`ExternalFloorReplayCasOutcome::Uncertain`] is treated as an
/// ambiguous write: the server instance closes and no external operation is
/// executed. Recovery then requires an independently trusted checkpoint and
/// reconciliation with the backend; blind retry is forbidden.
pub trait ExternalFloorReplayStore {
    fn load(&self) -> io::Result<ExternalFloorReplayCheckpoint>;

    fn compare_and_swap(
        &self,
        expected: ExternalFloorReplayCheckpoint,
        replacement: ExternalFloorReplayCheckpoint,
    ) -> io::Result<ExternalFloorReplayCasOutcome>;
}

#[derive(Debug)]
pub enum ExternalFloorDurableReplayError {
    InvalidCheckpoint(&'static str),
    Store(io::Error),
    CheckpointMismatch {
        trusted: ExternalFloorReplayCheckpoint,
        stored: ExternalFloorReplayCheckpoint,
    },
    SessionNotAuthorized,
    ReplayOrOutOfOrder {
        expected: u64,
        found: u64,
    },
    SequenceExhausted,
    RevisionExhausted,
    CompareAndSwapConflict(ExternalFloorReplayCheckpoint),
    CompareAndSwapUncertain,
    Closed,
}

impl fmt::Display for ExternalFloorDurableReplayError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            output,
            "durable external floor replay state rejected: {self:?}"
        )
    }
}

impl std::error::Error for ExternalFloorDurableReplayError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Store(error) => Some(error),
            _ => None,
        }
    }
}

/// Fail-closed owner of one exact durable replay checkpoint.
pub struct DurableExternalFloorReplayGuard<S> {
    store: S,
    checkpoint: ExternalFloorReplayCheckpoint,
    closed: bool,
}

impl<S: ExternalFloorReplayStore> DurableExternalFloorReplayGuard<S> {
    /// Open only when durable state exactly matches independently retained
    /// trusted state. This makes rollback and unexpected advancement visible.
    pub fn open(
        store: S,
        trusted: ExternalFloorReplayCheckpoint,
    ) -> Result<Self, ExternalFloorDurableReplayError> {
        validate_replay_checkpoint(trusted)?;
        let stored = store
            .load()
            .map_err(ExternalFloorDurableReplayError::Store)?;
        validate_replay_checkpoint(stored)?;
        if stored != trusted {
            return Err(ExternalFloorDurableReplayError::CheckpointMismatch { trusted, stored });
        }
        Ok(Self {
            store,
            checkpoint: trusted,
            closed: false,
        })
    }

    pub fn checkpoint(&self) -> ExternalFloorReplayCheckpoint {
        self.checkpoint
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Refuse all later reservations after an ambiguous downstream outcome.
    pub fn close(&mut self) {
        self.closed = true;
    }

    /// Atomically consume the exact next request sequence.
    ///
    /// Call this only after authenticating and canonically decoding the full
    /// request, and before performing any operation described by that request.
    pub fn reserve(
        &mut self,
        session_nonce: [u8; 32],
        sequence: u64,
    ) -> Result<ExternalFloorReplayCheckpoint, ExternalFloorDurableReplayError> {
        if self.closed {
            return Err(ExternalFloorDurableReplayError::Closed);
        }
        if session_nonce != self.checkpoint.session_nonce {
            return Err(ExternalFloorDurableReplayError::SessionNotAuthorized);
        }
        if sequence != self.checkpoint.next_sequence {
            return Err(ExternalFloorDurableReplayError::ReplayOrOutOfOrder {
                expected: self.checkpoint.next_sequence,
                found: sequence,
            });
        }
        let next_sequence = sequence
            .checked_add(1)
            .ok_or(ExternalFloorDurableReplayError::SequenceExhausted)?;
        let revision = self
            .checkpoint
            .revision
            .checked_add(1)
            .ok_or(ExternalFloorDurableReplayError::RevisionExhausted)?;
        let replacement = ExternalFloorReplayCheckpoint {
            revision,
            session_nonce,
            next_sequence,
        };
        let outcome = match self.store.compare_and_swap(self.checkpoint, replacement) {
            Ok(outcome) => outcome,
            Err(error) => {
                self.closed = true;
                return Err(ExternalFloorDurableReplayError::Store(error));
            }
        };
        match outcome {
            ExternalFloorReplayCasOutcome::Committed => {
                self.checkpoint = replacement;
                Ok(replacement)
            }
            ExternalFloorReplayCasOutcome::Conflict(current) => {
                self.closed = true;
                Err(ExternalFloorDurableReplayError::CompareAndSwapConflict(
                    current,
                ))
            }
            ExternalFloorReplayCasOutcome::Uncertain => {
                self.closed = true;
                Err(ExternalFloorDurableReplayError::CompareAndSwapUncertain)
            }
        }
    }
}

fn validate_replay_checkpoint(
    checkpoint: ExternalFloorReplayCheckpoint,
) -> Result<(), ExternalFloorDurableReplayError> {
    if checkpoint.session_nonce == [0; 32] {
        return Err(ExternalFloorDurableReplayError::InvalidCheckpoint(
            "authorized session nonce is all zero",
        ));
    }
    Ok(())
}

impl ExternalFloorReplayGuard {
    pub fn new(
        session_nonce: [u8; 32],
        next_sequence: u64,
    ) -> Result<Self, ExternalFloorAuthError> {
        if session_nonce == [0; 32] {
            return Err(ExternalFloorAuthError::InvalidConfiguration(
                "replay-guard session nonce is all zero",
            ));
        }
        Ok(Self {
            session_nonce,
            next_sequence,
        })
    }

    pub fn next_sequence(&self) -> u64 {
        self.next_sequence
    }

    fn accept(
        &mut self,
        session_nonce: [u8; 32],
        sequence: u64,
    ) -> Result<(), ExternalFloorAuthError> {
        if session_nonce != self.session_nonce {
            return Err(ExternalFloorAuthError::SessionMismatch);
        }
        if sequence != self.next_sequence {
            return Err(ExternalFloorAuthError::ReplayOrOutOfOrder {
                expected: self.next_sequence,
                found: sequence,
            });
        }
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(ExternalFloorAuthError::SequenceExhausted)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalFloorAuthError {
    InvalidConfiguration(&'static str),
    TooShort { len: usize },
    TooLong { len: usize, maximum: usize },
    BadMagic,
    UnsupportedVersion(u8),
    WrongDirection { expected: u8, found: u8 },
    IdentityMismatch,
    SessionMismatch,
    SequenceMismatch,
    RequestBindingMismatch,
    InvalidPayloadLength,
    AuthenticationFailed,
    ReplayOrOutOfOrder { expected: u64, found: u64 },
    SequenceExhausted,
    Codec(ExternalFloorCodecError),
}

impl fmt::Display for ExternalFloorAuthError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            output,
            "authenticated external floor envelope rejected: {self:?}"
        )
    }
}

impl std::error::Error for ExternalFloorAuthError {}

impl From<ExternalFloorCodecError> for ExternalFloorAuthError {
    fn from(error: ExternalFloorCodecError) -> Self {
        Self::Codec(error)
    }
}

pub fn encode_authenticated_external_floor_request(
    request: &ExternalFloorRequest,
    authentication: &ExternalFloorPeerAuthentication,
) -> Result<Vec<u8>, ExternalFloorAuthError> {
    let payload = encode_external_floor_request(request)?;
    encode_envelope(
        REQUEST_DIRECTION,
        authentication.client_peer,
        authentication.boundary_peer,
        request.session_nonce,
        request.sequence,
        request.binding,
        &payload,
        authentication,
    )
}

pub fn decode_authenticated_external_floor_request(
    encoded: &[u8],
    authentication: &ExternalFloorPeerAuthentication,
    replay_guard: &mut ExternalFloorReplayGuard,
) -> Result<ExternalFloorRequest, ExternalFloorAuthError> {
    let request = decode_authenticated_external_floor_request_inner(encoded, authentication)?;
    // Consume replay state only after both authentication and canonical inner
    // decoding succeed, so malformed traffic cannot advance the window.
    replay_guard.accept(request.session_nonce, request.sequence)?;
    Ok(request)
}

fn decode_authenticated_external_floor_request_inner(
    encoded: &[u8],
    authentication: &ExternalFloorPeerAuthentication,
) -> Result<ExternalFloorRequest, ExternalFloorAuthError> {
    let envelope = decode_envelope(
        encoded,
        REQUEST_DIRECTION,
        authentication.client_peer,
        authentication.boundary_peer,
        authentication,
    )?;
    let request = decode_external_floor_request(envelope.payload)?;
    validate_outer_binding(&envelope, &request)?;
    Ok(request)
}

pub fn encode_authenticated_external_floor_response(
    response: &ExternalFloorResponse,
    request: &ExternalFloorRequest,
    authentication: &ExternalFloorPeerAuthentication,
) -> Result<Vec<u8>, ExternalFloorAuthError> {
    let payload = encode_external_floor_response(response, request)?;
    encode_envelope(
        RESPONSE_DIRECTION,
        authentication.boundary_peer,
        authentication.client_peer,
        request.session_nonce,
        request.sequence,
        request.binding,
        &payload,
        authentication,
    )
}

pub fn decode_authenticated_external_floor_response(
    encoded: &[u8],
    request: &ExternalFloorRequest,
    authentication: &ExternalFloorPeerAuthentication,
) -> Result<ExternalFloorResponse, ExternalFloorAuthError> {
    let envelope = decode_envelope(
        encoded,
        RESPONSE_DIRECTION,
        authentication.boundary_peer,
        authentication.client_peer,
        authentication,
    )?;
    if envelope.session_nonce != request.session_nonce {
        return Err(ExternalFloorAuthError::SessionMismatch);
    }
    if envelope.sequence != request.sequence {
        return Err(ExternalFloorAuthError::SequenceMismatch);
    }
    if envelope.request_binding != request.binding {
        return Err(ExternalFloorAuthError::RequestBindingMismatch);
    }
    Ok(decode_external_floor_response(envelope.payload, request)?)
}

/// Byte transport used by [`AuthenticatedExternalFloorBoundary`].
pub trait ExternalFloorByteTransport {
    fn exchange(&self, request: &[u8]) -> io::Result<Vec<u8>>;
}

/// Client-side integration of authenticated framing with the typed adapter.
///
/// The typed adapter never repeats a request binding, including during
/// reconciliation, so accepting a response requires the exact in-flight
/// request's session, sequence, binding, direction, and peer identities.
pub struct AuthenticatedExternalFloorBoundary<T> {
    transport: T,
    authentication: ExternalFloorPeerAuthentication,
}

impl<T> AuthenticatedExternalFloorBoundary<T> {
    pub fn new(transport: T, authentication: ExternalFloorPeerAuthentication) -> Self {
        Self {
            transport,
            authentication,
        }
    }

    pub fn into_transport(self) -> T {
        self.transport
    }
}

impl<T: ExternalFloorByteTransport> ExternalFloorBoundary
    for AuthenticatedExternalFloorBoundary<T>
{
    fn transact(&self, request: ExternalFloorRequest) -> io::Result<ExternalFloorResponse> {
        let encoded = encode_authenticated_external_floor_request(&request, &self.authentication)
            .map_err(auth_io_error)?;
        let response = self.transport.exchange(&encoded)?;
        decode_authenticated_external_floor_response(&response, &request, &self.authentication)
            .map_err(auth_io_error)
    }
}

/// Server-side integration that durably consumes replay state before invoking
/// the external generation-floor boundary.
///
/// A lost response or boundary error leaves the sequence consumed. A boundary
/// error also closes this server instance. Recovery may require a fresh
/// authorized session and reconciliation, but never permits a potentially
/// executed CAS to be replayed.
pub struct DurableAuthenticatedExternalFloorServer<S, B> {
    replay: RefCell<DurableExternalFloorReplayGuard<S>>,
    boundary: B,
    authentication: ExternalFloorPeerAuthentication,
}

impl<S: ExternalFloorReplayStore, B: ExternalFloorBoundary>
    DurableAuthenticatedExternalFloorServer<S, B>
{
    pub fn open(
        store: S,
        trusted: ExternalFloorReplayCheckpoint,
        boundary: B,
        authentication: ExternalFloorPeerAuthentication,
    ) -> Result<Self, ExternalFloorDurableReplayError> {
        Ok(Self {
            replay: RefCell::new(DurableExternalFloorReplayGuard::open(store, trusted)?),
            boundary,
            authentication,
        })
    }

    pub fn handle(&self, encoded: &[u8]) -> io::Result<Vec<u8>> {
        let request =
            decode_authenticated_external_floor_request_inner(encoded, &self.authentication)
                .map_err(auth_io_error)?;
        self.replay
            .borrow_mut()
            .reserve(request.session_nonce, request.sequence)
            .map_err(|error| io::Error::new(io::ErrorKind::PermissionDenied, error))?;

        // The durable reservation deliberately precedes all boundary effects.
        let response = match self.boundary.transact(request) {
            Ok(response) => response,
            Err(error) => {
                self.replay.borrow_mut().close();
                return Err(error);
            }
        };
        match encode_authenticated_external_floor_response(
            &response,
            &request,
            &self.authentication,
        ) {
            Ok(encoded) => Ok(encoded),
            Err(error) => {
                self.replay.borrow_mut().close();
                Err(auth_io_error(error))
            }
        }
    }

    pub fn checkpoint(&self) -> ExternalFloorReplayCheckpoint {
        self.replay.borrow().checkpoint()
    }

    pub fn is_closed(&self) -> bool {
        self.replay.borrow().is_closed()
    }
}

fn auth_io_error(error: ExternalFloorAuthError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

struct DecodedEnvelope<'a> {
    session_nonce: [u8; 32],
    sequence: u64,
    request_binding: [u8; 32],
    payload: &'a [u8],
}

#[allow(clippy::too_many_arguments)]
fn encode_envelope(
    direction: u8,
    sender: [u8; 32],
    receiver: [u8; 32],
    session_nonce: [u8; 32],
    sequence: u64,
    request_binding: [u8; 32],
    payload: &[u8],
    authentication: &ExternalFloorPeerAuthentication,
) -> Result<Vec<u8>, ExternalFloorAuthError> {
    let payload_len =
        u16::try_from(payload.len()).map_err(|_| ExternalFloorAuthError::InvalidPayloadLength)?;
    if payload.is_empty() || payload.len() > EXTERNAL_FLOOR_CODEC_MAX_LEN {
        return Err(ExternalFloorAuthError::InvalidPayloadLength);
    }
    let mut encoded = Vec::with_capacity(HEADER_LEN + payload.len() + TAG_LEN);
    encoded.extend_from_slice(&EXTERNAL_FLOOR_AUTH_MAGIC);
    encoded.push(EXTERNAL_FLOOR_AUTH_VERSION);
    encoded.push(direction);
    encoded.extend_from_slice(&sender);
    encoded.extend_from_slice(&receiver);
    encoded.extend_from_slice(&session_nonce);
    encoded.extend_from_slice(&sequence.to_be_bytes());
    encoded.extend_from_slice(&request_binding);
    encoded.extend_from_slice(&payload_len.to_be_bytes());
    debug_assert_eq!(encoded.len(), HEADER_LEN);
    encoded.extend_from_slice(payload);
    let tag = authentication_tag(authentication, &encoded);
    encoded.extend_from_slice(&tag);
    Ok(encoded)
}

fn decode_envelope<'a>(
    encoded: &'a [u8],
    expected_direction: u8,
    expected_sender: [u8; 32],
    expected_receiver: [u8; 32],
    authentication: &ExternalFloorPeerAuthentication,
) -> Result<DecodedEnvelope<'a>, ExternalFloorAuthError> {
    if encoded.len() < MIN_LEN {
        return Err(ExternalFloorAuthError::TooShort { len: encoded.len() });
    }
    if encoded.len() > EXTERNAL_FLOOR_AUTH_MAX_LEN {
        return Err(ExternalFloorAuthError::TooLong {
            len: encoded.len(),
            maximum: EXTERNAL_FLOOR_AUTH_MAX_LEN,
        });
    }
    if encoded[..4] != EXTERNAL_FLOOR_AUTH_MAGIC {
        return Err(ExternalFloorAuthError::BadMagic);
    }
    if encoded[4] != EXTERNAL_FLOOR_AUTH_VERSION {
        return Err(ExternalFloorAuthError::UnsupportedVersion(encoded[4]));
    }
    if encoded[5] != expected_direction {
        return Err(ExternalFloorAuthError::WrongDirection {
            expected: expected_direction,
            found: encoded[5],
        });
    }
    if encoded[6..38] != expected_sender || encoded[38..70] != expected_receiver {
        return Err(ExternalFloorAuthError::IdentityMismatch);
    }
    let payload_len = u16::from_be_bytes([encoded[142], encoded[143]]) as usize;
    let expected_len = HEADER_LEN
        .checked_add(payload_len)
        .and_then(|length| length.checked_add(TAG_LEN))
        .ok_or(ExternalFloorAuthError::InvalidPayloadLength)?;
    if payload_len == 0
        || payload_len > EXTERNAL_FLOOR_CODEC_MAX_LEN
        || encoded.len() != expected_len
    {
        return Err(ExternalFloorAuthError::InvalidPayloadLength);
    }
    let tag_start = encoded.len() - TAG_LEN;
    let expected_tag = authentication_tag(authentication, &encoded[..tag_start]);
    if !tags_equal(&encoded[tag_start..], &expected_tag) {
        return Err(ExternalFloorAuthError::AuthenticationFailed);
    }
    Ok(DecodedEnvelope {
        session_nonce: encoded[70..102].try_into().expect("fixed session slice"),
        sequence: u64::from_be_bytes(encoded[102..110].try_into().expect("fixed sequence slice")),
        request_binding: encoded[110..142].try_into().expect("fixed binding slice"),
        payload: &encoded[HEADER_LEN..tag_start],
    })
}

fn validate_outer_binding(
    envelope: &DecodedEnvelope<'_>,
    request: &ExternalFloorRequest,
) -> Result<(), ExternalFloorAuthError> {
    if envelope.session_nonce != request.session_nonce {
        return Err(ExternalFloorAuthError::SessionMismatch);
    }
    if envelope.sequence != request.sequence {
        return Err(ExternalFloorAuthError::SequenceMismatch);
    }
    if envelope.request_binding != request.binding {
        return Err(ExternalFloorAuthError::RequestBindingMismatch);
    }
    Ok(())
}

fn authentication_tag(
    authentication: &ExternalFloorPeerAuthentication,
    payload: &[u8],
) -> [u8; 32] {
    let mut mac = Kmac::v256(&authentication.key, KMAC_CUSTOMIZATION);
    mac.update(payload);
    let mut tag = [0; 32];
    mac.finalize(&mut tag);
    tag
}

fn tags_equal(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .fold(0_u8, |difference, (left, right)| {
                difference | (left ^ right)
            })
            == 0
}
