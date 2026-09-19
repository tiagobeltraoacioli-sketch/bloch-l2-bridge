// SPDX-License-Identifier: MIT OR Apache-2.0
//! Canonical transport-neutral wire codec for the external generation floor.
//!
//! This codec supplies framing and strict structural validation only. It does
//! not authenticate peers, encrypt traffic, retain replay state, or turn a
//! transport into an anti-rollback boundary. Deployments must provide those
//! properties independently (for example with mutually authenticated TLS and
//! an HSM-backed service).

use core::fmt;

use tiny_keccak::{Hasher, Keccak};

use crate::external_floor::{
    request_binding, ExternalFloorOperation, ExternalFloorOutcome, ExternalFloorRequest,
    ExternalFloorResponse,
};
use crate::source_store::SourceFloorState;

/// Four-byte discriminator for external-floor codec records.
pub const EXTERNAL_FLOOR_CODEC_MAGIC: [u8; 4] = *b"BXFL";
/// Wire format version accepted by this codec.
pub const EXTERNAL_FLOOR_CODEC_VERSION: u8 = 1;
/// Largest valid v1 record (a compare-and-swap request).
pub const EXTERNAL_FLOOR_CODEC_MAX_LEN: usize = 193;

const HEADER_LEN: usize = 6;
const RESPONSE_BINDING_DOMAIN: &[u8] = b"BLOCH-L2-EXTERNAL-FLOOR-RESPONSE-CODEC-v1\0";
const MESSAGE_REQUEST: u8 = 0;
const MESSAGE_RESPONSE: u8 = 1;
const REQUEST_PREFIX_LEN: usize = HEADER_LEN + 32 + 32 + 8 + 1;
const REQUEST_BINDING_LEN: usize = 32;
const STATE_LEN: usize = 8 + 1 + 32;
const READ_REQUEST_LEN: usize = REQUEST_PREFIX_LEN + REQUEST_BINDING_LEN;
const CAS_REQUEST_LEN: usize = REQUEST_PREFIX_LEN + 2 * STATE_LEN + REQUEST_BINDING_LEN;
const RESPONSE_PREFIX_LEN: usize = HEADER_LEN + 32 + 1;
const RESPONSE_BINDING_LEN: usize = 32;
const SINGLE_STATE_RESPONSE_LEN: usize = RESPONSE_PREFIX_LEN + STATE_LEN + RESPONSE_BINDING_LEN;
const ADVANCED_RESPONSE_LEN: usize = RESPONSE_PREFIX_LEN + 2 * STATE_LEN + RESPONSE_BINDING_LEN;

/// Failure returned by the strict external-floor wire decoder or encoder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalFloorCodecError {
    TooShort { len: usize },
    TooLong { len: usize, maximum: usize },
    BadMagic,
    UnsupportedVersion(u8),
    WrongMessageKind { expected: u8, found: u8 },
    UnsupportedTag { field: &'static str, value: u8 },
    NonCanonical(&'static str),
    InvalidState(&'static str),
    BindingMismatch,
}

impl fmt::Display for ExternalFloorCodecError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort { len } => {
                write!(output, "external floor record is too short ({len} bytes)")
            }
            Self::TooLong { len, maximum } => write!(
                output,
                "external floor record is too long ({len} bytes; maximum {maximum})"
            ),
            Self::BadMagic => write!(output, "external floor record has bad magic"),
            Self::UnsupportedVersion(version) => {
                write!(output, "unsupported external floor codec version {version}")
            }
            Self::WrongMessageKind { expected, found } => write!(
                output,
                "wrong external floor message kind (expected {expected}, found {found})"
            ),
            Self::UnsupportedTag { field, value } => {
                write!(output, "unsupported external floor {field} tag {value}")
            }
            Self::NonCanonical(reason) => {
                write!(output, "non-canonical external floor record: {reason}")
            }
            Self::InvalidState(reason) => write!(output, "invalid external floor state: {reason}"),
            Self::BindingMismatch => write!(output, "external floor record binding mismatch"),
        }
    }
}

impl std::error::Error for ExternalFloorCodecError {}

/// Encode one request in the unique v1 binary representation.
///
/// The supplied request must already contain the binding derived from all of
/// its semantic fields. This prevents callers from serializing hand-built,
/// internally inconsistent requests.
pub fn encode_external_floor_request(
    request: &ExternalFloorRequest,
) -> Result<Vec<u8>, ExternalFloorCodecError> {
    validate_request(request)?;
    let mut encoded = Vec::with_capacity(match request.operation {
        ExternalFloorOperation::Read => READ_REQUEST_LEN,
        ExternalFloorOperation::CompareAndSwap { .. } => CAS_REQUEST_LEN,
    });
    write_header(&mut encoded, MESSAGE_REQUEST);
    encoded.extend_from_slice(&request.deployment_domain);
    encoded.extend_from_slice(&request.session_nonce);
    encoded.extend_from_slice(&request.sequence.to_be_bytes());
    match request.operation {
        ExternalFloorOperation::Read => encoded.push(0),
        ExternalFloorOperation::CompareAndSwap {
            expected,
            requested,
        } => {
            encoded.push(1);
            encode_state(&mut encoded, expected);
            encode_state(&mut encoded, requested);
        }
    }
    encoded.extend_from_slice(&request.binding);
    Ok(encoded)
}

/// Decode one request, rejecting unknown versions, malformed states, trailing
/// data, and any mutation not covered by the request binding.
pub fn decode_external_floor_request(
    encoded: &[u8],
) -> Result<ExternalFloorRequest, ExternalFloorCodecError> {
    validate_header(encoded, MESSAGE_REQUEST)?;
    if encoded.len() < REQUEST_PREFIX_LEN {
        return Err(ExternalFloorCodecError::TooShort { len: encoded.len() });
    }
    let operation_tag = encoded[HEADER_LEN + 32 + 32 + 8];
    let expected_len = match operation_tag {
        0 => READ_REQUEST_LEN,
        1 => CAS_REQUEST_LEN,
        value => {
            return Err(ExternalFloorCodecError::UnsupportedTag {
                field: "operation",
                value,
            })
        }
    };
    require_exact_len(encoded, expected_len)?;

    let mut cursor = HEADER_LEN;
    let deployment_domain = take_array::<32>(encoded, &mut cursor);
    let session_nonce = take_array::<32>(encoded, &mut cursor);
    let sequence = u64::from_be_bytes(take_array::<8>(encoded, &mut cursor));
    cursor += 1;
    let operation = if operation_tag == 0 {
        ExternalFloorOperation::Read
    } else {
        ExternalFloorOperation::CompareAndSwap {
            expected: decode_state(encoded, &mut cursor)?,
            requested: decode_state(encoded, &mut cursor)?,
        }
    };
    let binding = take_array::<32>(encoded, &mut cursor);
    debug_assert_eq!(cursor, encoded.len());
    let request = ExternalFloorRequest {
        deployment_domain,
        session_nonce,
        sequence,
        operation,
        binding,
    };
    validate_request(&request)?;
    Ok(request)
}

/// Encode one response in the unique v1 binary representation.
pub fn encode_external_floor_response(
    response: &ExternalFloorResponse,
    request: &ExternalFloorRequest,
) -> Result<Vec<u8>, ExternalFloorCodecError> {
    validate_request(request)?;
    validate_response(response, request)?;
    let mut encoded = Vec::with_capacity(match response.outcome {
        ExternalFloorOutcome::Advanced { .. } => ADVANCED_RESPONSE_LEN,
        _ => SINGLE_STATE_RESPONSE_LEN,
    });
    write_header(&mut encoded, MESSAGE_RESPONSE);
    encoded.extend_from_slice(&response.request_binding);
    match response.outcome {
        ExternalFloorOutcome::Current(state) => {
            encoded.push(0);
            encode_state(&mut encoded, state);
        }
        ExternalFloorOutcome::Advanced { previous, current } => {
            encoded.push(1);
            encode_state(&mut encoded, previous);
            encode_state(&mut encoded, current);
        }
        ExternalFloorOutcome::Conflict { current } => {
            encoded.push(2);
            encode_state(&mut encoded, current);
        }
    }
    let binding = response_record_binding(&encoded);
    encoded.extend_from_slice(&binding);
    Ok(encoded)
}

/// Decode one response for an exact request binding.
///
/// Requiring the caller's expected binding avoids a decode-then-compare gap.
/// This check is not peer authentication: the transport or response
/// attestation must still authenticate both the request binding and outcome.
pub fn decode_external_floor_response(
    encoded: &[u8],
    request: &ExternalFloorRequest,
) -> Result<ExternalFloorResponse, ExternalFloorCodecError> {
    validate_request(request)?;
    validate_header(encoded, MESSAGE_RESPONSE)?;
    if encoded.len() < RESPONSE_PREFIX_LEN {
        return Err(ExternalFloorCodecError::TooShort { len: encoded.len() });
    }
    let outcome_tag = encoded[HEADER_LEN + 32];
    let expected_len = match outcome_tag {
        0 | 2 => SINGLE_STATE_RESPONSE_LEN,
        1 => ADVANCED_RESPONSE_LEN,
        value => {
            return Err(ExternalFloorCodecError::UnsupportedTag {
                field: "outcome",
                value,
            })
        }
    };
    require_exact_len(encoded, expected_len)?;
    let payload_end = encoded.len() - RESPONSE_BINDING_LEN;
    let supplied_record_binding = &encoded[payload_end..];
    if supplied_record_binding != response_record_binding(&encoded[..payload_end]) {
        return Err(ExternalFloorCodecError::BindingMismatch);
    }

    let mut cursor = HEADER_LEN;
    let request_binding = take_array::<32>(encoded, &mut cursor);
    if request_binding != request.binding {
        return Err(ExternalFloorCodecError::BindingMismatch);
    }
    cursor += 1;
    let first = decode_state(encoded, &mut cursor)?;
    let outcome = match outcome_tag {
        0 => ExternalFloorOutcome::Current(first),
        1 => ExternalFloorOutcome::Advanced {
            previous: first,
            current: decode_state(encoded, &mut cursor)?,
        },
        2 => ExternalFloorOutcome::Conflict { current: first },
        _ => unreachable!("outcome tag was checked above"),
    };
    debug_assert_eq!(cursor, payload_end);
    let response = ExternalFloorResponse {
        request_binding,
        outcome,
    };
    validate_response(&response, request)?;
    Ok(response)
}

fn response_record_binding(payload: &[u8]) -> [u8; 32] {
    let mut hash = Keccak::v256();
    hash.update(RESPONSE_BINDING_DOMAIN);
    hash.update(payload);
    let mut binding = [0; 32];
    hash.finalize(&mut binding);
    binding
}

fn write_header(encoded: &mut Vec<u8>, message_kind: u8) {
    encoded.extend_from_slice(&EXTERNAL_FLOOR_CODEC_MAGIC);
    encoded.push(EXTERNAL_FLOOR_CODEC_VERSION);
    encoded.push(message_kind);
}

fn validate_header(encoded: &[u8], expected_kind: u8) -> Result<(), ExternalFloorCodecError> {
    if encoded.len() > EXTERNAL_FLOOR_CODEC_MAX_LEN {
        return Err(ExternalFloorCodecError::TooLong {
            len: encoded.len(),
            maximum: EXTERNAL_FLOOR_CODEC_MAX_LEN,
        });
    }
    if encoded.len() < HEADER_LEN {
        return Err(ExternalFloorCodecError::TooShort { len: encoded.len() });
    }
    if encoded[..4] != EXTERNAL_FLOOR_CODEC_MAGIC {
        return Err(ExternalFloorCodecError::BadMagic);
    }
    if encoded[4] != EXTERNAL_FLOOR_CODEC_VERSION {
        return Err(ExternalFloorCodecError::UnsupportedVersion(encoded[4]));
    }
    if encoded[5] != expected_kind {
        return Err(ExternalFloorCodecError::WrongMessageKind {
            expected: expected_kind,
            found: encoded[5],
        });
    }
    Ok(())
}

fn require_exact_len(encoded: &[u8], expected: usize) -> Result<(), ExternalFloorCodecError> {
    if encoded.len() < expected {
        Err(ExternalFloorCodecError::TooShort { len: encoded.len() })
    } else if encoded.len() > expected {
        Err(ExternalFloorCodecError::NonCanonical(
            "trailing or duplicate fields",
        ))
    } else {
        Ok(())
    }
}

fn encode_state(encoded: &mut Vec<u8>, state: SourceFloorState) {
    encoded.extend_from_slice(&state.generation.to_be_bytes());
    match state.snapshot_commitment {
        Some(commitment) => {
            encoded.push(1);
            encoded.extend_from_slice(&commitment);
        }
        None => {
            encoded.push(0);
            encoded.extend_from_slice(&[0; 32]);
        }
    }
}

fn decode_state(
    encoded: &[u8],
    cursor: &mut usize,
) -> Result<SourceFloorState, ExternalFloorCodecError> {
    let generation = u64::from_be_bytes(take_array::<8>(encoded, cursor));
    let presence = encoded[*cursor];
    *cursor += 1;
    let slot = take_array::<32>(encoded, cursor);
    let snapshot_commitment = match presence {
        0 if slot == [0; 32] => None,
        0 => {
            return Err(ExternalFloorCodecError::NonCanonical(
                "absent commitment has nonzero reserved bytes",
            ))
        }
        1 => Some(slot),
        value => {
            return Err(ExternalFloorCodecError::UnsupportedTag {
                field: "commitment-presence",
                value,
            })
        }
    };
    let state = SourceFloorState {
        generation,
        snapshot_commitment,
    };
    validate_state(state)?;
    Ok(state)
}

fn take_array<const N: usize>(encoded: &[u8], cursor: &mut usize) -> [u8; N] {
    let mut value = [0; N];
    value.copy_from_slice(&encoded[*cursor..*cursor + N]);
    *cursor += N;
    value
}

fn validate_request(request: &ExternalFloorRequest) -> Result<(), ExternalFloorCodecError> {
    if request.deployment_domain == [0; 32] {
        return Err(ExternalFloorCodecError::InvalidState(
            "deployment domain is all zero",
        ));
    }
    if request.session_nonce == [0; 32] {
        return Err(ExternalFloorCodecError::InvalidState(
            "session nonce is all zero",
        ));
    }
    if let ExternalFloorOperation::CompareAndSwap {
        expected,
        requested,
    } = request.operation
    {
        validate_state(expected)?;
        validate_state(requested)?;
        if requested.snapshot_commitment.is_none() {
            return Err(ExternalFloorCodecError::InvalidState(
                "CAS requested state is not snapshot-bound",
            ));
        }
        validate_transition(expected, requested)?;
    }
    if request.binding != request_binding(request) {
        return Err(ExternalFloorCodecError::BindingMismatch);
    }
    Ok(())
}

fn validate_response(
    response: &ExternalFloorResponse,
    request: &ExternalFloorRequest,
) -> Result<(), ExternalFloorCodecError> {
    if response.request_binding != request.binding {
        return Err(ExternalFloorCodecError::BindingMismatch);
    }
    match (request.operation, response.outcome) {
        (ExternalFloorOperation::Read, ExternalFloorOutcome::Current(state)) => {
            validate_state(state)
        }
        (
            ExternalFloorOperation::CompareAndSwap {
                expected,
                requested,
            },
            ExternalFloorOutcome::Advanced { previous, current },
        ) if previous == expected && current == requested => Ok(()),
        (
            ExternalFloorOperation::CompareAndSwap { expected, .. },
            ExternalFloorOutcome::Conflict { current },
        ) if valid_conflict(expected, current) => Ok(()),
        _ => Err(ExternalFloorCodecError::InvalidState(
            "response outcome does not match its bound request",
        )),
    }
}

fn validate_transition(
    expected: SourceFloorState,
    requested: SourceFloorState,
) -> Result<(), ExternalFloorCodecError> {
    if requested.generation < expected.generation {
        return Err(ExternalFloorCodecError::InvalidState(
            "CAS transition moves backwards",
        ));
    }
    if requested.generation == expected.generation
        && (expected.snapshot_commitment.is_some() || requested == expected)
    {
        return Err(ExternalFloorCodecError::InvalidState(
            "CAS transition rebinds or repeats a generation",
        ));
    }
    Ok(())
}

fn valid_conflict(expected: SourceFloorState, current: SourceFloorState) -> bool {
    validate_state(current).is_ok()
        && current != expected
        && (current.generation > expected.generation
            || (current.generation == expected.generation
                && expected.snapshot_commitment.is_none()))
}

fn validate_state(state: SourceFloorState) -> Result<(), ExternalFloorCodecError> {
    if state.generation != 0 && state.snapshot_commitment.is_none() {
        return Err(ExternalFloorCodecError::InvalidState(
            "nonzero generation is not snapshot-bound",
        ));
    }
    Ok(())
}
