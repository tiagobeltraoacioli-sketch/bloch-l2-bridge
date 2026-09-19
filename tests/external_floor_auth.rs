// SPDX-License-Identifier: MIT OR Apache-2.0
#![cfg(unix)]

use std::cell::{Cell, RefCell};
use std::io;

use bloch_l2_bridge::{
    decode_authenticated_external_floor_request, decode_authenticated_external_floor_response,
    encode_authenticated_external_floor_request, encode_authenticated_external_floor_response,
    AuthenticatedExternalFloorBoundary, ExternalFloorAuthError, ExternalFloorBoundary,
    ExternalFloorByteTransport, ExternalFloorOperation, ExternalFloorOutcome,
    ExternalFloorPeerAuthentication, ExternalFloorReplayGuard, ExternalFloorRequest,
    ExternalFloorResponse, ExternalGenerationFloor, SourceFloorState, SourceGenerationFloor,
    EXTERNAL_FLOOR_AUTH_MAGIC, EXTERNAL_FLOOR_AUTH_MAX_LEN, EXTERNAL_FLOOR_AUTH_VERSION,
};
use tiny_keccak::{Hasher, Kmac};

const KEY: [u8; 32] = [0x31; 32];
const CLIENT: [u8; 32] = [0xc1; 32];
const BOUNDARY: [u8; 32] = [0xb2; 32];
const SESSION: [u8; 32] = [0x5a; 32];
const KMAC_CUSTOMIZATION: &[u8] = b"BLOCH-L2-EXTERNAL-FLOOR-AUTH-v1\0";

fn authentication() -> ExternalFloorPeerAuthentication {
    ExternalFloorPeerAuthentication::new(KEY, CLIENT, BOUNDARY).unwrap()
}

fn fresh() -> SourceFloorState {
    SourceFloorState {
        generation: 0,
        snapshot_commitment: None,
    }
}

fn bound(generation: u64, byte: u8) -> SourceFloorState {
    SourceFloorState {
        generation,
        snapshot_commitment: Some([byte; 32]),
    }
}

struct Capture(RefCell<Vec<ExternalFloorRequest>>);

impl ExternalFloorBoundary for &Capture {
    fn transact(&self, request: ExternalFloorRequest) -> io::Result<ExternalFloorResponse> {
        self.0.borrow_mut().push(request);
        let outcome = match request.operation {
            ExternalFloorOperation::Read => ExternalFloorOutcome::Current(fresh()),
            ExternalFloorOperation::CompareAndSwap {
                expected,
                requested,
            } => ExternalFloorOutcome::Advanced {
                previous: expected,
                current: requested,
            },
        };
        Ok(ExternalFloorResponse {
            request_binding: request.binding,
            outcome,
        })
    }
}

fn requests() -> Vec<ExternalFloorRequest> {
    let capture = Capture(RefCell::new(Vec::new()));
    let floor = ExternalGenerationFloor::new(&capture, [0xd0; 32], SESSION).unwrap();
    floor.current().unwrap();
    floor.advance(bound(1, 0x11)).unwrap();
    capture.0.into_inner()
}

fn response(request: ExternalFloorRequest) -> ExternalFloorResponse {
    let outcome = match request.operation {
        ExternalFloorOperation::Read => ExternalFloorOutcome::Current(fresh()),
        ExternalFloorOperation::CompareAndSwap {
            expected,
            requested,
        } => ExternalFloorOutcome::Advanced {
            previous: expected,
            current: requested,
        },
    };
    ExternalFloorResponse {
        request_binding: request.binding,
        outcome,
    }
}

#[test]
fn request_and_response_round_trip_with_exact_roles_and_binding() {
    let authentication = authentication();
    let request = requests()[0];
    let mut guard = ExternalFloorReplayGuard::new(SESSION, 0).unwrap();
    let encoded = encode_authenticated_external_floor_request(&request, &authentication).unwrap();
    assert_eq!(&encoded[..4], &EXTERNAL_FLOOR_AUTH_MAGIC);
    assert_eq!(encoded[4], EXTERNAL_FLOOR_AUTH_VERSION);
    assert!(encoded.len() <= EXTERNAL_FLOOR_AUTH_MAX_LEN);
    assert_eq!(
        decode_authenticated_external_floor_request(&encoded, &authentication, &mut guard).unwrap(),
        request
    );
    assert_eq!(guard.next_sequence(), 1);

    let response = response(request);
    let encoded =
        encode_authenticated_external_floor_response(&response, &request, &authentication).unwrap();
    assert_eq!(
        decode_authenticated_external_floor_response(&encoded, &request, &authentication).unwrap(),
        response
    );
}

#[test]
fn reflection_and_role_or_peer_substitution_are_rejected() {
    let authentication = authentication();
    let request = requests()[0];
    let request_wire =
        encode_authenticated_external_floor_request(&request, &authentication).unwrap();
    assert!(matches!(
        decode_authenticated_external_floor_response(&request_wire, &request, &authentication),
        Err(ExternalFloorAuthError::WrongDirection { .. })
    ));

    let response_wire =
        encode_authenticated_external_floor_response(&response(request), &request, &authentication)
            .unwrap();
    let mut guard = ExternalFloorReplayGuard::new(SESSION, 0).unwrap();
    assert!(matches!(
        decode_authenticated_external_floor_request(&response_wire, &authentication, &mut guard),
        Err(ExternalFloorAuthError::WrongDirection { .. })
    ));

    let substituted = ExternalFloorPeerAuthentication::new(KEY, [0xc2; 32], BOUNDARY).unwrap();
    let substituted_wire =
        encode_authenticated_external_floor_request(&request, &substituted).unwrap();
    assert_eq!(
        decode_authenticated_external_floor_request(&substituted_wire, &authentication, &mut guard)
            .unwrap_err(),
        ExternalFloorAuthError::IdentityMismatch
    );
}

#[test]
fn wrong_key_tampering_truncation_and_trailing_data_fail_closed() {
    let authentication = authentication();
    let request = requests()[0];
    let canonical = encode_authenticated_external_floor_request(&request, &authentication).unwrap();

    let wrong_key = ExternalFloorPeerAuthentication::new([0x32; 32], CLIENT, BOUNDARY).unwrap();
    let mut guard = ExternalFloorReplayGuard::new(SESSION, 0).unwrap();
    assert_eq!(
        decode_authenticated_external_floor_request(&canonical, &wrong_key, &mut guard)
            .unwrap_err(),
        ExternalFloorAuthError::AuthenticationFailed
    );

    for offset in [70usize, 102, 110, 144] {
        let mut tampered = canonical.clone();
        tampered[offset] ^= 1;
        assert_eq!(
            decode_authenticated_external_floor_request(&tampered, &authentication, &mut guard)
                .unwrap_err(),
            ExternalFloorAuthError::AuthenticationFailed,
            "offset {offset} was not authenticated"
        );
    }
    for length in [0usize, 143, canonical.len() - 1] {
        assert!(decode_authenticated_external_floor_request(
            &canonical[..length],
            &authentication,
            &mut guard
        )
        .is_err());
    }
    let mut trailing = canonical;
    trailing.push(0);
    assert_eq!(
        decode_authenticated_external_floor_request(&trailing, &authentication, &mut guard)
            .unwrap_err(),
        ExternalFloorAuthError::InvalidPayloadLength
    );
}

fn refresh_authentication_tag(encoded: &mut [u8]) {
    let tag_start = encoded.len() - 32;
    let mut mac = Kmac::v256(&KEY, KMAC_CUSTOMIZATION);
    mac.update(&encoded[..tag_start]);
    let mut tag = [0; 32];
    mac.finalize(&mut tag);
    encoded[tag_start..].copy_from_slice(&tag);
}

#[test]
fn authenticated_outer_fields_must_duplicate_the_canonical_inner_request() {
    let authentication = authentication();
    let request = requests()[0];
    let canonical = encode_authenticated_external_floor_request(&request, &authentication).unwrap();

    let cases = [
        (70usize, ExternalFloorAuthError::SessionMismatch),
        (109, ExternalFloorAuthError::SequenceMismatch),
        (110, ExternalFloorAuthError::RequestBindingMismatch),
    ];
    for (offset, expected) in cases {
        let mut substituted = canonical.clone();
        substituted[offset] ^= 1;
        refresh_authentication_tag(&mut substituted);
        let mut guard = ExternalFloorReplayGuard::new(SESSION, 0).unwrap();
        assert_eq!(
            decode_authenticated_external_floor_request(&substituted, &authentication, &mut guard)
                .unwrap_err(),
            expected
        );
        assert_eq!(guard.next_sequence(), 0);
    }
}

#[test]
fn replay_out_of_order_and_session_substitution_do_not_advance_window() {
    let authentication = authentication();
    let requests = requests();
    let first = encode_authenticated_external_floor_request(&requests[0], &authentication).unwrap();
    let second =
        encode_authenticated_external_floor_request(&requests[1], &authentication).unwrap();
    let other_session_request = {
        let capture = Capture(RefCell::new(Vec::new()));
        let floor = ExternalGenerationFloor::new(&capture, [0xd0; 32], [0x6b; 32]).unwrap();
        floor.current().unwrap();
        capture.0.into_inner()[0]
    };
    let other_session =
        encode_authenticated_external_floor_request(&other_session_request, &authentication)
            .unwrap();

    let mut guard = ExternalFloorReplayGuard::new(SESSION, 0).unwrap();
    assert_eq!(
        decode_authenticated_external_floor_request(&second, &authentication, &mut guard)
            .unwrap_err(),
        ExternalFloorAuthError::ReplayOrOutOfOrder {
            expected: 0,
            found: 1
        }
    );
    assert_eq!(
        decode_authenticated_external_floor_request(&other_session, &authentication, &mut guard)
            .unwrap_err(),
        ExternalFloorAuthError::SessionMismatch
    );
    decode_authenticated_external_floor_request(&first, &authentication, &mut guard).unwrap();
    assert_eq!(
        decode_authenticated_external_floor_request(&first, &authentication, &mut guard)
            .unwrap_err(),
        ExternalFloorAuthError::ReplayOrOutOfOrder {
            expected: 1,
            found: 0
        }
    );
    decode_authenticated_external_floor_request(&second, &authentication, &mut guard).unwrap();
    assert_eq!(guard.next_sequence(), 2);
}

#[test]
fn response_cannot_be_substituted_between_requests_or_sessions() {
    let authentication = authentication();
    let requests = requests();
    let response_wire = encode_authenticated_external_floor_response(
        &response(requests[0]),
        &requests[0],
        &authentication,
    )
    .unwrap();
    assert!(matches!(
        decode_authenticated_external_floor_response(&response_wire, &requests[1], &authentication),
        Err(ExternalFloorAuthError::SequenceMismatch)
            | Err(ExternalFloorAuthError::RequestBindingMismatch)
    ));
}

#[test]
fn invalid_configuration_is_rejected_and_secret_is_redacted() {
    assert!(ExternalFloorPeerAuthentication::new([0; 32], CLIENT, BOUNDARY).is_err());
    assert!(ExternalFloorPeerAuthentication::new(KEY, [0; 32], BOUNDARY).is_err());
    assert!(ExternalFloorPeerAuthentication::new(KEY, CLIENT, CLIENT).is_err());
    assert!(ExternalFloorReplayGuard::new([0; 32], 0).is_err());
    let debug = format!("{:?}", authentication());
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains("49, 49, 49"));
}

struct Loopback {
    state: Cell<SourceFloorState>,
    guard: RefCell<ExternalFloorReplayGuard>,
    authentication: ExternalFloorPeerAuthentication,
}

impl ExternalFloorByteTransport for Loopback {
    fn exchange(&self, encoded: &[u8]) -> io::Result<Vec<u8>> {
        let request = decode_authenticated_external_floor_request(
            encoded,
            &self.authentication,
            &mut self.guard.borrow_mut(),
        )
        .map_err(io::Error::other)?;
        let outcome = match request.operation {
            ExternalFloorOperation::Read => ExternalFloorOutcome::Current(self.state.get()),
            ExternalFloorOperation::CompareAndSwap {
                expected,
                requested,
            } if expected == self.state.get() => {
                self.state.set(requested);
                ExternalFloorOutcome::Advanced {
                    previous: expected,
                    current: requested,
                }
            }
            ExternalFloorOperation::CompareAndSwap { .. } => ExternalFloorOutcome::Conflict {
                current: self.state.get(),
            },
        };
        encode_authenticated_external_floor_response(
            &ExternalFloorResponse {
                request_binding: request.binding,
                outcome,
            },
            &request,
            &self.authentication,
        )
        .map_err(io::Error::other)
    }
}

#[test]
fn typed_floor_runs_through_authenticated_byte_transport() {
    let transport = Loopback {
        state: Cell::new(fresh()),
        guard: RefCell::new(ExternalFloorReplayGuard::new(SESSION, 0).unwrap()),
        authentication: authentication(),
    };
    let boundary = AuthenticatedExternalFloorBoundary::new(transport, authentication());
    let floor = ExternalGenerationFloor::new(boundary, [0xd0; 32], SESSION).unwrap();
    assert_eq!(floor.current().unwrap(), fresh());
    floor.advance(bound(1, 0x44)).unwrap();
    assert_eq!(floor.current().unwrap(), bound(1, 0x44));
}

#[test]
fn arbitrary_bounded_inputs_never_panic_or_consume_replay_state() {
    let authentication = authentication();
    let request = requests()[0];
    for length in 0..=EXTERNAL_FLOOR_AUTH_MAX_LEN {
        let bytes = vec![0xa5; length];
        let mut guard = ExternalFloorReplayGuard::new(SESSION, 0).unwrap();
        let _ = decode_authenticated_external_floor_request(&bytes, &authentication, &mut guard);
        let _ = decode_authenticated_external_floor_response(&bytes, &request, &authentication);
        assert_eq!(guard.next_sequence(), 0);
    }
}
