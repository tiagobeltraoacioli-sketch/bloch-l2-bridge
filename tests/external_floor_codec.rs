// SPDX-License-Identifier: MIT OR Apache-2.0
#![cfg(unix)]

use std::cell::{Cell, RefCell};
use std::io;

use bloch_l2_bridge::{
    decode_external_floor_request, decode_external_floor_response, encode_external_floor_request,
    encode_external_floor_response, ExternalFloorBoundary, ExternalFloorCodecError,
    ExternalFloorOperation, ExternalFloorOutcome, ExternalFloorRequest, ExternalFloorResponse,
    ExternalGenerationFloor, SourceFloorState, SourceGenerationFloor, EXTERNAL_FLOOR_CODEC_MAGIC,
    EXTERNAL_FLOOR_CODEC_MAX_LEN, EXTERNAL_FLOOR_CODEC_VERSION,
};
use tiny_keccak::{Hasher, Keccak};

const RESPONSE_BINDING_DOMAIN: &[u8] = b"BLOCH-L2-EXTERNAL-FLOOR-RESPONSE-CODEC-v1\0";

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

struct CaptureBoundary {
    state: Cell<SourceFloorState>,
    requests: RefCell<Vec<ExternalFloorRequest>>,
}

impl CaptureBoundary {
    fn new() -> Self {
        Self {
            state: Cell::new(fresh()),
            requests: RefCell::new(Vec::new()),
        }
    }
}

impl ExternalFloorBoundary for &CaptureBoundary {
    fn transact(&self, request: ExternalFloorRequest) -> io::Result<ExternalFloorResponse> {
        self.requests.borrow_mut().push(request);
        let outcome = match request.operation {
            ExternalFloorOperation::Read => ExternalFloorOutcome::Current(self.state.get()),
            ExternalFloorOperation::CompareAndSwap {
                expected,
                requested,
            } => {
                assert_eq!(self.state.get(), expected);
                self.state.set(requested);
                ExternalFloorOutcome::Advanced {
                    previous: expected,
                    current: requested,
                }
            }
        };
        Ok(ExternalFloorResponse {
            request_binding: request.binding,
            outcome,
        })
    }
}

fn captured_requests() -> Vec<ExternalFloorRequest> {
    let boundary = CaptureBoundary::new();
    let floor = ExternalGenerationFloor::new(&boundary, [0xa5; 32], [0x5a; 32]).unwrap();
    floor.current().unwrap();
    floor.advance(bound(1, 0x11)).unwrap();
    boundary.requests.into_inner()
}

#[test]
fn request_variants_have_one_exact_round_trip() {
    let requests = captured_requests();
    assert!(matches!(
        requests[0].operation,
        ExternalFloorOperation::Read
    ));
    let cas = requests
        .iter()
        .find(|request| {
            matches!(
                request.operation,
                ExternalFloorOperation::CompareAndSwap { .. }
            )
        })
        .unwrap();

    for request in [&requests[0], cas] {
        let encoded = encode_external_floor_request(request).unwrap();
        assert_eq!(&encoded[..4], &EXTERNAL_FLOOR_CODEC_MAGIC);
        assert_eq!(encoded[4], EXTERNAL_FLOOR_CODEC_VERSION);
        assert_eq!(encoded[5], 0);
        assert!(encoded.len() <= EXTERNAL_FLOOR_CODEC_MAX_LEN);
        assert_eq!(decode_external_floor_request(&encoded).unwrap(), *request);
        assert_eq!(encode_external_floor_request(request).unwrap(), encoded);
    }
    assert_eq!(
        encode_external_floor_request(&requests[0]).unwrap().len(),
        111
    );
    assert_eq!(
        bloch_l2_bridge::hex::encode(&encode_external_floor_request(&requests[0]).unwrap()),
        "4258464c0100\
         a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5\
         5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a\
         0000000000000000\
         00\
         d4bb9ca4f78d872abb36f44069e24292f497cc0e94b5f74771fa2bf37feac6f4"
    );
    assert_eq!(encode_external_floor_request(cas).unwrap().len(), 193);
}

#[test]
fn all_response_variants_have_one_exact_round_trip() {
    let requests = captured_requests();
    let responses = [
        (
            requests[0],
            ExternalFloorResponse {
                request_binding: requests[0].binding,
                outcome: ExternalFloorOutcome::Current(fresh()),
            },
        ),
        (
            requests[2],
            ExternalFloorResponse {
                request_binding: requests[2].binding,
                outcome: ExternalFloorOutcome::Advanced {
                    previous: fresh(),
                    current: bound(1, 0x11),
                },
            },
        ),
        (
            requests[2],
            ExternalFloorResponse {
                request_binding: requests[2].binding,
                outcome: ExternalFloorOutcome::Conflict {
                    current: bound(2, 0x33),
                },
            },
        ),
    ];

    for (request, response) in responses {
        let encoded = encode_external_floor_response(&response, &request).unwrap();
        assert_eq!(encoded[5], 1);
        assert_eq!(
            decode_external_floor_response(&encoded, &request).unwrap(),
            response
        );
        assert_eq!(
            encode_external_floor_response(&response, &request).unwrap(),
            encoded
        );
    }
}

#[test]
fn mutation_of_any_bound_request_field_is_rejected() {
    let request = captured_requests()[0];
    let canonical = encode_external_floor_request(&request).unwrap();
    for offset in [6usize, 38, 70, 77] {
        let mut mutated = canonical.clone();
        mutated[offset] ^= 1;
        assert_eq!(
            decode_external_floor_request(&mutated).unwrap_err(),
            ExternalFloorCodecError::BindingMismatch,
            "offset {offset} escaped the full request binding"
        );
    }

    let mut binding = canonical;
    *binding.last_mut().unwrap() ^= 1;
    assert_eq!(
        decode_external_floor_request(&binding).unwrap_err(),
        ExternalFloorCodecError::BindingMismatch
    );
}

#[test]
fn response_requires_the_callers_exact_request_binding() {
    let request = captured_requests()[0];
    let request_binding = request.binding;
    let response = ExternalFloorResponse {
        request_binding,
        outcome: ExternalFloorOutcome::Current(fresh()),
    };
    let encoded = encode_external_floor_response(&response, &request).unwrap();
    let wrong_request = captured_requests()[1];
    assert_eq!(
        decode_external_floor_response(&encoded, &wrong_request).unwrap_err(),
        ExternalFloorCodecError::BindingMismatch
    );

    let mut altered = encoded;
    altered[6] ^= 1;
    assert_eq!(
        decode_external_floor_response(&altered, &request).unwrap_err(),
        ExternalFloorCodecError::BindingMismatch
    );
}

#[test]
fn response_outcome_is_covered_by_its_record_binding() {
    let request = captured_requests()[0];
    let request_binding = request.binding;
    let response = ExternalFloorResponse {
        request_binding,
        outcome: ExternalFloorOutcome::Current(bound(7, 0x77)),
    };
    let mut encoded = encode_external_floor_response(&response, &request).unwrap();
    // Mutate one generation byte while retaining a structurally valid state.
    encoded[46] ^= 1;
    assert_eq!(
        decode_external_floor_response(&encoded, &request).unwrap_err(),
        ExternalFloorCodecError::BindingMismatch
    );
}

#[test]
fn version_magic_kind_and_unknown_tags_fail_closed() {
    let request = captured_requests()[0];
    let canonical = encode_external_floor_request(&request).unwrap();

    let mut bad = canonical.clone();
    bad[0] ^= 1;
    assert_eq!(
        decode_external_floor_request(&bad).unwrap_err(),
        ExternalFloorCodecError::BadMagic
    );
    let mut bad = canonical.clone();
    bad[4] = 2;
    assert_eq!(
        decode_external_floor_request(&bad).unwrap_err(),
        ExternalFloorCodecError::UnsupportedVersion(2)
    );
    let mut bad = canonical.clone();
    bad[5] = 1;
    assert_eq!(
        decode_external_floor_request(&bad).unwrap_err(),
        ExternalFloorCodecError::WrongMessageKind {
            expected: 0,
            found: 1,
        }
    );
    let mut bad = canonical;
    bad[78] = 9;
    assert_eq!(
        decode_external_floor_request(&bad).unwrap_err(),
        ExternalFloorCodecError::UnsupportedTag {
            field: "operation",
            value: 9,
        }
    );
}

#[test]
fn truncation_trailing_duplicates_and_oversize_are_rejected() {
    let request = captured_requests()[0];
    let canonical = encode_external_floor_request(&request).unwrap();

    for length in [0usize, 5, 6, 78, canonical.len() - 1] {
        assert!(matches!(
            decode_external_floor_request(&canonical[..length]),
            Err(ExternalFloorCodecError::TooShort { .. })
        ));
    }

    let mut trailing = canonical.clone();
    trailing.push(0);
    assert_eq!(
        decode_external_floor_request(&trailing).unwrap_err(),
        ExternalFloorCodecError::NonCanonical("trailing or duplicate fields")
    );

    let mut duplicate = canonical.clone();
    duplicate.extend_from_slice(&canonical);
    assert_eq!(
        decode_external_floor_request(&duplicate).unwrap_err(),
        ExternalFloorCodecError::TooLong {
            len: 222,
            maximum: EXTERNAL_FLOOR_CODEC_MAX_LEN,
        }
    );
}

#[test]
fn absent_commitment_must_have_a_zero_reserved_slot() {
    let request = captured_requests()[0];
    let response = ExternalFloorResponse {
        request_binding: request.binding,
        outcome: ExternalFloorOutcome::Current(fresh()),
    };
    let mut encoded = encode_external_floor_response(&response, &request).unwrap();
    // header + request binding + outcome + generation + presence
    encoded[48] = 1;
    refresh_response_binding(&mut encoded);
    assert_eq!(
        decode_external_floor_response(&encoded, &request).unwrap_err(),
        ExternalFloorCodecError::NonCanonical("absent commitment has nonzero reserved bytes")
    );
}

fn refresh_response_binding(encoded: &mut [u8]) {
    let payload_end = encoded.len() - 32;
    let mut hash = Keccak::v256();
    hash.update(RESPONSE_BINDING_DOMAIN);
    hash.update(&encoded[..payload_end]);
    let mut binding = [0; 32];
    hash.finalize(&mut binding);
    encoded[payload_end..].copy_from_slice(&binding);
}

#[test]
fn hand_built_invalid_typed_values_cannot_be_encoded() {
    let request = captured_requests()[0];
    let mut zero_domain = request;
    zero_domain.deployment_domain = [0; 32];
    assert!(matches!(
        encode_external_floor_request(&zero_domain),
        Err(ExternalFloorCodecError::InvalidState(_))
    ));

    let unbound_nonzero = SourceFloorState {
        generation: 1,
        snapshot_commitment: None,
    };
    let response = ExternalFloorResponse {
        request_binding: request.binding,
        outcome: ExternalFloorOutcome::Current(unbound_nonzero),
    };
    assert_eq!(
        encode_external_floor_response(&response, &request).unwrap_err(),
        ExternalFloorCodecError::InvalidState("nonzero generation is not snapshot-bound")
    );
}

#[test]
fn typed_but_impossible_transitions_and_outcomes_are_rejected() {
    let requests = captured_requests();
    let mut backwards = requests[2];
    backwards.operation = ExternalFloorOperation::CompareAndSwap {
        expected: bound(2, 0x20),
        requested: bound(1, 0x21),
    };
    assert_eq!(
        encode_external_floor_request(&backwards).unwrap_err(),
        ExternalFloorCodecError::InvalidState("CAS transition moves backwards")
    );

    let wrong_shape = ExternalFloorResponse {
        request_binding: requests[2].binding,
        outcome: ExternalFloorOutcome::Current(bound(1, 0x11)),
    };
    assert_eq!(
        encode_external_floor_response(&wrong_shape, &requests[2]).unwrap_err(),
        ExternalFloorCodecError::InvalidState("response outcome does not match its bound request")
    );

    let impossible_conflict = ExternalFloorResponse {
        request_binding: requests[2].binding,
        outcome: ExternalFloorOutcome::Conflict { current: fresh() },
    };
    assert_eq!(
        encode_external_floor_response(&impossible_conflict, &requests[2]).unwrap_err(),
        ExternalFloorCodecError::InvalidState("response outcome does not match its bound request")
    );
}

#[test]
fn arbitrary_short_and_bounded_inputs_never_panic() {
    let request = captured_requests()[0];
    for length in 0..=EXTERNAL_FLOOR_CODEC_MAX_LEN {
        let bytes = vec![0xa5; length];
        let _ = decode_external_floor_request(&bytes);
        let _ = decode_external_floor_response(&bytes, &request);
    }
}
