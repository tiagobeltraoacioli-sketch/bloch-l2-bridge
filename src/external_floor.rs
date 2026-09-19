// SPDX-License-Identifier: MIT OR Apache-2.0
//! Protocol adapter for an external transactional source-generation floor.
//!
//! This module deliberately implements no network transport, authentication,
//! secret storage, or anti-rollback storage.  It validates the replies of a
//! separately authenticated boundary and turns each update into one
//! compare-and-swap transaction.  The boundary still has to guarantee durable
//! monotonic state and the caller still has to authenticate the channel (or an
//! equivalent attestation).  In particular, wrapping a local file transport in
//! this adapter does not make that file non-rollbackable.

use std::cell::Cell;
use std::io;

use tiny_keccak::{Hasher, Keccak};

use crate::source_store::{SourceFloorState, SourceGenerationFloor};

const REQUEST_DOMAIN: &[u8] = b"BLOCH-L2-EXTERNAL-SOURCE-FLOOR-REQUEST-v1\0";

/// Operation submitted to an independently protected transactional boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalFloorOperation {
    /// Return the current durable state.
    Read,
    /// Atomically replace `expected` with `requested`, or report a conflict.
    CompareAndSwap {
        expected: SourceFloorState,
        requested: SourceFloorState,
    },
}

/// Bound request passed to [`ExternalFloorBoundary`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExternalFloorRequest {
    /// Deployment-specific domain. It must not be reused by another floor.
    pub deployment_domain: [u8; 32],
    /// Unique nonce for this adapter session, supplied by trusted integration.
    pub session_nonce: [u8; 32],
    /// Strictly increasing request sequence within the session.
    pub sequence: u64,
    /// Requested read or transactional mutation.
    pub operation: ExternalFloorOperation,
    /// Domain-separated commitment to all preceding fields.
    pub binding: [u8; 32],
}

impl ExternalFloorRequest {
    fn new(
        deployment_domain: [u8; 32],
        session_nonce: [u8; 32],
        sequence: u64,
        operation: ExternalFloorOperation,
    ) -> Self {
        let mut request = Self {
            deployment_domain,
            session_nonce,
            sequence,
            operation,
            binding: [0; 32],
        };
        request.binding = request_binding(&request);
        request
    }
}

/// Result returned by an external floor transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalFloorOutcome {
    /// Result of a read operation.
    Current(SourceFloorState),
    /// Successful CAS, including both sides of the committed transition.
    Advanced {
        previous: SourceFloorState,
        current: SourceFloorState,
    },
    /// CAS did not run because its expected state was stale.
    Conflict { current: SourceFloorState },
}

/// Response whose binding must echo the exact request it answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExternalFloorResponse {
    pub request_binding: [u8; 32],
    pub outcome: ExternalFloorOutcome,
}

/// Result of explicitly reconciling one ambiguous CAS with a fresh read.
///
/// Reconciliation never resubmits the CAS.  `NotCommitted` means the
/// independently protected boundary still contains the exact pre-CAS state;
/// `Conflict` means another durable transition won the race.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalFloorReconciliation {
    Committed {
        previous: SourceFloorState,
        current: SourceFloorState,
    },
    NotCommitted {
        current: SourceFloorState,
    },
    Conflict {
        current: SourceFloorState,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AmbiguousCas {
    expected: SourceFloorState,
    requested: SourceFloorState,
}

/// Synchronous transport to an authenticated transactional boundary.
///
/// An error returned for a CAS is necessarily ambiguous: the boundary might
/// have committed before the response was lost. [`ExternalGenerationFloor`]
/// therefore poisons that instance and refuses every later operation.
pub trait ExternalFloorBoundary {
    fn transact(&self, request: ExternalFloorRequest) -> io::Result<ExternalFloorResponse>;
}

/// Fail-closed adapter from a transactional boundary to [`SourceGenerationFloor`].
///
/// `session_nonce` must be freshly and unpredictably generated outside this
/// crate for each adapter instance.  Its purpose is replay separation, not
/// authentication. The boundary and channel remain responsible for authentic
/// responses and truly non-rollbackable durable state.
pub struct ExternalGenerationFloor<B> {
    boundary: B,
    deployment_domain: [u8; 32],
    session_nonce: Cell<[u8; 32]>,
    next_sequence: Cell<u64>,
    uncertain: Cell<bool>,
    ambiguous_cas: Cell<Option<AmbiguousCas>>,
}

impl<B: ExternalFloorBoundary> ExternalGenerationFloor<B> {
    pub fn new(
        boundary: B,
        deployment_domain: [u8; 32],
        session_nonce: [u8; 32],
    ) -> io::Result<Self> {
        if deployment_domain == [0; 32] {
            return Err(invalid_input(
                "external floor deployment domain is all zero",
            ));
        }
        if session_nonce == [0; 32] {
            return Err(invalid_input("external floor session nonce is all zero"));
        }
        Ok(Self {
            boundary,
            deployment_domain,
            session_nonce: Cell::new(session_nonce),
            next_sequence: Cell::new(0),
            uncertain: Cell::new(false),
            ambiguous_cas: Cell::new(None),
        })
    }

    /// Whether a CAS may have committed without a valid acknowledgement.
    pub fn is_uncertain(&self) -> bool {
        self.uncertain.get()
    }

    /// Consume the adapter so reconciliation can retain the configured boundary.
    ///
    /// Constructing a new adapter requires a fresh session nonce and does not
    /// itself reconcile the external durable state.
    pub fn into_boundary(self) -> B {
        self.boundary
    }

    /// Resolve one ambiguous CAS by reading under a new adapter session.
    ///
    /// The nonce must be freshly and unpredictably generated by the trusted
    /// integration and must differ from the previous session.  This method
    /// issues exactly one `Read`; it never retries the ambiguous mutation.
    /// Any transport, binding, shape, or monotonicity failure leaves the
    /// adapter uncertain and requires another call with another fresh nonce.
    pub fn reconcile(
        &self,
        new_session_nonce: [u8; 32],
    ) -> io::Result<ExternalFloorReconciliation> {
        if !self.uncertain.get() {
            return Err(invalid_input(
                "external floor is not awaiting reconciliation",
            ));
        }
        let ambiguous = self
            .ambiguous_cas
            .get()
            .ok_or_else(|| io::Error::other("external floor has no reconcilable ambiguous CAS"))?;
        if new_session_nonce == [0; 32] || new_session_nonce == self.session_nonce.get() {
            return Err(invalid_input(
                "external floor reconciliation requires a fresh nonzero session nonce",
            ));
        }

        // Rotate before transport.  Even a lost read response consumes this
        // session so a later reconciliation cannot repeat its binding.
        self.session_nonce.set(new_session_nonce);
        self.next_sequence.set(1);
        let request = ExternalFloorRequest::new(
            self.deployment_domain,
            new_session_nonce,
            0,
            ExternalFloorOperation::Read,
        );
        let response = self.boundary.transact(request).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("external floor reconciliation remains uncertain: {error}"),
            )
        })?;
        if response.request_binding != request.binding {
            return Err(invalid_data(
                "external floor reconciliation response is replayed or misbound; outcome remains uncertain",
            ));
        }
        let ExternalFloorOutcome::Current(current) = response.outcome else {
            return Err(invalid_data(
                "external floor returned an invalid reconciliation outcome; outcome remains uncertain",
            ));
        };
        validate_state(current)?;

        let result = if current == ambiguous.requested {
            ExternalFloorReconciliation::Committed {
                previous: ambiguous.expected,
                current,
            }
        } else if current == ambiguous.expected {
            ExternalFloorReconciliation::NotCommitted { current }
        } else if valid_conflict(ambiguous.expected, current) {
            ExternalFloorReconciliation::Conflict { current }
        } else {
            return Err(invalid_data(
                "external floor reconciliation observed an impossible state; outcome remains uncertain",
            ));
        };

        self.ambiguous_cas.set(None);
        self.uncertain.set(false);
        Ok(result)
    }

    fn request(&self, operation: ExternalFloorOperation) -> io::Result<ExternalFloorRequest> {
        if self.uncertain.get() {
            return Err(io::Error::other(
                "external floor outcome is uncertain; explicit reconciliation required",
            ));
        }
        let sequence = self.next_sequence.get();
        let next = sequence.checked_add(1).ok_or_else(|| {
            self.uncertain.set(true);
            io::Error::other("external floor request sequence exhausted")
        })?;
        self.next_sequence.set(next);
        Ok(ExternalFloorRequest::new(
            self.deployment_domain,
            self.session_nonce.get(),
            sequence,
            operation,
        ))
    }

    fn read_current(&self) -> io::Result<SourceFloorState> {
        let request = self.request(ExternalFloorOperation::Read)?;
        let response = self.boundary.transact(request)?;
        if response.request_binding != request.binding {
            return Err(invalid_data(
                "external floor response is replayed or misbound",
            ));
        }
        match response.outcome {
            ExternalFloorOutcome::Current(state) => {
                validate_state(state)?;
                Ok(state)
            }
            _ => Err(invalid_data(
                "external floor returned an invalid read outcome",
            )),
        }
    }

    fn compare_and_swap(
        &self,
        expected: SourceFloorState,
        requested: SourceFloorState,
    ) -> io::Result<()> {
        let request = self.request(ExternalFloorOperation::CompareAndSwap {
            expected,
            requested,
        })?;
        let response = match self.boundary.transact(request) {
            Ok(response) => response,
            Err(error) => {
                self.ambiguous_cas.set(Some(AmbiguousCas {
                    expected,
                    requested,
                }));
                self.uncertain.set(true);
                return Err(io::Error::new(
                    error.kind(),
                    format!("external floor CAS outcome is uncertain: {error}"),
                ));
            }
        };
        if response.request_binding != request.binding {
            self.ambiguous_cas.set(Some(AmbiguousCas {
                expected,
                requested,
            }));
            self.uncertain.set(true);
            return Err(invalid_data(
                "external floor CAS response is replayed or misbound; outcome is uncertain",
            ));
        }
        match response.outcome {
            ExternalFloorOutcome::Advanced { previous, current }
                if previous == expected && current == requested =>
            {
                Ok(())
            }
            ExternalFloorOutcome::Conflict { current } => {
                if !valid_conflict(expected, current) {
                    self.ambiguous_cas.set(Some(AmbiguousCas {
                        expected,
                        requested,
                    }));
                    self.uncertain.set(true);
                    Err(invalid_data(
                        "external floor returned an impossible CAS conflict; outcome is uncertain",
                    ))
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        "external floor compare-and-swap conflict",
                    ))
                }
            }
            _ => {
                self.ambiguous_cas.set(Some(AmbiguousCas {
                    expected,
                    requested,
                }));
                self.uncertain.set(true);
                Err(invalid_data(
                    "external floor returned an invalid CAS outcome; outcome is uncertain",
                ))
            }
        }
    }
}

impl<B: ExternalFloorBoundary> SourceGenerationFloor for ExternalGenerationFloor<B> {
    fn current(&self) -> io::Result<SourceFloorState> {
        self.read_current()
    }

    fn advance(&self, requested: SourceFloorState) -> io::Result<()> {
        validate_bound_state(requested)?;
        let current = self.read_current()?;
        if requested.generation < current.generation {
            return Err(invalid_input("external floor cannot move backwards"));
        }
        if requested.generation == current.generation {
            if current == requested {
                return Ok(());
            }
            if current.snapshot_commitment.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "external floor generation is bound to another snapshot",
                ));
            }
        }
        self.compare_and_swap(current, requested)
    }
}

fn validate_state(state: SourceFloorState) -> io::Result<()> {
    if state.generation != 0 && state.snapshot_commitment.is_none() {
        return Err(invalid_data(
            "external floor returned an unbound nonzero generation",
        ));
    }
    Ok(())
}

fn validate_bound_state(state: SourceFloorState) -> io::Result<()> {
    if state.snapshot_commitment.is_none() {
        return Err(invalid_input(
            "external floor advance requires a snapshot commitment",
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

fn update_state(hash: &mut Keccak, state: SourceFloorState) {
    hash.update(&state.generation.to_be_bytes());
    match state.snapshot_commitment {
        Some(commitment) => {
            hash.update(&[1]);
            hash.update(&commitment);
        }
        None => hash.update(&[0]),
    }
}

fn request_binding(request: &ExternalFloorRequest) -> [u8; 32] {
    let mut hash = Keccak::v256();
    hash.update(REQUEST_DOMAIN);
    hash.update(&request.deployment_domain);
    hash.update(&request.session_nonce);
    hash.update(&request.sequence.to_be_bytes());
    match request.operation {
        ExternalFloorOperation::Read => hash.update(&[0]),
        ExternalFloorOperation::CompareAndSwap {
            expected,
            requested,
        } => {
            hash.update(&[1]);
            update_state(&mut hash, expected);
            update_state(&mut hash, requested);
        }
    }
    let mut binding = [0; 32];
    hash.finalize(&mut binding);
    binding
}

fn invalid_input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
