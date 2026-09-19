// SPDX-License-Identifier: MIT OR Apache-2.0
//! # bloch-l2-bridge — SCAFFOLD, UNAUDITED, not a working L2.
//!
//! **The v1 L1 vault is CUSTODY, full stop — nothing here moves value.**
//!
//! Bridge *types* for the design-only Bloch EVM L2
//! (`docs/specs/BLOCH-L2-EVM-DESIGN.md` §5): the `L2D0` deposit envelope
//! codec, the `ATOM_SCALE` sats↔wei conversion, the withdrawal-message
//! leaf encoding, the keccak256 depth-32 incremental Merkle tree with
//! inclusion-proof verification, the `K(amount)` confirmation-depth
//! schedule, the pure deposit-watcher replay core (`watcher`, no
//! networking), the withdrawal queue / proof bundle / typed §5 release
//! checklist (`release`, no keys, no quorum crypto), the
//! proof-of-reserves predicate (`reserves`, DETECTS-not-PREVENTS), and a
//! WBLCH / Uniswap-v2 deploy **harness config** (no deploys, no chain
//! interaction; the only compiler it ever invokes is a pinned solc 0.8.24,
//! when present, to compile-and-hash the contract sources it pins).
//!
//! Honesty invariants, mirrored from the spec and non-negotiable:
//! * Bloch today is k=4, low-hashrate, 51%-attackable, unaudited. No finite
//!   confirmation depth is finality, and no `K` may be represented as such.
//! * The validity proof (elsewhere, unbuilt) proves state transitions about
//!   a *named* L1 view — never L1 canonicality.
//! * The L2 is an owned Postern product; only the anchoring rail is
//!   ownerless.
//! * Everything here is testnet / zero-value until the
//!   POSTERNDEX-BRIDGE-DESIGN §0 gates clear.

pub mod atoms;
pub mod envelope;
#[cfg(unix)]
pub mod external_floor;
#[cfg(unix)]
pub mod external_floor_auth;
#[cfg(unix)]
pub mod external_floor_codec;
#[cfg(unix)]
pub mod external_floor_custodian;
#[cfg(unix)]
pub mod external_floor_custodian_anchor_file;
#[cfg(unix)]
pub mod external_floor_custodian_authority_file;
#[cfg(unix)]
pub mod external_floor_custodian_file;
#[cfg(unix)]
pub mod external_floor_custodian_mtls;
#[cfg(unix)]
pub mod external_floor_custodian_tcp;
#[cfg(unix)]
pub mod external_floor_file;
pub mod harness;
pub mod hex;
pub mod merkle;
pub mod release;
pub mod reserves;
#[cfg(unix)]
pub mod source_store;
pub mod status;
pub mod stubs;
#[cfg(unix)]
pub mod unix_floor;
pub mod watcher;
pub mod withdrawal;

pub use atoms::{atoms_to_wei, wei_to_atoms, AtomConversionError, ATOM_SCALE};
pub use envelope::{extract_deposit_envelope, DecodeError, DepositEnvelope, TxOutput};
#[cfg(unix)]
pub use external_floor::{
    ExternalFloorBoundary, ExternalFloorOperation, ExternalFloorOutcome,
    ExternalFloorReconciliation, ExternalFloorRequest, ExternalFloorResponse,
    ExternalGenerationFloor,
};
#[cfg(unix)]
pub use external_floor_auth::{
    decode_authenticated_external_floor_request, decode_authenticated_external_floor_response,
    encode_authenticated_external_floor_request, encode_authenticated_external_floor_response,
    AuthenticatedExternalFloorBoundary, CustodiedDurableAuthenticatedExternalFloorServer,
    DurableAuthenticatedExternalFloorServer, DurableExternalFloorReplayGuard,
    ExternalFloorAuthError, ExternalFloorByteTransport, ExternalFloorDurableReplayError,
    ExternalFloorPeerAuthentication, ExternalFloorReplayCasOutcome, ExternalFloorReplayCheckpoint,
    ExternalFloorReplayGuard, ExternalFloorReplayStore, EXTERNAL_FLOOR_AUTH_MAGIC,
    EXTERNAL_FLOOR_AUTH_MAX_LEN, EXTERNAL_FLOOR_AUTH_VERSION,
};
#[cfg(unix)]
pub use external_floor_codec::{
    decode_external_floor_request, decode_external_floor_response, encode_external_floor_request,
    encode_external_floor_response, ExternalFloorCodecError, EXTERNAL_FLOOR_CODEC_MAGIC,
    EXTERNAL_FLOOR_CODEC_MAX_LEN, EXTERNAL_FLOOR_CODEC_VERSION,
};
#[cfg(unix)]
pub use external_floor_custodian::{
    AuthenticatedExternalFloorCustodian, AuthenticatedExternalFloorCustodianServer,
    ExternalFloorCustodianAuthentication, ExternalFloorCustodianProtocolError,
    ExternalFloorCustodianTransport, ExternalFloorCustodianTransportCheckpoint,
    EXTERNAL_FLOOR_CUSTODIAN_MAGIC, EXTERNAL_FLOOR_CUSTODIAN_MAX_LEN,
    EXTERNAL_FLOOR_CUSTODIAN_MIN_LEN, EXTERNAL_FLOOR_CUSTODIAN_VERSION,
};
#[cfg(unix)]
pub use external_floor_custodian_anchor_file::{
    external_floor_custodian_anchor_approval_message,
    external_floor_custodian_anchor_continuity_acceptance_message,
    external_floor_custodian_anchor_continuity_authorization_message,
    verify_external_floor_custodian_anchor_approval,
    verify_external_floor_custodian_anchor_continuity, ExternalFloorCustodianAnchorApproval,
    ExternalFloorCustodianAnchorContinuityApproval, UnixExternalFloorCustodianAnchorStore,
    EXTERNAL_FLOOR_CUSTODIAN_ANCHOR_APPROVAL_MESSAGE_LEN,
    EXTERNAL_FLOOR_CUSTODIAN_ANCHOR_CONTINUITY_MESSAGE_LEN,
    EXTERNAL_FLOOR_CUSTODIAN_ANCHOR_RECORD_LEN,
};
#[cfg(unix)]
pub use external_floor_custodian_authority_file::{
    external_floor_custodian_expected_authority_checkpoint,
    ExternalFloorCustodianAuthorityCheckpoint, ExternalFloorCustodianAuthorityTuple,
    UnixExternalFloorCustodianAuthorityStore, EXTERNAL_FLOOR_CUSTODIAN_AUTHORITY_RECORD_LEN,
};
#[cfg(unix)]
pub use external_floor_custodian_file::{
    DurableAuthenticatedExternalFloorCustodian, ExternalFloorCustodianAnchorCasOutcome,
    ExternalFloorCustodianAnchorStore, ExternalFloorCustodianClientAnchor,
    ExternalFloorCustodianClientInspection, ExternalFloorCustodianPendingInspection,
    EXTERNAL_FLOOR_CUSTODIAN_CLIENT_RECORD_LEN,
};
#[cfg(unix)]
pub use external_floor_custodian_mtls::{
    handle_external_floor_custodian_mtls_connection, ExternalFloorCustodianMtlsClientConfig,
    ExternalFloorCustodianMtlsServerPolicy, MtlsExternalFloorCustodianTransport,
};
#[cfg(unix)]
pub use external_floor_custodian_tcp::{
    handle_external_floor_custodian_tcp_connection, ExternalFloorCustodianTcpClientConfig,
    ExternalFloorCustodianTcpServerPolicy, TcpExternalFloorCustodianTransport,
};
#[cfg(unix)]
pub use external_floor_file::{
    UnixCustodiedExternalFloorServer, UnixExternalFloorReplayStore, UnixExternalFloorServerConfig,
    UnixExternalFloorServerOpenError, EXTERNAL_FLOOR_REPLAY_RECORD_LEN,
};
pub use merkle::{keccak256, verify_inclusion, IncrementalMerkleTree, TREE_DEPTH};
pub use release::{
    evaluate_release_checklist, AnchoredEpochView, CheckOutcome, ChecklistVerdict, NullifierLog,
    ReleaseChecklist, ReleaseObservation, WithdrawalProofBundle, WithdrawalQueue,
};
pub use reserves::{check_reserves, is_exactly_backed, ReserveCheck, ReserveStatement};
#[cfg(unix)]
pub use source_store::{
    persist_versioned_source, restore_versioned_source, SourceFloorState, SourceGenerationFloor,
    SourceStoreError,
};
pub use status::{
    confirmation_depth, ConfirmationRequirement, DepositEvent, WithdrawalEvent, WithdrawalStatus,
};
#[cfg(unix)]
pub use unix_floor::{UnixFloorAuthentication, UnixGenerationFloor};
pub use watcher::{
    BlockSource, BlockSourceView, DepositWatcher, L1Block, L1Tx, SourceCheckpoint,
    SourceGenerationExhausted, SourceViewToken, VaultSet, VersionedMemorySource,
    VersionedMemoryView, VersionedSourceRestoreError, VersionedSourceSeal, WatcherSnapshotError,
    WatcherState, WatcherSyncError, WatcherUpdate,
};
pub use withdrawal::{WithdrawalInclusion, WithdrawalMessage, UNANCHORED_ROOT};
