// SPDX-License-Identifier: MIT OR Apache-2.0
//! Authority-pinned Unix construction path for the durable BXRC client.
//!
//! The authority receipt is selected by a checkpoint retained outside its
//! filesystem rollback domain. It establishes an approved operational-anchor
//! floor and stays pinned for the runtime lifetime. This composition does not
//! turn either local directory into independent anti-rollback storage.

use std::io::{self, Error, ErrorKind};
use std::path::PathBuf;

use zeroize::{Zeroize, Zeroizing};

use crate::{
    DurableAuthenticatedExternalFloorCustodian, ExternalFloorCustodianAnchorCasOutcome,
    ExternalFloorCustodianAnchorStore, ExternalFloorCustodianAuthentication,
    ExternalFloorCustodianAuthorityCheckpoint, ExternalFloorCustodianClientAnchor,
    ExternalFloorCustodianTransport, UnixExternalFloorCustodianAnchorStore,
    UnixExternalFloorCustodianAuthorityStore,
};

fn invalid(message: &'static str) -> Error {
    Error::new(ErrorKind::InvalidInput, message)
}

/// Operational anchor store guarded by one exact accepted-authority receipt.
///
/// The authority receipt pins an approved anchor floor. Normal durable-client
/// operations advance the independently retained operational head without
/// rewriting offline authority history. A head above the floor is trusted to
/// the operational store; this adapter cannot prove its ancestry. The receipt
/// remains locked and is rechecked around each operation so a live replacement
/// fails closed.
pub struct AuthorityPinnedUnixExternalFloorCustodianAnchorStore {
    authority: UnixExternalFloorCustodianAuthorityStore,
    anchor: UnixExternalFloorCustodianAnchorStore,
    accepted: ExternalFloorCustodianAuthorityCheckpoint,
}

impl AuthorityPinnedUnixExternalFloorCustodianAnchorStore {
    pub fn open(
        authority_directory: &std::path::Path,
        expected_authority: ExternalFloorCustodianAuthorityCheckpoint,
        anchor_directory: &std::path::Path,
    ) -> io::Result<Self> {
        if authority_directory == anchor_directory {
            return Err(invalid(
                "BXRC authority and operational anchor directories must differ",
            ));
        }
        let authority = UnixExternalFloorCustodianAuthorityStore::open_expected(
            authority_directory,
            expected_authority,
        )?;
        let anchor = UnixExternalFloorCustodianAnchorStore::open(anchor_directory)?;
        let operational = anchor.load()?;
        let floor = expected_authority.authority.anchor;
        if operational.revision < floor.revision
            || (operational.revision == floor.revision && operational != floor)
        {
            return Err(Error::new(
                ErrorKind::PermissionDenied,
                "BXRC operational anchor is below or conflicts with accepted authority floor",
            ));
        }
        Ok(Self {
            authority,
            anchor,
            accepted: expected_authority,
        })
    }

    pub fn accepted_authority(&self) -> ExternalFloorCustodianAuthorityCheckpoint {
        self.accepted
    }

    fn verify_authority(&self) -> io::Result<()> {
        if self.authority.checkpoint()? != self.accepted {
            return Err(Error::new(
                ErrorKind::PermissionDenied,
                "BXRC accepted authority changed during runtime",
            ));
        }
        Ok(())
    }
}

impl ExternalFloorCustodianAnchorStore for AuthorityPinnedUnixExternalFloorCustodianAnchorStore {
    fn load(&self) -> io::Result<ExternalFloorCustodianClientAnchor> {
        self.verify_authority()?;
        let anchor = self.anchor.load()?;
        self.verify_authority()?;
        Ok(anchor)
    }

    fn compare_and_swap(
        &self,
        expected: ExternalFloorCustodianClientAnchor,
        replacement: ExternalFloorCustodianClientAnchor,
    ) -> io::Result<ExternalFloorCustodianAnchorCasOutcome> {
        self.verify_authority()?;
        let outcome = self.anchor.compare_and_swap(expected, replacement)?;
        // A failure here is deliberately ambiguous to the caller: the anchor
        // CAS may have committed, so the durable client must stay poisoned.
        self.verify_authority()?;
        Ok(outcome)
    }
}

/// Durable BXRC client produced by the authority-pinned Unix factory.
pub type UnixAuthorityPinnedExternalFloorCustodian<T> = DurableAuthenticatedExternalFloorCustodian<
    T,
    AuthorityPinnedUnixExternalFloorCustodianAnchorStore,
>;

/// Explicit, no-default runtime inputs for an authority-pinned BXRC client.
pub struct UnixExternalFloorCustodianRuntimeConfig {
    checkpoint_directory: PathBuf,
    anchor_directory: PathBuf,
    authority_directory: PathBuf,
    expected_authority: ExternalFloorCustodianAuthorityCheckpoint,
    authentication: Option<ExternalFloorCustodianAuthentication>,
    checkpoint_authentication_key: Zeroizing<[u8; 32]>,
}

impl core::fmt::Debug for UnixExternalFloorCustodianRuntimeConfig {
    fn fmt(&self, output: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        output
            .debug_struct("UnixExternalFloorCustodianRuntimeConfig")
            .field("checkpoint_directory", &self.checkpoint_directory)
            .field("anchor_directory", &self.anchor_directory)
            .field("authority_directory", &self.authority_directory)
            .field("expected_authority", &self.expected_authority)
            .field("authentication", &"[REDACTED]")
            .field("checkpoint_authentication_key", &"[REDACTED]")
            .finish()
    }
}

impl UnixExternalFloorCustodianRuntimeConfig {
    pub fn new(
        checkpoint_directory: PathBuf,
        anchor_directory: PathBuf,
        authority_directory: PathBuf,
        expected_authority: ExternalFloorCustodianAuthorityCheckpoint,
        authentication: ExternalFloorCustodianAuthentication,
        mut checkpoint_authentication_key: [u8; 32],
    ) -> io::Result<Self> {
        if !checkpoint_directory.is_absolute()
            || !anchor_directory.is_absolute()
            || !authority_directory.is_absolute()
        {
            checkpoint_authentication_key.zeroize();
            return Err(invalid("BXRC runtime directories must be absolute"));
        }
        if checkpoint_directory == anchor_directory
            || checkpoint_directory == authority_directory
            || anchor_directory == authority_directory
        {
            checkpoint_authentication_key.zeroize();
            return Err(invalid("BXRC runtime directories must be distinct"));
        }
        if checkpoint_authentication_key == [0; 32] {
            checkpoint_authentication_key.zeroize();
            return Err(invalid(
                "BXRC checkpoint authentication key must not be all zero",
            ));
        }
        Ok(Self {
            checkpoint_directory,
            anchor_directory,
            authority_directory,
            expected_authority,
            authentication: Some(authentication),
            checkpoint_authentication_key: Zeroizing::new(checkpoint_authentication_key),
        })
    }

    /// Opens all three local stores and performs the authority/anchor binding
    /// before constructing a client capable of transport I/O.
    pub fn open<T: ExternalFloorCustodianTransport>(
        mut self,
        transport: T,
    ) -> io::Result<UnixAuthorityPinnedExternalFloorCustodian<T>> {
        let anchor_store = AuthorityPinnedUnixExternalFloorCustodianAnchorStore::open(
            &self.authority_directory,
            self.expected_authority,
            &self.anchor_directory,
        )?;
        let authentication = self
            .authentication
            .take()
            .ok_or_else(|| invalid("BXRC runtime authentication was already consumed"))?;
        DurableAuthenticatedExternalFloorCustodian::open(
            &self.checkpoint_directory,
            anchor_store,
            transport,
            authentication,
            core::mem::take(&mut *self.checkpoint_authentication_key),
        )
    }
}
