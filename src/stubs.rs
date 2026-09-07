// SPDX-License-Identifier: MIT OR Apache-2.0
//! Honest stubs — the large integrations this scaffold does NOT contain.
//!
//! Every item here is a `// SCAFFOLD:` marker with just enough type
//! surface to name the missing component. Nothing in this module is
//! callable into useful behavior; every method returns
//! [`NotImplemented`]. This is deliberate: claiming any of these worked
//! would violate the project's honesty rule.

/// The single error every stub returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotImplemented(pub &'static str);

impl core::fmt::Display for NotImplemented {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "SCAFFOLD: {} is not implemented — this is not a working L2",
            self.0
        )
    }
}

impl std::error::Error for NotImplemented {}

// SCAFFOLD: vault keyholder / KEY-SIGNING logic. The pure §5 checklist
// EVALUATION now lives in `crate::release::evaluate_release_checklist`
// (items [2][3][4][5][6] checked for real; [1] FRI and [7] rate limit are
// Scaffold there too) — but everything from "checklist says nothing
// blocks" to an actual co-signed payout tx is THIS stub: holding an
// ML-DSA-65 vault shard key, building/signing the payout tx, and the
// quorum co-sign round. The v1 L1 vault is CUSTODY, full stop — a
// disclosed operator-held key set, NOT cryptographic M-of-N (no
// production threshold ML-DSA exists). Nothing here holds keys or signs
// anything, and no fake cryptographic quorum will be scaffolded.
#[derive(Debug, Default)]
pub struct ReleaseAgent;

impl ReleaseAgent {
    /// SCAFFOLD: would co-sign the payout input AFTER the §5 checklist
    /// (see `crate::release`) — the signing itself is not implemented.
    pub fn evaluate_release(
        &self,
        _withdrawal: &crate::withdrawal::WithdrawalMessage,
        _proof_branch: &[[u8; 32]; crate::merkle::TREE_DEPTH],
    ) -> Result<(), NotImplemented> {
        Err(NotImplemented("ReleaseAgent::evaluate_release"))
    }

    /// SCAFFOLD: would sign this keyholder's vault-shard input of the L1
    /// payout transaction. No key material exists in this crate.
    pub fn co_sign_payout(
        &self,
        _bundle: &crate::release::WithdrawalProofBundle,
    ) -> Result<(), NotImplemented> {
        Err(NotImplemented("ReleaseAgent::co_sign_payout"))
    }
}

// SCAFFOLD: the RPC-BACKED L1 deposit watcher. The pure replay core
// (height->hash journal, rewind-on-mismatch, K(amount) gating, dedupe by
// deposit_id) now exists and is tested in `crate::watcher` — what is
// still missing is everything that touches a node: the JSON-RPC client
// (getblockcount / getblockhash / getblockbyheight, the bloch-tokens
// indexer.rs discipline) that would implement `watcher::BlockSource`
// over a live chain. No RPC client exists in this crate.
#[derive(Debug, Default)]
pub struct L1DepositWatcher;

impl L1DepositWatcher {
    /// SCAFFOLD: would poll the node and feed `crate::watcher::
    /// DepositWatcher::sync` from a live `BlockSource`.
    pub fn poll(&mut self) -> Result<Vec<crate::status::DepositEvent>, NotImplemented> {
        Err(NotImplemented("L1DepositWatcher::poll"))
    }
}

// SCAFFOLD: FederatedGateway / outside assets (wBTC, wUSDT, wETH) are
// EXPLICITLY OUT OF SCOPE for v1 — the bridge does ONLY WBLCH, per
// contracts/wblch/WBLCH.sol's scope note and §5(B). The type exists only
// so the exclusion is visible in the API surface.
#[derive(Debug, Default)]
pub struct FederatedGatewayOutOfScope;

impl FederatedGatewayOutOfScope {
    pub fn mint(&self) -> Result<(), NotImplemented> {
        Err(NotImplemented(
            "FederatedGateway (outside assets) — out of scope: v1 is WBLCH only",
        ))
    }
}

// SCAFFOLD: contract compilation / deployment / any chain interaction.
// The harness module only VALIDATES a JSON description; it never invokes
// solc, never crafts a transaction, never connects anywhere.
#[derive(Debug, Default)]
pub struct Deployer;

impl Deployer {
    pub fn deploy(&self, _config: &crate::harness::DeployConfig) -> Result<(), NotImplemented> {
        Err(NotImplemented(
            "Deployer::deploy — config-only harness, no live deploys",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stubs_refuse_honestly() {
        // Every stub returns NotImplemented instead of pretending.
        assert!(L1DepositWatcher.poll().is_err());
        assert!(FederatedGatewayOutOfScope.mint().is_err());
        let msg = crate::withdrawal::WithdrawalMessage {
            nonce: 0,
            l2_sender: [0; 20],
            l1_recipient: [0; 20],
            amount_atoms: 0,
            epoch_number: 0,
        };
        let branch = [[0u8; 32]; crate::merkle::TREE_DEPTH];
        let err = ReleaseAgent.evaluate_release(&msg, &branch).unwrap_err();
        assert!(err.to_string().contains("SCAFFOLD"));
        assert!(err.to_string().contains("not a working L2"));
    }
}
