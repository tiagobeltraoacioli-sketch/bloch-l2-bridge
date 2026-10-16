// SPDX-License-Identifier: MIT OR Apache-2.0
//! Prove reviewed contract code and the USDC proxy implementation slot under
//! the exact deployment state root. This is not complete vault-state proof.

use crate::{
    ethereum_deployment_inclusion as inclusion, ethereum_header_ancestry as ancestry,
    merkle::keccak256,
};
use alloy_rlp::Encodable;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub const REQUEST_DOMAIN: &[u8] = b"BLOCH-ETHEREUM-DEPLOYMENT-STATE-v1\0";
pub const MAX_REQUEST_BYTES: usize = 1024 * 1024;
pub const MAX_STATE_PROOF_NODES: usize = 65;
pub const USDC_PROXY: &str = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48";
pub const IMPLEMENTATION_SLOT: &str =
    "0x7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3";

type Check<T> = Result<T, &'static str>;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct StorageProof {
    pub key: String,
    pub value: String,
    pub proof: Vec<String>,
}

/// Exact EIP-1186 account response, with a restricted storage-proof coverage.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AccountProof {
    pub address: String,
    pub nonce: String,
    pub balance: String,
    pub code_hash: String,
    pub storage_hash: String,
    pub account_proof: Vec<String>,
    pub storage_proof: Vec<StorageProof>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Contract {
    pub role: String,
    pub address: String,
    pub code: String,
    pub runtime_sha256: String,
    pub proof: AccountProof,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Evidence {
    pub schema: String,
    pub inclusion: inclusion::Evidence,
    pub contracts: Vec<Contract>,
}

#[derive(Debug)]
pub struct VerifiedCodeState {
    pub inclusion: inclusion::VerifiedInclusion,
    pub state_root: [u8; 32],
    pub implementation: [u8; 20],
}

fn require(ok: bool, message: &'static str) -> Check<()> {
    if ok {
        Ok(())
    } else {
        Err(message)
    }
}

fn address(value: &str) -> Check<[u8; 20]> {
    let bytes: [u8; 20] = ancestry::hex_bytes(value, 20)?
        .try_into()
        .map_err(|_| "account address width")?;
    require(bytes.iter().any(|b| *b != 0), "zero account address")?;
    Ok(bytes)
}

/// Canonical JSON-RPC QUANTITY to the minimal big-endian RLP integer payload.
fn quantity(value: &str, maximum: usize) -> Check<Vec<u8>> {
    let digits = value.strip_prefix("0x").ok_or("quantity prefix")?;
    require(
        !digits.is_empty()
            && digits.len() <= 2 * maximum
            && digits
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && (digits == "0" || !digits.starts_with('0')),
        "canonical bounded quantity required",
    )?;
    if digits == "0" {
        return Ok(Vec::new());
    }
    let even = if digits.len() % 2 == 0 {
        value.to_owned()
    } else {
        format!("0x0{digits}")
    };
    ancestry::hex_bytes(&even, maximum)
}

fn encoded_list(fields: &[&[u8]]) -> Vec<u8> {
    let mut payload = Vec::new();
    for field in fields {
        field.encode(&mut payload);
    }
    let mut encoded = Vec::new();
    alloy_rlp::Header {
        list: true,
        payload_length: payload.len(),
    }
    .encode(&mut encoded);
    encoded.extend_from_slice(&payload);
    encoded
}

fn verify_contract(root: [u8; 32], contract: &Contract) -> Check<()> {
    let selected = address(&contract.address)?;
    require(
        selected == address(&contract.proof.address)?,
        "proof account substitution",
    )?;
    let code = ancestry::hex_bytes(&contract.code, 65536)?;
    let reviewed_hash: [u8; 32] = Sha256::digest(&code).into();
    require(
        reviewed_hash == ancestry::hash(&contract.runtime_sha256)?,
        "reviewed runtime mismatch",
    )?;
    let code_hash = ancestry::hash(&contract.proof.code_hash)?;
    require(
        code_hash == keccak256(&code),
        "code does not match proven account",
    )?;
    let nonce = quantity(&contract.proof.nonce, 8)?;
    let balance = quantity(&contract.proof.balance, 32)?;
    let storage_root = ancestry::hash(&contract.proof.storage_hash)?;
    let account = encoded_list(&[&nonce, &balance, &storage_root, &code_hash]);
    inclusion::prove_key(
        root,
        &keccak256(&selected),
        account,
        &contract.proof.account_proof,
        MAX_STATE_PROOF_NODES,
    )
}

pub fn verify(evidence: &Evidence) -> Check<VerifiedCodeState> {
    require(
        evidence.schema == "postern.custody-deployment-state-request.v1",
        "state proof schema",
    )?;
    require(
        evidence.contracts.len() == 3,
        "exactly three contract proofs required",
    )?;
    let accepted = inclusion::verify(&evidence.inclusion)?;
    let header = ancestry::decode_header(&ancestry::hex_bytes(
        &evidence.inclusion.ancestry.headers[0],
        ancestry::MAX_HEADER_BYTES,
    )?)?;
    require(
        header.hash == accepted.block_hash,
        "deployment state header mismatch",
    )?;
    let addresses: Vec<[u8; 20]> = evidence
        .contracts
        .iter()
        .map(|c| address(&c.address))
        .collect::<Check<_>>()?;
    require(
        addresses.iter().copied().collect::<BTreeSet<_>>().len() == 3
            && addresses[0] == accepted.contract_address
            && addresses[1] == address(USDC_PROXY)?,
        "distinct vault, USDC proxy and implementation required",
    )?;
    for (index, role) in ["vault", "usdcProxy", "usdcImplementation"]
        .iter()
        .enumerate()
    {
        let contract = &evidence.contracts[index];
        require(contract.role == *role, "contract proof role/order mismatch")?;
        require(
            contract.proof.storage_proof.len() == usize::from(index == 1),
            "unexpected storage proof coverage",
        )?;
    }
    let slot = &evidence.contracts[1].proof.storage_proof[0];
    require(
        slot.key == IMPLEMENTATION_SLOT,
        "unexpected proxy storage slot",
    )?;
    let stored = quantity(&slot.value, 32)?;
    require(
        !stored.is_empty() && stored.len() <= 20,
        "nonzero implementation address required",
    )?;
    let mut implementation = [0u8; 20];
    implementation[20 - stored.len()..].copy_from_slice(&stored);
    require(
        implementation == addresses[2],
        "proxy implementation substitution",
    )?;
    let mut storage_value = Vec::new();
    stored.as_slice().encode(&mut storage_value);
    // Presence proofs only. Missing accounts and zero/absent storage are never
    // inferred from a truncated proof or from matching RPC declarations.
    std::panic::catch_unwind(|| {
        for contract in &evidence.contracts {
            verify_contract(header.state_root, contract)?;
        }
        inclusion::prove_key(
            ancestry::hash(&evidence.contracts[1].proof.storage_hash)?,
            &keccak256(&ancestry::hex_bytes(IMPLEMENTATION_SLOT, 32)?),
            storage_value,
            &slot.proof,
            MAX_STATE_PROOF_NODES,
        )
    })
    .map_err(|_| "malformed state trie proof")??;
    Ok(VerifiedCodeState {
        inclusion: accepted,
        state_root: header.state_root,
        implementation,
    })
}

pub fn verify_request(request: &[u8]) -> Check<VerifiedCodeState> {
    require(request.len() <= MAX_REQUEST_BYTES, "state request bound")?;
    let raw = request
        .strip_prefix(REQUEST_DOMAIN)
        .ok_or("state request domain")?;
    let evidence: Evidence = serde_json::from_slice(raw).map_err(|_| "invalid state proof JSON")?;
    verify(&evidence)
}
