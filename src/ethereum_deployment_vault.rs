// SPDX-License-Identifier: MIT OR Apache-2.0
//! Fixed-build initial vault controls/accounting and configured committee proofs.
//! This does not prove USDC reserves, the complete signer mapping or finality.

use crate::{
    ethereum_deployment_state as state, ethereum_header_ancestry as header,
    ethereum_storage_proof::verify_storage, hex, merkle::keccak256,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const REQUEST_DOMAIN: &[u8] = b"BLOCH-ETHEREUM-DEPLOYMENT-VAULT-v1\0";
pub const MAX_REQUEST_BYTES: usize = 1024 * 1024;
pub const BUILD: &[u8] = include_bytes!("../test-vectors/vault-storage-build/solc-0.8.24.json");
type Check<T> = Result<T, &'static str>;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Configuration {
    pub source_domain: String,
    pub native_domain: String,
    pub native_asset: String,
    pub cap: String,
    pub threshold: u8,
    pub transfer_mode: u8,
    pub signers: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Evidence {
    pub schema: String,
    pub state: state::Evidence,
    pub build_artifact_sha256: String,
    pub configuration: Configuration,
    pub storage_proof: Vec<state::StorageProof>,
}

#[derive(Debug)]
pub struct VerifiedVaultStorage {
    pub state: state::VerifiedCodeState,
    pub signer_count: usize,
    pub storage_proof_count: usize,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Build {
    source_sha256: String,
    creation_bytecode: String,
    runtime_template: String,
    immutables: BTreeMap<String, Vec<Location>>,
}
#[derive(Deserialize)]
struct Location {
    start: usize,
    length: usize,
}

fn require(ok: bool, message: &'static str) -> Check<()> {
    if ok {
        Ok(())
    } else {
        Err(message)
    }
}
fn word(number: u64) -> [u8; 32] {
    let mut bytes = [0; 32];
    bytes[24..].copy_from_slice(&number.to_be_bytes());
    bytes
}
fn address(value: &str) -> Check<[u8; 32]> {
    let raw = header::hex_bytes(value, 20)?;
    require(
        raw.len() == 20 && raw.iter().any(|b| *b != 0),
        "nonzero canonical address required",
    )?;
    let mut result = [0; 32];
    result[12..].copy_from_slice(&raw);
    Ok(result)
}
fn quantity(value: [u8; 32]) -> String {
    let encoded = hex::encode(&value);
    let trimmed = encoded.trim_start_matches('0');
    format!("0x{}", if trimmed.is_empty() { "0" } else { trimmed })
}
fn increment(value: &mut [u8; 32]) {
    for byte in value.iter_mut().rev() {
        let (next, carry) = byte.overflowing_add(1);
        *byte = next;
        if !carry {
            break;
        }
    }
}

/// The positions are fixed by the embedded, reproducible Solidity layout.
pub fn expected_slots(configuration: &Configuration) -> Check<Vec<([u8; 32], [u8; 32])>> {
    require(
        configuration.signers.len() == 5
            && configuration.threshold == 3
            && configuration.transfer_mode == 0,
        "three-of-five Ethereum custody configuration required",
    )?;
    let signers: Vec<[u8; 32]> = configuration
        .signers
        .iter()
        .map(|s| address(s))
        .collect::<Check<_>>()?;
    require(
        signers.windows(2).all(|pair| pair[0] < pair[1]),
        "sorted distinct signers required",
    )?;
    // Slot 2: depositCount, totalLocked, controlNonce, depositsEnabled,
    // releasesEnabled and all padding. Slot 5: reentrancy guard and padding.
    let mut result = vec![(word(0), word(5)), (word(2), word(0)), (word(5), word(0))];
    let mut element = keccak256(&word(0));
    for signer in &signers {
        result.push((element, *signer));
        increment(&mut element);
    }
    for signer in signers {
        result.push((keccak256(&[signer, word(1)].concat()), word(1)));
    }
    Ok(result)
}

fn check_build(evidence: &Evidence) -> Check<()> {
    let digest: [u8; 32] = Sha256::digest(BUILD).into();
    require(
        digest == header::hash(&evidence.build_artifact_sha256)?,
        "unreviewed vault build artifact",
    )?;
    let build: Build =
        serde_json::from_slice(BUILD).map_err(|_| "embedded build artifact invalid")?;
    let source_digest: [u8; 32] =
        Sha256::digest(include_bytes!("../contracts/usdt/USDTSourceVault.sol")).into();
    require(
        source_digest == header::hash(&build.source_sha256)?,
        "vault source/build drift",
    )?;
    let c = &evidence.configuration;
    let source = header::hash(&c.source_domain)?;
    let native = header::hash(&c.native_domain)?;
    let asset = header::hash(&c.native_asset)?;
    require(
        source != native && native != asset,
        "distinct source/native/asset identities required",
    )?;
    let cap = header::decimal(&c.cap)?;
    require(cap > 0, "positive custody cap required")?;
    let token = address(state::USDC_PROXY)?;
    let expected = BTreeMap::from([
        ("sourceDomain", source),
        ("nativeDomain", native),
        ("nativeAsset", asset),
        ("token", token),
        ("cap", word(cap)),
        ("threshold", word(u64::from(c.threshold))),
        ("transferMode", word(u64::from(c.transfer_mode))),
    ]);
    require(
        build.immutables.len() == expected.len(),
        "embedded immutable coverage",
    )?;
    let mut runtime = header::hex_bytes(&build.runtime_template, 65536)?;
    for (name, value) in expected {
        let locations = build
            .immutables
            .get(name)
            .ok_or("embedded immutable missing")?;
        require(
            !locations.is_empty(),
            "embedded immutable references missing",
        )?;
        for loc in locations {
            let end = loc.start.checked_add(loc.length).ok_or("immutable bound")?;
            let bytes = runtime.get_mut(loc.start..end).ok_or("immutable range")?;
            require(
                bytes.len() == 32 && bytes == [0; 32],
                "immutable reference overlap or nonzero template",
            )?;
            bytes.copy_from_slice(&value);
        }
    }
    require(
        runtime == header::hex_bytes(&evidence.state.contracts[0].code, 65536)?,
        "runtime differs from exact compiled vault",
    )?;
    let mut creation = header::hex_bytes(&build.creation_bytecode, 65536)?;
    for value in [
        source,
        native,
        asset,
        token,
        word(cap),
        word(u64::from(c.transfer_mode)),
        word(256),
        word(u64::from(c.threshold)),
        word(5),
    ] {
        creation.extend_from_slice(&value);
    }
    for signer in &c.signers {
        creation.extend_from_slice(&address(signer)?);
    }
    let creation_digest: [u8; 32] = Sha256::digest(&creation).into();
    require(
        creation_digest == header::hash(&evidence.state.inclusion.creation_input_sha256)?,
        "compiled constructor arguments differ",
    )
}

pub fn verify(evidence: &Evidence) -> Check<VerifiedVaultStorage> {
    require(
        evidence.schema == "postern.custody-deployment-vault-request.v1",
        "vault proof schema",
    )?;
    let slots = expected_slots(&evidence.configuration)?;
    require(
        evidence.storage_proof.len() == slots.len(),
        "complete fixed vault storage proof set required",
    )?;
    let state = state::verify(&evidence.state)?;
    check_build(evidence)?;
    let root = header::hash(&evidence.state.contracts[0].proof.storage_hash)?;
    for (proof, (slot, value)) in evidence.storage_proof.iter().zip(&slots) {
        require(
            proof.key == hex::encode_prefixed(slot) && proof.value == quantity(*value),
            "vault storage position/value mismatch",
        )?;
        verify_storage(root, *slot, *value, &proof.proof)?;
    }
    Ok(VerifiedVaultStorage {
        state,
        signer_count: evidence.configuration.signers.len(),
        storage_proof_count: slots.len(),
    })
}

pub fn verify_request(request: &[u8]) -> Check<VerifiedVaultStorage> {
    require(request.len() <= MAX_REQUEST_BYTES, "vault request bound")?;
    let raw = request
        .strip_prefix(REQUEST_DOMAIN)
        .ok_or("vault request domain")?;
    let evidence: Evidence = serde_json::from_slice(raw).map_err(|_| "invalid vault proof JSON")?;
    verify(&evidence)
}
