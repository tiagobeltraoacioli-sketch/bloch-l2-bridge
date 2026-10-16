// SPDX-License-Identifier: MIT OR Apache-2.0
//! Exact deployment transaction/receipt inclusion under retained header roots.
//! Caller-selected header anchors still require independent authentication.

use crate::{ethereum_header_ancestry as ancestry, merkle::keccak256};
use alloy_primitives::{Bytes, B256};
use alloy_rlp::{Decodable, Encodable};
use alloy_trie::{nodes::TrieNode, proof::verify_proof, Nibbles};
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};

pub const REQUEST_DOMAIN: &[u8] = b"BLOCH-ETHEREUM-DEPLOYMENT-INCLUSION-v1\0";
pub const MAX_REQUEST_BYTES: usize = 1024 * 1024;
pub const MAX_TRANSACTION_BYTES: usize = 64 * 1024;
pub const MAX_PROOF_NODES: usize = 32;
pub const MAX_PROOF_BYTES: usize = 256 * 1024;

type Check<T> = Result<T, &'static str>;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Evidence {
    pub schema: String,
    pub ancestry: ancestry::Evidence,
    pub transaction_index: String,
    pub transaction_hash: String,
    pub sender: String,
    pub contract_address: String,
    pub creation_input_sha256: String,
    pub receipt_type: String,
    pub cumulative_gas_used: String,
    pub transaction: String,
    pub transaction_proof: Vec<String>,
    pub receipt: String,
    pub receipt_proof: Vec<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct VerifiedInclusion {
    pub block_hash: [u8; 32],
    pub block_number: u64,
    pub transaction_hash: [u8; 32],
    pub transaction_index: u64,
    pub sender: [u8; 20],
    pub contract_address: [u8; 20],
}

fn require(ok: bool, message: &'static str) -> Check<()> {
    if ok {
        Ok(())
    } else {
        Err(message)
    }
}

#[derive(Clone, Copy)]
struct Field<'a> {
    list: bool,
    payload: &'a [u8],
    raw: &'a [u8],
}

fn fields(raw: &[u8], maximum: usize) -> Check<Vec<Field<'_>>> {
    let (list, mut payload, consumed) = ancestry::item(raw)?;
    require(
        list && consumed == raw.len(),
        "one canonical RLP list required",
    )?;
    let mut result = Vec::new();
    while !payload.is_empty() {
        require(result.len() < maximum, "RLP field limit")?;
        let (list, value, used) = ancestry::item(payload)?;
        result.push(Field {
            list,
            payload: value,
            raw: &payload[..used],
        });
        payload = &payload[used..];
    }
    Ok(result)
}

fn scalar(field: Field<'_>, maximum: usize) -> Check<&[u8]> {
    require(
        !field.list && field.payload.len() <= maximum,
        "scalar field width",
    )?;
    Ok(field.payload)
}

fn integer(field: Field<'_>, maximum: usize) -> Check<&[u8]> {
    let bytes = scalar(field, maximum)?;
    require(bytes.first() != Some(&0), "noncanonical integer")?;
    Ok(bytes)
}

fn uint64(field: Field<'_>) -> Check<u64> {
    Ok(integer(field, 8)?
        .iter()
        .fold(0, |n, b| n * 256 + u64::from(*b)))
}

fn list(payload: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::new();
    alloy_rlp::Header {
        list: true,
        payload_length: payload.len(),
    }
    .encode(&mut encoded);
    encoded.extend_from_slice(payload);
    encoded
}

fn address(value: &str) -> Check<[u8; 20]> {
    let decoded: [u8; 20] = ancestry::hex_bytes(value, 20)?
        .try_into()
        .map_err(|_| "address width")?;
    require(decoded.iter().any(|b| *b != 0), "zero address")?;
    Ok(decoded)
}

fn envelope(raw: &[u8]) -> Check<(u8, &[u8])> {
    match raw.first() {
        Some(1 | 2) => Ok((raw[0], &raw[1..])),
        Some(0xc0..=0xff) => Ok((0, raw)),
        _ => Err("unsupported deployment envelope type"),
    }
}

fn access_list(field: Field<'_>) -> Check<()> {
    // Bounds apply to all entries, including repeats, which Ethereum permits.
    let mut keys = 0;
    for entry in fields(field.raw, 256)? {
        let pair = fields(entry.raw, 2)?;
        require(
            pair.len() == 2 && scalar(pair[0], 20)?.len() == 20,
            "access list address",
        )?;
        for key in fields(pair[1].raw, 1024)? {
            keys += 1;
            require(
                keys <= 1024 && scalar(key, 32)?.len() == 32,
                "access list storage key",
            )?;
        }
    }
    Ok(())
}

fn transaction(raw: &[u8], expected: &Evidence) -> Check<([u8; 20], [u8; 20], u8)> {
    let (kind, payload) = envelope(raw)?;
    let values = fields(payload, 12)?;
    let (count, nonce, gas, to, value, data, signature_at) = match kind {
        0 => (9, 0, 2, 3, 4, 5, 6),
        1 => (11, 1, 3, 4, 5, 6, 8),
        2 => (12, 1, 4, 5, 6, 7, 9),
        _ => unreachable!(),
    };
    require(values.len() == count, "transaction field count")?;
    if kind != 0 {
        require(
            uint64(values[0])? == 1,
            "deployment must select Ethereum mainnet",
        )?;
        access_list(values[signature_at - 1])?;
    }
    let nonce = uint64(values[nonce])?;
    require(uint64(values[gas])? > 0, "zero gas limit")?;
    for field in &values[if kind == 0 { 1 } else { 2 }..gas] {
        integer(*field, 32)?;
    }
    if kind == 2 {
        let priority = integer(values[2], 32)?;
        let maximum = integer(values[3], 32)?;
        require(
            (priority.len(), priority) <= (maximum.len(), maximum),
            "priority fee exceeds maximum",
        )?;
    }
    require(
        scalar(values[to], 20)?.is_empty(),
        "direct contract creation required",
    )?;
    require(
        integer(values[value], 32)?.is_empty(),
        "unfunded deployment required",
    )?;
    let input = scalar(values[data], MAX_TRANSACTION_BYTES)?;
    require(!input.is_empty(), "empty creation input")?;
    require(
        Sha256::digest(input).as_slice() == ancestry::hash(&expected.creation_input_sha256)?,
        "creation input mismatch",
    )?;

    let parity = uint64(values[signature_at])?;
    let mut unsigned: Vec<u8> = values[..signature_at]
        .iter()
        .flat_map(|f| f.raw.iter().copied())
        .collect();
    let parity = if kind == 0 {
        require(
            matches!(parity, 37 | 38),
            "EIP-155 mainnet signature required",
        )?;
        unsigned.extend_from_slice(&[1, 0x80, 0x80]);
        (parity - 37) as u8
    } else {
        require(parity <= 1, "invalid signature parity")?;
        parity as u8
    };
    let mut signing = if kind == 0 { Vec::new() } else { vec![kind] };
    signing.extend_from_slice(&list(&unsigned));
    let mut signature = [0u8; 64];
    for (offset, field) in [
        (0, values[signature_at + 1]),
        (32, values[signature_at + 2]),
    ] {
        let component = integer(field, 32)?;
        require(!component.is_empty(), "zero signature scalar")?;
        signature[offset + 32 - component.len()..offset + 32].copy_from_slice(component);
    }
    let signature = Signature::from_slice(&signature).map_err(|_| "invalid secp256k1 signature")?;
    require(signature.normalize_s().is_none(), "high-s signature")?;
    let key = VerifyingKey::recover_from_prehash(
        &keccak256(&signing),
        &signature,
        RecoveryId::from_byte(parity).ok_or("signature parity")?,
    )
    .map_err(|_| "sender recovery failed")?;
    let public = key.to_encoded_point(false);
    let sender: [u8; 20] = keccak256(&public.as_bytes()[1..])[12..].try_into().unwrap();
    require(
        sender == address(&expected.sender)?,
        "recovered sender mismatch",
    )?;
    let mut creation = vec![0x94];
    creation.extend_from_slice(&sender);
    nonce.encode(&mut creation);
    let contract: [u8; 20] = keccak256(&list(&creation))[12..].try_into().unwrap();
    require(
        contract == address(&expected.contract_address)?,
        "CREATE address mismatch",
    )?;
    Ok((sender, contract, kind))
}

fn receipt(raw: &[u8], kind: u8, expected: &Evidence) -> Check<()> {
    let (observed, payload) = envelope(raw)?;
    require(
        observed == kind && u64::from(kind) == ancestry::decimal(&expected.receipt_type)?,
        "receipt type mismatch",
    )?;
    let values = fields(payload, 4)?;
    require(values.len() == 4, "receipt field count")?;
    require(
        uint64(values[0])? == 1,
        "successful post-Byzantium receipt required",
    )?;
    let cumulative = uint64(values[1])?;
    require(
        cumulative > 0 && cumulative == ancestry::decimal(&expected.cumulative_gas_used)?,
        "cumulative gas mismatch",
    )?;
    require(
        scalar(values[2], 256)? == [0u8; 256] && fields(values[3].raw, 0)?.is_empty(),
        "constructor logs must be empty",
    )?;
    Ok(())
}

fn prove(root: [u8; 32], index: u64, value: Vec<u8>, nodes: &[String]) -> Check<()> {
    let mut key = Vec::new();
    index.encode(&mut key);
    prove_key(root, &key, value, nodes, MAX_PROOF_NODES)
}

/// Presence only: the complete exact leaf value must be reached. This helper
/// does not accept absence/zero-storage assertions or an incomplete path.
pub(crate) fn prove_key(
    root: [u8; 32],
    key: &[u8],
    value: Vec<u8>,
    nodes: &[String],
    maximum_nodes: usize,
) -> Check<()> {
    require(
        !nodes.is_empty() && nodes.len() <= maximum_nodes,
        "proof node count",
    )?;
    require(
        !key.is_empty() && key.len() <= 32 && !value.is_empty(),
        "proof key/value bound",
    )?;
    let mut total = 0usize;
    let mut decoded = Vec::with_capacity(nodes.len());
    for node in nodes {
        let bytes = ancestry::hex_bytes(node, MAX_TRANSACTION_BYTES + 1024)?;
        total += bytes.len();
        require(total <= MAX_PROOF_BYTES, "proof byte bound")?;
        // Re-encoding rejects trailing bytes and noncanonical trie encodings.
        let mut input = bytes.as_slice();
        let trie = TrieNode::decode(&mut input).map_err(|_| "invalid trie node")?;
        let mut canonical = Vec::new();
        trie.encode(&mut canonical);
        require(
            input.is_empty() && canonical == bytes,
            "noncanonical trie node",
        )?;
        decoded.push(Bytes::from(bytes));
    }
    verify_proof(
        B256::from(root),
        Nibbles::unpack(key),
        Some(value),
        &decoded,
    )
    .map_err(|_| "trie inclusion refused")
}

pub fn verify(evidence: &Evidence) -> Check<VerifiedInclusion> {
    require(
        evidence.schema == "postern.custody-deployment-inclusion-request.v1",
        "inclusion schema",
    )?;
    let headers = ancestry::verify(&evidence.ancestry)?;
    let header = headers.first().ok_or("missing deployment header")?;
    let index = ancestry::decimal(&evidence.transaction_index)?;
    let tx = ancestry::hex_bytes(&evidence.transaction, MAX_TRANSACTION_BYTES)?;
    let tx_hash = keccak256(&tx);
    require(
        tx_hash == ancestry::hash(&evidence.transaction_hash)?,
        "transaction hash mismatch",
    )?;
    let (sender, contract, kind) = transaction(&tx, evidence)?;
    let raw_receipt = ancestry::hex_bytes(&evidence.receipt, 4096)?;
    receipt(&raw_receipt, kind, evidence)?;
    require(
        ancestry::decimal(&evidence.cumulative_gas_used)? <= header.gas_used,
        "receipt gas exceeds block gas",
    )?;
    // Malformed inline trie combinations can panic in the dependency. Treat
    // every such input as refusal; no capability is returned from a panic.
    std::panic::catch_unwind(|| {
        prove(
            header.transactions_root,
            index,
            tx,
            &evidence.transaction_proof,
        )?;
        prove(
            header.receipts_root,
            index,
            raw_receipt,
            &evidence.receipt_proof,
        )
    })
    .map_err(|_| "malformed trie proof")??;
    Ok(VerifiedInclusion {
        block_hash: header.hash,
        block_number: header.number,
        transaction_hash: tx_hash,
        transaction_index: index,
        sender,
        contract_address: contract,
    })
}

pub fn verify_request(request: &[u8]) -> Check<VerifiedInclusion> {
    require(
        request.len() <= MAX_REQUEST_BYTES,
        "inclusion request bound",
    )?;
    let json = request
        .strip_prefix(REQUEST_DOMAIN)
        .ok_or("inclusion request domain")?;
    let evidence: Evidence = serde_json::from_slice(json).map_err(|_| "invalid inclusion JSON")?;
    verify(&evidence)
}
