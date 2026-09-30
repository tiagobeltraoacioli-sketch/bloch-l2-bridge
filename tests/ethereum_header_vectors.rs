// SPDX-License-Identifier: MIT OR Apache-2.0
//! Independent historical header vector, not current deployment/finality evidence.
use bloch_l2_bridge::{
    ethereum_header_ancestry::{decode_header, verify, Anchor, Evidence},
    hex,
};

const RAW: &str = include_str!("../test-vectors/ethereum-header-ancestry/mainnet-genesis.rlp.hex");
const MAINNET_GENESIS: &str = "0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3";

#[test]
fn historical_mainnet_genesis_matches_its_independent_hash() {
    let raw = hex::decode(RAW.trim()).unwrap();
    assert_eq!(raw.len(), 535);
    let header = decode_header(&raw).unwrap();
    assert_eq!(hex::encode_prefixed(&header.hash), MAINNET_GENESIS);
    assert_eq!(header.number, 0);
    assert_eq!(header.timestamp, 0);
    assert_eq!(header.parent_hash, [0; 32]);

    let evidence = Evidence {
        schema: "postern.custody-deployment-ancestry.v2".into(),
        // Synthetic envelope bindings: this vector authenticates no deployment.
        manifest_canonical_sha256: hex::encode_prefixed(&[1; 32]),
        comparison_canonical_sha256: hex::encode_prefixed(&[2; 32]),
        anchors: vec![Anchor {
            block_number: "0".into(),
            block_hash: MAINNET_GENESIS.into(),
            parent_hash: Some(hex::encode_prefixed(&[0; 32])),
            timestamp: Some("0".into()),
            state_root: hex::encode_prefixed(&header.state_root),
            transactions_root: hex::encode_prefixed(&header.transactions_root),
            receipts_root: hex::encode_prefixed(&header.receipts_root),
        }],
        headers: vec![RAW.trim().into()],
    };
    assert_eq!(verify(&evidence).unwrap(), vec![header]);

    // Changing a real header byte cannot preserve the independently pinned hash.
    let mut changed = evidence;
    let mut raw = raw;
    *raw.last_mut().unwrap() ^= 1;
    changed.headers[0] = hex::encode_prefixed(&raw);
    assert!(verify(&changed).is_err());
}
