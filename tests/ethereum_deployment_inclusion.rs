use bloch_l2_bridge::{
    ethereum_deployment_inclusion::{
        verify, verify_request, Evidence, MAX_REQUEST_BYTES, REQUEST_DOMAIN,
    },
    hex,
    merkle::keccak256,
};
use serde_json::Value;

fn vectors() -> Vec<Value> {
    let parsed: Value = serde_json::from_str(include_str!(
        "../test-vectors/ethereum-deployment-inclusion/synthetic.json"
    ))
    .unwrap();
    parsed["cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["request"].clone())
        .collect()
}

fn check(value: Value) -> bool {
    let evidence: Evidence = serde_json::from_value(value).unwrap();
    verify(&evidence).is_ok()
}

#[test]
fn independently_signed_legacy_access_list_and_dynamic_fee_vectors() {
    let vectors = vectors();
    assert_eq!(vectors.len(), 12);
    for value in vectors {
        let evidence: Evidence = serde_json::from_value(value).unwrap();
        let result = verify(&evidence).unwrap();
        assert_eq!(
            result.transaction_index.to_string(),
            evidence.transaction_index
        );
        assert_eq!(hex::encode_prefixed(&result.sender), evidence.sender);
        assert_eq!(
            hex::encode_prefixed(&result.contract_address),
            evidence.contract_address
        );
        let mut request = REQUEST_DOMAIN.to_vec();
        request.extend_from_slice(&serde_json::to_vec(&serde_json::json!({})).unwrap());
        assert!(verify_request(&request).is_err());
    }
}

#[test]
fn identities_positions_and_creation_input_must_match() {
    let original = vectors()[0].clone();
    for (field, value) in [
        ("transactionIndex", "1".to_owned()),
        ("transactionIndex", "00".to_owned()),
        ("transactionIndex", "18446744073709551616".to_owned()),
        ("transactionHash", hex::encode_prefixed(&[99; 32])),
        ("sender", hex::encode_prefixed(&[99; 20])),
        ("contractAddress", hex::encode_prefixed(&[99; 20])),
        ("creationInputSha256", hex::encode_prefixed(&[99; 32])),
        ("receiptType", "1".to_owned()),
        ("cumulativeGasUsed", "80001".to_owned()),
    ] {
        let mut bad = original.clone();
        bad[field] = value.into();
        assert!(!check(bad), "accepted changed {field}");
    }
}

#[test]
fn changed_valid_transactions_cannot_reuse_another_positions_proof() {
    let rows = vectors();
    for kind in 0..3 {
        let mut bad = rows[4 * kind].clone();
        let other = &rows[4 * kind + 1];
        for field in ["transaction", "transactionHash", "contractAddress"] {
            bad[field] = other[field].clone();
        }
        assert!(!check(bad));
    }
}

#[test]
fn proof_bytes_order_and_completeness_are_strict() {
    let original = vectors()[3].clone();
    for field in ["transactionProof", "receiptProof"] {
        for action in 0..6 {
            let mut bad = original.clone();
            let nodes = bad[field].as_array_mut().unwrap();
            match action {
                0 => {
                    nodes.pop();
                }
                1 => {
                    nodes.reverse();
                }
                2 => {
                    nodes.push(nodes[0].clone());
                }
                3 => {
                    nodes[0] = (nodes[0].as_str().unwrap().to_owned() + "00").into();
                }
                4 => {
                    nodes.clear();
                }
                _ => {
                    *nodes = vec![nodes[0].clone(); 33];
                }
            }
            assert!(!check(bad), "accepted {field} action {action}");
        }
    }
    let mut bad = original;
    bad["transactionProof"][0] = format!("0x{}", "00".repeat(66561)).into();
    assert!(!check(bad));
}

#[test]
fn changed_receipt_with_recomputed_expected_fields_still_needs_inclusion() {
    let rows = vectors();
    for kind in 0..3 {
        let mut bad = rows[4 * kind].clone();
        bad["receipt"] = rows[4 * kind + 1]["receipt"].clone();
        bad["cumulativeGasUsed"] = rows[4 * kind + 1]["cumulativeGasUsed"].clone();
        assert!(!check(bad));
    }
}

#[test]
fn malformed_and_changed_signed_envelopes_are_refused() {
    let original = vectors()[8].clone();
    for raw in [
        "0x", "0x00", "0x03c0", "0x04c0", "0xc0", "0xc180", "0xc28100",
    ] {
        let mut bad = original.clone();
        bad["transaction"] = raw.into();
        bad["transactionHash"] =
            hex::encode_prefixed(&keccak256(&hex::decode(raw).unwrap())).into();
        assert!(!check(bad));
    }
    let raw = hex::decode(original["transaction"].as_str().unwrap()).unwrap();
    for index in 0..raw.len() {
        let mut bytes = raw.clone();
        bytes[index] ^= 1;
        let mut bad = original.clone();
        bad["transaction"] = hex::encode_prefixed(&bytes).into();
        bad["transactionHash"] = hex::encode_prefixed(&keccak256(&bytes)).into();
        assert!(!check(bad), "accepted mutated signed byte {index}");
    }
}

#[test]
fn request_domain_schema_unknown_duplicate_and_size_refuse() {
    let json = serde_json::to_vec(&vectors()[0]).unwrap();
    let request = [REQUEST_DOMAIN, &json].concat();
    assert!(verify_request(&request).is_ok());
    assert!(verify_request(&json).is_err());
    assert!(verify_request(&vec![0; MAX_REQUEST_BYTES + 1]).is_err());
    let mut value = vectors()[0].clone();
    value["extra"] = true.into();
    assert!(
        verify_request(&[REQUEST_DOMAIN, &serde_json::to_vec(&value).unwrap()].concat()).is_err()
    );
    let duplicate = String::from_utf8(json).unwrap().replacen(
        "\"transactionIndex\":",
        "\"transactionIndex\":\"0\",\"transactionIndex\":",
        1,
    );
    assert!(verify_request(&[REQUEST_DOMAIN, duplicate.as_bytes()].concat()).is_err());
}
