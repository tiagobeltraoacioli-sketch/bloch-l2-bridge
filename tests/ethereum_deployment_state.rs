use bloch_l2_bridge::{
    ethereum_deployment_state::{
        verify, verify_request, Evidence, MAX_REQUEST_BYTES, REQUEST_DOMAIN,
    },
    hex,
    merkle::keccak256,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

fn vectors() -> Vec<Value> {
    let parsed: Value = serde_json::from_str(include_str!(
        "../test-vectors/ethereum-deployment-state/synthetic.json"
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
    serde_json::from_value::<Evidence>(value).is_ok_and(|evidence| verify(&evidence).is_ok())
}

#[test]
fn independent_secure_account_and_storage_tries_bind_all_three_codes() {
    let rows = vectors();
    assert_eq!(rows.len(), 4);
    for value in rows {
        let evidence: Evidence = serde_json::from_value(value).unwrap();
        let result = verify(&evidence).unwrap();
        assert_eq!(
            hex::encode_prefixed(&result.implementation),
            evidence.contracts[2].address
        );
        assert_eq!(
            hex::encode_prefixed(&result.state_root),
            evidence.inclusion.ancestry.anchors[0].state_root
        );
        assert_eq!(
            hex::encode_prefixed(&result.inclusion.contract_address),
            evidence.contracts[0].address
        );
    }
}

#[test]
fn recomputed_review_pins_and_rpc_code_hashes_cannot_replace_proven_code() {
    for index in 0..3 {
        let mut bad = vectors()[0].clone();
        let code = hex::decode("0x60036000fd").unwrap();
        bad["contracts"][index]["code"] = hex::encode_prefixed(&code).into();
        bad["contracts"][index]["runtimeSha256"] =
            hex::encode_prefixed(&Sha256::digest(&code)).into();
        bad["contracts"][index]["proof"]["codeHash"] =
            hex::encode_prefixed(&keccak256(&code)).into();
        assert!(!check(bad));
    }
}

#[test]
fn account_claims_role_order_and_address_substitution_are_rejected() {
    let original = vectors()[0].clone();
    for index in 0..3 {
        for (field, value) in [
            ("nonce", "0x2".to_owned()),
            ("balance", "0x1".to_owned()),
            ("storageHash", hex::encode_prefixed(&[99; 32])),
            ("codeHash", hex::encode_prefixed(&[99; 32])),
            ("address", hex::encode_prefixed(&[99; 20])),
        ] {
            let mut bad = original.clone();
            bad["contracts"][index]["proof"][field] = value.into();
            assert!(!check(bad), "accepted altered {field} for contract {index}");
        }
        let mut bad = original.clone();
        let replacement: Value = hex::encode_prefixed(&[99; 20]).into();
        bad["contracts"][index]["address"] = replacement.clone();
        bad["contracts"][index]["proof"]["address"] = replacement;
        assert!(!check(bad));
    }
    for action in 0..3 {
        let mut bad = original.clone();
        let contracts = bad["contracts"].as_array_mut().unwrap();
        match action {
            0 => {
                contracts.swap(0, 1);
            }
            1 => {
                contracts.pop();
            }
            _ => {
                contracts.push(contracts[0].clone());
            }
        }
        assert!(!check(bad));
    }
}

#[test]
fn wrong_slot_zero_absence_and_implementation_substitution_are_rejected() {
    let original = vectors()[0].clone();
    for (field, value) in [
        ("key", hex::encode_prefixed(&[99; 32])),
        ("value", "0x0".to_owned()),
        ("value", "0x1".to_owned()),
        ("value", format!("0x1{}", "00".repeat(20))),
    ] {
        let mut bad = original.clone();
        bad["contracts"][1]["proof"]["storageProof"][0][field] = value.into();
        assert!(!check(bad));
    }
    let mut bad = original.clone();
    let replacement: Value = hex::encode_prefixed(&[99; 20]).into();
    bad["contracts"][1]["proof"]["storageProof"][0]["value"] = replacement.clone();
    bad["contracts"][2]["address"] = replacement.clone();
    bad["contracts"][2]["proof"]["address"] = replacement;
    assert!(!check(bad));
    for index in 0..3 {
        let mut bad = original.clone();
        bad["contracts"][index]["proof"]["storageProof"] = if index == 1 {
            serde_json::json!([])
        } else {
            original["contracts"][1]["proof"]["storageProof"].clone()
        };
        assert!(!check(bad));
    }
}

#[test]
fn truncated_reordered_extended_and_malformed_presence_proofs_refuse() {
    let original = vectors()[0].clone();
    let paths = [
        "/contracts/0/proof/accountProof",
        "/contracts/1/proof/accountProof",
        "/contracts/2/proof/accountProof",
        "/contracts/1/proof/storageProof/0/proof",
    ];
    for path in paths {
        for action in 0..7 {
            let mut bad = original.clone();
            let nodes = bad.pointer_mut(path).unwrap().as_array_mut().unwrap();
            assert!(nodes.len() >= 2);
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
                5 => {
                    *nodes = vec![nodes[0].clone(); 66];
                }
                _ => {
                    nodes[0] = "0xc28100".into();
                }
            }
            assert!(!check(bad), "accepted action {action} for {path}");
        }
    }
}

#[test]
fn quantities_are_canonical_and_bounded_before_rlp_encoding() {
    for field in ["nonce", "balance"] {
        for value in ["0x", "0x00", "0x01", "0X1", "0xA", "1", "-1"] {
            let mut bad = vectors()[0].clone();
            bad["contracts"][0]["proof"][field] = value.into();
            assert!(!check(bad));
        }
        let mut bad = vectors()[0].clone();
        bad["contracts"][0]["proof"][field] =
            format!("0x1{}", "00".repeat(if field == "nonce" { 8 } else { 32 })).into();
        assert!(!check(bad));
    }
}

#[test]
fn changed_header_state_root_and_reused_inclusion_refuse() {
    let mut bad = vectors()[0].clone();
    bad["inclusion"]["ancestry"]["anchors"][0]["stateRoot"] =
        hex::encode_prefixed(&[99; 32]).into();
    assert!(!check(bad));
    // Another internally valid inclusion header still cannot prove these accounts.
    let base: Value = serde_json::from_str(include_str!(
        "../test-vectors/ethereum-deployment-inclusion/synthetic.json"
    ))
    .unwrap();
    let mut bad = vectors()[0].clone();
    bad["inclusion"] = base["cases"][0]["request"].clone();
    assert!(!check(bad));
}

#[test]
fn exact_domain_schemas_unknown_duplicate_and_oversized_requests_refuse() {
    let value = vectors()[0].clone();
    let json = serde_json::to_vec(&value).unwrap();
    assert!(verify_request(&[REQUEST_DOMAIN, &json].concat()).is_ok());
    assert!(verify_request(&json).is_err());
    assert!(verify_request(&vec![0; MAX_REQUEST_BYTES + 1]).is_err());
    for path in [
        "",
        "/contracts/0",
        "/contracts/0/proof",
        "/contracts/1/proof/storageProof/0",
    ] {
        let mut bad = value.clone();
        bad.pointer_mut(path)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("extra".into(), true.into());
        assert!(!check(bad));
    }
    let duplicate =
        String::from_utf8(json)
            .unwrap()
            .replacen("\"nonce\":", "\"nonce\":\"0x1\",\"nonce\":", 1);
    assert!(verify_request(&[REQUEST_DOMAIN, duplicate.as_bytes()].concat()).is_err());
}
