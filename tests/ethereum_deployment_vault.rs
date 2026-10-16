use alloy_rlp::Encodable;
use bloch_l2_bridge::{
    ethereum_deployment_vault::{
        verify, verify_request, Evidence, MAX_REQUEST_BYTES, REQUEST_DOMAIN,
    },
    ethereum_storage_proof::verify_storage,
    hex,
    merkle::keccak256,
};
use serde_json::Value;

fn fixture() -> Value {
    serde_json::from_str::<Value>(include_str!(
        "../test-vectors/ethereum-deployment-vault/anvil-shanghai.json"
    ))
    .unwrap()["request"]
        .clone()
}
fn check(value: Value) -> bool {
    serde_json::from_value::<Evidence>(value).is_ok_and(|evidence| verify(&evidence).is_ok())
}
fn word(value: u8) -> [u8; 32] {
    let mut bytes = [0; 32];
    bytes[31] = value;
    bytes
}
fn scalar(bytes: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();
    bytes.encode(&mut result);
    result
}
fn list(items: Vec<Vec<u8>>) -> Vec<u8> {
    let payload: Vec<u8> = items.into_iter().flatten().collect();
    let mut result = Vec::new();
    alloy_rlp::Header {
        list: true,
        payload_length: payload.len(),
    }
    .encode(&mut result);
    result.extend(payload);
    result
}
fn compact(key: &[u8], leaf: bool) -> Vec<u8> {
    let odd = key.len() % 2;
    let mut nibbles = vec![2 * u8::from(leaf) + odd as u8];
    if odd == 0 {
        nibbles.push(0);
    }
    nibbles.extend_from_slice(key);
    nibbles.chunks_exact(2).map(|p| p[0] * 16 + p[1]).collect()
}
fn path(slot: [u8; 32]) -> Vec<u8> {
    keccak256(&slot)
        .iter()
        .flat_map(|b| [b >> 4, b & 15])
        .collect()
}

#[test]
fn locally_executed_constructor_proves_exact_build_configuration_and_initial_storage() {
    let evidence: Evidence = serde_json::from_value(fixture()).unwrap();
    let accepted = verify(&evidence).unwrap();
    assert_eq!(accepted.signer_count, 5);
    assert_eq!(accepted.storage_proof_count, 13);
    assert_eq!(accepted.state.inclusion.block_number, 1);
}

#[test]
fn every_incomplete_anvil_proof_is_refused_including_zero_claims() {
    let evidence: Evidence = serde_json::from_value(fixture()).unwrap();
    let root: [u8; 32] = hex::decode(&evidence.state.contracts[0].proof.storage_hash)
        .unwrap()
        .try_into()
        .unwrap();
    let slots = bloch_l2_bridge::ethereum_deployment_vault::expected_slots(&evidence.configuration)
        .unwrap();
    for (proof, (slot, value)) in evidence.storage_proof.iter().zip(slots) {
        assert!(verify_storage(root, slot, value, &proof.proof).is_ok());
        for count in 0..proof.proof.len() {
            assert!(
                verify_storage(root, slot, value, &proof.proof[..count]).is_err(),
                "accepted prefix {count} for {}",
                proof.key
            );
        }
        let mut extended = proof.proof.clone();
        extended.push(extended[0].clone());
        assert!(verify_storage(root, slot, value, &extended).is_err());
        let changed = if value == [0; 32] { word(1) } else { [0; 32] };
        assert!(verify_storage(root, slot, changed, &proof.proof).is_err());
    }
}

#[test]
fn compiled_runtime_constructor_arguments_and_build_pin_are_independent_requirements() {
    for (field, value) in [
        ("sourceDomain", Value::from(hex::encode_prefixed(&[99; 32]))),
        ("nativeDomain", Value::from(hex::encode_prefixed(&[98; 32]))),
        ("nativeAsset", Value::from(hex::encode_prefixed(&[97; 32]))),
        ("cap", Value::from("1")),
        ("threshold", Value::from(2)),
        ("transferMode", Value::from(1)),
    ] {
        let mut bad = fixture();
        bad["configuration"][field] = value;
        assert!(!check(bad), "accepted changed immutable {field}");
    }
    let mut bad = fixture();
    bad["configuration"]["signers"][4] = hex::encode_prefixed(&[99; 20]).into();
    assert!(!check(bad));
    let mut bad = fixture();
    bad["buildArtifactSha256"] = hex::encode_prefixed(&[99; 32]).into();
    assert!(!check(bad));
}

#[test]
fn vault_storage_keys_values_order_and_coverage_are_exact() {
    for action in 0..8 {
        let mut bad = fixture();
        let proofs = bad["storageProof"].as_array_mut().unwrap();
        match action {
            0 => {
                proofs.pop();
            }
            1 => {
                proofs.push(proofs[0].clone());
            }
            2 => {
                proofs.swap(1, 2);
            }
            3 => {
                proofs[1]["value"] = "0x1".into();
            }
            4 => {
                proofs[1]["proof"] = serde_json::json!([]);
            }
            5 => {
                proofs[0]["value"] = "0x05".into();
            }
            6 => {
                proofs[1]["key"] = hex::encode_prefixed(&word(3)).into();
            }
            _ => {
                proofs[3]["proof"] = proofs[4]["proof"].clone();
            }
        }
        assert!(!check(bad), "accepted storage mutation {action}");
    }
}

#[test]
fn empty_root_and_divergent_leaf_are_explicit_terminal_absence() {
    let slot = word(7);
    assert!(verify_storage(keccak256(&[0x80]), slot, [0; 32], &[]).is_ok());
    assert!(verify_storage(keccak256(&[0x80]), slot, [0; 32], &["0x80".into()]).is_ok());
    assert!(verify_storage(keccak256(&[0x80]), slot, word(1), &[]).is_err());
    assert!(verify_storage(
        keccak256(&[0x80]),
        slot,
        [0; 32],
        &["0x80".into(), "0x80".into()]
    )
    .is_err());
    let mut other = path(slot);
    other[63] ^= 1;
    let leaf = list(vec![scalar(&compact(&other, true)), scalar(&scalar(&[1]))]);
    let proof = [hex::encode_prefixed(&leaf)];
    assert!(verify_storage(keccak256(&leaf), slot, [0; 32], &proof).is_ok());
    assert!(verify_storage(keccak256(&leaf), slot, word(1), &proof).is_err());
    let zero_leaf = list(vec![
        scalar(&compact(&path(slot), true)),
        scalar(&scalar(&[])),
    ]);
    assert!(verify_storage(
        keccak256(&zero_leaf),
        slot,
        [0; 32],
        &[hex::encode_prefixed(&zero_leaf)]
    )
    .is_err());
}

#[test]
fn missing_branch_child_is_absent_but_missing_referenced_child_is_incomplete() {
    let slot = word(7);
    let key = path(slot);
    let mut branch = vec![scalar(&[]); 17];
    branch[usize::from((key[0] + 1) % 16)] = scalar(&[0xaa; 32]);
    branch[usize::from((key[0] + 2) % 16)] = scalar(&[0xbb; 32]);
    let root = list(branch.clone());
    assert!(verify_storage(
        keccak256(&root),
        slot,
        [0; 32],
        &[hex::encode_prefixed(&root)]
    )
    .is_ok());
    branch[usize::from(key[0])] = scalar(&[0xcc; 32]);
    let root = list(branch);
    assert!(verify_storage(
        keccak256(&root),
        slot,
        [0; 32],
        &[hex::encode_prefixed(&root)]
    )
    .is_err());
}

#[test]
fn embedded_children_extension_divergence_and_reference_canonicality() {
    let slot = word(9);
    let key = path(slot);
    let leaf = list(vec![
        scalar(&compact(&key[63..], true)),
        scalar(&scalar(&[1])),
    ]);
    let other = list(vec![scalar(&compact(&[0], true)), scalar(&scalar(&[2]))]);
    let mut fields = vec![scalar(&[]); 17];
    fields[usize::from(key[62])] = leaf;
    fields[usize::from((key[62] + 1) % 16)] = other;
    let branch = list(fields);
    assert!(branch.len() < 32);
    let extension = list(vec![scalar(&compact(&key[..62], false)), branch.clone()]);
    let proof = [hex::encode_prefixed(&extension)];
    assert!(verify_storage(keccak256(&extension), slot, word(1), &proof).is_ok());
    assert!(verify_storage(keccak256(&extension), slot, [0; 32], &proof).is_err());
    let mut divergent = key[..62].to_vec();
    divergent[0] ^= 1;
    let extension = list(vec![scalar(&compact(&divergent, false)), branch.clone()]);
    assert!(verify_storage(
        keccak256(&extension),
        slot,
        [0; 32],
        &[hex::encode_prefixed(&extension)]
    )
    .is_ok());
    let hashed_short = list(vec![
        scalar(&compact(&key[..62], false)),
        scalar(&keccak256(&branch)),
    ]);
    assert!(verify_storage(
        keccak256(&hashed_short),
        slot,
        word(1),
        &[
            hex::encode_prefixed(&hashed_short),
            hex::encode_prefixed(&branch)
        ]
    )
    .is_err());
    let mut invalid_path = compact(&key, true);
    invalid_path[0] = 0x40;
    let invalid = list(vec![scalar(&invalid_path), scalar(&scalar(&[1]))]);
    assert!(verify_storage(
        keccak256(&invalid),
        slot,
        word(1),
        &[hex::encode_prefixed(&invalid)]
    )
    .is_err());
}

#[test]
fn unknown_duplicate_wrong_domain_and_oversized_requests_refuse() {
    let original = fixture();
    let json = serde_json::to_vec(&original).unwrap();
    assert!(verify_request(&[REQUEST_DOMAIN, &json].concat()).is_ok());
    assert!(verify_request(&json).is_err());
    assert!(verify_request(&vec![0; MAX_REQUEST_BYTES + 1]).is_err());
    for path in ["", "/configuration", "/storageProof/0"] {
        let mut bad = original.clone();
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
            .replacen("\"cap\":", "\"cap\":\"1\",\"cap\":", 1);
    assert!(verify_request(&[REQUEST_DOMAIN, duplicate.as_bytes()].concat()).is_err());
}
