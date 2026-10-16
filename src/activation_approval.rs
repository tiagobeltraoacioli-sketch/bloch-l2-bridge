//! Fail-closed verification of a v2 bridge activation approval.
//!
//! The caller supplies an independently pinned authority-policy digest and a
//! pinned, read-only predecessor checkpoint. This module deliberately owns no
//! replay state: the approval ceremony remains the single monotonic-state
//! authority.

use ring::signature::{UnparsedPublicKey, ED25519};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub const APPROVAL_DOMAIN: &[u8] = b"BLOCH-BRIDGE-ACTIVATION-APPROVAL-v2\0";

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalCheckpoint {
    pub schema: String,
    #[serde(rename = "authorityPolicySha256")]
    pub authority_policy_sha256: String,
    #[serde(rename = "lastApprovalSequence")]
    pub last_approval_sequence: String,
    #[serde(rename = "lastApprovalSha256")]
    pub last_approval_sha256: String,
}

fn object<'a>(value: &'a Value, field: &str) -> Result<&'a serde_json::Map<String, Value>, String> {
    value
        .get(field)
        .and_then(Value::as_object)
        .ok_or_else(|| format!("missing object {field}"))
}

fn string<'a>(value: &'a serde_json::Map<String, Value>, field: &str) -> Result<&'a str, String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing string {field}"))
}

fn word(value: &str, size: usize) -> Result<Vec<u8>, String> {
    let encoded = value.strip_prefix("0x").ok_or("hex word lacks 0x prefix")?;
    if encoded.len() != size * 2 || !encoded.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("invalid fixed-width hex word".into());
    }
    (0..size)
        .map(|index| {
            u8::from_str_radix(&encoded[index * 2..index * 2 + 2], 16)
                .map_err(|_| "invalid hex word".into())
        })
        .collect()
}

fn canonical_sha256(value: &Value) -> Result<String, String> {
    let encoded = serde_json::to_vec(value).map_err(|error| error.to_string())?;
    Ok(format!("0x{:x}", Sha256::digest(encoded)))
}

fn decimal(value: &str) -> Result<u64, String> {
    if value.is_empty()
        || value.len() > 20
        || !value.bytes().all(|b| b.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err("non-canonical uint64".into());
    }
    value.parse().map_err(|_| "uint64 overflow".into())
}

/// Verify the policy-bound signature and exact successor of a pinned predecessor.
pub fn verify_activation_approval(
    bundle: &Value,
    expected_policy_sha256: &str,
    checkpoint: &ApprovalCheckpoint,
) -> Result<(), String> {
    let policy = object(bundle, "authorityPolicy")?;
    let authority = object(bundle, "authorityQualification")?;
    let activation_authority = policy
        .get("activationAuthority")
        .and_then(Value::as_object)
        .ok_or("missing activation authority")?;

    let expected_policy = word(expected_policy_sha256, 32)?;
    let policy_digest = word(string(policy, "authorityPolicySha256")?, 32)?;
    if policy_digest != expected_policy {
        return Err("bundle authority policy is not the independently pinned policy".into());
    }
    if word(&checkpoint.authority_policy_sha256, 32)? != expected_policy {
        return Err("checkpoint binds another authority policy".into());
    }
    if string(activation_authority, "algorithm")? != "ed25519" {
        return Err("unsupported activation approval algorithm".into());
    }

    let package = json!({
        "schema": "postern.bridge-activation-approval-package.v2",
        "manifestCanonicalSha256": string(authority, "manifestCanonicalSha256")?.to_ascii_lowercase(),
        "routeId": string(authority, "routeId")?.to_ascii_lowercase(),
        "authorityPolicySha256": string(authority, "authorityPolicySha256")?.to_ascii_lowercase(),
        "custodyCeremonySha256": string(authority, "custodyCeremonySha256")?.to_ascii_lowercase(),
        "nativeRolesCeremonySha256": string(authority, "nativeRolesCeremonySha256")?.to_ascii_lowercase(),
        "settlementVerificationSha256": canonical_sha256(bundle.get("settlementVerification").ok_or("missing settlement verification")?)?,
        "deploymentVerificationSha256": canonical_sha256(bundle.get("deploymentVerification").ok_or("missing deployment verification")?)?,
        "disposableCycleSha256": canonical_sha256(bundle.get("disposableCycle").ok_or("missing disposable cycle")?)?,
        "approvalCheckpointHeight": string(authority, "approvalCheckpointHeight")?,
        "observedNativeHeight": string(authority, "observedNativeHeight")?,
        "approvalValidUntilHeight": string(authority, "approvalValidUntilHeight")?,
        "approvalSequence": string(authority, "approvalSequence")?,
        "previousApprovalSha256": string(authority, "previousApprovalSha256")?.to_ascii_lowercase(),
        "decision": string(authority, "decision")?,
    });
    let package_sha256 = canonical_sha256(&package)?;
    if !package_sha256.eq_ignore_ascii_case(string(authority, "approvalPackageSha256")?) {
        return Err("approval package commitment mismatch".into());
    }

    let sequence = decimal(string(authority, "approvalSequence")?)?;
    let last_sequence = decimal(&checkpoint.last_approval_sequence)?;
    if last_sequence.checked_add(1) != Some(sequence) {
        return Err("approval sequence is not the exact checkpoint successor".into());
    }
    if word(string(authority, "previousApprovalSha256")?, 32)?
        != word(&checkpoint.last_approval_sha256, 32)?
    {
        return Err("approval predecessor does not match checkpoint".into());
    }

    let signature_text = string(authority, "activationApprovalSignature")?;
    let signature = word(signature_text, 64)?;
    let public_key = word(string(activation_authority, "publicKey")?, 32)?;
    let package_hash = word(&package_sha256, 32)?;
    let mut message = Vec::with_capacity(APPROVAL_DOMAIN.len() + package_hash.len());
    message.extend_from_slice(APPROVAL_DOMAIN);
    message.extend_from_slice(&package_hash);
    UnparsedPublicKey::new(&ED25519, public_key)
        .verify(&message, &signature)
        .map_err(|_| "invalid Ed25519 activation approval".to_string())?;

    let certificate = json!({
        "schema": "postern.bridge-activation-approval-certificate.v2",
        "authorityPolicySha256": string(authority, "authorityPolicySha256")?.to_ascii_lowercase(),
        "approvalPackageSha256": package_sha256,
        "signature": signature_text.to_ascii_lowercase(),
    });
    if !canonical_sha256(&certificate)?
        .eq_ignore_ascii_case(string(authority, "activationApprovalSha256")?)
    {
        return Err("approval certificate commitment mismatch".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::{
        rand::SystemRandom,
        signature::{Ed25519KeyPair, KeyPair},
    };

    fn hex(bytes: &[u8]) -> String {
        format!(
            "0x{}",
            bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        )
    }

    fn fixture() -> (Value, String, ApprovalCheckpoint) {
        let key_document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let key = Ed25519KeyPair::from_pkcs8(key_document.as_ref()).unwrap();
        let policy_digest = hex(&Sha256::digest(b"reviewed-policy"));
        let zero = hex(&[0; 32]);
        let report = json!({});
        let package = json!({
            "schema": "postern.bridge-activation-approval-package.v2",
            "manifestCanonicalSha256": hex(&Sha256::digest(b"manifest")),
            "routeId": hex(&Sha256::digest(b"route")),
            "authorityPolicySha256": policy_digest,
            "custodyCeremonySha256": hex(&Sha256::digest(b"custody")),
            "nativeRolesCeremonySha256": hex(&Sha256::digest(b"roles")),
            "settlementVerificationSha256": canonical_sha256(&report).unwrap(),
            "deploymentVerificationSha256": canonical_sha256(&report).unwrap(),
            "disposableCycleSha256": canonical_sha256(&report).unwrap(),
            "approvalCheckpointHeight": "10",
            "observedNativeHeight": "10",
            "approvalValidUntilHeight": "20",
            "approvalSequence": "1",
            "previousApprovalSha256": zero,
            "decision": "approve-activation-when-all-gates-satisfied",
        });
        let package_digest = canonical_sha256(&package).unwrap();
        let mut message = APPROVAL_DOMAIN.to_vec();
        message.extend_from_slice(&word(&package_digest, 32).unwrap());
        let signature = hex(key.sign(&message).as_ref());
        let certificate = json!({
            "schema": "postern.bridge-activation-approval-certificate.v2",
            "authorityPolicySha256": policy_digest,
            "approvalPackageSha256": package_digest,
            "signature": signature,
        });
        let bundle = json!({
            "authorityPolicy": {
                "authorityPolicySha256": policy_digest,
                "activationAuthority": {
                    "algorithm": "ed25519",
                    "publicKey": hex(key.public_key().as_ref()),
                },
            },
            "authorityQualification": {
                "manifestCanonicalSha256": package["manifestCanonicalSha256"],
                "routeId": package["routeId"],
                "authorityPolicySha256": policy_digest,
                "custodyCeremonySha256": package["custodyCeremonySha256"],
                "nativeRolesCeremonySha256": package["nativeRolesCeremonySha256"],
                "approvalCheckpointHeight": "10",
                "observedNativeHeight": "10",
                "approvalValidUntilHeight": "20",
                "approvalSequence": "1",
                "previousApprovalSha256": zero,
                "decision": "approve-activation-when-all-gates-satisfied",
                "approvalPackageSha256": package_digest,
                "activationApprovalSignature": signature,
                "activationApprovalSha256": canonical_sha256(&certificate).unwrap(),
            },
            "settlementVerification": report,
            "deploymentVerification": report,
            "disposableCycle": report,
        });
        let checkpoint = ApprovalCheckpoint {
            schema: "postern.bridge-activation-approval-checkpoint.v2".into(),
            authority_policy_sha256: policy_digest.clone(),
            last_approval_sequence: "0".into(),
            last_approval_sha256: zero,
        };
        (bundle, policy_digest, checkpoint)
    }

    #[test]
    fn genuine_policy_bound_successor_is_accepted() {
        let (bundle, policy, checkpoint) = fixture();
        verify_activation_approval(&bundle, &policy, &checkpoint).unwrap();
    }

    #[test]
    fn signature_policy_and_monotonic_substitutions_fail_closed() {
        let (bundle, policy, checkpoint) = fixture();
        let mut cases = Vec::new();
        let mut tampered = bundle.clone();
        tampered["authorityQualification"]["activationApprovalSignature"] =
            Value::String(hex(&[0x55; 64]));
        cases.push((tampered, policy.clone(), checkpoint.clone()));
        cases.push((
            bundle.clone(),
            hex(&Sha256::digest(b"other-policy")),
            checkpoint.clone(),
        ));
        let mut replay = checkpoint.clone();
        replay.last_approval_sequence = "1".into();
        cases.push((bundle.clone(), policy.clone(), replay));
        let mut wrong_predecessor = checkpoint;
        wrong_predecessor.last_approval_sha256 = hex(&Sha256::digest(b"other-predecessor"));
        cases.push((bundle, policy.clone(), wrong_predecessor));
        for (candidate, expected_policy, state) in cases {
            assert!(verify_activation_approval(&candidate, &expected_policy, &state).is_err());
        }
    }
}
