//! Observation-only verifier for independently anchored bridge authorities.

use ring::signature::{UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

const ROOT_POP_DOMAIN: &[u8] = b"BLOCH-BRIDGE-TRUST-ROOT-POP-v1\0";
const AUTHORITY_POP_DOMAIN: &[u8] = b"BLOCH-BRIDGE-OPERATIONAL-AUTHORITY-POP-v1\0";
const APPROVAL_DOMAIN: &[u8] = b"BLOCH-BRIDGE-OPERATIONAL-AUTHORITY-APPROVAL-v1\0";
const ROLES: [&str; 8] = [
    "custodian-1",
    "custodian-2",
    "custodian-3",
    "custodian-4",
    "custodian-5",
    "native-issuer",
    "fee-sponsor",
    "activation-authority",
];

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrustIntake {
    pub schema: String,
    #[serde(rename = "trustAnchorPackage")]
    pub trust_anchor_package: TrustAnchorPackage,
    #[serde(rename = "operationalAuthorityPackage")]
    pub operational_authority_package: OperationalAuthorityPackage,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrustAnchorPackage {
    pub schema: String,
    pub domain: String,
    #[serde(rename = "packageSequence")]
    pub package_sequence: String,
    #[serde(rename = "previousPackageSha256")]
    pub previous_package_sha256: String,
    pub roots: Vec<RootAuthority>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RootAuthority {
    #[serde(rename = "authorityId")]
    pub authority_id: String,
    #[serde(rename = "organizationId")]
    pub organization_id: String,
    #[serde(rename = "publicKey")]
    pub public_key: String,
    #[serde(rename = "recoveryDeclarationSha256")]
    pub recovery_declaration_sha256: String,
    #[serde(rename = "conflictDeclarationSha256")]
    pub conflict_declaration_sha256: String,
    #[serde(rename = "proofOfPossessionSignature")]
    pub proof_of_possession_signature: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationalAuthorityPackage {
    pub schema: String,
    #[serde(rename = "manifestCanonicalSha256")]
    pub manifest_canonical_sha256: String,
    #[serde(rename = "ceremonyPackageCanonicalSha256")]
    pub ceremony_package_canonical_sha256: String,
    #[serde(rename = "custodyThreshold")]
    pub custody_threshold: u64,
    pub authorities: Vec<OperationalAuthority>,
    #[serde(rename = "rootApprovals")]
    pub root_approvals: Vec<RootApproval>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationalAuthority {
    pub role: String,
    #[serde(rename = "authorityId")]
    pub authority_id: String,
    #[serde(rename = "organizationId")]
    pub organization_id: String,
    #[serde(rename = "publicKey")]
    pub public_key: String,
    #[serde(rename = "appointmentRecordSha256")]
    pub appointment_record_sha256: String,
    #[serde(rename = "recoveryDeclarationSha256")]
    pub recovery_declaration_sha256: String,
    #[serde(rename = "conflictDeclarationSha256")]
    pub conflict_declaration_sha256: String,
    #[serde(rename = "proofOfPossessionSignature")]
    pub proof_of_possession_signature: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RootApproval {
    #[serde(rename = "authorityId")]
    pub authority_id: String,
    pub signature: String,
}

#[derive(Serialize)]
struct RootPop<'a> {
    domain: &'a str,
    #[serde(rename = "packageSequence")]
    package_sequence: &'a str,
    #[serde(rename = "previousPackageSha256")]
    previous_package_sha256: &'a str,
    #[serde(rename = "authorityId")]
    authority_id: &'a str,
    #[serde(rename = "organizationId")]
    organization_id: &'a str,
    #[serde(rename = "publicKey")]
    public_key: &'a str,
    #[serde(rename = "recoveryDeclarationSha256")]
    recovery: &'a str,
    #[serde(rename = "conflictDeclarationSha256")]
    conflict: &'a str,
}

#[derive(Serialize)]
struct OperationalPop<'a> {
    role: &'a str,
    #[serde(rename = "authorityId")]
    authority_id: &'a str,
    #[serde(rename = "organizationId")]
    organization_id: &'a str,
    #[serde(rename = "publicKey")]
    public_key: &'a str,
    #[serde(rename = "appointmentRecordSha256")]
    appointment: &'a str,
    #[serde(rename = "recoveryDeclarationSha256")]
    recovery: &'a str,
    #[serde(rename = "conflictDeclarationSha256")]
    conflict: &'a str,
    #[serde(rename = "manifestCanonicalSha256")]
    manifest: &'a str,
    #[serde(rename = "ceremonyPackageCanonicalSha256")]
    ceremony: &'a str,
}

#[derive(Serialize)]
struct OperationalUnsigned<'a> {
    schema: &'a str,
    #[serde(rename = "manifestCanonicalSha256")]
    manifest: &'a str,
    #[serde(rename = "ceremonyPackageCanonicalSha256")]
    ceremony: &'a str,
    #[serde(rename = "custodyThreshold")]
    threshold: u64,
    authorities: &'a [OperationalAuthority],
}

fn bytes<const N: usize>(value: &str, label: &str, zero: bool) -> Result<[u8; N], String> {
    let value = value
        .strip_prefix("0x")
        .ok_or_else(|| format!("{label} lacks 0x"))?;
    if value.len() != N * 2
        || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
        || value.bytes().any(|byte| byte.is_ascii_uppercase())
    {
        return Err(format!("invalid canonical {label}"));
    }
    let mut output = [0_u8; N];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| format!("invalid {label}"))?;
    }
    if !zero
        && (!output.iter().any(|byte| *byte != 0)
            || output.windows(2).all(|pair| pair[0] == pair[1]))
    {
        return Err(format!("placeholder {label}"));
    }
    Ok(output)
}

fn message<T: Serialize>(domain: &[u8], value: &T) -> Result<Vec<u8>, String> {
    let mut message = domain.to_vec();
    message.extend(serde_json::to_vec(value).map_err(|error| error.to_string())?);
    Ok(message)
}

fn verify(key: &[u8; 32], message: &[u8], signature: &str) -> Result<(), String> {
    let signature = bytes::<64>(signature, "Ed25519 signature", false)?;
    UnparsedPublicKey::new(&ED25519, key)
        .verify(message, &signature)
        .map_err(|_| "Ed25519 proof failed".into())
}

fn sequence(value: &str) -> Result<u64, String> {
    if value.is_empty()
        || value.len() > 20
        || !value.bytes().all(|b| b.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err("canonical trust package sequence required".into());
    }
    value
        .parse()
        .map_err(|_| "trust package sequence overflow".into())
}

/// Verify exact identities, possession proofs and a two-of-three independent root quorum.
pub fn verify_trust_intake(
    intake: &TrustIntake,
    expected_anchor_sha256: &[u8; 32],
) -> Result<[u8; 32], String> {
    if intake.schema != "postern.bridge-authority-trust-intake.v1"
        || intake.trust_anchor_package.schema != "postern.bridge-authority-trust-anchor.v1"
        || intake.trust_anchor_package.domain != "bloch-bridge-authority-trust-v1"
        || intake.operational_authority_package.schema
            != "postern.bridge-operational-authority-package.v1"
    {
        return Err("unsupported authority trust intake schema".into());
    }
    let anchor_bytes =
        serde_json::to_vec(&intake.trust_anchor_package).map_err(|error| error.to_string())?;
    if Sha256::digest(&anchor_bytes).as_slice() != expected_anchor_sha256 {
        return Err("trust anchor package does not match compiled root".into());
    }
    let anchor_sequence = sequence(&intake.trust_anchor_package.package_sequence)?;
    let anchor_previous = bytes::<32>(
        &intake.trust_anchor_package.previous_package_sha256,
        "previous trust anchor package",
        true,
    )?;
    if (anchor_sequence == 1) != anchor_previous.iter().all(|byte| *byte == 0) {
        return Err("trust anchor sequence/predecessor mismatch".into());
    }
    if intake.trust_anchor_package.roots.len() != 3 {
        return Err("exactly three trust root authorities required".into());
    }
    let mut root_ids = BTreeSet::new();
    let mut root_orgs = BTreeSet::new();
    let mut root_keys = BTreeSet::new();
    let mut root_declarations = BTreeSet::new();
    let mut roots = Vec::new();
    for root in &intake.trust_anchor_package.roots {
        let id = bytes::<32>(&root.authority_id, "root authority identity", false)?;
        let org = bytes::<32>(&root.organization_id, "root organization", false)?;
        let key = bytes::<32>(&root.public_key, "root public key", false)?;
        let recovery = bytes::<32>(
            &root.recovery_declaration_sha256,
            "root recovery declaration",
            false,
        )?;
        let conflict = bytes::<32>(
            &root.conflict_declaration_sha256,
            "root conflict declaration",
            false,
        )?;
        if !root_ids.insert(id) || !root_orgs.insert(org) || !root_keys.insert(key) {
            return Err("trust roots must have distinct identities, organizations and keys".into());
        }
        if !root_declarations.insert(recovery) || !root_declarations.insert(conflict) {
            return Err("trust root recovery and conflict declarations must be distinct".into());
        }
        let pop = RootPop {
            domain: &intake.trust_anchor_package.domain,
            package_sequence: &intake.trust_anchor_package.package_sequence,
            previous_package_sha256: &intake.trust_anchor_package.previous_package_sha256,
            authority_id: &root.authority_id,
            organization_id: &root.organization_id,
            public_key: &root.public_key,
            recovery: &root.recovery_declaration_sha256,
            conflict: &root.conflict_declaration_sha256,
        };
        verify(
            &key,
            &message(ROOT_POP_DOMAIN, &pop)?,
            &root.proof_of_possession_signature,
        )?;
        roots.push((id, key));
    }

    let operational = &intake.operational_authority_package;
    bytes::<32>(&operational.manifest_canonical_sha256, "manifest", false)?;
    bytes::<32>(
        &operational.ceremony_package_canonical_sha256,
        "ceremony",
        false,
    )?;
    if operational.custody_threshold != 3 || operational.authorities.len() != ROLES.len() {
        return Err("exact three-of-five custody and eight authorities required".into());
    }
    let mut ids = BTreeSet::new();
    let mut orgs = BTreeSet::new();
    let mut keys = BTreeSet::new();
    let mut declarations = root_declarations;
    for (authority, role) in operational.authorities.iter().zip(ROLES) {
        if authority.role != role {
            return Err("operational authority role order mismatch".into());
        }
        let id = bytes::<32>(&authority.authority_id, "authority identity", false)?;
        let org = bytes::<32>(&authority.organization_id, "authority organization", false)?;
        let key = bytes::<32>(&authority.public_key, "authority public key", false)?;
        let appointment = bytes::<32>(
            &authority.appointment_record_sha256,
            "appointment record",
            false,
        )?;
        let recovery = bytes::<32>(
            &authority.recovery_declaration_sha256,
            "recovery declaration",
            false,
        )?;
        let conflict = bytes::<32>(
            &authority.conflict_declaration_sha256,
            "conflict declaration",
            false,
        )?;
        if !ids.insert(id)
            || !orgs.insert(org)
            || !keys.insert(key)
            || !declarations.insert(appointment)
            || !declarations.insert(recovery)
            || !declarations.insert(conflict)
        {
            return Err("operational identities and evidence must be globally distinct".into());
        }
        if root_ids.contains(&id) || root_orgs.contains(&org) || root_keys.contains(&key) {
            return Err("operational authority overlaps a trust root".into());
        }
        let pop = OperationalPop {
            role: &authority.role,
            authority_id: &authority.authority_id,
            organization_id: &authority.organization_id,
            public_key: &authority.public_key,
            appointment: &authority.appointment_record_sha256,
            recovery: &authority.recovery_declaration_sha256,
            conflict: &authority.conflict_declaration_sha256,
            manifest: &operational.manifest_canonical_sha256,
            ceremony: &operational.ceremony_package_canonical_sha256,
        };
        verify(
            &key,
            &message(AUTHORITY_POP_DOMAIN, &pop)?,
            &authority.proof_of_possession_signature,
        )?;
    }
    if operational.root_approvals.len() < 2 || operational.root_approvals.len() > 3 {
        return Err("two-of-three trust root approval required".into());
    }
    let unsigned = OperationalUnsigned {
        schema: &operational.schema,
        manifest: &operational.manifest_canonical_sha256,
        ceremony: &operational.ceremony_package_canonical_sha256,
        threshold: operational.custody_threshold,
        authorities: &operational.authorities,
    };
    let mut approval_message = APPROVAL_DOMAIN.to_vec();
    approval_message.extend_from_slice(expected_anchor_sha256);
    approval_message.extend(serde_json::to_vec(&unsigned).map_err(|error| error.to_string())?);
    let root_map: std::collections::BTreeMap<_, _> = roots.into_iter().collect();
    let mut approved = BTreeSet::new();
    for approval in &operational.root_approvals {
        let id = bytes::<32>(&approval.authority_id, "approval root identity", false)?;
        let key = root_map.get(&id).ok_or("approval by an untrusted root")?;
        if !approved.insert(id) {
            return Err("duplicate trust root approval".into());
        }
        verify(key, &approval_message, &approval.signature)?;
    }
    let request = serde_json::to_vec(intake).map_err(|error| error.to_string())?;
    Ok(Sha256::digest(&request).into())
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

    fn digest(label: &str) -> String {
        hex(&Sha256::digest(label.as_bytes()))
    }

    fn key() -> Ed25519KeyPair {
        let document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        Ed25519KeyPair::from_pkcs8(document.as_ref()).unwrap()
    }

    fn fixture() -> (TrustIntake, [u8; 32]) {
        let root_keys: Vec<_> = (0..3).map(|_| key()).collect();
        let mut roots = Vec::new();
        let zero = hex(&[0; 32]);
        for (index, signer) in root_keys.iter().enumerate() {
            let mut root = RootAuthority {
                authority_id: digest(&format!("root-id-{index}")),
                organization_id: digest(&format!("root-org-{index}")),
                public_key: hex(signer.public_key().as_ref()),
                recovery_declaration_sha256: digest(&format!("root-recovery-{index}")),
                conflict_declaration_sha256: digest(&format!("root-conflict-{index}")),
                proof_of_possession_signature: hex(&[1; 64]),
            };
            let pop = RootPop {
                domain: "bloch-bridge-authority-trust-v1",
                package_sequence: "1",
                previous_package_sha256: &zero,
                authority_id: &root.authority_id,
                organization_id: &root.organization_id,
                public_key: &root.public_key,
                recovery: &root.recovery_declaration_sha256,
                conflict: &root.conflict_declaration_sha256,
            };
            root.proof_of_possession_signature = hex(signer
                .sign(&message(ROOT_POP_DOMAIN, &pop).unwrap())
                .as_ref());
            roots.push(root);
        }
        let anchor = TrustAnchorPackage {
            schema: "postern.bridge-authority-trust-anchor.v1".into(),
            domain: "bloch-bridge-authority-trust-v1".into(),
            package_sequence: "1".into(),
            previous_package_sha256: zero,
            roots,
        };
        let anchor_digest: [u8; 32] = Sha256::digest(serde_json::to_vec(&anchor).unwrap()).into();
        let authority_keys: Vec<_> = (0..8).map(|_| key()).collect();
        let manifest = digest("manifest");
        let ceremony = digest("ceremony");
        let mut authorities = Vec::new();
        for (index, (role, signer)) in ROLES.iter().zip(&authority_keys).enumerate() {
            let mut authority = OperationalAuthority {
                role: (*role).into(),
                authority_id: digest(&format!("authority-id-{index}")),
                organization_id: digest(&format!("authority-org-{index}")),
                public_key: hex(signer.public_key().as_ref()),
                appointment_record_sha256: digest(&format!("appointment-{index}")),
                recovery_declaration_sha256: digest(&format!("recovery-{index}")),
                conflict_declaration_sha256: digest(&format!("conflict-{index}")),
                proof_of_possession_signature: hex(&[2; 64]),
            };
            let pop = OperationalPop {
                role: &authority.role,
                authority_id: &authority.authority_id,
                organization_id: &authority.organization_id,
                public_key: &authority.public_key,
                appointment: &authority.appointment_record_sha256,
                recovery: &authority.recovery_declaration_sha256,
                conflict: &authority.conflict_declaration_sha256,
                manifest: &manifest,
                ceremony: &ceremony,
            };
            authority.proof_of_possession_signature = hex(signer
                .sign(&message(AUTHORITY_POP_DOMAIN, &pop).unwrap())
                .as_ref());
            authorities.push(authority);
        }
        let mut operational = OperationalAuthorityPackage {
            schema: "postern.bridge-operational-authority-package.v1".into(),
            manifest_canonical_sha256: manifest,
            ceremony_package_canonical_sha256: ceremony,
            custody_threshold: 3,
            authorities,
            root_approvals: vec![],
        };
        let unsigned = OperationalUnsigned {
            schema: &operational.schema,
            manifest: &operational.manifest_canonical_sha256,
            ceremony: &operational.ceremony_package_canonical_sha256,
            threshold: operational.custody_threshold,
            authorities: &operational.authorities,
        };
        let mut approval = APPROVAL_DOMAIN.to_vec();
        approval.extend_from_slice(&anchor_digest);
        approval.extend(serde_json::to_vec(&unsigned).unwrap());
        for (root, signer) in anchor.roots.iter().zip(&root_keys).take(2) {
            operational.root_approvals.push(RootApproval {
                authority_id: root.authority_id.clone(),
                signature: hex(signer.sign(&approval).as_ref()),
            });
        }
        (
            TrustIntake {
                schema: "postern.bridge-authority-trust-intake.v1".into(),
                trust_anchor_package: anchor,
                operational_authority_package: operational,
            },
            anchor_digest,
        )
    }

    #[test]
    fn independent_anchor_possession_and_quorum_are_verified() {
        let (intake, anchor) = fixture();
        assert!(verify_trust_intake(&intake, &anchor).is_ok());
    }

    #[test]
    fn self_selected_anchor_and_signature_substitution_fail() {
        let (mut intake, anchor) = fixture();
        let attacker_anchor: [u8; 32] = Sha256::digest(b"attacker anchor").into();
        assert!(verify_trust_intake(&intake, &attacker_anchor).is_err());
        intake.operational_authority_package.root_approvals[0].signature =
            intake.operational_authority_package.root_approvals[1]
                .signature
                .clone();
        assert!(verify_trust_intake(&intake, &anchor).is_err());
    }

    #[test]
    fn overlaps_missing_quorum_and_changed_declarations_fail() {
        let (mut intake, anchor) = fixture();
        intake.operational_authority_package.authorities[0].organization_id =
            intake.trust_anchor_package.roots[0].organization_id.clone();
        assert!(verify_trust_intake(&intake, &anchor).is_err());

        let (mut intake, anchor) = fixture();
        intake.operational_authority_package.root_approvals.pop();
        assert!(verify_trust_intake(&intake, &anchor).is_err());

        let (mut intake, anchor) = fixture();
        intake.operational_authority_package.authorities[0].recovery_declaration_sha256 =
            digest("changed recovery");
        assert!(verify_trust_intake(&intake, &anchor).is_err());
    }
}
