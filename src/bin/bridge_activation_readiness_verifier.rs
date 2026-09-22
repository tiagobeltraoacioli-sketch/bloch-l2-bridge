//! Exact-package verifier for a separately reviewed bridge readiness request.
//!
//! The request and its review-critical semantic commitments are compiled into
//! the executable. JSON must use the composer's unique canonical encoding. An
//! ordinary build has no pins and refuses every request.

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fmt::Write as _,
    io::{self, Read},
};

const REQUEST_DOMAIN: &[u8] = b"BLOCH-BRIDGE-ACTIVATION-READINESS-v3\0";
const MAX_REQUEST_BYTES: u64 = 128 * 1024;

#[derive(Clone, Copy)]
struct ReviewPins<'a> {
    request: Option<&'a str>,
    manifest: Option<&'a str>,
    route: Option<&'a str>,
    authority_policy: Option<&'a str>,
    approval_package: Option<&'a str>,
    settlement: Option<&'a str>,
    deployment: Option<&'a str>,
    cycle: Option<&'a str>,
    external_qualification: Option<&'a str>,
}

const REVIEW_PINS: ReviewPins<'static> = ReviewPins {
    request: option_env!("BLOCH_BRIDGE_READINESS_COMMITMENT_SHA256"),
    manifest: option_env!("BLOCH_BRIDGE_MANIFEST_SHA256"),
    route: option_env!("BLOCH_BRIDGE_ROUTE_ID"),
    authority_policy: option_env!("BLOCH_BRIDGE_AUTHORITY_POLICY_SHA256"),
    approval_package: option_env!("BLOCH_BRIDGE_APPROVAL_PACKAGE_SHA256"),
    settlement: option_env!("BLOCH_BRIDGE_SETTLEMENT_VERIFICATION_SHA256"),
    deployment: option_env!("BLOCH_BRIDGE_DEPLOYMENT_VERIFICATION_SHA256"),
    cycle: option_env!("BLOCH_BRIDGE_DISPOSABLE_CYCLE_SHA256"),
    external_qualification: option_env!("BLOCH_BRIDGE_EXTERNAL_AUTHORITY_QUALIFICATION_SHA256"),
};

fn pin(value: Option<&str>, label: &str) -> Result<[u8; 32], String> {
    let value = value.ok_or_else(|| format!("{label} was not embedded at build time"))?;
    let value = value
        .strip_prefix("0x")
        .ok_or_else(|| format!("{label} lacks 0x prefix"))?;
    if value.len() != 64
        || !value.bytes().all(|b| b.is_ascii_hexdigit())
        || value.bytes().any(|b| b.is_ascii_uppercase())
    {
        return Err(format!("{label} must be a lowercase 32-byte digest"));
    }
    let mut result = [0; 32];
    for (index, slot) in result.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| format!("invalid {label}"))?;
    }
    if !result.iter().any(|b| *b != 0) || result.windows(2).all(|p| p[0] == p[1]) {
        return Err(format!("placeholder {label} refused"));
    }
    Ok(result)
}

fn object<'a>(value: &'a Value, label: &str) -> Result<&'a Map<String, Value>, String> {
    value
        .as_object()
        .ok_or_else(|| format!("{label} must be an object"))
}

fn string_field<'a>(object: &'a Map<String, Value>, name: &str) -> Result<&'a str, String> {
    object
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing or invalid {name}"))
}

fn require_schema(object: &Map<String, Value>, expected: &str, label: &str) -> Result<(), String> {
    if string_field(object, "schema")? != expected {
        return Err(format!("unsupported {label} schema"));
    }
    Ok(())
}

fn sha256(value: &[u8]) -> [u8; 32] {
    Sha256::digest(value).into()
}

fn canonical_sha256(value: &Value) -> Result<[u8; 32], String> {
    serde_json::to_vec(value)
        .map(|bytes| sha256(&bytes))
        .map_err(|_| "readiness value cannot be serialized".into())
}

fn field_pin(object: &Map<String, Value>, name: &str, label: &str) -> Result<[u8; 32], String> {
    pin(Some(string_field(object, name)?), label)
}

fn verify_semantics(bundle: &Value, pins: ReviewPins<'_>) -> Result<(), String> {
    let root = object(bundle, "readiness bundle")?;
    let actual: BTreeSet<&str> = root.keys().map(String::as_str).collect();
    let expected = BTreeSet::from([
        "schema",
        "manifest",
        "settlementVerification",
        "deploymentVerification",
        "authorityPolicy",
        "authorityQualification",
        "externalAuthorityQualification",
        "disposableCycle",
    ]);
    if actual != expected {
        return Err("readiness bundle requires exact top-level fields".into());
    }
    require_schema(
        root,
        "postern.bridge-activation-readiness.v3",
        "readiness bundle",
    )?;

    let get = |name| root.get(name).ok_or_else(|| format!("missing {name}"));
    let manifest_value = get("manifest")?;
    let settlement_value = get("settlementVerification")?;
    let deployment_value = get("deploymentVerification")?;
    let policy_value = get("authorityPolicy")?;
    let authority_value = get("authorityQualification")?;
    let external_authority_value = get("externalAuthorityQualification")?;
    let cycle_value = get("disposableCycle")?;
    let manifest = object(manifest_value, "manifest")?;
    let settlement = object(settlement_value, "settlement verification")?;
    let deployment = object(deployment_value, "deployment verification")?;
    let policy = object(policy_value, "authority policy")?;
    let authority = object(authority_value, "authority qualification")?;
    let external_authority = object(external_authority_value, "external authority qualification")?;
    let cycle = object(cycle_value, "disposable cycle")?;

    require_schema(manifest, "postern.custody-deployment-plan.v1", "manifest")?;
    require_schema(
        settlement,
        "postern.l2-native-settlement-verification.v1",
        "settlement verification",
    )?;
    require_schema(
        deployment,
        "postern.custody-deployment-verification.v1",
        "deployment verification",
    )?;
    require_schema(
        policy,
        "postern.bridge-authority-policy.v2",
        "authority policy",
    )?;
    require_schema(
        authority,
        "postern.bridge-authority-qualification.v2",
        "authority qualification",
    )?;
    require_schema(
        external_authority,
        "postern.bridge-authority-external-qualification.v3",
        "external authority qualification",
    )?;
    require_schema(
        cycle,
        "postern.bridge-disposable-cycle.v1",
        "disposable cycle",
    )?;

    let manifest_pin = pin(pins.manifest, "manifest pin")?;
    let route_pin = pin(pins.route, "route pin")?;
    let policy_pin = pin(pins.authority_policy, "authority policy pin")?;
    let approval_pin = pin(pins.approval_package, "approval package pin")?;
    let settlement_pin = pin(pins.settlement, "settlement verification pin")?;
    let deployment_pin = pin(pins.deployment, "deployment verification pin")?;
    let cycle_pin = pin(pins.cycle, "disposable cycle pin")?;
    let external_qualification_pin = pin(
        pins.external_qualification,
        "external authority qualification pin",
    )?;
    if canonical_sha256(manifest_value)? != manifest_pin
        || canonical_sha256(settlement_value)? != settlement_pin
        || canonical_sha256(deployment_value)? != deployment_pin
        || canonical_sha256(cycle_value)? != cycle_pin
        || canonical_sha256(external_authority_value)? != external_qualification_pin
    {
        return Err("reviewed artifact commitment mismatch".into());
    }
    if field_pin(
        external_authority,
        "authorityPolicySha256",
        "external qualification authority policy pin",
    )? != policy_pin
        || field_pin(
            external_authority,
            "manifestCanonicalSha256",
            "external qualification manifest pin",
        )? != manifest_pin
        || field_pin(
            external_authority,
            "custodyCeremonySha256",
            "external qualification custody ceremony pin",
        )? != field_pin(
            authority,
            "custodyCeremonySha256",
            "authority custody ceremony",
        )?
        || field_pin(
            external_authority,
            "nativeRolesCeremonySha256",
            "external qualification native roles ceremony pin",
        )? != field_pin(
            authority,
            "nativeRolesCeremonySha256",
            "authority native roles ceremony",
        )?
    {
        return Err("external authority qualification binding mismatch".into());
    }
    if field_pin(
        policy,
        "authorityPolicySha256",
        "embedded authority policy pin",
    )? != policy_pin
        || field_pin(
            authority,
            "authorityPolicySha256",
            "qualified authority policy pin",
        )? != policy_pin
        || field_pin(authority, "approvalPackageSha256", "approval package pin")? != approval_pin
        || field_pin(
            authority,
            "settlementVerificationSha256",
            "settlement verification pin",
        )? != settlement_pin
        || field_pin(
            authority,
            "deploymentVerificationSha256",
            "deployment verification pin",
        )? != deployment_pin
    {
        return Err("reviewed package pin mismatch".into());
    }
    for (part, label) in [
        (settlement, "settlement"),
        (deployment, "deployment"),
        (authority, "authority"),
        (cycle, "cycle"),
    ] {
        if field_pin(part, "routeId", label)? != route_pin {
            return Err(format!("{label} binds another route"));
        }
    }
    for (part, label) in [
        (deployment, "deployment"),
        (policy, "authority policy"),
        (authority, "authority"),
        (cycle, "cycle"),
    ] {
        if field_pin(part, "manifestCanonicalSha256", label)? != manifest_pin {
            return Err(format!("{label} binds another manifest"));
        }
    }
    Ok(())
}

fn verify_request(request: &[u8], pins: ReviewPins<'_>) -> Result<[u8; 32], String> {
    if request.len() > MAX_REQUEST_BYTES as usize || !request.starts_with(REQUEST_DOMAIN) {
        return Err("invalid readiness request framing".into());
    }
    let payload = &request[REQUEST_DOMAIN.len()..];
    if !payload.is_ascii() {
        return Err("readiness bundle must use canonical ASCII JSON".into());
    }
    let bundle: Value =
        serde_json::from_slice(payload).map_err(|_| "invalid readiness bundle".to_string())?;
    let canonical = serde_json::to_vec(&bundle)
        .map_err(|_| "readiness bundle cannot be serialized".to_string())?;
    if canonical != payload {
        return Err("non-canonical readiness bundle".into());
    }
    verify_semantics(&bundle, pins)?;
    let actual = sha256(request);
    if actual != pin(pins.request, "readiness commitment")? {
        return Err("readiness request commitment mismatch".into());
    }
    Ok(actual)
}

fn lowercase_hex(value: &[u8]) -> String {
    let mut encoded = String::with_capacity(value.len() * 2);
    for byte in value {
        write!(&mut encoded, "{byte:02x}").expect("String write cannot fail");
    }
    encoded
}

fn run() -> Result<(), String> {
    if std::env::args_os().len() != 1 {
        return Err("readiness verifier accepts no runtime configuration".into());
    }
    let mut request = Vec::new();
    io::stdin()
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut request)
        .map_err(|e| e.to_string())?;
    println!("{}", lowercase_hex(&verify_request(&request, REVIEW_PINS)?));
    Ok(())
}

fn main() {
    if run().is_err() {
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn digest(value: &[u8]) -> String {
        format!("0x{:x}", Sha256::digest(value))
    }
    fn canonical_digest(value: &Value) -> String {
        digest(&serde_json::to_vec(value).unwrap())
    }

    fn fixture() -> (Vec<u8>, [String; 9]) {
        let route = digest(b"route");
        let manifest = json!({"schema":"postern.custody-deployment-plan.v1"});
        let manifest_digest = canonical_digest(&manifest);
        let settlement =
            json!({"routeId":route,"schema":"postern.l2-native-settlement-verification.v1"});
        let deployment = json!({"manifestCanonicalSha256":manifest_digest,"routeId":route,
            "schema":"postern.custody-deployment-verification.v1"});
        let policy_digest = digest(b"policy");
        let policy = json!({"authorityPolicySha256":policy_digest,"manifestCanonicalSha256":manifest_digest,
            "schema":"postern.bridge-authority-policy.v2"});
        let settlement_digest = canonical_digest(&settlement);
        let deployment_digest = canonical_digest(&deployment);
        let approval_digest = digest(b"approval");
        let custody_ceremony = digest(b"custody-ceremony");
        let native_roles_ceremony = digest(b"native-roles-ceremony");
        let authority = json!({"approvalPackageSha256":approval_digest,"authorityPolicySha256":policy_digest,
            "custodyCeremonySha256":custody_ceremony,
            "deploymentVerificationSha256":deployment_digest,"manifestCanonicalSha256":manifest_digest,
            "nativeRolesCeremonySha256":native_roles_ceremony,
            "routeId":route,"schema":"postern.bridge-authority-qualification.v2",
            "settlementVerificationSha256":settlement_digest});
        let external_authority = json!({
            "authorityPolicySha256":policy_digest,
            "custodyCeremonySha256":custody_ceremony,
            "manifestCanonicalSha256":manifest_digest,
            "nativeRolesCeremonySha256":native_roles_ceremony,
            "schema":"postern.bridge-authority-external-qualification.v3"
        });
        let external_authority_digest = canonical_digest(&external_authority);
        let cycle = json!({"manifestCanonicalSha256":manifest_digest,"routeId":route,
            "schema":"postern.bridge-disposable-cycle.v1"});
        let cycle_digest = canonical_digest(&cycle);
        let bundle = json!({"authorityPolicy":policy,"authorityQualification":authority,
            "deploymentVerification":deployment,"disposableCycle":cycle,
            "externalAuthorityQualification":external_authority,"manifest":manifest,
            "schema":"postern.bridge-activation-readiness.v3","settlementVerification":settlement});
        let request = [REQUEST_DOMAIN, &serde_json::to_vec(&bundle).unwrap()].concat();
        let pins = [
            digest(&request),
            manifest_digest,
            route,
            policy_digest,
            approval_digest,
            settlement_digest,
            deployment_digest,
            cycle_digest,
            external_authority_digest,
        ];
        (request, pins)
    }

    fn pins(v: &[String; 9]) -> ReviewPins<'_> {
        ReviewPins {
            request: Some(&v[0]),
            manifest: Some(&v[1]),
            route: Some(&v[2]),
            authority_policy: Some(&v[3]),
            approval_package: Some(&v[4]),
            settlement: Some(&v[5]),
            deployment: Some(&v[6]),
            cycle: Some(&v[7]),
            external_qualification: Some(&v[8]),
        }
    }

    #[test]
    fn only_canonical_semantically_pinned_request_is_accepted() {
        let (request, values) = fixture();
        assert_eq!(
            verify_request(&request, pins(&values)).unwrap(),
            sha256(&request)
        );
        let mut noncanonical = request.clone();
        noncanonical.push(b' ');
        let mut changed = values.clone();
        changed[0] = digest(&noncanonical);
        assert!(verify_request(&noncanonical, pins(&changed)).is_err());
    }

    #[test]
    fn every_review_pin_is_mandatory_and_binding() {
        let (request, values) = fixture();
        for index in 0..values.len() {
            let mut absent = pins(&values);
            match index {
                0 => absent.request = None,
                1 => absent.manifest = None,
                2 => absent.route = None,
                3 => absent.authority_policy = None,
                4 => absent.approval_package = None,
                5 => absent.settlement = None,
                6 => absent.deployment = None,
                7 => absent.cycle = None,
                8 => absent.external_qualification = None,
                _ => unreachable!(),
            }
            assert!(
                verify_request(&request, absent).is_err(),
                "missing pin {index}"
            );
            let mut changed = values.clone();
            changed[index] = digest(format!("other-{index}").as_bytes());
            assert!(verify_request(&request, pins(&changed)).is_err());
        }
    }

    #[test]
    fn framing_schema_and_placeholders_fail_closed() {
        let (request, values) = fixture();
        let wrong = [b"BLOCH-BRIDGE-ACTIVATION-READINESS-v1\0".as_slice(), b"{}"].concat();
        assert!(verify_request(&wrong, pins(&values)).is_err());
        let oversized = vec![b'x'; MAX_REQUEST_BYTES as usize + 1];
        assert!(verify_request(&oversized, pins(&values)).is_err());
        let mut placeholder = values.clone();
        placeholder[3] = format!("0x{}", "11".repeat(32));
        assert!(verify_request(&request, pins(&placeholder)).is_err());
    }
}
