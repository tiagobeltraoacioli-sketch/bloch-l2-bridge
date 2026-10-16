"""Strict public-input preflight for bridge authority ceremonies.

This module binds eight public authority appointments and three ceremony
records to one already-qualified custody manifest and authority policy.  It
does not authenticate the referenced records and can never authorize a key,
deployment, transaction, bridge operation or activation.
"""
import hashlib

from custody_deployment_manifest import (
    canonical_sha256,
    validate_custody_deployment_manifest,
)
from usdt_observer.common import require, word


APPOINTMENT_FIELDS = {
    "role", "operatorId", "organizationId", "publicKeySha256", "sourceSigner",
    "custodyAttestationSha256", "appointmentRecordSha256",
    "keyCeremonyRecordSha256", "recoveryProcedureSha256", "conflictCheckSha256",
}
CEREMONY_FIELDS = {
    "schema", "participants", "threshold", "transcriptSha256",
    "recoveryExerciseSha256", "independentWitnessReportSha256",
}
PACKAGE_FIELDS = {
    "schema", "manifest", "authorityPolicy", "appointments", "custodyCeremony",
    "nativeRolesCeremony", "activationAuthorityCeremony", "controls",
}
POLICY_FIELDS = {
    "schema", "manifestCanonicalSha256", "activationAuthority",
    "authorityPolicySha256",
}
ACTIVATION_AUTHORITY_FIELDS = {
    "operatorId", "organizationId", "algorithm", "publicKey",
    "custodyAttestationSha256",
}
CONTROLS = {
    "keysLoaded": False,
    "signingAllowed": False,
    "deploymentAllowed": False,
    "broadcastAllowed": False,
    "activationAuthorized": False,
}
ROLES = tuple([f"custodian-{index}" for index in range(1, 6)] + [
    "native-issuer", "fee-sponsor", "activation-authority",
])


def _fields(value, expected, label):
    require(type(value) is dict and set(value) == expected,
            f"{label}: exact fields required")


def _pin(value, size, label):
    raw = word(value, size)
    require(any(raw) and len(set(raw)) > 1,
            f"{label}: non-placeholder value required")
    return raw


def _policy(policy, manifest, manifest_digest):
    _fields(policy, POLICY_FIELDS, "authority policy")
    require(policy["schema"] == "postern.bridge-authority-policy.v2",
            "unsupported authority policy")
    require(policy["manifestCanonicalSha256"].lower() == manifest_digest.lower(),
            "authority policy binds another manifest")
    authority = policy["activationAuthority"]
    _fields(authority, ACTIVATION_AUTHORITY_FIELDS, "activation authority")
    require(authority["algorithm"] == "ed25519",
            "Ed25519 activation authority required")
    operator = _pin(authority["operatorId"], 32, "activation operator")
    organization = _pin(authority["organizationId"], 32, "activation organization")
    public_key = _pin(authority["publicKey"], 32, "activation public key")
    attestation = _pin(
        authority["custodyAttestationSha256"], 32, "activation custody attestation"
    )
    expected = canonical_sha256({
        "schema": "postern.bridge-authority-policy.v2",
        "custody": manifest["custody"],
        "roles": manifest["roles"],
        "activationAuthority": authority,
    })
    require(policy["authorityPolicySha256"].lower() == expected.lower(),
            "authority policy commitment mismatch")
    operational = list(manifest["custody"]["custodians"]) + [
        manifest["roles"]["issuer"], manifest["roles"]["sponsor"]
    ]
    require(operator not in {word(item["operator_id"], 32) for item in operational},
            "activation operator must be independent")
    require(organization not in {
        word(item["organization_id"], 32) for item in operational
    }, "activation organization must be independent")
    require(hashlib.sha256(public_key).digest() not in {
        word(item["bloch_public_key_sha256"], 32) for item in operational
    }, "activation public key must be independent")
    require(attestation not in {
        word(item["custody_attestation_sha256"], 32) for item in operational
    }, "activation custody attestation must be independent")
    return operator, organization, hashlib.sha256(public_key).digest(), attestation


def _appointment(value, expected, source_signer):
    _fields(value, APPOINTMENT_FIELDS, f"{expected['role']} appointment")
    require(value["role"] == expected["role"], "appointment order or role mismatch")
    for field, size in (
        ("operatorId", 32), ("organizationId", 32), ("publicKeySha256", 32),
        ("custodyAttestationSha256", 32), ("appointmentRecordSha256", 32),
        ("keyCeremonyRecordSha256", 32), ("recoveryProcedureSha256", 32),
        ("conflictCheckSha256", 32),
    ):
        raw = _pin(value[field], size, f"{value['role']} {field}")
        if field in expected:
            require(raw == expected[field], f"{value['role']} {field} mismatch")
    if source_signer is None:
        require(value["sourceSigner"] is None,
                f"{value['role']} must not claim an Ethereum signer")
    else:
        require(_pin(value["sourceSigner"], 20, f"{value['role']} source signer")
                == source_signer, f"{value['role']} source signer mismatch")


def _ceremony(value, schema, participants, threshold, label):
    _fields(value, CEREMONY_FIELDS, label)
    require(value["schema"] == schema, f"unsupported {label} schema")
    require(type(value["participants"]) is list
            and value["participants"] == list(participants),
            f"{label}: exact ordered participants required")
    require(type(value["threshold"]) is int and not isinstance(value["threshold"], bool)
            and value["threshold"] == threshold, f"{label}: threshold mismatch")
    for field in (
        "transcriptSha256", "recoveryExerciseSha256", "independentWitnessReportSha256"
    ):
        _pin(value[field], 32, f"{label} {field}")
    return canonical_sha256(value)


def verify_bridge_authority_ceremony(package):
    """Validate public ceremony bindings and return a non-authorizing report."""
    _fields(package, PACKAGE_FIELDS, "authority ceremony package")
    require(package["schema"] == "postern.bridge-authority-ceremony-package.v1",
            "unsupported authority ceremony package")
    manifest = package["manifest"]
    validate_custody_deployment_manifest(manifest)
    manifest_digest = canonical_sha256(manifest)

    activation = _policy(package["authorityPolicy"], manifest, manifest_digest)

    expected = []
    for index, custodian in enumerate(manifest["custody"]["custodians"], 1):
        expected.append(({
            "role": f"custodian-{index}",
            "operatorId": word(custodian["operator_id"], 32),
            "organizationId": word(custodian["organization_id"], 32),
            "publicKeySha256": word(custodian["bloch_public_key_sha256"], 32),
            "custodyAttestationSha256": word(
                custodian["custody_attestation_sha256"], 32
            ),
        }, word(custodian["ethereum_signer"], 20)))
    for role, name in (("native-issuer", "issuer"), ("fee-sponsor", "sponsor")):
        authority = manifest["roles"][name]
        expected.append(({
            "role": role,
            "operatorId": word(authority["operator_id"], 32),
            "organizationId": word(authority["organization_id"], 32),
            "publicKeySha256": word(authority["bloch_public_key_sha256"], 32),
            "custodyAttestationSha256": word(
                authority["custody_attestation_sha256"], 32
            ),
        }, None))
    expected.append(({
        "role": "activation-authority", "operatorId": activation[0],
        "organizationId": activation[1], "publicKeySha256": activation[2],
        "custodyAttestationSha256": activation[3],
    }, None))

    appointments = package["appointments"]
    require(type(appointments) is list and len(appointments) == 8,
            "exactly eight ordered appointments required")
    for appointment, (binding, signer) in zip(appointments, expected):
        _appointment(appointment, binding, signer)
    appointment_artifacts = []
    for field in (
        "appointmentRecordSha256", "keyCeremonyRecordSha256",
        "recoveryProcedureSha256", "conflictCheckSha256",
    ):
        values = [word(item[field], 32) for item in appointments]
        require(len(set(values)) == 8,
                f"each authority requires a distinct {field}")
        appointment_artifacts.extend(values)
    require(len(set(appointment_artifacts)) == len(appointment_artifacts),
            "appointment evidence records must be globally distinct")

    custody_digest = _ceremony(
        package["custodyCeremony"], "postern.bridge-custody-ceremony.v1", ROLES[:5], 3,
        "custody ceremony",
    )
    native_digest = _ceremony(
        package["nativeRolesCeremony"], "postern.bridge-native-roles-ceremony.v1",
        ROLES[5:7], 1, "native roles ceremony",
    )
    activation_digest = _ceremony(
        package["activationAuthorityCeremony"],
        "postern.bridge-activation-authority-ceremony.v1", ROLES[7:], 1,
        "activation authority ceremony",
    )
    ceremony_artifacts = [
        word(package[name][field], 32)
        for name in (
            "custodyCeremony", "nativeRolesCeremony", "activationAuthorityCeremony"
        )
        for field in (
            "transcriptSha256", "recoveryExerciseSha256",
            "independentWitnessReportSha256",
        )
    ]
    require(len(set(ceremony_artifacts)) == len(ceremony_artifacts),
            "ceremony evidence records must be globally distinct")
    require(not set(ceremony_artifacts).intersection(appointment_artifacts),
            "ceremony and appointment evidence records must be distinct")
    require(type(package["controls"]) is dict
            and all(type(value) is bool for value in package["controls"].values())
            and package["controls"] == CONTROLS,
            "ceremony controls must remain disabled and unauthorized")

    return {
        "schema": "postern.bridge-authority-ceremony-preflight.v1",
        "packageCanonicalSha256": canonical_sha256(package),
        "manifestCanonicalSha256": manifest_digest,
        "authorityPolicySha256": package["authorityPolicy"]["authorityPolicySha256"].lower(),
        "custodyCeremonySha256": custody_digest,
        "nativeRolesCeremonySha256": native_digest,
        "activationAuthorityCeremonySha256": activation_digest,
        "authorityCount": 8,
        "custodyThreshold": 3,
        "publicBindingsConsistent": True,
        "externalRecordsAuthenticated": False,
        "custodyQualified": False,
        "authoritiesQualified": False,
        "keysLoaded": False,
        "signingAllowed": False,
        "deploymentAllowed": False,
        "broadcastAllowed": False,
        "activationAuthorized": False,
    }
