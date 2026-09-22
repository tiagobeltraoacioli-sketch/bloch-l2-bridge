"""Compose authenticated bridge prerequisites without changing bridge state.

The custody and settlement checkers intentionally emit non-authorizing
reports.  This module binds those reports to an authority qualification and a
disposable-value round trip, requires the checksum-pinned approval subverifier,
then asks a separate immutable checksum-pinned verifier to authenticate the
complete package. It has no RPC, key, signing, broadcast, mint, release, pause
or activation capability.
"""
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile

from custody_deployment_manifest import canonical_sha256
from usdt_observer.common import UINT64_MAX, require, word
from usdt_observer.verifier_process import run_verifier


DOMAIN = b"BLOCH-BRIDGE-ACTIVATION-READINESS-v3\0"
MAX_VERIFIER_BYTES = 64 * 1024 * 1024
MAX_REQUEST_BYTES = 128 * 1024
MAX_DISPOSABLE_BASE_UNITS = 10_000_000  # 10 USDC at six decimals.
MAX_APPROVAL_CHECKPOINT_AGE = 32
MAX_APPROVAL_LIFETIME = 720
SETTLEMENT_FIELDS = {
    "schema", "routeId", "l2ChainId", "l2BlockNumber", "l2BlockHash",
    "nativeCheckpointHeight", "nativeCheckpointRoot", "nativeSettlementRecord",
    "verifierSha256", "evidenceCommitmentSha256", "settlementGateSatisfied",
    "finalityVerifiedForSettlement", "activationAuthorized", "mintAuthorized",
    "releaseAuthorized", "bridgeReady",
}
DEPLOYMENT_FIELDS = {
    "schema", "manifestCanonicalSha256", "transactionHash", "blockHash",
    "blockNumber", "vaultAddress", "routeId", "creationInputSha256",
    "tokenProxyRuntimeSha256", "tokenImplementationRuntimeSha256",
    "vaultRuntimeSha256", "finalizedReceiptConsistent", "constructorStateMatched",
    "committeeMatched", "tokenProxyImplementationMatched", "paused", "empty",
    "sourceRpcAuthenticated", "deploymentAuthenticated", "activationAuthorized",
    "broadcastAllowed",
}
AUTHORITY_FIELDS = {
    "schema", "manifestCanonicalSha256", "routeId", "custodianCount",
    "custodyThreshold", "distinctAuthorityCount", "authorityPolicySha256",
    "custodyCeremonySha256", "nativeRolesCeremonySha256",
    "settlementVerificationSha256", "deploymentVerificationSha256",
    "sourceDeploymentAuthenticated", "nativeGatewayAuthenticated",
    "settlementAuthenticated", "activationApprovalSha256",
    "activationApprovalSignature",
    "approvalCheckpointHeight", "observedNativeHeight", "approvalValidUntilHeight",
    "approvalSequence", "previousApprovalSha256", "approvalPackageSha256",
    "decision",
}
AUTHORITY_POLICY_FIELDS = {
    "schema", "manifestCanonicalSha256", "activationAuthority",
    "authorityPolicySha256",
}
ACTIVATION_AUTHORITY_FIELDS = {
    "operatorId", "organizationId", "algorithm", "publicKey",
    "custodyAttestationSha256",
}
CYCLE_FIELDS = {
    "schema", "manifestCanonicalSha256", "routeId", "deploymentTransactionHash",
    "settlementEvidenceCommitmentSha256", "amountBaseUnits", "depositTransactionHash",
    "nativeMintTransactionId", "nativeBurnTransactionId", "releaseTransactionHash",
    "sourceLockedBefore", "sourceLockedAfter", "nativeSupplyBefore",
    "nativeSupplyAfter", "reserveReconciliationSha256", "rollbackExerciseSha256",
    "depositVerified", "mintVerified", "burnVerified", "releaseVerified",
    "sourceReserveReconciled", "nativeSupplyReconciled", "rollbackPauseExercised",
}
BUNDLE_FIELDS = {
    "schema", "manifest", "settlementVerification", "deploymentVerification",
    "authorityPolicy", "authorityQualification", "externalAuthorityQualification",
    "disposableCycle",
}
EXTERNAL_QUALIFICATION_FIELDS = {
    "schema", "ceremonyPackageCanonicalSha256", "manifestCanonicalSha256",
    "authorityPolicySha256", "custodyCeremonySha256",
    "nativeRolesCeremonySha256", "activationAuthorityCeremonySha256",
    "reviewPolicySha256", "reviewerCount", "reviewThreshold",
    "externalRecordsAuthenticated", "custodyQualified", "authoritiesQualified",
    "keysLoaded", "signingAllowed", "deploymentAllowed", "broadcastAllowed",
    "activationAuthorized",
}


def _fields(value, expected, label):
    require(type(value) is dict and set(value) == expected,
            f"{label}: exact fields required")


def _boolean(value, expected, label):
    require(type(value) is bool and value is expected, f"{label}: {expected} required")


def _pin(value, label):
    raw = word(value, 32)
    require(any(raw) and len(set(raw)) > 1, f"{label}: non-placeholder hash required")
    return raw


def _decimal(value, label, *, positive=False):
    require(
        type(value) is str and 1 <= len(value) <= 20 and value.isascii()
        and value.isdecimal() and (value == "0" or value[0] != "0"),
        f"{label}: canonical uint64 required",
    )
    number = int(value)
    require(number <= UINT64_MAX and (not positive or number > 0),
            f"{label}: canonical uint64 required")
    return number


def _validate_settlement(report):
    _fields(report, SETTLEMENT_FIELDS, "settlement verification")
    require(report["schema"] == "postern.l2-native-settlement-verification.v1",
            "unsupported settlement verification")
    require(type(report["l2ChainId"]) is int and report["l2ChainId"] == 700771,
            "selected L2 chain required")
    _decimal(report["l2BlockNumber"], "settled L2 block", positive=True)
    _decimal(report["nativeCheckpointHeight"], "native checkpoint", positive=True)
    for field in ("routeId", "l2BlockHash", "nativeCheckpointRoot",
                  "nativeSettlementRecord", "verifierSha256",
                  "evidenceCommitmentSha256"):
        _pin(report[field], f"settlement {field}")
    for field in ("settlementGateSatisfied", "finalityVerifiedForSettlement"):
        _boolean(report[field], True, f"settlement {field}")
    for field in ("activationAuthorized", "mintAuthorized", "releaseAuthorized",
                  "bridgeReady"):
        _boolean(report[field], False, f"settlement {field}")


def _validate_deployment(report):
    _fields(report, DEPLOYMENT_FIELDS, "deployment verification")
    require(report["schema"] == "postern.custody-deployment-verification.v1",
            "unsupported deployment verification")
    _decimal(report["blockNumber"], "deployment block", positive=True)
    word(report["vaultAddress"], 20)
    for field in (
        "manifestCanonicalSha256", "transactionHash", "blockHash", "routeId",
        "creationInputSha256", "tokenProxyRuntimeSha256",
        "tokenImplementationRuntimeSha256", "vaultRuntimeSha256",
    ):
        _pin(report[field], f"deployment {field}")
    for field in (
        "finalizedReceiptConsistent", "constructorStateMatched", "committeeMatched",
        "tokenProxyImplementationMatched", "paused", "empty",
    ):
        _boolean(report[field], True, f"deployment {field}")
    for field in ("sourceRpcAuthenticated", "deploymentAuthenticated",
                  "activationAuthorized", "broadcastAllowed"):
        _boolean(report[field], False, f"deployment {field}")


def _validate_authority(report):
    _fields(report, AUTHORITY_FIELDS, "authority qualification")
    require(report["schema"] == "postern.bridge-authority-qualification.v2",
            "unsupported authority qualification")
    require(type(report["custodianCount"]) is int and report["custodianCount"] == 5,
            "five qualified custodians required")
    require(type(report["custodyThreshold"]) is int
            and report["custodyThreshold"] == 3, "three-of-five custody required")
    require(type(report["distinctAuthorityCount"]) is int
            and report["distinctAuthorityCount"] == 8,
            "custodians, issuer, sponsor and activation authority must remain distinct")
    for field in (
        "manifestCanonicalSha256", "routeId", "authorityPolicySha256",
        "custodyCeremonySha256", "nativeRolesCeremonySha256",
        "settlementVerificationSha256", "deploymentVerificationSha256",
        "activationApprovalSha256", "approvalPackageSha256",
    ):
        _pin(report[field], f"authority {field}")
    signature = word(report["activationApprovalSignature"], 64)
    require(any(signature) and len(set(signature)) > 1,
            "authority activationApprovalSignature: non-placeholder signature required")
    for field in ("sourceDeploymentAuthenticated", "nativeGatewayAuthenticated",
                  "settlementAuthenticated"):
        _boolean(report[field], True, f"authority {field}")
    checkpoint = _decimal(
        report["approvalCheckpointHeight"], "approval checkpoint", positive=True
    )
    observed = _decimal(
        report["observedNativeHeight"], "approval observation", positive=True
    )
    valid_until = _decimal(
        report["approvalValidUntilHeight"], "approval expiry", positive=True
    )
    require(checkpoint <= observed <= valid_until,
            "activation approval is future-dated or expired")
    require(observed - checkpoint <= MAX_APPROVAL_CHECKPOINT_AGE,
            "activation approval checkpoint is stale")
    require(valid_until - checkpoint <= MAX_APPROVAL_LIFETIME,
            "activation approval lifetime exceeds policy")
    sequence = _decimal(
        report["approvalSequence"], "activation approval sequence", positive=True
    )
    previous = word(report["previousApprovalSha256"], 32)
    if sequence == 1:
        require(not any(previous),
                "first activation approval must have the zero predecessor")
    else:
        require(any(previous) and len(set(previous)) > 1,
                "successor activation approval requires a non-placeholder predecessor")
    require(report["decision"] == "approve-activation-when-all-gates-satisfied",
            "conditional activation approval required")


def _validate_external_qualification(
    report, trusted_review_policy_sha256, trusted_external_qualification_sha256,
):
    """Authenticate a non-authorizing qualification report with external pins."""
    _fields(report, EXTERNAL_QUALIFICATION_FIELDS, "external authority qualification")
    require(report["schema"] == "postern.bridge-authority-external-qualification.v2",
            "unsupported external authority qualification")
    for field in (
        "ceremonyPackageCanonicalSha256", "manifestCanonicalSha256",
        "authorityPolicySha256", "custodyCeremonySha256",
        "nativeRolesCeremonySha256", "activationAuthorityCeremonySha256",
        "reviewPolicySha256",
    ):
        _pin(report[field], f"external qualification {field}")
        require(report[field] == report[field].lower(),
                f"external qualification {field}: canonical lowercase hex required")
    require(type(report["reviewThreshold"]) is int
            and report["reviewThreshold"] == 3,
            "external qualification three-reviewer threshold required")
    require(type(report["reviewerCount"]) is int
            and not isinstance(report["reviewerCount"], bool)
            and 3 <= report["reviewerCount"] <= 5,
            "external qualification quorum required")
    for field in (
        "externalRecordsAuthenticated", "custodyQualified", "authoritiesQualified",
    ):
        _boolean(report[field], True, f"external qualification {field}")
    for field in (
        "keysLoaded", "signingAllowed", "deploymentAllowed", "broadcastAllowed",
        "activationAuthorized",
    ):
        _boolean(report[field], False, f"external qualification {field}")

    review_policy = "0x" + _pin(
        trusted_review_policy_sha256, "trusted external review policy"
    ).hex()
    qualification = "0x" + _pin(
        trusted_external_qualification_sha256,
        "trusted external qualification report",
    ).hex()
    require(type(trusted_review_policy_sha256) is str
            and trusted_review_policy_sha256 == review_policy,
            "trusted review policy digest must be canonical lowercase hex")
    require(type(trusted_external_qualification_sha256) is str
            and trusted_external_qualification_sha256 == qualification,
            "trusted qualification digest must be canonical lowercase hex")
    require(report["reviewPolicySha256"] == review_policy,
            "external qualification binds an untrusted review policy")
    require(canonical_sha256(report).lower() == qualification,
            "external qualification report does not match trusted digest")
    return qualification


def _validate_authority_policy(policy, manifest, manifest_digest):
    """Bind one public activation authority to the seven operational roles."""
    _fields(policy, AUTHORITY_POLICY_FIELDS, "activation authority policy")
    require(policy["schema"] == "postern.bridge-authority-policy.v2",
            "unsupported activation authority policy")
    require(policy["manifestCanonicalSha256"].lower() == manifest_digest.lower(),
            "activation authority policy binds another manifest")
    authority = policy["activationAuthority"]
    _fields(authority, ACTIVATION_AUTHORITY_FIELDS, "activation authority")
    require(authority["algorithm"] == "ed25519",
            "reviewed activation authority algorithm required")
    operator = _pin(authority["operatorId"], "activation authority operator")
    organization = _pin(
        authority["organizationId"], "activation authority organization"
    )
    public_key = _pin(authority["publicKey"], "activation authority public key")
    attestation = _pin(
        authority["custodyAttestationSha256"],
        "activation authority custody attestation",
    )

    operational = list(manifest["custody"]["custodians"]) + [
        manifest["roles"]["issuer"], manifest["roles"]["sponsor"]
    ]
    require(operator not in {
        word(value["operator_id"], 32) for value in operational
    }, "activation authority operator must be independent")
    require(organization not in {
        word(value["organization_id"], 32) for value in operational
    }, "activation authority organization must be independent")
    public_key_digest = hashlib.sha256(public_key).digest()
    require(public_key_digest not in {
        word(value["bloch_public_key_sha256"], 32) for value in operational
    }, "activation authority key must be independent")
    require(attestation not in {
        word(value["custody_attestation_sha256"], 32) for value in operational
    }, "activation authority custody attestation must be independent")

    expected = canonical_sha256({
        "schema": "postern.bridge-authority-policy.v2",
        "custody": manifest["custody"],
        "roles": manifest["roles"],
        "activationAuthority": authority,
    })
    require(policy["authorityPolicySha256"].lower() == expected.lower(),
            "activation authority policy commitment mismatch")
    return expected


def _approval_package(
    manifest_digest, route, policy_digest, settlement, deployment, cycle, authority
):
    """Return the exact non-circular object an external approval must sign."""
    return {
        "schema": "postern.bridge-activation-approval-package.v2",
        "manifestCanonicalSha256": manifest_digest.lower(),
        "routeId": route.lower(),
        "authorityPolicySha256": policy_digest.lower(),
        "custodyCeremonySha256": authority["custodyCeremonySha256"].lower(),
        "nativeRolesCeremonySha256": authority["nativeRolesCeremonySha256"].lower(),
        "settlementVerificationSha256": canonical_sha256(settlement).lower(),
        "deploymentVerificationSha256": canonical_sha256(deployment).lower(),
        "disposableCycleSha256": canonical_sha256(cycle).lower(),
        "approvalCheckpointHeight": authority["approvalCheckpointHeight"],
        "observedNativeHeight": authority["observedNativeHeight"],
        "approvalValidUntilHeight": authority["approvalValidUntilHeight"],
        "approvalSequence": authority["approvalSequence"],
        "previousApprovalSha256": authority["previousApprovalSha256"].lower(),
        "decision": authority["decision"],
    }


def _approval_certificate(policy_digest, package_digest, signature):
    """Return the exact certificate whose digest is retained as predecessor."""
    return {
        "schema": "postern.bridge-activation-approval-certificate.v2",
        "authorityPolicySha256": policy_digest.lower(),
        "approvalPackageSha256": package_digest.lower(),
        "signature": signature.lower(),
    }


def _validate_cycle(report, cap):
    _fields(report, CYCLE_FIELDS, "disposable cycle")
    require(report["schema"] == "postern.bridge-disposable-cycle.v1",
            "unsupported disposable cycle")
    for field in (
        "manifestCanonicalSha256", "routeId", "deploymentTransactionHash",
        "settlementEvidenceCommitmentSha256", "depositTransactionHash",
        "nativeMintTransactionId", "nativeBurnTransactionId",
        "releaseTransactionHash", "reserveReconciliationSha256",
        "rollbackExerciseSha256",
    ):
        _pin(report[field], f"cycle {field}")
    amount = _decimal(report["amountBaseUnits"], "disposable amount", positive=True)
    require(amount <= min(cap, MAX_DISPOSABLE_BASE_UNITS),
            "disposable cycle exceeds rehearsal cap")
    source_before = _decimal(report["sourceLockedBefore"], "source reserve before")
    source_after = _decimal(report["sourceLockedAfter"], "source reserve after")
    native_before = _decimal(report["nativeSupplyBefore"], "native supply before")
    native_after = _decimal(report["nativeSupplyAfter"], "native supply after")
    require(source_before == source_after and native_before == native_after,
            "disposable cycle did not return to its starting balances")
    operations = {
        word(report["depositTransactionHash"], 32),
        word(report["nativeMintTransactionId"], 32),
        word(report["nativeBurnTransactionId"], 32),
        word(report["releaseTransactionHash"], 32),
    }
    require(len(operations) == 4, "cycle operations must have distinct identities")
    require(not operations.intersection({
        word(report["reserveReconciliationSha256"], 32),
        word(report["rollbackExerciseSha256"], 32),
    }) and report["reserveReconciliationSha256"].lower()
            != report["rollbackExerciseSha256"].lower(),
            "cycle evidence commitments must have distinct identities")
    for field in (
        "depositVerified", "mintVerified", "burnVerified", "releaseVerified",
        "sourceReserveReconciled", "nativeSupplyReconciled",
        "rollbackPauseExercised",
    ):
        _boolean(report[field], True, f"cycle {field}")


def _validated_request(
    bundle, trusted_review_policy_sha256, trusted_external_qualification_sha256,
):
    _fields(bundle, BUNDLE_FIELDS, "readiness bundle")
    require(bundle["schema"] == "postern.bridge-activation-readiness.v3",
            "unsupported bridge readiness schema")
    manifest = bundle["manifest"]
    # Import lazily so this module cannot accidentally weaken manifest policy.
    from custody_deployment_manifest import validate_custody_deployment_manifest
    manifest_report = validate_custody_deployment_manifest(manifest)
    digest = canonical_sha256(manifest)
    settlement = bundle["settlementVerification"]
    deployment = bundle["deploymentVerification"]
    policy = bundle["authorityPolicy"]
    authority = bundle["authorityQualification"]
    external_authority = bundle["externalAuthorityQualification"]
    cycle = bundle["disposableCycle"]
    _validate_settlement(settlement)
    _validate_deployment(deployment)
    _validate_authority(authority)
    external_qualification_digest = _validate_external_qualification(
        external_authority, trusted_review_policy_sha256,
        trusted_external_qualification_sha256,
    )
    _validate_cycle(cycle, manifest["cap"]["base_units"])

    require(manifest_report["manifestCanonicalSha256"] == digest,
            "manifest canonicalization mismatch")
    require(all(value.lower() == digest.lower() for value in (
        deployment["manifestCanonicalSha256"],
        authority["manifestCanonicalSha256"],
        cycle["manifestCanonicalSha256"],
    )), "readiness artifacts bind different manifests")
    route = settlement["routeId"].lower()
    require(deployment["routeId"].lower() == route
            and authority["routeId"].lower() == route
            and cycle["routeId"].lower() == route,
            "readiness artifacts bind different routes")
    from custody_deployment_evidence import _route
    expected_route = _route(manifest, int(deployment["blockNumber"]))["route_id"]
    require(route == expected_route.lower(), "readiness route is not manifest-derived")
    require(deployment["vaultAddress"].lower()
            == manifest["source"]["vault_address"].lower(),
            "deployment report binds another vault")
    require(cycle["deploymentTransactionHash"].lower()
            == deployment["transactionHash"].lower(),
            "cycle binds another deployment")
    require(cycle["settlementEvidenceCommitmentSha256"].lower()
            == settlement["evidenceCommitmentSha256"].lower(),
            "cycle binds another settlement")
    require(authority["custodianCount"] == manifest["custody"]["threshold"] + 2
            and authority["custodyThreshold"] == manifest["custody"]["threshold"],
            "authority qualification conflicts with custody policy")
    authority_policy = _validate_authority_policy(policy, manifest, digest)
    require(authority["authorityPolicySha256"].lower()
            == authority_policy.lower(),
            "authority qualification binds another custody policy")
    require(external_authority["manifestCanonicalSha256"] == digest.lower(),
            "external qualification binds another manifest")
    require(external_authority["authorityPolicySha256"] == authority_policy.lower(),
            "external qualification binds another authority policy")
    require(external_authority["custodyCeremonySha256"]
            == authority["custodyCeremonySha256"].lower(),
            "external qualification binds another custody ceremony")
    require(external_authority["nativeRolesCeremonySha256"]
            == authority["nativeRolesCeremonySha256"].lower(),
            "external qualification binds another native roles ceremony")
    require(authority["settlementVerificationSha256"].lower()
            == canonical_sha256(settlement).lower(),
            "authority qualification binds another settlement verification")
    require(authority["deploymentVerificationSha256"].lower()
            == canonical_sha256(deployment).lower(),
            "authority qualification binds another deployment verification")
    require(authority["approvalCheckpointHeight"]
            == settlement["nativeCheckpointHeight"],
            "activation approval binds another native checkpoint")
    approval_package = _approval_package(
        digest, route, authority_policy, settlement, deployment, cycle, authority
    )
    require(authority["approvalPackageSha256"].lower()
            == canonical_sha256(approval_package).lower(),
            "activation approval binds another package")
    certificate = _approval_certificate(
        authority_policy,
        authority["approvalPackageSha256"],
        authority["activationApprovalSignature"],
    )
    require(authority["activationApprovalSha256"].lower()
            == canonical_sha256(certificate).lower(),
            "activation approval certificate commitment mismatch")

    encoded = json.dumps(
        bundle, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    request = DOMAIN + encoded
    require(len(request) <= MAX_REQUEST_BYTES, "readiness bundle exceeds verifier limit")
    return request, digest, route, external_qualification_digest


def _stage_verifier(path):
    path = Path(path)
    require(path.is_absolute(), "absolute readiness verifier required")
    flags = getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    source = os.open(path, os.O_RDONLY | flags)
    temporary = tempfile.TemporaryDirectory(prefix="bloch-readiness-verifier-")
    destination = Path(temporary.name) / "verifier"
    output = None
    try:
        before = os.fstat(source)
        current = path.lstat()
        require(stat.S_ISREG(before.st_mode)
                and (before.st_dev, before.st_ino) == (current.st_dev, current.st_ino)
                and 0 < before.st_size <= MAX_VERIFIER_BYTES
                and not before.st_mode & 0o022,
                "immutable regular readiness verifier required")
        output = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | flags,
                         0o500)
        digest = hashlib.sha256()
        while chunk := os.read(source, 1024 * 1024):
            digest.update(chunk)
            pending = memoryview(chunk)
            while pending:
                pending = pending[os.write(output, pending):]
        os.fsync(output)
        after = os.fstat(source)
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
                "readiness verifier changed while hashing")
        os.close(output)
        output = None
        os.close(source)
        return temporary, destination, digest.digest()
    except BaseException:
        if output is not None:
            os.close(output)
        os.close(source)
        temporary.cleanup()
        raise


def verify_bridge_activation_readiness(
    executable, expected_sha256, approval_executable, approval_expected_sha256,
    authority_policy_sha256, approval_checkpoint, approval_checkpoint_sha256,
    bundle, trusted_review_policy_sha256, trusted_external_qualification_sha256,
):
    """Authenticate the complete package; return permission, never perform it."""
    request, manifest_digest, route, external_qualification_digest = _validated_request(
        bundle, trusted_review_policy_sha256,
        trusted_external_qualification_sha256,
    )
    expected = word(expected_sha256, 32)
    approval_expected = word(approval_expected_sha256, 32)
    approval_temporary = None
    temporary = None
    try:
        approval_temporary, approval_staged, approval_actual = _stage_verifier(
            approval_executable
        )
        require(approval_actual == approval_expected,
                "approval verifier checksum mismatch")
        approval_result = run_verifier([
            str(approval_staged), authority_policy_sha256,
            str(Path(approval_checkpoint).absolute()), approval_checkpoint_sha256,
        ], input=request, timeout=10)
        commitment = hashlib.sha256(request).hexdigest()
        require(
            approval_result.returncode == 0
            and approval_result.stdout
            == (commitment.upper() + "\n").encode("ascii"),
            "bridge approval verifier refused",
        )

        temporary, staged, actual = _stage_verifier(executable)
        require(actual == expected, "readiness verifier checksum mismatch")
        result = run_verifier([str(staged)], input=request, timeout=10)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError("readiness verifier unavailable") from exc
    finally:
        if temporary is not None:
            temporary.cleanup()
        if approval_temporary is not None:
            approval_temporary.cleanup()
    require(result.returncode == 0
            and result.stdout == (commitment + "\n").encode("ascii"),
            "bridge readiness verifier refused")
    return {
        "schema": "postern.bridge-activation-readiness-verification.v3",
        "manifestCanonicalSha256": manifest_digest,
        "routeId": route,
        "verifierSha256": "0x" + expected.hex(),
        "approvalVerifierSha256": "0x" + approval_expected.hex(),
        "readinessCommitmentSha256": "0x" + commitment,
        "externalAuthorityQualificationSha256": external_qualification_digest,
        "settlementVerified": True,
        "custodyAuthoritiesVerified": True,
        "externalAuthorityReviewVerified": True,
        "pausedDeploymentVerified": True,
        "disposableCycleVerified": True,
        "activationAuthorized": True,
        "mintAuthorized": True,
        "releaseAuthorized": True,
        "bridgeReady": True,
        "broadcastPerformed": False,
    }
