"""Compose authenticated bridge prerequisites without changing bridge state.

The custody and settlement checkers intentionally emit non-authorizing
reports.  This module binds those reports to an authority qualification and a
disposable-value round trip, then asks one immutable checksum-pinned verifier
to authenticate the complete package.  It has no RPC, key, signing, broadcast,
mint, release, pause or activation capability.
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


DOMAIN = b"BLOCH-BRIDGE-ACTIVATION-READINESS-v1\0"
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
    "approvalCheckpointHeight", "observedNativeHeight", "approvalValidUntilHeight",
    "decision",
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
    "authorityQualification", "disposableCycle",
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
    require(report["schema"] == "postern.bridge-authority-qualification.v1",
            "unsupported authority qualification")
    require(type(report["custodianCount"]) is int and report["custodianCount"] == 5,
            "five qualified custodians required")
    require(type(report["custodyThreshold"]) is int
            and report["custodyThreshold"] == 3, "three-of-five custody required")
    require(type(report["distinctAuthorityCount"]) is int
            and report["distinctAuthorityCount"] == 7,
            "custodians, issuer and sponsor must remain distinct")
    for field in (
        "manifestCanonicalSha256", "routeId", "authorityPolicySha256",
        "custodyCeremonySha256", "nativeRolesCeremonySha256",
        "settlementVerificationSha256", "deploymentVerificationSha256",
        "activationApprovalSha256",
    ):
        _pin(report[field], f"authority {field}")
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
    require(report["decision"] == "approve-activation-when-all-gates-satisfied",
            "conditional activation approval required")


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


def _validated_request(bundle):
    _fields(bundle, BUNDLE_FIELDS, "readiness bundle")
    require(bundle["schema"] == "postern.bridge-activation-readiness.v1",
            "unsupported bridge readiness schema")
    manifest = bundle["manifest"]
    # Import lazily so this module cannot accidentally weaken manifest policy.
    from custody_deployment_manifest import validate_custody_deployment_manifest
    manifest_report = validate_custody_deployment_manifest(manifest)
    digest = canonical_sha256(manifest)
    settlement = bundle["settlementVerification"]
    deployment = bundle["deploymentVerification"]
    authority = bundle["authorityQualification"]
    cycle = bundle["disposableCycle"]
    _validate_settlement(settlement)
    _validate_deployment(deployment)
    _validate_authority(authority)
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
    authority_policy = canonical_sha256({
        "custody": manifest["custody"],
        "roles": manifest["roles"],
    })
    require(authority["authorityPolicySha256"].lower()
            == authority_policy.lower(),
            "authority qualification binds another custody policy")
    require(authority["settlementVerificationSha256"].lower()
            == canonical_sha256(settlement).lower(),
            "authority qualification binds another settlement verification")
    require(authority["deploymentVerificationSha256"].lower()
            == canonical_sha256(deployment).lower(),
            "authority qualification binds another deployment verification")
    require(authority["approvalCheckpointHeight"]
            == settlement["nativeCheckpointHeight"],
            "activation approval binds another native checkpoint")

    encoded = json.dumps(
        bundle, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    request = DOMAIN + encoded
    require(len(request) <= MAX_REQUEST_BYTES, "readiness bundle exceeds verifier limit")
    return request, digest, route


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


def verify_bridge_activation_readiness(executable, expected_sha256, bundle):
    """Authenticate the complete package; return permission, never perform it."""
    request, manifest_digest, route = _validated_request(bundle)
    expected = word(expected_sha256, 32)
    temporary = None
    try:
        temporary, staged, actual = _stage_verifier(executable)
        require(actual == expected, "readiness verifier checksum mismatch")
        result = run_verifier([str(staged)], input=request, timeout=10)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError("readiness verifier unavailable") from exc
    finally:
        if temporary is not None:
            temporary.cleanup()
    commitment = hashlib.sha256(request).hexdigest()
    require(result.returncode == 0
            and result.stdout == (commitment + "\n").encode("ascii"),
            "bridge readiness verifier refused")
    return {
        "schema": "postern.bridge-activation-readiness-verification.v1",
        "manifestCanonicalSha256": manifest_digest,
        "routeId": route,
        "verifierSha256": "0x" + expected.hex(),
        "readinessCommitmentSha256": "0x" + commitment,
        "settlementVerified": True,
        "custodyAuthoritiesVerified": True,
        "pausedDeploymentVerified": True,
        "disposableCycleVerified": True,
        "activationAuthorized": True,
        "mintAuthorized": True,
        "releaseAuthorized": True,
        "bridgeReady": True,
        "broadcastPerformed": False,
    }
