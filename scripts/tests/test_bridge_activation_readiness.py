"""Adversarial composition tests for the final bridge readiness gate."""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(SCRIPTS / "tests"))

from bridge_activation_readiness import (  # noqa: E402
    _approval_certificate,
    _approval_package,
    _validate_authority_policy,
    _validated_request,
    verify_bridge_activation_readiness,
)
from custody_deployment_evidence import (  # noqa: E402
    validate_custody_deployment_evidence,
)
from custody_deployment_manifest import canonical_sha256  # noqa: E402
from test_custody_deployment_evidence import fixture as deployment_fixture  # noqa: E402


def digest(label):
    return "0x" + hashlib.sha256(label.encode("ascii")).hexdigest()


def fixture():
    manifest, evidence = deployment_fixture()
    deployment = validate_custody_deployment_evidence(manifest, evidence)
    # The lower-level fixture deliberately uses repeated-byte stand-ins.  This
    # gate accepts only non-placeholder public identities.
    for field in (
        "transactionHash", "blockHash", "creationInputSha256",
        "tokenProxyRuntimeSha256", "tokenImplementationRuntimeSha256",
        "vaultRuntimeSha256",
    ):
        deployment[field] = digest("deployment-" + field)
    route = deployment["routeId"]
    manifest_digest = canonical_sha256(manifest)
    settlement = {
        "schema": "postern.l2-native-settlement-verification.v1",
        "routeId": route,
        "l2ChainId": 700771,
        "l2BlockNumber": "41",
        "l2BlockHash": digest("l2-block"),
        "nativeCheckpointHeight": "912",
        "nativeCheckpointRoot": digest("native-checkpoint"),
        "nativeSettlementRecord": digest("native-settlement-record"),
        "verifierSha256": digest("settlement-verifier"),
        "evidenceCommitmentSha256": digest("settlement-evidence"),
        "settlementGateSatisfied": True,
        "finalityVerifiedForSettlement": True,
        "activationAuthorized": False,
        "mintAuthorized": False,
        "releaseAuthorized": False,
        "bridgeReady": False,
    }
    activation_authority = {
        "operatorId": digest("activation-operator"),
        "organizationId": digest("activation-organization"),
        "algorithm": "ed25519",
        "publicKey": digest("activation-public-key"),
        "custodyAttestationSha256": digest("activation-custody-attestation"),
    }
    policy_digest = canonical_sha256({
        "schema": "postern.bridge-authority-policy.v2",
        "custody": manifest["custody"],
        "roles": manifest["roles"],
        "activationAuthority": activation_authority,
    })
    policy = {
        "schema": "postern.bridge-authority-policy.v2",
        "manifestCanonicalSha256": manifest_digest,
        "activationAuthority": activation_authority,
        "authorityPolicySha256": policy_digest,
    }
    cycle = {
        "schema": "postern.bridge-disposable-cycle.v1",
        "manifestCanonicalSha256": manifest_digest,
        "routeId": route,
        "deploymentTransactionHash": deployment["transactionHash"],
        "settlementEvidenceCommitmentSha256": settlement["evidenceCommitmentSha256"],
        "amountBaseUnits": "1",
        "depositTransactionHash": digest("cycle-deposit"),
        "nativeMintTransactionId": digest("cycle-mint"),
        "nativeBurnTransactionId": digest("cycle-burn"),
        "releaseTransactionHash": digest("cycle-release"),
        "sourceLockedBefore": "0",
        "sourceLockedAfter": "0",
        "nativeSupplyBefore": "0",
        "nativeSupplyAfter": "0",
        "reserveReconciliationSha256": digest("cycle-reconciliation"),
        "rollbackExerciseSha256": digest("cycle-rollback"),
        "depositVerified": True,
        "mintVerified": True,
        "burnVerified": True,
        "releaseVerified": True,
        "sourceReserveReconciled": True,
        "nativeSupplyReconciled": True,
        "rollbackPauseExercised": True,
    }
    authority = {
        "schema": "postern.bridge-authority-qualification.v2",
        "manifestCanonicalSha256": manifest_digest,
        "routeId": route,
        "custodianCount": 5,
        "custodyThreshold": 3,
        "distinctAuthorityCount": 8,
        "authorityPolicySha256": policy_digest,
        "custodyCeremonySha256": digest("custody-ceremony"),
        "nativeRolesCeremonySha256": digest("native-roles-ceremony"),
        "settlementVerificationSha256": canonical_sha256(settlement),
        "deploymentVerificationSha256": canonical_sha256(deployment),
        "sourceDeploymentAuthenticated": True,
        "nativeGatewayAuthenticated": True,
        "settlementAuthenticated": True,
        "activationApprovalSha256": digest("not-yet-computed-certificate"),
        "activationApprovalSignature": "0x" + hashlib.sha512(
            b"transport-only-signature-fixture"
        ).hexdigest(),
        "approvalCheckpointHeight": "912",
        "observedNativeHeight": "913",
        "approvalValidUntilHeight": "1000",
        "approvalSequence": "1",
        "previousApprovalSha256": "0x" + "00" * 32,
        "approvalPackageSha256": digest("not-yet-computed"),
        "decision": "approve-activation-when-all-gates-satisfied",
    }
    authority["approvalPackageSha256"] = canonical_sha256(_approval_package(
        manifest_digest, route, policy_digest, settlement, deployment, cycle, authority
    ))
    authority["activationApprovalSha256"] = canonical_sha256(_approval_certificate(
        policy_digest,
        authority["approvalPackageSha256"],
        authority["activationApprovalSignature"],
    ))
    external_authority = {
        "schema": "postern.bridge-authority-external-qualification.v1",
        "ceremonyPackageCanonicalSha256": digest("external-ceremony-package"),
        "manifestCanonicalSha256": manifest_digest,
        "authorityPolicySha256": policy_digest,
        "custodyCeremonySha256": authority["custodyCeremonySha256"],
        "nativeRolesCeremonySha256": authority["nativeRolesCeremonySha256"],
        "activationAuthorityCeremonySha256": digest(
            "activation-authority-ceremony"
        ),
        "reviewPolicySha256": digest("external-review-policy"),
        "reviewerCount": 3,
        "reviewThreshold": 3,
        "externalRecordsAuthenticated": True,
        "custodyQualified": True,
        "authoritiesQualified": True,
        "keysLoaded": False,
        "signingAllowed": False,
        "deploymentAllowed": False,
        "broadcastAllowed": False,
        "activationAuthorized": False,
    }
    return {
        "schema": "postern.bridge-activation-readiness.v3",
        "manifest": manifest,
        "settlementVerification": settlement,
        "deploymentVerification": deployment,
        "authorityPolicy": policy,
        "authorityQualification": authority,
        "externalAuthorityQualification": external_authority,
        "disposableCycle": cycle,
    }


def verifier(directory, output="digest"):
    path = Path(directory) / ("readiness-verifier-" + output)
    if path.exists():
        return path, "0x" + hashlib.sha256(path.read_bytes()).hexdigest()
    body = (
        "#!/usr/bin/env python3\n"
        "import hashlib, sys\n"
        "data = sys.stdin.buffer.read()\n"
    )
    if output == "digest":
        body += "print(hashlib.sha256(data).hexdigest())\n"
    elif output == "upper":
        body += "print(hashlib.sha256(data).hexdigest().upper())\n"
    elif output == "wrong":
        body += "print('00' * 32)\n"
    else:
        body += "sys.exit(1)\n"
    path.write_text(body)
    path.chmod(0o500)
    return path, "0x" + hashlib.sha256(path.read_bytes()).hexdigest()


def approval_verifier(directory, bundle, output="approval"):
    path = Path(directory) / ("approval-verifier-" + output)
    if path.exists():
        return path, "0x" + hashlib.sha256(path.read_bytes()).hexdigest()
    policy = bundle["authorityPolicy"]["authorityPolicySha256"]
    body = (
        "#!/usr/bin/env python3\n"
        "import hashlib, pathlib, sys\n"
        f"expected_policy = {policy!r}\n"
        "if len(sys.argv) != 4 or sys.argv[1].lower() != expected_policy.lower():\n"
        "    sys.exit(1)\n"
        "checkpoint = pathlib.Path(sys.argv[2]).read_bytes()\n"
        "if ('0x' + hashlib.sha256(checkpoint).hexdigest()).lower() != sys.argv[3].lower():\n"
        "    sys.exit(1)\n"
        "data = sys.stdin.buffer.read()\n"
    )
    if output == "approval":
        body += "print(hashlib.sha256(data).hexdigest().upper())\n"
    else:
        body += "print(hashlib.sha256(data).hexdigest())\n"
    path.write_text(body)
    path.chmod(0o500)
    return path, "0x" + hashlib.sha256(path.read_bytes()).hexdigest()


def checkpoint(directory, bundle):
    path = Path(directory) / "approval-checkpoint.json"
    if path.exists():
        return path, "0x" + hashlib.sha256(path.read_bytes()).hexdigest()
    value = {
        "schema": "postern.bridge-activation-approval-checkpoint.v2",
        "authorityPolicySha256": bundle["authorityPolicy"]["authorityPolicySha256"],
        "lastApprovalSequence": "0",
        "lastApprovalSha256": "0x" + "00" * 32,
    }
    path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")))
    path.chmod(0o400)
    return path, "0x" + hashlib.sha256(path.read_bytes()).hexdigest()


def verify(executable, pin, bundle, directory):
    state, state_pin = checkpoint(directory, bundle)
    approval, approval_pin = approval_verifier(directory, bundle)
    return verify_bridge_activation_readiness(
        executable, pin, approval, approval_pin,
        bundle["authorityPolicy"]["authorityPolicySha256"], state, state_pin, bundle,
        bundle["externalAuthorityQualification"]["reviewPolicySha256"],
        canonical_sha256(bundle["externalAuthorityQualification"]),
    )


def validated(bundle):
    return _validated_request(
        bundle,
        bundle["externalAuthorityQualification"]["reviewPolicySha256"],
        canonical_sha256(bundle["externalAuthorityQualification"]),
    )


def trust_args(bundle):
    return (
        bundle["externalAuthorityQualification"]["reviewPolicySha256"],
        canonical_sha256(bundle["externalAuthorityQualification"]),
    )


class BridgeActivationReadinessTest(unittest.TestCase):
    def test_complete_authenticated_bundle_only_returns_permission(self):
        bundle = fixture()
        before = copy.deepcopy(bundle)
        with tempfile.TemporaryDirectory() as directory:
            executable, pin = verifier(directory)
            report = verify(executable, pin, bundle, directory)
        self.assertEqual(bundle, before)
        self.assertEqual(
            report["schema"],
            "postern.bridge-activation-readiness-verification.v3",
        )
        for field in (
            "settlementVerified", "custodyAuthoritiesVerified",
            "externalAuthorityReviewVerified",
            "pausedDeploymentVerified", "disposableCycleVerified",
            "activationAuthorized", "mintAuthorized", "releaseAuthorized",
            "bridgeReady",
        ):
            self.assertTrue(report[field])
        self.assertFalse(report["broadcastPerformed"])
        self.assertEqual(report["routeId"], bundle["settlementVerification"]["routeId"])
        self.assertTrue(report["approvalVerifierSha256"].startswith("0x"))

    def test_every_false_or_premature_prerequisite_refuses_before_spawn(self):
        mutations = []
        for section, fields in (
            ("settlementVerification", ("settlementGateSatisfied",
                                        "finalityVerifiedForSettlement")),
            ("deploymentVerification", ("finalizedReceiptConsistent",
                                        "constructorStateMatched", "committeeMatched",
                                        "tokenProxyImplementationMatched", "paused", "empty")),
            ("authorityQualification", ("sourceDeploymentAuthenticated",
                                        "nativeGatewayAuthenticated",
                                        "settlementAuthenticated")),
            ("disposableCycle", ("depositVerified", "mintVerified", "burnVerified",
                                 "releaseVerified", "sourceReserveReconciled",
                                 "nativeSupplyReconciled", "rollbackPauseExercised")),
        ):
            mutations.extend((section, field, False) for field in fields)
        mutations.extend(("settlementVerification", field, True) for field in (
            "activationAuthorized", "mintAuthorized", "releaseAuthorized", "bridgeReady"
        ))
        mutations.extend(("deploymentVerification", field, True) for field in (
            "sourceRpcAuthenticated", "deploymentAuthenticated", "activationAuthorized",
            "broadcastAllowed",
        ))
        with patch("bridge_activation_readiness.run_verifier") as run:
            for section, field, value in mutations:
                bundle = fixture()
                bundle[section][field] = value
                with self.subTest(section=section, field=field), self.assertRaises(ValueError):
                    verify_bridge_activation_readiness(
                        Path(sys.executable), digest("x"),
                        Path(sys.executable), digest("approval"), digest("policy"),
                        Path("checkpoint"), digest("checkpoint"), bundle,
                        *trust_args(bundle),
                    )
        run.assert_not_called()

    def test_cross_artifact_substitution_and_unknown_fields_refuse(self):
        mutations = [
            lambda value: value.update(
                schema="postern.bridge-activation-readiness.v2"),
            lambda value: value["authorityPolicy"]["activationAuthority"].update(
                publicKey=digest("substituted-activation-key")),
            lambda value: value["authorityPolicy"]["activationAuthority"].update(
                algorithm="secp256k1"),
            lambda value: value["authorityQualification"].update(
                routeId=digest("other-route")),
            lambda value: value["disposableCycle"].update(
                deploymentTransactionHash=digest("other-deployment")),
            lambda value: value["disposableCycle"].update(
                settlementEvidenceCommitmentSha256=digest("other-settlement")),
            lambda value: value["authorityQualification"].update(custodyThreshold=2),
            lambda value: value["authorityQualification"].update(
                authorityPolicySha256=digest("other-authority-policy")),
            lambda value: value["authorityQualification"].update(
                approvalCheckpointHeight="911"),
            lambda value: value["authorityQualification"].update(
                settlementVerificationSha256=digest("other-settlement-report")),
            lambda value: value["authorityQualification"].update(
                deploymentVerificationSha256=digest("other-deployment-report")),
            lambda value: value["authorityQualification"].update(
                approvalPackageSha256=digest("other-approval-package")),
            lambda value: value["deploymentVerification"].update(
                vaultAddress="0x" + "11" * 20),
            lambda value: value["deploymentVerification"].update(extra=True),
            lambda value: value.pop("authorityQualification"),
        ]
        for mutate in mutations:
            bundle = fixture()
            mutate(bundle)
            with self.subTest(mutation=mutate), self.assertRaises(ValueError):
                validated(bundle)

    def test_activation_authority_is_eighth_independent_identity(self):
        collisions = (
            ("operatorId", "operator_id"),
            ("organizationId", "organization_id"),
            ("custodyAttestationSha256", "custody_attestation_sha256"),
        )
        for policy_field, manifest_field in collisions:
            bundle = fixture()
            authority = bundle["authorityPolicy"]["activationAuthority"]
            authority[policy_field] = (
                bundle["manifest"]["custody"]["custodians"][0][manifest_field]
            )
            policy_digest = canonical_sha256({
                "schema": "postern.bridge-authority-policy.v2",
                "custody": bundle["manifest"]["custody"],
                "roles": bundle["manifest"]["roles"],
                "activationAuthority": authority,
            })
            bundle["authorityPolicy"]["authorityPolicySha256"] = policy_digest
            bundle["authorityQualification"]["authorityPolicySha256"] = policy_digest
            with self.subTest(field=policy_field), self.assertRaises(ValueError):
                validated(bundle)

        bundle = fixture()
        manifest = copy.deepcopy(bundle["manifest"])
        policy = copy.deepcopy(bundle["authorityPolicy"])
        public_key = bytes.fromhex(
            policy["activationAuthority"]["publicKey"][2:]
        )
        manifest["custody"]["custodians"][0]["bloch_public_key_sha256"] = (
            "0x" + hashlib.sha256(public_key).hexdigest()
        )
        manifest_digest = canonical_sha256(manifest)
        policy["manifestCanonicalSha256"] = manifest_digest
        policy["authorityPolicySha256"] = canonical_sha256({
            "schema": "postern.bridge-authority-policy.v2",
            "custody": manifest["custody"],
            "roles": manifest["roles"],
            "activationAuthority": policy["activationAuthority"],
        })
        with self.assertRaises(ValueError):
            _validate_authority_policy(policy, manifest, manifest_digest)

    def test_external_qualification_is_non_authorizing_and_externally_pinned(self):
        for field in (
            "keysLoaded", "signingAllowed", "deploymentAllowed",
            "broadcastAllowed", "activationAuthorized",
        ):
            bundle = fixture()
            bundle["externalAuthorityQualification"][field] = True
            with self.subTest(field=field), self.assertRaises(ValueError):
                validated(bundle)

        bundle = fixture()
        with self.assertRaisesRegex(ValueError, "untrusted review policy"):
            _validated_request(
                bundle, digest("attacker-review-policy"),
                canonical_sha256(bundle["externalAuthorityQualification"]),
            )
        with self.assertRaisesRegex(ValueError, "trusted digest"):
            _validated_request(
                bundle,
                bundle["externalAuthorityQualification"]["reviewPolicySha256"],
                digest("attacker-qualification-report"),
            )

    def test_external_qualification_cross_bindings_and_pending_shapes_refuse(self):
        mutations = [
            lambda report: report.update(
                manifestCanonicalSha256=digest("other-manifest")),
            lambda report: report.update(
                authorityPolicySha256=digest("other-authority-policy")),
            lambda report: report.update(
                custodyCeremonySha256=digest("other-custody-ceremony")),
            lambda report: report.update(
                nativeRolesCeremonySha256=digest("other-native-roles-ceremony")),
            lambda report: report.update(reviewerCount=2),
            lambda report: report.update(reviewThreshold=2),
            lambda report: report.update(externalRecordsAuthenticated=False),
            lambda report: report.update(extra=True),
        ]
        for mutate in mutations:
            bundle = fixture()
            mutate(bundle["externalAuthorityQualification"])
            with self.subTest(mutation=mutate), self.assertRaises(ValueError):
                validated(bundle)

        pending = json.loads((ROOT / "mainnet-custody/authority-qualification.pending.json")
                             .read_text(encoding="utf-8"))
        bundle = fixture()
        bundle["externalAuthorityQualification"] = pending
        with self.assertRaises((ValueError, TypeError)):
            _validated_request(bundle, digest("pending-policy"), digest("pending-report"))

    def test_prior_package_or_sequence_cannot_be_replayed(self):
        original = fixture()
        mutations = []

        changed_cycle = copy.deepcopy(original)
        changed_cycle["disposableCycle"]["depositTransactionHash"] = digest(
            "replacement-cycle-deposit"
        )
        mutations.append(changed_cycle)

        changed_sequence = copy.deepcopy(original)
        changed_sequence["authorityQualification"]["approvalSequence"] = "2"
        mutations.append(changed_sequence)

        zero_predecessor = copy.deepcopy(original)
        zero_predecessor["authorityQualification"]["approvalSequence"] = "2"
        zero_predecessor["authorityQualification"]["approvalPackageSha256"] = (
            canonical_sha256(_approval_package(
                canonical_sha256(zero_predecessor["manifest"]),
                zero_predecessor["settlementVerification"]["routeId"],
                zero_predecessor["authorityPolicy"]["authorityPolicySha256"],
                zero_predecessor["settlementVerification"],
                zero_predecessor["deploymentVerification"],
                zero_predecessor["disposableCycle"],
                zero_predecessor["authorityQualification"],
            ))
        )
        mutations.append(zero_predecessor)

        nonzero_genesis = copy.deepcopy(original)
        nonzero_genesis["authorityQualification"]["previousApprovalSha256"] = digest(
            "unexpected-predecessor"
        )
        mutations.append(nonzero_genesis)

        for bundle in mutations:
            with self.subTest(bundle=bundle), self.assertRaises(ValueError):
                validated(bundle)

    def test_cycle_must_be_small_distinct_and_balance_neutral(self):
        mutations = [
            lambda cycle, manifest: cycle.update(amountBaseUnits="0"),
            lambda cycle, manifest: cycle.update(
                amountBaseUnits=str(manifest["cap"]["base_units"] + 1)),
            lambda cycle, manifest: cycle.update(amountBaseUnits="10000001"),
            lambda cycle, manifest: cycle.update(sourceLockedAfter="1"),
            lambda cycle, manifest: cycle.update(nativeSupplyAfter="1"),
            lambda cycle, manifest: cycle.update(
                nativeBurnTransactionId=cycle["nativeMintTransactionId"]),
            lambda cycle, manifest: cycle.update(sourceLockedBefore="00"),
            lambda cycle, manifest: cycle.update(
                rollbackExerciseSha256=cycle["depositTransactionHash"]),
        ]
        for mutate in mutations:
            bundle = fixture()
            mutate(bundle["disposableCycle"], bundle["manifest"])
            with self.subTest(mutation=mutate), self.assertRaises(ValueError):
                validated(bundle)

    def test_activation_approval_must_be_current_and_bounded(self):
        mutations = [
            {"observedNativeHeight": "911"},
            {"observedNativeHeight": "1001"},
            {"observedNativeHeight": "945", "approvalValidUntilHeight": "1000"},
            {"approvalValidUntilHeight": "1633"},
            {"observedNativeHeight": "0913"},
        ]
        for values in mutations:
            bundle = fixture()
            bundle["authorityQualification"].update(values)
            with self.subTest(values=values), self.assertRaises(ValueError):
                validated(bundle)

    def test_verifier_pin_permissions_and_exact_output_fail_closed(self):
        bundle = fixture()
        with tempfile.TemporaryDirectory() as directory:
            executable, pin = verifier(directory)
            with self.assertRaises(ValueError):
                verify(executable, digest("wrong-pin"), bundle, directory)
            executable, pin = verifier(directory, "wrong")
            with self.assertRaises(ValueError):
                verify(executable, pin, bundle, directory)
            executable, pin = verifier(directory, "failure")
            with self.assertRaises(ValueError):
                verify(executable, pin, bundle, directory)
            executable.chmod(0o522)
            with self.assertRaises(ValueError):
                verify(executable, pin, bundle, directory)

    def test_approval_verifier_is_mandatory_and_protocol_separated(self):
        bundle = fixture()
        with tempfile.TemporaryDirectory() as directory:
            full, full_pin = verifier(directory)
            state, state_pin = checkpoint(directory, bundle)
            approval, approval_pin = approval_verifier(directory, bundle)
            policy = bundle["authorityPolicy"]["authorityPolicySha256"]

            with self.assertRaises(ValueError):
                verify_bridge_activation_readiness(
                    full, full_pin, approval, digest("wrong-approval-pin"),
                    policy, state, state_pin, bundle, *trust_args(bundle),
                )

            malicious_echo, malicious_pin = verifier(directory)
            with self.assertRaises(ValueError):
                verify_bridge_activation_readiness(
                    full, full_pin, malicious_echo, malicious_pin,
                    policy, state, state_pin, bundle, *trust_args(bundle),
                )

            uppercase_echo, _ = verifier(directory, "upper")
            with self.assertRaises(ValueError):
                verify_bridge_activation_readiness(
                    full, full_pin, uppercase_echo, approval_pin,
                    policy, state, state_pin, bundle, *trust_args(bundle),
                )

            with self.assertRaises(ValueError):
                verify_bridge_activation_readiness(
                    full, full_pin, approval, approval_pin,
                    digest("wrong-policy"), state, state_pin, bundle,
                    *trust_args(bundle),
                )
            with self.assertRaises(ValueError):
                verify_bridge_activation_readiness(
                    full, full_pin, approval, approval_pin,
                    policy, Path(directory) / "missing-checkpoint",
                    digest("wrong-checkpoint"), bundle, *trust_args(bundle),
                )

            with self.assertRaises(ValueError):
                verify_bridge_activation_readiness(
                    approval, approval_pin, approval, approval_pin,
                    policy, state, state_pin, bundle, *trust_args(bundle),
                )

    def test_cli_refusal_is_machine_readable_and_never_writes_state(self):
        bundle = fixture()
        cli = SCRIPTS / "check-bridge-activation-readiness.py"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle_path = root / "bundle.json"
            bundle_path.write_text(json.dumps(bundle))
            executable, pin = verifier(directory)
            state, state_pin = checkpoint(directory, bundle)
            approval, approval_pin = approval_verifier(directory, bundle)
            before = sorted(root.iterdir())
            missing_approval = subprocess.run(
                [sys.executable, str(cli), "--bundle", str(bundle_path),
                 "--verifier", str(executable), "--verifier-sha256", pin,
                 "--authority-policy-sha256",
                 bundle["authorityPolicy"]["authorityPolicySha256"],
                 "--approval-checkpoint", str(state),
                 "--approval-checkpoint-sha256", state_pin,
                 "--trusted-review-policy-sha256", trust_args(bundle)[0],
                 "--trusted-external-qualification-sha256", trust_args(bundle)[1]],
                capture_output=True, text=True, timeout=10, check=False,
            )
            self.assertNotEqual(missing_approval.returncode, 0)
            result = subprocess.run(
                [sys.executable, str(cli), "--bundle", str(bundle_path),
                 "--verifier", str(executable), "--verifier-sha256", pin,
                 "--approval-verifier", str(approval),
                 "--approval-verifier-sha256", approval_pin,
                 "--authority-policy-sha256",
                 bundle["authorityPolicy"]["authorityPolicySha256"],
                 "--approval-checkpoint", str(state),
                 "--approval-checkpoint-sha256", state_pin,
                 "--trusted-review-policy-sha256", trust_args(bundle)[0],
                 "--trusted-external-qualification-sha256", trust_args(bundle)[1]],
                capture_output=True, text=True, timeout=10, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(json.loads(result.stdout)["bridgeReady"])
            self.assertEqual(sorted(root.iterdir()), before)
            result = subprocess.run(
                [sys.executable, str(cli), "--bundle", str(bundle_path),
                 "--verifier", str(executable), "--verifier-sha256", digest("wrong"),
                 "--approval-verifier", str(approval),
                 "--approval-verifier-sha256", approval_pin,
                 "--authority-policy-sha256",
                 bundle["authorityPolicy"]["authorityPolicySha256"],
                 "--approval-checkpoint", str(state),
                 "--approval-checkpoint-sha256", state_pin,
                 "--trusted-review-policy-sha256", trust_args(bundle)[0],
                 "--trusted-external-qualification-sha256", trust_args(bundle)[1]],
                capture_output=True, text=True, timeout=10, check=False,
            )
            self.assertEqual(result.returncode, 1)
            refusal = json.loads(result.stderr)
            for field in ("activationAuthorized", "mintAuthorized",
                          "releaseAuthorized", "bridgeReady"):
                self.assertFalse(refusal[field])


if __name__ == "__main__":
    unittest.main()
