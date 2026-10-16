"""Adversarial tests for the non-authorizing authority ceremony preflight."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
TESTS = SCRIPTS / "tests"
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(TESTS))

from bridge_authority_ceremony import verify_bridge_authority_ceremony  # noqa: E402
from custody_deployment_manifest import canonical_sha256  # noqa: E402
from test_custody_deployment_manifest import candidate, pin  # noqa: E402


def ceremony(schema, participants, threshold, label):
    return {
        "schema": schema,
        "participants": participants,
        "threshold": threshold,
        "transcriptSha256": pin(f"{label}-transcript"),
        "recoveryExerciseSha256": pin(f"{label}-recovery"),
        "independentWitnessReportSha256": pin(f"{label}-witness"),
    }


def package():
    manifest = candidate()
    authority = {
        "operatorId": pin("activation-operator"),
        "organizationId": pin("activation-organization"),
        "algorithm": "ed25519",
        "publicKey": pin("activation-public-key"),
        "custodyAttestationSha256": pin("activation-attestation"),
    }
    policy = {
        "schema": "postern.bridge-authority-policy.v2",
        "manifestCanonicalSha256": canonical_sha256(manifest),
        "activationAuthority": authority,
        "authorityPolicySha256": canonical_sha256({
            "schema": "postern.bridge-authority-policy.v2",
            "custody": manifest["custody"],
            "roles": manifest["roles"],
            "activationAuthority": authority,
        }),
    }
    bindings = []
    for index, member in enumerate(manifest["custody"]["custodians"], 1):
        bindings.append((f"custodian-{index}", member, member["ethereum_signer"]))
    bindings.extend([
        ("native-issuer", manifest["roles"]["issuer"], None),
        ("fee-sponsor", manifest["roles"]["sponsor"], None),
        ("activation-authority", {
            "operator_id": authority["operatorId"],
            "organization_id": authority["organizationId"],
            "bloch_public_key_sha256": "0x" + hashlib.sha256(
                bytes.fromhex(authority["publicKey"][2:])
            ).hexdigest(),
            "custody_attestation_sha256": authority["custodyAttestationSha256"],
        }, None),
    ])
    appointments = []
    for index, (role, member, signer) in enumerate(bindings, 1):
        appointments.append({
            "role": role,
            "operatorId": member["operator_id"],
            "organizationId": member["organization_id"],
            "publicKeySha256": member["bloch_public_key_sha256"],
            "sourceSigner": signer,
            "custodyAttestationSha256": member["custody_attestation_sha256"],
            "appointmentRecordSha256": pin(f"appointment-{index}"),
            "keyCeremonyRecordSha256": pin(f"key-ceremony-{index}"),
            "recoveryProcedureSha256": pin(f"recovery-{index}"),
            "conflictCheckSha256": pin(f"conflict-{index}"),
        })
    return {
        "schema": "postern.bridge-authority-ceremony-package.v1",
        "manifest": manifest,
        "authorityPolicy": policy,
        "appointments": appointments,
        "custodyCeremony": ceremony(
            "postern.bridge-custody-ceremony.v1",
            [f"custodian-{index}" for index in range(1, 6)], 3, "custody",
        ),
        "nativeRolesCeremony": ceremony(
            "postern.bridge-native-roles-ceremony.v1",
            ["native-issuer", "fee-sponsor"], 1, "native",
        ),
        "activationAuthorityCeremony": ceremony(
            "postern.bridge-activation-authority-ceremony.v1",
            ["activation-authority"], 1, "activation",
        ),
        "controls": {
            "keysLoaded": False,
            "signingAllowed": False,
            "deploymentAllowed": False,
            "broadcastAllowed": False,
            "activationAuthorized": False,
        },
    }


class BridgeAuthorityCeremonyTest(unittest.TestCase):
    def test_valid_public_package_remains_unqualified_and_non_authorizing(self):
        value = package()
        report = verify_bridge_authority_ceremony(value)
        self.assertEqual(report["packageCanonicalSha256"], canonical_sha256(value))
        self.assertEqual(report["authorityCount"], 8)
        self.assertEqual(report["custodyThreshold"], 3)
        self.assertTrue(report["publicBindingsConsistent"])
        for field in (
            "externalRecordsAuthenticated", "custodyQualified", "authoritiesQualified",
            "keysLoaded", "signingAllowed", "deploymentAllowed", "broadcastAllowed",
            "activationAuthorized",
        ):
            self.assertFalse(report[field])

    def test_appointments_are_exact_ordered_and_bound_to_selected_authorities(self):
        mutations = [
            lambda value: value["appointments"].pop(),
            lambda value: value["appointments"].reverse(),
            lambda value: value["appointments"][0].update(role="custodian-2"),
            lambda value: value["appointments"][0].update(
                operatorId=value["appointments"][1]["operatorId"]),
            lambda value: value["appointments"][0].update(sourceSigner=None),
            lambda value: value["appointments"][5].update(sourceSigner=pin("signer", 20)),
            lambda value: value["appointments"][0].update(
                appointmentRecordSha256="0x" + "11" * 32),
            lambda value: value["appointments"][1].update(
                recoveryProcedureSha256=value["appointments"][0]["recoveryProcedureSha256"]),
            lambda value: value["appointments"][1].update(
                conflictCheckSha256=value["appointments"][0]["appointmentRecordSha256"]),
            lambda value: value["appointments"][0].update(extra=True),
        ]
        for mutate in mutations:
            value = package()
            mutate(value)
            with self.subTest(mutation=mutate), self.assertRaises((ValueError, TypeError)):
                verify_bridge_authority_ceremony(value)

    def test_activation_authority_policy_and_independence_are_recomputed(self):
        mutations = [
            lambda value: value["authorityPolicy"].update(
                manifestCanonicalSha256=pin("other-manifest")),
            lambda value: value["authorityPolicy"].update(
                authorityPolicySha256=pin("other-policy")),
            lambda value: value["authorityPolicy"]["activationAuthority"].update(
                algorithm="secp256k1"),
            lambda value: value["authorityPolicy"]["activationAuthority"].update(
                operatorId=value["manifest"]["roles"]["issuer"]["operator_id"]),
            lambda value: value["authorityPolicy"]["activationAuthority"].update(
                publicKey="0x" + "22" * 32),
        ]
        for mutate in mutations:
            value = package()
            mutate(value)
            with self.subTest(mutation=mutate), self.assertRaises((ValueError, TypeError)):
                verify_bridge_authority_ceremony(value)

    def test_ceremonies_and_controls_are_fail_closed(self):
        mutations = [
            lambda value: value["custodyCeremony"]["participants"].reverse(),
            lambda value: value["custodyCeremony"].update(threshold=2),
            lambda value: value["custodyCeremony"].update(threshold=True),
            lambda value: value["nativeRolesCeremony"].update(
                participants=["fee-sponsor", "native-issuer"]),
            lambda value: value["activationAuthorityCeremony"].update(
                transcriptSha256=None),
            lambda value: value["activationAuthorityCeremony"].update(
                transcriptSha256=value["custodyCeremony"]["transcriptSha256"]),
            lambda value: value["activationAuthorityCeremony"].update(
                transcriptSha256=value["appointments"][0]["appointmentRecordSha256"]),
            lambda value: value["controls"].update(keysLoaded=True),
            lambda value: value["controls"].update(signingAllowed=1),
            lambda value: value["controls"].update(signingAllowed=0),
            lambda value: value["controls"].update(activationAuthorized=True),
            lambda value: value.update(extra=True),
        ]
        for mutate in mutations:
            value = package()
            mutate(value)
            with self.subTest(mutation=mutate), self.assertRaises((ValueError, TypeError)):
                verify_bridge_authority_ceremony(value)

    def test_cli_refuses_pending_and_has_no_authorizing_mode(self):
        cli = SCRIPTS / "check-bridge-authority-ceremony.py"
        pending = ROOT / "mainnet-custody/authority-ceremony.pending.json"
        refused = subprocess.run(
            [sys.executable, str(cli), str(pending)], capture_output=True, text=True,
            timeout=10, check=False,
        )
        self.assertEqual(refused.returncode, 1)
        self.assertIn('"activationAuthorized":false', refused.stderr)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ceremony.json"
            path.write_text(json.dumps(package()))
            accepted = subprocess.run(
                [sys.executable, str(cli), str(path)], capture_output=True, text=True,
                timeout=10, check=False,
            )
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            self.assertFalse(json.loads(accepted.stdout)["authoritiesQualified"])
            self.assertEqual(subprocess.run(
                [sys.executable, str(cli), str(path), "--activate"],
                capture_output=True, timeout=10, check=False,
            ).returncode, 2)


if __name__ == "__main__":
    unittest.main()
