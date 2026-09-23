"""Tests for the public offline authority ceremony coordinator."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
CLI = ROOT / "scripts/prepare-bridge-authority-trust-ceremony.py"


def digest(label, size=32):
    output = b""
    counter = 0
    while len(output) < size:
        output += hashlib.sha256(f"{label}-{counter}".encode()).digest()
        counter += 1
    return "0x" + output[:size].hex()


def intake(root_signatures=False, authority_signatures=False, approvals=False):
    roots = []
    for index in range(3):
        roots.append({
            "authorityId": digest(f"root-id-{index}"),
            "organizationId": digest(f"root-org-{index}"),
            "publicKey": digest(f"root-key-{index}"),
            "recoveryDeclarationSha256": digest(f"root-recovery-{index}"),
            "conflictDeclarationSha256": digest(f"root-conflict-{index}"),
            "proofOfPossessionSignature": (
                digest(f"root-signature-{index}", 64) if root_signatures else None
            ),
        })
    roles = [
        "custodian-1", "custodian-2", "custodian-3", "custodian-4",
        "custodian-5", "native-issuer", "fee-sponsor", "activation-authority",
    ]
    authorities = []
    for index, role in enumerate(roles):
        authorities.append({
            "role": role,
            "authorityId": digest(f"authority-id-{index}"),
            "organizationId": digest(f"authority-org-{index}"),
            "publicKey": digest(f"authority-key-{index}"),
            "appointmentRecordSha256": digest(f"appointment-{index}"),
            "recoveryDeclarationSha256": digest(f"recovery-{index}"),
            "conflictDeclarationSha256": digest(f"conflict-{index}"),
            "proofOfPossessionSignature": (
                digest(f"authority-signature-{index}", 64)
                if authority_signatures else None
            ),
        })
    root_approvals = []
    if approvals:
        for index in range(2):
            root_approvals.append({
                "authorityId": roots[index]["authorityId"],
                "signature": digest(f"approval-{index}", 64),
            })
    return {
        "schema": "postern.bridge-authority-trust-intake.v1",
        "trustAnchorPackage": {
            "schema": "postern.bridge-authority-trust-anchor.v1",
            "domain": "bloch-bridge-authority-trust-v1",
            "packageSequence": "1",
            "previousPackageSha256": "0x" + "00" * 32,
            "roots": roots,
        },
        "operationalAuthorityPackage": {
            "schema": "postern.bridge-operational-authority-package.v1",
            "manifestCanonicalSha256": digest("manifest"),
            "ceremonyPackageCanonicalSha256": digest("ceremony"),
            "custodyThreshold": 3,
            "authorities": authorities,
            "rootApprovals": root_approvals,
        },
    }


class OfflineAuthorityCeremonyTest(unittest.TestCase):
    def run_cli(self, *arguments):
        return subprocess.run([sys.executable, str(CLI), *map(str, arguments)],
                              capture_output=True, text=True, timeout=10, check=False)

    def write(self, directory, value):
        path = Path(directory) / "intake.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def test_template_contains_no_identity_key_signature_or_approval(self):
        result = self.run_cli("template")
        self.assertEqual(result.returncode, 0, result.stderr)
        value = json.loads(result.stdout)
        self.assertEqual(len(value["trustAnchorPackage"]["roots"]), 3)
        self.assertEqual(len(value["operationalAuthorityPackage"]["authorities"]), 8)
        self.assertEqual(value["operationalAuthorityPackage"]["rootApprovals"], [])
        encoded = result.stdout.lower()
        self.assertNotIn("privatekey", encoded)
        for root in value["trustAnchorPackage"]["roots"]:
            self.assertTrue(all(item is None for item in root.values()))

    def test_root_requests_are_exact_domain_separated_public_messages(self):
        with tempfile.TemporaryDirectory() as directory:
            value = intake()
            path = self.write(directory, value)
            output = Path(directory) / "roots"
            result = self.run_cli("root-requests", path, output)
            self.assertEqual(result.returncode, 0, result.stderr)
            inventory = json.loads((output / "inventory.json").read_text())
            self.assertEqual(len(inventory["requests"]), 3)
            self.assertFalse(inventory["privateKeysIncluded"])
            message = (output / "trust-root-1-pop.message.bin").read_bytes()
            expected_value = {
                "domain": "bloch-bridge-authority-trust-v1",
                "packageSequence": "1",
                "previousPackageSha256": "0x" + "00" * 32,
                **{key: value["trustAnchorPackage"]["roots"][0][key] for key in (
                    "authorityId", "organizationId", "publicKey",
                    "recoveryDeclarationSha256", "conflictDeclarationSha256",
                )},
            }
            expected = (b"BLOCH-BRIDGE-TRUST-ROOT-POP-v1\0" +
                        json.dumps(expected_value, separators=(",", ":")).encode())
            self.assertEqual(message, expected)
            self.assertEqual(inventory["requests"][0]["messageSha256"],
                             "0x" + hashlib.sha256(message).hexdigest())
            for artifact in output.iterdir():
                self.assertEqual(artifact.stat().st_mode & 0o777, 0o600)

    def test_operational_and_approval_requests_follow_ceremony_phases(self):
        with tempfile.TemporaryDirectory() as directory:
            root_signed = self.write(directory, intake(root_signatures=True))
            authorities = Path(directory) / "authorities"
            result = self.run_cli("authority-requests", root_signed, authorities)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(len(list(authorities.glob("*.message.bin"))), 8)

            completed_pops = self.write(
                directory, intake(root_signatures=True, authority_signatures=True))
            approvals = Path(directory) / "approvals"
            result = self.run_cli("approval-requests", completed_pops, approvals)
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(len(list(approvals.glob("*.message.bin"))), 3)
            messages = [path.read_bytes() for path in approvals.glob("*.message.bin")]
            self.assertTrue(all(message == messages[0] for message in messages))
            self.assertTrue(messages[0].startswith(
                b"BLOCH-BRIDGE-OPERATIONAL-AUTHORITY-APPROVAL-v1\0"))
            self.assertEqual(report["approvalMessageSha256"],
                             "0x" + hashlib.sha256(messages[0]).hexdigest())

    def test_out_of_order_roles_placeholders_and_premature_signatures_fail(self):
        mutations = []
        value = intake()
        value["operationalAuthorityPackage"]["authorities"].reverse()
        mutations.append(("authority-requests", value))
        value = intake()
        value["trustAnchorPackage"]["roots"][0]["publicKey"] = "0x" + "11" * 32
        mutations.append(("root-requests", value))
        value = intake(root_signatures=True)
        value["operationalAuthorityPackage"]["authorities"][0][
            "proofOfPossessionSignature"] = digest("premature", 64)
        mutations.append(("authority-requests", value))
        for index, (command, value) in enumerate(mutations):
            with self.subTest(command=command), tempfile.TemporaryDirectory() as directory:
                path = self.write(directory, value)
                result = self.run_cli(command, path, Path(directory) / f"out-{index}")
                self.assertEqual(result.returncode, 1)
                self.assertIn('"activationAuthorized":false', result.stderr)

    def test_verify_requires_exact_reviewed_executable_hash_and_fail_closed_binary(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.write(
                directory,
                intake(root_signatures=True, authority_signatures=True, approvals=True),
            )
            verifier = Path(directory) / "verifier"
            verifier.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
            verifier.chmod(0o700)
            actual = "0x" + hashlib.sha256(verifier.read_bytes()).hexdigest()
            mismatch = self.run_cli("verify", path, "--verifier", verifier,
                                    "--verifier-sha256", digest("wrong-verifier"))
            self.assertEqual(mismatch.returncode, 1)
            refused = self.run_cli("verify", path, "--verifier", verifier,
                                   "--verifier-sha256", actual)
            self.assertEqual(refused.returncode, 1)
            self.assertNotIn("anchorPinnedVerifierAccepted", refused.stdout)

            verifier.chmod(0o722)
            writable = self.run_cli("verify", path, "--verifier", verifier,
                                    "--verifier-sha256", actual)
            self.assertEqual(writable.returncode, 1)

            verifier.chmod(0o700)
            hardlink = Path(directory) / "verifier-hardlink"
            os.link(verifier, hardlink)
            linked = self.run_cli("verify", path, "--verifier", verifier,
                                  "--verifier-sha256", actual)
            self.assertEqual(linked.returncode, 1)
            hardlink.unlink()

            symlink = Path(directory) / "verifier-symlink"
            symlink.symlink_to(verifier)
            linked = self.run_cli("verify", path, "--verifier", symlink,
                                  "--verifier-sha256", actual)
            self.assertEqual(linked.returncode, 1)


if __name__ == "__main__":
    unittest.main()
