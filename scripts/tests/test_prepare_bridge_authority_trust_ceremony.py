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

Q = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, Q - 2, Q) % Q
I = pow(2, (Q - 1) // 4, Q)


def xrecover(y):
    xx = (y * y - 1) * pow(D * y * y + 1, Q - 2, Q) % Q
    x = pow(xx, (Q + 3) // 8, Q)
    if (x * x - xx) % Q:
        x = x * I % Q
    return Q - x if x & 1 else x


BASE_Y = 4 * pow(5, Q - 2, Q) % Q
BASE = (xrecover(BASE_Y), BASE_Y)


def edwards(left, right):
    x1, y1 = left
    x2, y2 = right
    factor = D * x1 * x2 * y1 * y2
    return ((x1 * y2 + x2 * y1) * pow(1 + factor, Q - 2, Q) % Q,
            (y1 * y2 + x1 * x2) * pow(1 - factor, Q - 2, Q) % Q)


def scalar(point, value):
    result = (0, 1)
    while value:
        if value & 1:
            result = edwards(result, point)
        point = edwards(point, point)
        value >>= 1
    return result


def secret_scalar(seed):
    hashed = hashlib.sha512(seed).digest()
    return (int.from_bytes(hashed[:32], "little") & ((1 << 254) - 8)) | (1 << 254)


def encode_point(point):
    x, y = point
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def public_key(seed):
    return encode_point(scalar(BASE, secret_scalar(seed)))


def ed25519_sign(seed, message):
    hashed = hashlib.sha512(seed).digest()
    public = public_key(seed)
    nonce = int.from_bytes(hashlib.sha512(hashed[32:] + message).digest(), "little") % L
    encoded_r = encode_point(scalar(BASE, nonce))
    challenge = int.from_bytes(
        hashlib.sha512(encoded_r + public + message).digest(), "little") % L
    encoded_s = int.to_bytes((nonce + challenge * secret_scalar(seed)) % L, 32, "little")
    return encoded_r + encoded_s


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
    @classmethod
    def setUpClass(cls):
        subprocess.run([
            "cargo", "build", "--quiet", "--bin", "bridge_ed25519_public_verifier",
        ], cwd=ROOT, capture_output=True, timeout=120, check=True)
        cls.public_verifier = ROOT / "target/debug/bridge_ed25519_public_verifier"
        cls.public_verifier_sha256 = (
            "0x" + hashlib.sha256(cls.public_verifier.read_bytes()).hexdigest())

    def run_cli(self, *arguments):
        return subprocess.run([sys.executable, str(CLI), *map(str, arguments)],
                              capture_output=True, text=True, timeout=10, check=False)

    def write(self, directory, value):
        path = Path(directory) / "intake.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def key(self, directory, name):
        seed = hashlib.sha256(f"test-only-seed:{name}".encode()).digest()
        return seed, "0x" + public_key(seed).hex()

    def sign(self, private, message, output):
        Path(output).write_bytes(ed25519_sign(private, Path(message).read_bytes()))
        self.assertEqual(Path(output).stat().st_size, 64)

    def verifier_arguments(self):
        return [
            "--public-signature-verifier", self.public_verifier,
            "--public-signature-verifier-sha256", self.public_verifier_sha256,
        ]

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

    def test_detached_root_signature_import_and_create_once_apply(self):
        with tempfile.TemporaryDirectory() as directory:
            private, public = self.key(directory, "root-1")
            value = intake()
            value["trustAnchorPackage"]["roots"][0]["publicKey"] = public
            source = self.write(directory, value)
            requests = Path(directory) / "root-requests"
            self.assertEqual(self.run_cli(
                "root-requests", source, requests).returncode, 0)
            request = requests / "trust-root-1-pop.request.json"
            message = requests / "trust-root-1-pop.message.bin"
            signature = Path(directory) / "root-1.signature.bin"
            self.sign(private, message, signature)
            response = Path(directory) / "root-1.response.json"
            imported = self.run_cli(
                "import-signature", request, message, signature, response,
                *self.verifier_arguments())
            self.assertEqual(imported.returncode, 0, imported.stderr)
            self.assertEqual(response.stat().st_mode & 0o777, 0o600)

            request_before = request.read_bytes()
            alias_import = self.run_cli(
                "import-signature", request, message, signature, request,
                *self.verifier_arguments())
            self.assertEqual(alias_import.returncode, 1)
            self.assertEqual(request.read_bytes(), request_before)

            applied_path = Path(directory) / "intake.root-1.json"
            applied = self.run_cli("apply-signature", source, response, applied_path,
                                   *self.verifier_arguments())
            self.assertEqual(applied.returncode, 0, applied.stderr)
            self.assertEqual(applied_path.stat().st_mode & 0o777, 0o600)
            applied_value = json.loads(applied_path.read_text())
            self.assertEqual(
                applied_value["trustAnchorPackage"]["roots"][0]
                ["proofOfPossessionSignature"],
                "0x" + signature.read_bytes().hex(),
            )
            self.assertIsNone(value["trustAnchorPackage"]["roots"][0]
                              ["proofOfPossessionSignature"])

            duplicate = Path(directory) / "duplicate.json"
            refused = self.run_cli(
                "apply-signature", applied_path, response, duplicate,
                *self.verifier_arguments())
            self.assertEqual(refused.returncode, 1)
            self.assertFalse(duplicate.exists())

            before = source.read_bytes()
            alias = self.run_cli("apply-signature", source, response, source,
                                 *self.verifier_arguments())
            self.assertEqual(alias.returncode, 1)
            self.assertEqual(source.read_bytes(), before)

    def test_role_index_foreign_signature_and_partial_package_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            private, public = self.key(directory, "selected-root")
            foreign_private, _ = self.key(directory, "foreign-root")
            value = intake()
            value["trustAnchorPackage"]["roots"][0]["publicKey"] = public
            source = self.write(directory, value)
            requests = Path(directory) / "root-requests"
            self.assertEqual(self.run_cli(
                "root-requests", source, requests).returncode, 0)
            request = requests / "trust-root-1-pop.request.json"
            message = requests / "trust-root-1-pop.message.bin"

            foreign_signature = Path(directory) / "foreign.signature.bin"
            self.sign(foreign_private, message, foreign_signature)
            foreign_response = Path(directory) / "foreign.response.json"
            refused = self.run_cli("import-signature", request, message,
                                   foreign_signature, foreign_response,
                                   *self.verifier_arguments())
            self.assertEqual(refused.returncode, 1)
            self.assertFalse(foreign_response.exists())

            signature = Path(directory) / "selected.signature.bin"
            self.sign(private, message, signature)
            response = Path(directory) / "selected.response.json"
            self.assertEqual(self.run_cli(
                "import-signature", request, message, signature, response,
                *self.verifier_arguments()).returncode, 0)
            substituted = json.loads(response.read_text())
            substituted["role"] = "trust-root-2"
            substituted_path = Path(directory) / "substituted.response.json"
            substituted_path.write_text(json.dumps(substituted), encoding="utf-8")
            output = Path(directory) / "substituted-output.json"
            refused = self.run_cli(
                "apply-signature", source, substituted_path, output,
                *self.verifier_arguments())
            self.assertEqual(refused.returncode, 1)
            self.assertFalse(output.exists())

            substituted = json.loads(response.read_text())
            substituted["authorityId"] = value["trustAnchorPackage"]["roots"][1][
                "authorityId"]
            substituted_path.write_text(json.dumps(substituted), encoding="utf-8")
            refused = self.run_cli(
                "apply-signature", source, substituted_path, output,
                *self.verifier_arguments())
            self.assertEqual(refused.returncode, 1)
            self.assertFalse(output.exists())

            # An operational signature cannot be applied before all root PoP
            # slots have been populated, even when the signature itself is valid.
            authority_private, authority_public = self.key(directory, "custodian-1")
            staged = intake(root_signatures=True)
            staged["operationalAuthorityPackage"]["authorities"][0][
                "publicKey"] = authority_public
            staged_path = Path(directory) / "staged.json"
            staged_path.write_text(json.dumps(staged), encoding="utf-8")
            authority_requests = Path(directory) / "authority-requests"
            self.assertEqual(self.run_cli(
                "authority-requests", staged_path, authority_requests).returncode, 0)
            authority_message = authority_requests / "custodian-1-pop.message.bin"
            authority_signature = Path(directory) / "authority.signature.bin"
            self.sign(authority_private, authority_message, authority_signature)
            authority_response = Path(directory) / "authority.response.json"
            self.assertEqual(self.run_cli(
                "import-signature",
                authority_requests / "custodian-1-pop.request.json",
                authority_message, authority_signature, authority_response,
                *self.verifier_arguments(),
            ).returncode, 0)
            staged["trustAnchorPackage"]["roots"][2][
                "proofOfPossessionSignature"] = None
            partial = Path(directory) / "partial.json"
            partial.write_text(json.dumps(staged), encoding="utf-8")
            partial_output = Path(directory) / "partial-output.json"
            refused = self.run_cli(
                "apply-signature", partial, authority_response, partial_output,
                *self.verifier_arguments())
            self.assertEqual(refused.returncode, 1)
            self.assertFalse(partial_output.exists())

    def test_operational_and_root_approval_signatures_apply_to_exact_slots(self):
        with tempfile.TemporaryDirectory() as directory:
            authority_seed, authority_public = self.key(directory, "exact-custodian")
            value = intake(root_signatures=True)
            value["operationalAuthorityPackage"]["authorities"][0][
                "publicKey"] = authority_public
            source = self.write(directory, value)
            requests = Path(directory) / "authority-requests"
            self.assertEqual(self.run_cli(
                "authority-requests", source, requests).returncode, 0)
            message = requests / "custodian-1-pop.message.bin"
            signature = Path(directory) / "custodian.signature.bin"
            self.sign(authority_seed, message, signature)
            response = Path(directory) / "custodian.response.json"
            self.assertEqual(self.run_cli(
                "import-signature", requests / "custodian-1-pop.request.json",
                message, signature, response, *self.verifier_arguments(),
            ).returncode, 0)
            applied = Path(directory) / "authority-applied.json"
            result = self.run_cli(
                "apply-signature", source, response, applied,
                *self.verifier_arguments())
            self.assertEqual(result.returncode, 0, result.stderr)
            applied_value = json.loads(applied.read_text())
            self.assertEqual(
                applied_value["operationalAuthorityPackage"]["authorities"][0]
                ["proofOfPossessionSignature"],
                "0x" + signature.read_bytes().hex(),
            )

            approval_seed, approval_public = self.key(directory, "exact-root-2")
            approval_value = intake(root_signatures=True, authority_signatures=True)
            approval_value["trustAnchorPackage"]["roots"][1][
                "publicKey"] = approval_public
            approval_source = Path(directory) / "approval-source.json"
            approval_source.write_text(json.dumps(approval_value), encoding="utf-8")
            approval_requests = Path(directory) / "approval-requests"
            self.assertEqual(self.run_cli(
                "approval-requests", approval_source, approval_requests).returncode, 0)
            approval_message = approval_requests / "trust-root-2-approval.message.bin"
            approval_signature = Path(directory) / "approval.signature.bin"
            self.sign(approval_seed, approval_message, approval_signature)
            approval_response = Path(directory) / "approval.response.json"
            self.assertEqual(self.run_cli(
                "import-signature",
                approval_requests / "trust-root-2-approval.request.json",
                approval_message, approval_signature, approval_response,
                *self.verifier_arguments(),
            ).returncode, 0)
            approval_applied = Path(directory) / "approval-applied.json"
            result = self.run_cli(
                "apply-signature", approval_source, approval_response,
                approval_applied, *self.verifier_arguments())
            self.assertEqual(result.returncode, 0, result.stderr)
            approvals = json.loads(approval_applied.read_text())[
                "operationalAuthorityPackage"]["rootApprovals"]
            self.assertEqual(approvals, [{
                "authorityId": approval_value["trustAnchorPackage"]["roots"][1]
                ["authorityId"],
                "signature": "0x" + approval_signature.read_bytes().hex(),
            }])
            duplicate_output = Path(directory) / "duplicate-approval.json"
            refused = self.run_cli(
                "apply-signature", approval_applied, approval_response,
                duplicate_output, *self.verifier_arguments())
            self.assertEqual(refused.returncode, 1)
            self.assertFalse(duplicate_output.exists())


if __name__ == "__main__":
    unittest.main()
