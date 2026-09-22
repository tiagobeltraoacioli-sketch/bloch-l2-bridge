"""Adversarial tests for authenticated external authority qualification."""
import copy
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
from bridge_authority_qualification import (  # noqa: E402
    DOMAIN, SSH_NAMESPACE, verify_bridge_authority_qualification,
)
from custody_deployment_manifest import canonical_sha256  # noqa: E402
from test_bridge_authority_ceremony import package as ceremony_package  # noqa: E402
from test_custody_deployment_manifest import pin  # noqa: E402


def policy(directory):
    reviewers = []
    private_keys = {}
    for index in range(1, 6):
        private_key = Path(directory) / f"reviewer-{index}"
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "",
             "-f", str(private_key)], capture_output=True, timeout=10, check=True,
        )
        public_key = (private_key.with_suffix(".pub").read_text(encoding="ascii")
                      .strip().split())
        public_key = " ".join(public_key[:2])
        reviewer_id = pin(f"external-reviewer-{index}")
        reviewers.append({
            "reviewerId": reviewer_id,
            "organizationId": pin(f"external-review-organization-{index}"),
            "algorithm": "ed25519",
            "publicKey": public_key,
        })
        private_keys[reviewer_id] = private_key
    return {
        "schema": "postern.bridge-authority-review-policy.v1",
        "threshold": 3,
        "reviewers": reviewers,
    }, private_keys


def sign(private_key, message):
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        message_path = root / "message"
        message_path.write_bytes(message)
        subprocess.run(
            ["ssh-keygen", "-Y", "sign", "-f", str(private_key),
             "-n", SSH_NAMESPACE, str(message_path)],
            capture_output=True, timeout=10, check=True,
        )
        return (Path(str(message_path) + ".sig").read_text(encoding="ascii"))


def qualification(ceremony, review_policy, private_keys, count=3):
    preflight = verify_bridge_authority_ceremony(ceremony)
    bindings = {
        "ceremonyPackageCanonicalSha256": preflight["packageCanonicalSha256"],
        "manifestCanonicalSha256": preflight["manifestCanonicalSha256"],
        "authorityPolicySha256": preflight["authorityPolicySha256"],
        "custodyCeremonySha256": preflight["custodyCeremonySha256"],
        "nativeRolesCeremonySha256": preflight["nativeRolesCeremonySha256"],
        "activationAuthorityCeremonySha256": preflight[
            "activationAuthorityCeremonySha256"
        ],
        "reviewPolicySha256": canonical_sha256(review_policy),
    }
    attestations = []
    for index, reviewer in enumerate(review_policy["reviewers"][:count], 1):
        attestation = {
            "reviewerId": reviewer["reviewerId"],
            "organizationId": reviewer["organizationId"],
            **bindings,
            "reviewRecordSha256": pin(f"external-review-record-{index}"),
            "decision": "qualify-authorities-without-activation",
        }
        message = DOMAIN + json.dumps(
            attestation, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        ).encode("ascii")
        attestation["signature"] = sign(
            private_keys[reviewer["reviewerId"]], message
        )
        attestations.append(attestation)
    return {
        "schema": "postern.bridge-authority-qualification-review.v1",
        **bindings,
        "attestations": attestations,
        "controls": {
            "keysLoaded": False,
            "signingAllowed": False,
            "deploymentAllowed": False,
            "broadcastAllowed": False,
            "activationAuthorized": False,
        },
    }


class BridgeAuthorityQualificationTest(unittest.TestCase):
    def setUp(self):
        self.key_directory = tempfile.TemporaryDirectory()
        self.ceremony = ceremony_package()
        self.policy, self.private_keys = policy(self.key_directory.name)
        self.trusted_policy_digest = canonical_sha256(self.policy)
        self.value = qualification(self.ceremony, self.policy, self.private_keys)

    def tearDown(self):
        self.key_directory.cleanup()

    def test_authenticated_quorum_qualifies_without_authorizing(self):
        report = verify_bridge_authority_qualification(
            self.ceremony, self.value, self.policy, self.trusted_policy_digest
        )
        self.assertEqual(report["reviewerCount"], 3)
        self.assertTrue(report["externalRecordsAuthenticated"])
        self.assertTrue(report["custodyQualified"])
        self.assertTrue(report["authoritiesQualified"])
        for field in (
            "keysLoaded", "signingAllowed", "deploymentAllowed",
            "broadcastAllowed", "activationAuthorized",
        ):
            self.assertFalse(report[field])

    def test_exact_commitments_and_signatures_are_required(self):
        mutations = [
            lambda value: value.update(ceremonyPackageCanonicalSha256=pin("other")),
            lambda value: value.update(
                ceremonyPackageCanonicalSha256=value[
                    "ceremonyPackageCanonicalSha256"
                ].upper()),
            lambda value: value["attestations"][0].update(
                manifestCanonicalSha256=pin("other-manifest")),
            lambda value: value["attestations"][0].update(
                reviewRecordSha256=value["attestations"][1]["reviewRecordSha256"]),
            lambda value: value["attestations"][0].update(
                decision="activate"),
            lambda value: value["attestations"][0].update(
                signature=value["attestations"][1]["signature"]),
            lambda value: value["controls"].update(signingAllowed=True),
            lambda value: value.update(extra=True),
        ]
        for mutate in mutations:
            value = copy.deepcopy(self.value)
            mutate(value)
            with self.subTest(mutation=mutate), self.assertRaises((ValueError, TypeError)):
                verify_bridge_authority_qualification(
                    self.ceremony, value, self.policy, self.trusted_policy_digest
                )

    def test_quorum_untrusted_duplicate_and_substitution_are_refused(self):
        values = []
        too_few = copy.deepcopy(self.value)
        too_few["attestations"].pop()
        values.append((too_few, self.policy))
        duplicate = copy.deepcopy(self.value)
        duplicate["attestations"][1] = copy.deepcopy(duplicate["attestations"][0])
        values.append((duplicate, self.policy))
        substituted_policy = copy.deepcopy(self.policy)
        substituted_policy["reviewers"][0]["organizationId"] = pin("substitute")
        values.append((self.value, substituted_policy))
        changed_ceremony = copy.deepcopy(self.ceremony)
        changed_ceremony["appointments"][0]["appointmentRecordSha256"] = pin("changed")
        values.append((self.value, self.policy, changed_ceremony))
        for item in values:
            value, review_policy = item[:2]
            ceremony = item[2] if len(item) == 3 else self.ceremony
            with self.subTest(item=item), self.assertRaises((ValueError, TypeError)):
                verify_bridge_authority_qualification(
                    ceremony, value, review_policy, self.trusted_policy_digest
                )

    def test_reviewers_must_be_external_and_independent(self):
        mutations = [
            lambda value: value["reviewers"][0].update(
                reviewerId=self.ceremony["appointments"][0]["operatorId"]),
            lambda value: value["reviewers"][0].update(
                organizationId=self.ceremony["appointments"][0]["organizationId"]),
            lambda value: value["reviewers"][1].update(
                reviewerId=value["reviewers"][0]["reviewerId"]),
            lambda value: value["reviewers"][1].update(
                organizationId=value["reviewers"][0]["organizationId"]),
            lambda value: value["reviewers"][1].update(
                publicKey=value["reviewers"][0]["publicKey"]),
            lambda value: value.update(threshold=2),
            lambda value: value["reviewers"].pop(),
        ]
        for mutate in mutations:
            review_policy = copy.deepcopy(self.policy)
            mutate(review_policy)
            with self.subTest(mutation=mutate), self.assertRaises((ValueError, TypeError)):
                verify_bridge_authority_qualification(
                    self.ceremony, self.value, review_policy,
                    self.trusted_policy_digest,
                )

    def test_self_selected_fully_signed_policy_is_not_a_trust_root(self):
        with tempfile.TemporaryDirectory() as directory:
            attacker_policy, attacker_keys = policy(directory)
            attacker_qualification = qualification(
                self.ceremony, attacker_policy, attacker_keys
            )
            with self.assertRaisesRegex(ValueError, "trusted digest"):
                verify_bridge_authority_qualification(
                    self.ceremony, attacker_qualification, attacker_policy,
                    self.trusted_policy_digest,
                )
        with self.assertRaisesRegex(ValueError, "canonical lowercase"):
            verify_bridge_authority_qualification(
                self.ceremony, self.value, self.policy,
                "0x" + self.trusted_policy_digest[2:].upper(),
            )
        with self.assertRaises(TypeError):
            verify_bridge_authority_qualification(
                self.ceremony, self.value, self.policy
            )

    def test_checked_in_pending_state_and_cli_fail_closed(self):
        cli = SCRIPTS / "check-bridge-authority-qualification.py"
        completed = subprocess.run(
            [sys.executable, str(cli),
             "--ceremony", str(ROOT / "mainnet-custody/authority-ceremony.pending.json"),
             "--qualification", str(ROOT / "mainnet-custody/authority-qualification.pending.json"),
             "--review-policy", str(ROOT / "mainnet-custody/authority-review-policy.pending.json"),
             "--trusted-review-policy-sha256", pin("pending-trusted-policy")],
            capture_output=True, text=True, timeout=10, check=False,
        )
        self.assertEqual(completed.returncode, 1)
        self.assertIn('"activationAuthorized":false', completed.stderr)
        self.assertEqual(subprocess.run(
            [sys.executable, str(cli), "--activate"],
            capture_output=True, timeout=10, check=False,
        ).returncode, 2)


if __name__ == "__main__":
    unittest.main()
