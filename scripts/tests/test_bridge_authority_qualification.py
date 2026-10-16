"""Adversarial tests for authenticated external authority qualification."""
import copy
import hashlib
import json
from pathlib import Path
import shutil
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


def qualification_checkpoint(ceremony, review_policy, sequence="0", last=None):
    preflight = verify_bridge_authority_ceremony(ceremony)
    return {
        "schema": "postern.bridge-authority-qualification-checkpoint.v1",
        "reviewPolicySha256": canonical_sha256(review_policy),
        "ceremonyPackageCanonicalSha256": preflight["packageCanonicalSha256"],
        "lastQualificationSequence": sequence,
        "lastQualificationSha256": last or "0x" + "00" * 32,
    }


def qualification(ceremony, review_policy, private_keys, count=3,
                  checkpoint_value=None):
    preflight = verify_bridge_authority_ceremony(ceremony)
    checkpoint_value = checkpoint_value or qualification_checkpoint(
        ceremony, review_policy
    )
    next_sequence = str(int(checkpoint_value["lastQualificationSequence"]) + 1)
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
        "qualificationCheckpointSha256": canonical_sha256(checkpoint_value),
        "qualificationSequence": next_sequence,
        "previousQualificationSha256": checkpoint_value[
            "lastQualificationSha256"
        ],
    }
    appointment_evidence = [
        item[field].lower()
        for item in ceremony["appointments"]
        for field in (
            "appointmentRecordSha256", "keyCeremonyRecordSha256",
            "recoveryProcedureSha256", "conflictCheckSha256",
        )
    ]
    ceremony_evidence = [
        ceremony[name][field].lower()
        for name in (
            "custodyCeremony", "nativeRolesCeremony",
            "activationAuthorityCeremony",
        )
        for field in (
            "transcriptSha256", "recoveryExerciseSha256",
            "independentWitnessReportSha256",
        )
    ]
    records, attestations = [], []
    for reviewer in review_policy["reviewers"][:count]:
        record = {
            "schema": "postern.bridge-authority-review-record.v1",
            "reviewerId": reviewer["reviewerId"],
            "organizationId": reviewer["organizationId"],
            "ceremonyPackageCanonicalSha256": bindings[
                "ceremonyPackageCanonicalSha256"
            ],
            "reviewPolicySha256": bindings["reviewPolicySha256"],
            "qualificationCheckpointSha256": bindings[
                "qualificationCheckpointSha256"
            ],
            "qualificationSequence": bindings["qualificationSequence"],
            "previousQualificationSha256": bindings[
                "previousQualificationSha256"
            ],
            "appointmentEvidenceSha256": appointment_evidence,
            "ceremonyEvidenceSha256": ceremony_evidence,
            "decision": "authenticate-public-records-without-activation",
        }
        records.append(record)
        attestation = {
            "reviewerId": reviewer["reviewerId"],
            "organizationId": reviewer["organizationId"],
            **bindings,
            "reviewRecordSha256": canonical_sha256(record),
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
        "schema": "postern.bridge-authority-qualification-review.v2",
        **bindings,
        "reviewRecords": records,
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
        self.checkpoint = qualification_checkpoint(self.ceremony, self.policy)
        self.trusted_checkpoint_digest = canonical_sha256(self.checkpoint)
        self.value = qualification(
            self.ceremony, self.policy, self.private_keys,
            checkpoint_value=self.checkpoint,
        )
        ssh_keygen = shutil.which("ssh-keygen")
        if ssh_keygen is None:
            self.fail("ssh-keygen is required for qualification tests")
        self.ssh_keygen = str(Path(ssh_keygen).resolve())
        self.trusted_ssh_keygen_digest = (
            "0x" + hashlib.sha256(Path(self.ssh_keygen).read_bytes()).hexdigest()
        )

    def verify(self, ceremony=None, value=None, review_policy=None, policy_digest=None,
               checkpoint_value=None, checkpoint_digest=None, **kwargs):
        return verify_bridge_authority_qualification(
            self.ceremony if ceremony is None else ceremony,
            self.value if value is None else value,
            self.policy if review_policy is None else review_policy,
            self.trusted_policy_digest if policy_digest is None else policy_digest,
            checkpoint=(
                self.checkpoint if checkpoint_value is None else checkpoint_value
            ),
            trusted_checkpoint_sha256=(
                self.trusted_checkpoint_digest
                if checkpoint_digest is None else checkpoint_digest
            ),
            ssh_keygen=kwargs.get("ssh_keygen", self.ssh_keygen),
            trusted_ssh_keygen_sha256=kwargs.get(
                "trusted_ssh_keygen_sha256", self.trusted_ssh_keygen_digest
            ),
        )

    def tearDown(self):
        self.key_directory.cleanup()

    def test_signed_quorum_remains_observation_only_without_external_roots(self):
        report = self.verify()
        self.assertEqual(
            report["schema"], "postern.bridge-authority-external-observation.v1"
        )
        self.assertEqual(report["reviewerCount"], 3)
        self.assertFalse(report["externalRecordsAuthenticated"])
        self.assertFalse(report["custodyQualified"])
        self.assertFalse(report["authoritiesQualified"])
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
                self.verify(value=value)

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
                self.verify(
                    ceremony=ceremony, value=value, review_policy=review_policy
                )

    def test_opaque_incomplete_or_cross_reviewer_records_are_refused(self):
        mutations = [
            lambda value: value["reviewRecords"].pop(),
            lambda value: value["reviewRecords"][0][
                "appointmentEvidenceSha256"
            ].pop(),
            lambda value: value["reviewRecords"][0][
                "ceremonyEvidenceSha256"
            ].__setitem__(0, pin("substituted-ceremony-record")),
            lambda value: value["reviewRecords"][0].update(
                ceremonyPackageCanonicalSha256=pin("other-ceremony-package")
            ),
            lambda value: value["reviewRecords"][0].update(
                reviewerId=value["reviewRecords"][1]["reviewerId"]
            ),
            lambda value: value["reviewRecords"][0].update(
                decision="qualify-and-activate"
            ),
            lambda value: value["reviewRecords"][0].update(extra=True),
        ]
        for mutate in mutations:
            value = copy.deepcopy(self.value)
            mutate(value)
            with self.subTest(mutation=mutate), self.assertRaises(
                (ValueError, TypeError)
            ):
                self.verify(value=value)

    def test_checkpoint_requires_exact_monotonic_successor_and_predecessor(self):
        first_digest = canonical_sha256(self.value)
        advanced = qualification_checkpoint(
            self.ceremony, self.policy, sequence="1", last=first_digest
        )
        advanced_digest = canonical_sha256(advanced)
        with self.assertRaisesRegex(ValueError, "exact checkpoint successor"):
            self.verify(
                checkpoint_value=advanced, checkpoint_digest=advanced_digest
            )
        successor = qualification(
            self.ceremony, self.policy, self.private_keys,
            checkpoint_value=advanced,
        )
        report = self.verify(
            value=successor, checkpoint_value=advanced,
            checkpoint_digest=advanced_digest,
        )
        self.assertEqual(report["qualificationSequence"], "2")
        self.assertEqual(report["previousQualificationSha256"], first_digest)

        attacks = []
        wrong_policy = copy.deepcopy(advanced)
        wrong_policy["reviewPolicySha256"] = pin("wrong-policy")
        attacks.append((wrong_policy, canonical_sha256(wrong_policy)))
        rollback = copy.deepcopy(advanced)
        rollback["lastQualificationSequence"] = "0"
        rollback["lastQualificationSha256"] = "0x" + "00" * 32
        attacks.append((rollback, canonical_sha256(rollback)))
        for checkpoint_value, checkpoint_digest in attacks:
            with self.subTest(checkpoint=checkpoint_value), self.assertRaises(
                (ValueError, TypeError)
            ):
                self.verify(
                    value=successor, checkpoint_value=checkpoint_value,
                    checkpoint_digest=checkpoint_digest,
                )
        with self.assertRaisesRegex(ValueError, "trusted digest"):
            self.verify(checkpoint_digest=pin("self-selected-other-checkpoint"))

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
                self.verify(review_policy=review_policy)

    def test_self_selected_fully_signed_policy_is_not_a_trust_root(self):
        with tempfile.TemporaryDirectory() as directory:
            attacker_policy, attacker_keys = policy(directory)
            attacker_qualification = qualification(
                self.ceremony, attacker_policy, attacker_keys
            )
            with self.assertRaisesRegex(ValueError, "trusted digest"):
                self.verify(
                    value=attacker_qualification, review_policy=attacker_policy
                )
        with self.assertRaisesRegex(ValueError, "canonical lowercase"):
            self.verify(
                policy_digest="0x" + self.trusted_policy_digest[2:].upper()
            )
        with self.assertRaises(TypeError):
            verify_bridge_authority_qualification(
                self.ceremony, self.value, self.policy
            )

    def test_signature_verifier_is_absolute_immutable_and_externally_pinned(self):
        with tempfile.TemporaryDirectory() as directory:
            fake = Path(directory) / "fake-ssh-keygen"
            fake.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
            fake.chmod(0o700)
            fake_digest = "0x" + hashlib.sha256(fake.read_bytes()).hexdigest()
            with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                self.verify(
                    trusted_ssh_keygen_sha256=pin("wrong-signature-verifier")
                )
            with self.assertRaisesRegex(ValueError, "absolute"):
                self.verify(
                    ssh_keygen="ssh-keygen",
                    trusted_ssh_keygen_sha256=fake_digest,
                )
            with self.assertRaisesRegex(ValueError, "immutable regular"):
                self.verify(
                    ssh_keygen=str(fake),
                    trusted_ssh_keygen_sha256=fake_digest,
                )
        with self.assertRaisesRegex(ValueError, "canonical lowercase"):
            self.verify(
                trusted_ssh_keygen_sha256=(
                    "0x" + self.trusted_ssh_keygen_digest[2:].upper()
                )
            )
        true_path = shutil.which("true")
        if true_path is None:
            self.fail("true is required for signature-verifier attack test")
        true_path = str(Path(true_path).resolve())
        true_digest = "0x" + hashlib.sha256(Path(true_path).read_bytes()).hexdigest()
        with self.assertRaisesRegex(
            ValueError, "negative probe|signature authentication"
        ):
            self.verify(
                ssh_keygen=true_path,
                trusted_ssh_keygen_sha256=true_digest,
            )

    def test_checked_in_pending_state_and_cli_fail_closed(self):
        cli = SCRIPTS / "check-bridge-authority-qualification.py"
        checkpoint_path = Path(self.key_directory.name) / "checkpoint.json"
        checkpoint_path.write_text(
            json.dumps(self.checkpoint), encoding="ascii"
        )
        completed = subprocess.run(
            [sys.executable, str(cli),
             "--ceremony", str(ROOT / "mainnet-custody/authority-ceremony.pending.json"),
             "--qualification", str(ROOT / "mainnet-custody/authority-qualification.pending.json"),
             "--review-policy", str(ROOT / "mainnet-custody/authority-review-policy.pending.json"),
             "--trusted-review-policy-sha256", pin("pending-trusted-policy"),
             "--qualification-checkpoint", str(checkpoint_path),
             "--trusted-qualification-checkpoint-sha256",
             self.trusted_checkpoint_digest,
             "--ssh-keygen", self.ssh_keygen,
             "--trusted-ssh-keygen-sha256", self.trusted_ssh_keygen_digest],
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
