"""Adversarial comparison tests using synthetic, non-authorizing captures."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

from custody_deployment_compare import (  # noqa: E402
    NON_AUTHORIZING,
    compare_custody_deployment_evidence,
)
from custody_deployment_evidence import validate_custody_deployment_evidence  # noqa: E402
from custody_deployment_manifest import canonical_sha256  # noqa: E402
from test_custody_deployment_evidence import fixture  # noqa: E402
from usdt_observer.common import MAX_JSON  # noqa: E402


def captures():
    manifest, evidence = fixture()
    return manifest, [
        {"source": "node-a", "evidence": evidence},
        {"source": "node-b", "evidence": copy.deepcopy(evidence)},
    ]


class CustodyDeploymentComparisonTest(unittest.TestCase):
    def assert_inert(self, report):
        for key in NON_AUTHORIZING:
            self.assertIs(report[key], False, key)

    def test_identical_captures_agree_without_counting_distinct_operators(self):
        manifest, observations = captures()
        before = copy.deepcopy((manifest, observations))
        report = compare_custody_deployment_evidence(manifest, observations)
        self.assertTrue(report["deploymentSnapshotAgreement"])
        self.assertTrue(report["finalizedCheckpointIdentitiesMatch"])
        self.assertEqual(report["captureCount"], 2)
        self.assertEqual(report["distinctEvidenceCount"], 1)
        self.assertEqual(report["manifestCanonicalSha256"], canonical_sha256(manifest))
        self.assertEqual(report["captures"][0]["evidenceCanonicalSha256"],
                         canonical_sha256(observations[0]["evidence"]))
        self.assert_inert(report)
        self.assertEqual((manifest, observations), before)

    def test_different_finalized_tips_are_retained_without_ancestry_claim(self):
        manifest, observations = captures()
        tip = observations[1]["evidence"]["source_evidence"]["finalized_block"]
        tip.update(number="0x66", hash="0x" + "43" * 32)
        report = compare_custody_deployment_evidence(manifest, observations)
        self.assertTrue(report["deploymentSnapshotAgreement"])
        self.assertFalse(report["finalizedCheckpointIdentitiesMatch"])
        self.assertEqual(report["distinctEvidenceCount"], 2)
        self.assertEqual([row["finalizedBlockNumber"] for row in report["captures"]],
                         ["101", "102"])
        self.assertEqual(report["captures"][1]["finalizedBlockCanonicalSha256"],
                         canonical_sha256(tip))
        self.assert_inert(report)

    def test_result_is_deterministic_across_capture_order(self):
        manifest, observations = captures()
        self.assertEqual(compare_custody_deployment_evidence(manifest, observations),
                         compare_custody_deployment_evidence(manifest, observations[::-1]))

    def test_same_height_with_conflicting_finalized_hashes_is_refused(self):
        manifest, observations = captures()
        observations[1]["evidence"]["source_evidence"]["finalized_block"]["hash"] = "0x" + "43" * 32
        with self.assertRaisesRegex(ValueError, "conflicting reported block identities"):
            compare_custody_deployment_evidence(manifest, observations)

    def test_same_finalized_identity_requires_entire_block_object_agreement(self):
        for field, value in (("parentHash", "0x" + "79" * 32),
                             ("timestamp", "0x123"),
                             ("transactions", ["0x" + "89" * 32])):
            manifest, observations = captures()
            observations[1]["evidence"]["source_evidence"]["finalized_block"][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "captured objects"):
                compare_custody_deployment_evidence(manifest, observations)

    def test_deployment_as_finalized_tip_requires_matching_complete_block(self):
        manifest, observations = captures()
        for observation in observations:
            source = observation["evidence"]["source_evidence"]
            source["finalized_block"] = copy.deepcopy(source["canonical_block"])
        report = compare_custody_deployment_evidence(manifest, observations)
        self.assertTrue(report["deploymentSnapshotAgreement"])
        self.assertTrue(report["finalizedCheckpointIdentitiesMatch"])
        self.assert_inert(report)
        observations[1]["evidence"]["source_evidence"]["finalized_block"]["parentHash"] = "0x" + "79" * 32
        with self.assertRaisesRegex(ValueError, "captured objects"):
            compare_custody_deployment_evidence(manifest, observations)

    def test_same_hash_at_two_heights_is_refused_including_deployment_block(self):
        for height, block_hash in (("0x66", "0x" + "42" * 32),
                                   ("0x66", "0x" + "41" * 32)):
            manifest, observations = captures()
            observations[1]["evidence"]["source_evidence"]["finalized_block"].update(
                number=height, hash=block_hash)
            with self.subTest(height=height, block_hash=block_hash), self.assertRaises(ValueError):
                compare_custody_deployment_evidence(manifest, observations)

    def test_complete_snapshot_is_compared_not_just_verification_summary(self):
        mutations = [
            lambda ev: ev["source_evidence"]["canonical_block"]["transactions"].append("0x" + "78" * 32),
            lambda ev: ev["source_evidence"]["receipt"].update(gasUsed="0x100"),
            lambda ev: ev["source_evidence"]["genesis"].update(extraData="0x00"),
        ]
        for mutate in mutations:
            manifest, observations = captures()
            mutate(observations[1]["evidence"])
            self.assertEqual(validate_custody_deployment_evidence(manifest, observations[0]["evidence"]),
                             validate_custody_deployment_evidence(manifest, observations[1]["evidence"]))
            with self.subTest(mutation=mutate), self.assertRaises(ValueError):
                compare_custody_deployment_evidence(manifest, observations)

    def test_different_valid_deployments_cannot_be_combined(self):
        manifest, observations = captures()
        other = observations[1]["evidence"]
        tx_hash = "0x" + "81" * 32
        other["transaction"]["hash"] = tx_hash
        other["source_evidence"]["receipt"]["transactionHash"] = tx_hash
        other["source_evidence"]["canonical_block"]["transactions"] = [tx_hash]
        validate_custody_deployment_evidence(manifest, other)
        with self.assertRaises(ValueError):
            compare_custody_deployment_evidence(manifest, observations)

    def test_each_capture_must_pass_complete_deployment_validation(self):
        mutations = [
            lambda ev: ev.update(manifest_canonical_sha256="0x" + "88" * 32),
            lambda ev: ev["source_evidence"]["receipt"].update(logs=[{}]),
            lambda ev: ev["source_evidence"]["finalized_block"].update(number="0x63"),
            lambda ev: ev["transaction"].update(input="0x6003"),
            lambda ev: ev["token_runtime"].update(implementation_code="0x6003"),
            lambda ev: ev["vault_runtime"]["configuration"]["controls"].update(
                depositsEnabled="0x" + "00" * 31 + "01"),
            lambda ev: ev["vault_runtime"]["reserves"].update(token_balance="0x" + "00" * 31 + "01"),
        ]
        for mutate in mutations:
            manifest, observations = captures()
            # Agreement between two invalid captures is still invalid.
            for observation in observations:
                mutate(observation["evidence"])
            with self.subTest(mutation=mutate), self.assertRaises(ValueError):
                compare_custody_deployment_evidence(manifest, observations)

    def test_capture_count_labels_and_envelope_are_strict(self):
        manifest, observations = captures()
        for value in (None, {}, observations[:1], observations * 5):
            with self.subTest(value=type(value)), self.assertRaises(ValueError):
                compare_custody_deployment_evidence(manifest, value)
        for source in ("node-a", "Node-A", "", "x" * 65, "https://example.test", "../secret", 1, "á"):
            candidate = copy.deepcopy(observations)
            candidate[1]["source"] = source
            with self.subTest(source=source), self.assertRaises(ValueError):
                compare_custody_deployment_evidence(manifest, candidate)
        for candidate in (dict(observations[0], extra=True), {"source": "node-c"}, None):
            with self.assertRaises(ValueError):
                compare_custody_deployment_evidence(manifest, [observations[0], candidate])

    def test_up_to_eight_captures_preserve_every_digest(self):
        manifest, observations = captures()
        observations = [{"source": "node-" + str(i), "evidence": observations[0]["evidence"]}
                        for i in range(8)]
        report = compare_custody_deployment_evidence(manifest, observations)
        self.assertEqual(len(report["captures"]), 8)
        self.assertEqual(report["distinctEvidenceCount"], 1)
        self.assert_inert(report)

    def test_library_rejects_oversized_and_non_json_numbers(self):
        for value in ("x" * MAX_JSON, float("nan"), float("inf"), 0.5, 10 ** 30):
            manifest, observations = captures()
            observations[0]["evidence"]["source_evidence"]["receipt"]["extra"] = value
            with self.subTest(kind=type(value)), self.assertRaises(ValueError):
                compare_custody_deployment_evidence(manifest, observations)

    def test_cli_is_read_only_and_returns_safe_machine_readable_refusal(self):
        manifest, observations = captures()
        cli = SCRIPTS / "compare-custody-deployment-evidence.py"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest_path, first_path, second_path = [root / name for name in (
                "manifest.json", "first.json", "second.json")]
            manifest_path.write_text(json.dumps(manifest))
            first_path.write_text(json.dumps(observations[0]["evidence"]))
            second_path.write_text(json.dumps(observations[1]["evidence"]))
            before = {path.name: path.read_bytes() for path in root.iterdir()}
            command = [sys.executable, str(cli), str(manifest_path),
                       "--capture", "node-a=" + str(first_path),
                       "--capture", "node-b=" + str(second_path)]
            result = subprocess.run(command, capture_output=True, text=True, timeout=10, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assert_inert(json.loads(result.stdout))
            self.assertEqual(before, {path.name: path.read_bytes() for path in root.iterdir()})

            second_path.write_text('{"schema":"DO-NOT-EXPOSE","schema":false}')
            result = subprocess.run(command, capture_output=True, text=True, timeout=10, check=False)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stdout, "")
            self.assertNotIn("DO-NOT-EXPOSE", result.stderr)
            self.assertNotIn(str(root), result.stderr)
            refusal = json.loads(result.stderr)
            self.assertFalse(refusal["deploymentSnapshotAgreement"])
            self.assert_inert(refusal)

            result = subprocess.run(command + ["--broadcast"], capture_output=True,
                                    text=True, timeout=10, check=False)
            self.assertEqual(result.returncode, 2)


if __name__ == "__main__":
    unittest.main()
