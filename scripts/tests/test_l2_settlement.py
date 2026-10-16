"""Fail-closed tests for the explicit L2/native settlement prerequisite."""
import copy
import hashlib
import json
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from usdt_observer.l2_settlement import (  # noqa: E402
    BLOCH_MAINNET_GENESIS,
    verify_l2_settlement,
)


def hx(label):
    return "0x" + hashlib.sha256(label.encode()).hexdigest()


def fixture():
    route = hx("route")
    return route, {
        "schema": "postern.l2-native-settlement-evidence.v1",
        "route_id": route,
        "l2_chain_id": 700771,
        "l2_block_number": "42",
        "l2_block_hash": hx("l2-block"),
        "l2_state_root": hx("l2-state"),
        "l2_execution_domain": hx("execution-domain"),
        "proof_program_hash": hx("proof-program"),
        "source_cursor": hx("source-cursor"),
        "native_network": "bloch-mainnet",
        "native_genesis_hash": BLOCH_MAINNET_GENESIS,
        "native_checkpoint_height": "82321",
        "native_checkpoint_root": hx("native-checkpoint"),
        "native_settlement_record": hx("settlement-record"),
        "native_transaction_id": hx("native-transaction"),
        "ancestry_proof_sha256": hx("ancestry-proof"),
        "execution_proof_sha256": hx("execution-proof"),
        "settlement_proof_sha256": hx("settlement-proof"),
    }


class L2SettlementTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.verifier = self.root / "verifier"
        self.verifier.write_text(
            "#!/usr/bin/env python3\n"
            "import hashlib,sys\n"
            "value=sys.stdin.buffer.read()\n"
            "print(hashlib.sha256(value).hexdigest())\n"
        )
        self.verifier.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
        self.digest = "0x" + hashlib.sha256(self.verifier.read_bytes()).hexdigest()
        self.route, self.evidence = fixture()
        self.proofs = {}
        for label in ("ancestry", "execution", "settlement"):
            path = self.root / f"{label}.proof"
            path.write_bytes(f"{label}-proof".encode())
            self.proofs[label] = path

    def verify(self, evidence=None):
        return verify_l2_settlement(
            self.verifier, self.digest,
            self.evidence if evidence is None else evidence, self.route,
            ancestry_proof=self.proofs["ancestry"],
            execution_proof=self.proofs["execution"],
            settlement_proof=self.proofs["settlement"],
        )

    def test_pinned_verifier_can_satisfy_only_the_settlement_gate(self):
        report = self.verify()
        self.assertTrue(report["settlementGateSatisfied"])
        self.assertTrue(report["finalityVerifiedForSettlement"])
        for field in ("activationAuthorized", "mintAuthorized",
                      "releaseAuthorized", "bridgeReady"):
            self.assertFalse(report[field])
        self.assertEqual(report["l2ChainId"], 700771)

    def test_missing_unknown_or_wrong_context_is_refused(self):
        mutations = [
            lambda value: value.pop("settlement_proof_sha256"),
            lambda value: value.update(extra=True),
            lambda value: value.update(l2_chain_id=84001),
            lambda value: value.update(l2_chain_id=True),
            lambda value: value.update(l2_block_number="0"),
            lambda value: value.update(l2_block_number="01"),
            lambda value: value.update(native_network="bloch-devnet"),
            lambda value: value.update(native_genesis_hash=hx("other-genesis")),
            lambda value: value.update(native_checkpoint_root="0x" + "00" * 32),
            lambda value: value.update(native_settlement_record="0x" + "00" * 32),
        ]
        for mutate in mutations:
            value = copy.deepcopy(self.evidence)
            mutate(value)
            with self.subTest(mutation=mutate), self.assertRaises(ValueError):
                self.verify(value)
        with self.assertRaises(ValueError):
            verify_l2_settlement(
                self.verifier, self.digest, self.evidence, hx("other-route"),
                ancestry_proof=self.proofs["ancestry"],
                execution_proof=self.proofs["execution"],
                settlement_proof=self.proofs["settlement"],
            )

    def test_unpinned_writable_or_refusing_verifier_is_refused(self):
        with self.assertRaises(ValueError):
            verify_l2_settlement(
                self.verifier, hx("wrong-verifier"), self.evidence, self.route,
                ancestry_proof=self.proofs["ancestry"],
                execution_proof=self.proofs["execution"],
                settlement_proof=self.proofs["settlement"],
            )
        self.verifier.chmod(0o722)
        with self.assertRaises(ValueError):
            self.verify()
        self.verifier.chmod(0o700)
        self.verifier.write_text(
            "#!/usr/bin/env python3\n"
            "import sys\n"
            "sys.stdin.buffer.read()\n"
            "print('0' * 64)\n"
        )
        self.verifier.chmod(0o700)
        digest = "0x" + hashlib.sha256(self.verifier.read_bytes()).hexdigest()
        with self.assertRaises(ValueError):
            verify_l2_settlement(
                self.verifier, digest, self.evidence, self.route,
                ancestry_proof=self.proofs["ancestry"],
                execution_proof=self.proofs["execution"],
                settlement_proof=self.proofs["settlement"],
            )

    def test_missing_or_hash_mismatched_proof_artifact_is_refused(self):
        self.proofs["execution"].write_bytes(b"tampered")
        with self.assertRaisesRegex(ValueError, "checksum"):
            self.verify()
        self.proofs["execution"].unlink()
        with self.assertRaisesRegex(ValueError, "unavailable"):
            self.verify()

    def test_path_replacement_after_open_cannot_change_executed_verifier(self):
        original_stage = __import__(
            "usdt_observer.l2_settlement", fromlist=["_stage_verifier"]
        )._stage_verifier

        replacement = self.root / "replacement"
        replacement.write_text(
            "#!/usr/bin/env python3\nimport sys\nsys.stdin.buffer.read()\nprint('0' * 64)\n"
        )
        replacement.chmod(0o700)

        def replace_after_stage(path):
            temporary, staged_path, digest = original_stage(path)
            replacement.replace(self.verifier)
            return temporary, staged_path, digest

        module = __import__("usdt_observer.l2_settlement", fromlist=["_stage_verifier"])
        saved = module._stage_verifier
        module._stage_verifier = replace_after_stage
        self.addCleanup(setattr, module, "_stage_verifier", saved)
        report = self.verify()
        self.assertTrue(report["settlementGateSatisfied"])

    def test_cli_refusal_never_claims_authority(self):
        evidence = self.root / "evidence.json"
        evidence.write_text(json.dumps(self.evidence))
        cli = Path(__file__).resolve().parents[1] / "check-l2-settlement.py"
        result = subprocess.run(
            [sys.executable, str(cli), "--evidence", str(evidence),
             "--verifier", str(self.verifier), "--verifier-sha256", hx("wrong"),
             "--route-id", self.route,
             "--ancestry-proof", str(self.proofs["ancestry"]),
             "--execution-proof", str(self.proofs["execution"]),
             "--settlement-proof", str(self.proofs["settlement"])],
            capture_output=True, text=True,
            timeout=10, check=False,
        )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, "")
        report = json.loads(result.stderr)
        self.assertFalse(report["settlementGateSatisfied"])
        self.assertFalse(report["bridgeReady"])


if __name__ == "__main__":
    unittest.main()
