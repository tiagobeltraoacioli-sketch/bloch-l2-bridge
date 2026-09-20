"""Adversarial tests for inert, finalized vault deployment evidence."""
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
sys.path.insert(0, str(SCRIPTS))

from custody_deployment_evidence import (  # noqa: E402
    _route,
    validate_custody_deployment_evidence,
)
from custody_deployment_manifest import canonical_sha256  # noqa: E402
from test_custody_deployment_manifest import candidate  # noqa: E402
from usdt_observer.common import abi_uint  # noqa: E402
from usdt_observer.vault_state import expected_words  # noqa: E402


def hx(value):
    return "0x" + value.hex()


def fixture():
    manifest = candidate()
    runtime_code = bytes.fromhex("60006000fd")
    creation_input = bytes.fromhex("60016000556002600055")
    manifest["source"]["vault_runtime_sha256"] = hx(hashlib.sha256(runtime_code).digest())
    manifest["source"]["vault_creation_input_sha256"] = hx(
        hashlib.sha256(creation_input).digest()
    )
    route = _route(manifest, 100)
    configuration = {name: hx(value) for name, value in expected_words(route).items()}
    configuration.update({
        "controls": {
            "controlNonce": hx(abi_uint(0)),
            "depositsEnabled": hx(abi_uint(0)),
            "releasesEnabled": hx(abi_uint(0)),
        },
        "counters": {"depositCount": hx(abi_uint(0))},
        "signers": [hx(bytes(12) + bytes.fromhex(value[2:]))
                    for value in route["committee_signers"]],
        "memberships": [hx(abi_uint(1)) for _ in route["committee_signers"]],
    })
    tx_hash = "0x" + "31" * 32
    block_hash = "0x" + "41" * 32
    sender = "0x" + "51" * 20
    source_evidence = {
        "chain_id": "0x1",
        "genesis": {"number": "0x0", "hash": manifest["source"]["genesis_hash"]},
        "receipt": {
            "status": "0x1",
            "blockNumber": "0x64",
            "blockHash": block_hash,
            "transactionHash": tx_hash,
            "transactionIndex": "0x0",
            "from": sender,
            "to": None,
            "contractAddress": manifest["source"]["vault_address"],
            "logs": [],
        },
        "canonical_block": {
            "number": "0x64", "hash": block_hash, "transactions": [tx_hash],
        },
        "finalized_block": {"number": "0x65", "hash": "0x" + "42" * 32},
    }
    evidence = {
        "schema": "postern.custody-deployment-evidence.v1",
        "manifest_canonical_sha256": canonical_sha256(manifest),
        "source_evidence": source_evidence,
        "transaction": {
            "hash": tx_hash,
            "block_hash": block_hash,
            "block_number": "0x64",
            "transaction_index": "0x0",
            "from": sender,
            "to": None,
            "input": hx(creation_input),
        },
        "vault_runtime": {
            "block_hash": block_hash,
            "block_number": "0x64",
            "address": manifest["source"]["vault_address"],
            "code": hx(runtime_code),
            "configuration": configuration,
            "reserves": {
                "total_locked": hx(abi_uint(0)),
                "token_balance": hx(abi_uint(0)),
            },
        },
    }
    return manifest, evidence


class CustodyDeploymentEvidenceTest(unittest.TestCase):
    def test_exact_paused_empty_deployment_is_consistent_but_non_authorizing(self):
        manifest, evidence = fixture()
        before = copy.deepcopy((manifest, evidence))
        report = validate_custody_deployment_evidence(manifest, evidence)
        self.assertTrue(report["finalizedReceiptConsistent"])
        self.assertTrue(report["constructorStateMatched"])
        self.assertTrue(report["committeeMatched"])
        self.assertTrue(report["paused"])
        self.assertTrue(report["empty"])
        self.assertFalse(report["sourceRpcAuthenticated"])
        self.assertFalse(report["deploymentAuthenticated"])
        self.assertFalse(report["activationAuthorized"])
        self.assertFalse(report["broadcastAllowed"])
        self.assertEqual((manifest, evidence), before)

    def test_manifest_and_creation_transaction_are_exactly_bound(self):
        mutations = [
            lambda manifest, evidence: evidence.update(
                manifest_canonical_sha256="0x" + "61" * 32),
            lambda manifest, evidence: evidence["transaction"].update(input="0x6002"),
            lambda manifest, evidence: evidence["transaction"].update(to="0x" + "62" * 20),
            lambda manifest, evidence: evidence["transaction"].update(hash="0x" + "63" * 32),
            lambda manifest, evidence: evidence["source_evidence"]["receipt"].update(
                contractAddress="0x" + "64" * 20),
            lambda manifest, evidence: evidence["source_evidence"]["receipt"].update(
                {"from": "0x" + "65" * 20}),
        ]
        for mutate in mutations:
            manifest, evidence = fixture()
            mutate(manifest, evidence)
            with self.subTest(mutation=mutate), self.assertRaises(ValueError):
                validate_custody_deployment_evidence(manifest, evidence)

    def test_only_unused_paused_and_empty_state_is_accepted(self):
        paths = [
            ("configuration", "controls", "controlNonce"),
            ("configuration", "controls", "depositsEnabled"),
            ("configuration", "controls", "releasesEnabled"),
            ("configuration", "counters", "depositCount"),
            ("reserves", "total_locked"),
            ("reserves", "token_balance"),
        ]
        for path in paths:
            manifest, evidence = fixture()
            target = evidence["vault_runtime"]
            for part in path[:-1]:
                target = target[part]
            target[path[-1]] = hx(abi_uint(1))
            with self.subTest(path=path), self.assertRaises(ValueError):
                validate_custody_deployment_evidence(manifest, evidence)

    def test_runtime_constructor_committee_and_finality_mismatches_are_refused(self):
        mutations = [
            lambda evidence: evidence["vault_runtime"].update(code="0x60016000fd"),
            lambda evidence: evidence["vault_runtime"]["configuration"].update(
                sourceDomain="0x" + "71" * 32),
            lambda evidence: evidence["vault_runtime"]["configuration"]["signers"].reverse(),
            lambda evidence: evidence["source_evidence"]["receipt"].update(status="0x0"),
            lambda evidence: evidence["source_evidence"]["finalized_block"].update(number="0x63"),
            lambda evidence: evidence["source_evidence"]["canonical_block"].update(
                transactions=["0x" + "72" * 32]),
        ]
        for mutate in mutations:
            manifest, evidence = fixture()
            mutate(evidence)
            with self.subTest(mutation=mutate), self.assertRaises(ValueError):
                validate_custody_deployment_evidence(manifest, evidence)

    def test_unknown_missing_and_oversized_fields_fail_closed(self):
        manifest, evidence = fixture()
        invalid = [
            None,
            {},
            dict(evidence, extra=True),
            {key: value for key, value in evidence.items() if key != "transaction"},
        ]
        for value in invalid:
            with self.assertRaises(ValueError):
                validate_custody_deployment_evidence(manifest, value)
        evidence["transaction"]["input"] = "0x" + "00" * 262145
        with self.assertRaises(ValueError):
            validate_custody_deployment_evidence(manifest, evidence)

    def test_cli_never_authorizes_or_writes_state(self):
        manifest, evidence = fixture()
        cli = SCRIPTS / "check-custody-deployment-evidence.py"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest_path = root / "manifest.json"
            evidence_path = root / "evidence.json"
            manifest_path.write_text(json.dumps(manifest))
            evidence_path.write_text(json.dumps(evidence))
            result = subprocess.run(
                [sys.executable, str(cli), str(manifest_path), str(evidence_path)],
                capture_output=True, text=True, timeout=10, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout)
            self.assertFalse(report["deploymentAuthenticated"])
            self.assertFalse(report["activationAuthorized"])
            self.assertEqual(sorted(root.iterdir()), [evidence_path, manifest_path])
            self.assertEqual(
                subprocess.run(
                    [sys.executable, str(cli), str(manifest_path), str(evidence_path),
                     "--broadcast"],
                    capture_output=True, timeout=10, check=False,
                ).returncode,
                2,
            )


if __name__ == "__main__":
    unittest.main()
