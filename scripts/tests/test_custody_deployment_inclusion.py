"""Offline integration with real trie/signature checks; synthetic public inputs only."""
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
sys.path.insert(0, str(ROOT / "scripts"))

from custody_deployment_ancestry import _context
from custody_deployment_compare import NON_AUTHORIZING
from custody_deployment_evidence import _route
from custody_deployment_inclusion import SCHEMA, verify_custody_deployment_inclusion
from custody_deployment_manifest import canonical_sha256
from test_custody_deployment_evidence import fixture
from verifier_fixture import private_copy
from usdt_observer.vault_state import expected_words

VECTORS = json.loads((ROOT / 'test-vectors/ethereum-deployment-inclusion/synthetic.json').read_text())["cases"]


def inclusion_fixture(kind=0):
    row = VECTORS[kind * 4]
    request = row["request"]
    manifest, captured = fixture()
    manifest["source"]["vault_address"] = request["contractAddress"]
    manifest["source"]["vault_creation_input_sha256"] = request["creationInputSha256"]
    captured["manifest_canonical_sha256"] = canonical_sha256(manifest)
    captured["transaction"]["hash"] = request["transactionHash"]
    captured["transaction"]["from"] = request["sender"]
    captured["transaction"]["input"] = row["input"]
    anchor = request["ancestry"]["anchors"][0]
    block_hash = anchor["blockHash"]
    for path in ("transaction", "token_runtime", "vault_runtime"):
        captured[path]["block_hash"] = block_hash
    captured["vault_runtime"]["address"] = request["contractAddress"]
    captured["vault_runtime"]["configuration"].update({
        key: "0x" + value.hex() for key, value in expected_words(_route(manifest, 100)).items()
    })
    receipt = captured["source_evidence"]["receipt"]
    receipt.update({"transactionHash": request["transactionHash"], "from": request["sender"],
                    "contractAddress": request["contractAddress"], "blockHash": block_hash,
                    "type": hex(kind), "cumulativeGasUsed": hex(int(request["cumulativeGasUsed"])),
                    "logsBloom": "0x" + "00" * 256})
    block = {"number": "0x64", "hash": block_hash, "transactions": [request["transactionHash"]],
             "parentHash": anchor["parentHash"], "timestamp": hex(int(anchor["timestamp"])),
             **{key: anchor[key] for key in ("stateRoot", "transactionsRoot", "receiptsRoot")}}
    captured["source_evidence"]["canonical_block"] = copy.deepcopy(block)
    captured["source_evidence"]["finalized_block"] = copy.deepcopy(block)
    captures = [{"source": source, "evidence": copy.deepcopy(captured)} for source in ("node-a", "node-b")]
    comparison, _, anchors = _context(manifest, captures)
    ancestry = {**copy.deepcopy(request["ancestry"]), "anchors": anchors,
                "manifestCanonicalSha256": canonical_sha256(manifest),
                "comparisonCanonicalSha256": canonical_sha256(comparison)}
    inclusion = {"schema": SCHEMA, "manifestCanonicalSha256": canonical_sha256(manifest),
                 "comparisonCanonicalSha256": canonical_sha256(comparison),
                 "ancestryEvidenceCanonicalSha256": canonical_sha256(ancestry),
                 **{key: copy.deepcopy(request[key]) for key in ("transaction", "transactionProof", "receipt", "receiptProof")}}
    return manifest, captures, ancestry, inclusion


def rebind(manifest, captures, ancestry, inclusion):
    comparison, _, anchors = _context(manifest, captures)
    ancestry.update(anchors=anchors, manifestCanonicalSha256=canonical_sha256(manifest),
                    comparisonCanonicalSha256=canonical_sha256(comparison))
    inclusion.update(manifestCanonicalSha256=canonical_sha256(manifest),
                     comparisonCanonicalSha256=canonical_sha256(comparison),
                     ancestryEvidenceCanonicalSha256=canonical_sha256(ancestry))


class InclusionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        result = subprocess.run([str(Path.home() / '.cargo/bin/cargo'), '+1.94.1', 'build', '--offline', '--locked',
                                 '--features', 'ethereum-inclusion',
                                 '--bin', 'ethereum_deployment_inclusion_verifier'], cwd=ROOT,
                                capture_output=True, text=True, timeout=120)
        if result.returncode:
            raise AssertionError('real inclusion verifier build failed: ' + result.stderr)
        target = Path(os.environ.get('CARGO_TARGET_DIR', ROOT / 'target'))
        cls.built = (ROOT / target if not target.is_absolute() else target) / 'debug/ethereum_deployment_inclusion_verifier'
        # A private copy with an explicit mode, never cargo's output under the process umask (verifier_fixture.py).
        cls.executable = private_copy(cls, cls.built)
        cls.pin = '0x' + hashlib.sha256(cls.executable.read_bytes()).hexdigest()

    def verify(self, inputs, **kwargs):
        return verify_custody_deployment_inclusion(*inputs, executable=str(self.executable),
                                                  expected_verifier_sha256=kwargs.get('pin', self.pin))

    def test_all_supported_envelopes_bind_original_captures_without_authorization(self):
        for kind in range(3):
            inputs = inclusion_fixture(kind)
            before = copy.deepcopy(inputs)
            with self.subTest(kind=kind):
                report = self.verify(inputs)
                for field in ('transactionInclusionVerified', 'receiptInclusionVerified', 'creationSignatureVerified',
                              'creationInputVerified', 'createAddressDerived', 'capturedHeaderRootsVerified'):
                    self.assertIs(report[field], True)
                for field in (*NON_AUTHORIZING, 'anchorAuthenticationVerified', 'verifierIdentityAuthenticated',
                              'consensusRulesVerified', 'completeBlockContentsVerified', 'capturedStateProofsVerified',
                              'runtimeExecutionReplayed'):
                    self.assertIs(report[field], False)
                self.assertEqual(inputs, before)

    def test_recomputed_envelope_hashes_cannot_hide_captured_receipt_or_sender_changes(self):
        for field, changed in (('cumulativeGasUsed', '0x13881'), ('type', '0x1'), ('from', '0x'+'99'*20)):
            inputs = inclusion_fixture()
            manifest, captures, ancestry, inclusion = inputs
            for capture in captures:
                captured = capture['evidence']
                captured['source_evidence']['receipt'][field] = changed
                if field == 'from':
                    captured['transaction']['from'] = changed
            rebind(*inputs)
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.verify(inputs)

    def test_missing_consensus_receipt_fields_refuse_before_starting_verifier(self):
        for field in ('type', 'logsBloom', 'cumulativeGasUsed'):
            inputs = inclusion_fixture()
            for capture in inputs[1]:
                del capture['evidence']['source_evidence']['receipt'][field]
            rebind(*inputs)
            with patch('custody_deployment_inclusion._stage_verifier') as stage:
                with self.assertRaises(ValueError):
                    self.verify(inputs)
                stage.assert_not_called()

    def test_corrupt_raw_proofs_cross_capture_substitution_and_bad_pin_refuse(self):
        for field in ('transaction', 'receipt', 'transactionProof', 'receiptProof',
                      'manifestCanonicalSha256', 'comparisonCanonicalSha256', 'ancestryEvidenceCanonicalSha256'):
            inputs = inclusion_fixture()
            inclusion = inputs[3]
            if field.endswith('Proof'):
                inclusion[field].pop()
            else:
                inclusion[field] = '0x' + '99' * 32
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.verify(inputs)
        with self.assertRaises(ValueError):
            self.verify(inclusion_fixture(), pin='0x'+'99'*32)

    def test_cli_executes_real_verifier_and_hides_input_on_refusal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest, captures, ancestry, inclusion = inclusion_fixture()
            for name, value in [('manifest', manifest), ('a', captures[0]['evidence']), ('b', captures[1]['evidence']),
                                ('ancestry', ancestry), ('inclusion', inclusion)]:
                (root / (name + '.json')).write_text(json.dumps(value))
            args = [sys.executable, str(ROOT / 'scripts/check-custody-deployment-inclusion.py'), str(root/'manifest.json'),
                    '--capture', 'node-a='+str(root/'a.json'), '--capture', 'node-b='+str(root/'b.json'),
                    '--ancestry', str(root/'ancestry.json'), '--inclusion', str(root/'inclusion.json'),
                    '--verifier', str(self.executable), '--verifier-sha256', self.pin]
            result = subprocess.run(args, capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIs(json.loads(result.stdout)['receiptInclusionVerified'], True)
            (root/'inclusion.json').write_text('{"schema":"do-not-echo-this-private-marker","schema":false}')
            result = subprocess.run(args, capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 1)
            self.assertNotIn(directory, result.stderr)
            self.assertNotIn('do-not-echo', result.stderr)
            self.assertEqual(result.stdout, '')
            for field in NON_AUTHORIZING:
                self.assertIs(json.loads(result.stderr)[field], False)


if __name__ == '__main__':
    unittest.main()
