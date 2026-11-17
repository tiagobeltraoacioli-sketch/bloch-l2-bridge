"""Raw-header collection and real Rust verifier integration, synthetic evidence only."""
import copy
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

from custody_deployment_ancestry import (  # noqa: E402
    DOMAIN,
    MAX_HEADERS,
    _context,
    collect_custody_deployment_ancestry,
    verify_custody_deployment_ancestry,
)
from custody_deployment_compare import NON_AUTHORIZING  # noqa: E402
from custody_deployment_manifest import canonical_sha256  # noqa: E402
from usdt_observer.common import Invalid  # noqa: E402
from test_custody_deployment_evidence import fixture  # noqa: E402
from verifier_fixture import private_copy  # noqa: E402


VECTORS = json.loads((Path(__file__).parent / "fixtures" / "ethereum_headers.synthetic.json").read_text())["headers"]


def ancestry_fixture():
    manifest, deployment = fixture()
    tx_hash = deployment["transaction"]["hash"]
    blocks = {
        int(row["number"]): {
            "number": hex(int(row["number"])), "hash": row["hash"],
            "parentHash": row["parentHash"], "timestamp": hex(int(row["timestamp"])),
            "transactions": [tx_hash] if index == 0 else [],
            "stateRoot": "0x"+"03"*32, "transactionsRoot": "0x"+"04"*32, "receiptsRoot": "0x"+"05"*32,
        } for index, row in enumerate(VECTORS)
    }
    block_hash = blocks[100]["hash"]
    deployment["transaction"]["block_hash"] = block_hash
    deployment["token_runtime"]["block_hash"] = block_hash
    deployment["vault_runtime"]["block_hash"] = block_hash
    deployment["source_evidence"]["receipt"]["blockHash"] = block_hash
    deployment["source_evidence"]["canonical_block"] = blocks[100]
    captures = []
    for index, height in enumerate((101, 102)):
        evidence = copy.deepcopy(deployment)
        evidence["source_evidence"]["finalized_block"] = copy.deepcopy(blocks[height])
        captures.append({"source": "node-" + str(index), "evidence": evidence})
    return manifest, captures, blocks


class SyntheticRpc:
    def __init__(self, manifest, blocks):
        self.manifest, self.blocks = manifest, blocks
        self.calls = []
        self.raw = {row["hash"]: row["raw"] for row in VECTORS}

    def eth(self, method, params):
        self.calls.append((method, params))
        if method == "eth_chainId":
            return "0x1"
        if method == "eth_getBlockByNumber":
            if params == ["0x0", False]:
                return {"number": "0x0", "hash": self.manifest["source"]["genesis_hash"]}
            return copy.deepcopy(self.blocks[int(params[0], 16)])
        if method == "eth_getBlockByHash":
            return copy.deepcopy(next(block for block in self.blocks.values() if block["hash"] == params[0]))
        if method == "debug_getRawHeader":
            return self.raw[params[0]]
        raise AssertionError("unexpected synthetic RPC method")


class AncestryCollectionTest(unittest.TestCase):
    def test_bounded_hash_walk_and_canonical_rechecks_preserve_raw_bytes(self):
        manifest, captures, blocks = ancestry_fixture()
        before = copy.deepcopy((manifest, captures, blocks))
        source = SyntheticRpc(manifest, blocks)
        evidence = collect_custody_deployment_ancestry(manifest, captures, source)
        self.assertEqual(evidence["headers"], [row["raw"] for row in VECTORS])
        self.assertEqual([anchor["blockNumber"] for anchor in evidence["anchors"]], ["100", "101", "102"])
        self.assertEqual([params[0] for method, params in source.calls if method == "debug_getRawHeader"],
                         [row["hash"] for row in reversed(VECTORS)])
        self.assertEqual(source.calls[-3:], [("eth_getBlockByNumber", [hex(number), False]) for number in (100, 101, 102)])
        self.assertEqual((manifest, captures, blocks), before)
        self.assertFalse(any("latest" in params for _, params in source.calls))
        self.assertNotIn("rawHeaderAncestryVerified", evidence)

    def test_all_roots_are_required_before_any_rpc(self):
        for field in ("stateRoot", "transactionsRoot", "receiptsRoot"):
            manifest, captures, blocks = ancestry_fixture()
            source = SyntheticRpc(manifest, blocks)
            for capture in captures:
                del capture["evidence"]["source_evidence"]["canonical_block"][field]
            with self.subTest(field=field), self.assertRaises(ValueError):
                collect_custody_deployment_ancestry(manifest, captures, source)
            self.assertEqual(source.calls, [])

    def test_missing_raw_method_has_no_reconstruction_or_fallback(self):
        manifest, captures, blocks = ancestry_fixture()
        source = SyntheticRpc(manifest, blocks)
        original = source.eth

        def unavailable(method, params):
            if method == "debug_getRawHeader":
                raise ValueError("private RPC response must not escape")
            return original(method, params)

        source.eth = unavailable
        with self.assertRaises(ValueError):
            collect_custody_deployment_ancestry(manifest, captures, source)
        self.assertEqual(source.calls[-1][0], "eth_getBlockByHash")

    def test_reorg_changed_anchor_and_broken_rpc_walk_are_refused(self):
        for change in ("final-recheck", "parent", "height", "raw-overflow", "wrong-chain", "wrong-genesis"):
            manifest, captures, blocks = ancestry_fixture()
            source = SyntheticRpc(manifest, blocks)
            original = source.eth
            canonical_reads = 0

            def corrupt(method, params):
                nonlocal canonical_reads
                result = original(method, params)
                if method == "eth_chainId" and change == "wrong-chain":
                    return "0x2"
                if method == "eth_getBlockByNumber":
                    if params[0] == "0x0" and change == "wrong-genesis":
                        result["hash"] = "0x" + "99" * 32
                    if params[0] == "0x64":
                        canonical_reads += 1
                        if canonical_reads == 2 and change == "final-recheck":
                            result["hash"] = "0x" + "99" * 32
                if method == "eth_getBlockByHash" and change in ("parent", "height"):
                    result["parentHash" if change == "parent" else "number"] = (
                        "0x" + "99" * 32 if change == "parent" else "0x63")
                if method == "debug_getRawHeader" and change == "raw-overflow":
                    return "0x" + "01" * 1025
                return result

            source.eth = corrupt
            with self.subTest(change=change), self.assertRaises(ValueError):
                collect_custody_deployment_ancestry(manifest, captures, source)

    def test_invalid_captures_and_oversized_span_refuse_before_rpc(self):
        for change in ("bad-capture", "too-far"):
            manifest, captures, blocks = ancestry_fixture()
            source = SyntheticRpc(manifest, blocks)
            if change == "bad-capture":
                captures[1]["evidence"]["transaction"]["input"] = "0x6003"
            else:
                captures[1]["evidence"]["source_evidence"]["finalized_block"]["number"] = hex(100 + MAX_HEADERS)
            with self.subTest(change=change), self.assertRaises(ValueError):
                collect_custody_deployment_ancestry(manifest, captures, source)
            self.assertEqual(source.calls, [])


class AncestryVerifierTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        result = subprocess.run(["cargo", "build", "--offline", "--bin", "ethereum_header_ancestry_verifier"],
                                cwd=ROOT, capture_output=True, text=True, timeout=120, check=False)
        if result.returncode != 0:
            raise AssertionError("real ancestry verifier build failed: " + result.stderr)
        target = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target"))
        if not target.is_absolute():
            target = ROOT / target
        cls.built = target / "debug" / "ethereum_header_ancestry_verifier"
        # A private copy with an explicit mode, never cargo's output under the process umask (verifier_fixture.py).
        cls.executable = private_copy(cls, cls.built)
        cls.pin = "0x" + hashlib.sha256(cls.executable.read_bytes()).hexdigest()

    def setUp(self):
        self.manifest, self.captures, self.blocks = ancestry_fixture()
        self.evidence = collect_custody_deployment_ancestry(
            self.manifest, self.captures, SyntheticRpc(self.manifest, self.blocks))

    def verify(self, **changes):
        return verify_custody_deployment_ancestry(
            changes.get("manifest", self.manifest), changes.get("captures", self.captures),
            changes.get("evidence", self.evidence), executable=str(self.executable),
            expected_verifier_sha256=changes.get("pin", self.pin))

    def assert_inert(self, report):
        for key in NON_AUTHORIZING:
            self.assertIs(report[key], False, key)
        for key in ("anchorAuthenticationVerified", "verifierIdentityAuthenticated", "consensusRulesVerified",
                    "receiptInclusionVerified", "capturedStateProofsVerified"):
            self.assertIs(report[key], False, key)

    def test_real_rust_binary_verifies_independently_generated_keccak_vectors(self):
        report = self.verify()
        self.assertTrue(report["rawHeaderAncestryVerified"])
        self.assertTrue(report["capturedHeaderRootsVerified"])
        self.assertTrue(report["captureComparisonRevalidated"])
        self.assertEqual(report["headerCount"], 3)
        self.assertEqual(report["ancestryEvidenceCanonicalSha256"], canonical_sha256(self.evidence))
        self.assert_inert(report)

    def test_capture_substitution_partial_anchor_sets_and_wrong_pins_refuse(self):
        for change in ("comparison", "manifest", "subset", "extra-anchor-field", "pin", "capture"):
            candidate = copy.deepcopy(self.evidence)
            if change == "comparison":
                candidate["comparisonCanonicalSha256"] = "0x" + "91" * 32
            elif change == "manifest":
                candidate["manifestCanonicalSha256"] = "0x" + "92" * 32
            elif change == "subset":
                candidate["anchors"].pop(1)
            elif change == "extra-anchor-field":
                candidate["anchors"][0]["trusted"] = True
            elif change == "capture":
                self.captures[0]["source"] = "substituted-source"
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.verify(evidence=candidate, pin="0x" + "93" * 32 if change == "pin" else self.pin)

    def test_broken_raw_bytes_reordering_and_truncation_fail_actual_verifier(self):
        for change in ("mutated", "reordered", "missing", "duplicate", "non-rlp"):
            candidate = copy.deepcopy(self.evidence)
            if change == "mutated":
                candidate["headers"][1] = candidate["headers"][1][:-2] + "ff"
            elif change == "reordered":
                candidate["headers"].reverse()
            elif change == "missing":
                candidate["headers"].pop(1)
            elif change == "duplicate":
                candidate["headers"][1] = candidate["headers"][0]
            else:
                candidate["headers"][1] = "0xc0"
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.verify(evidence=candidate)

    def test_capture_parent_and_timestamp_are_bound_to_raw_header_fields(self):
        for field, value in (("timestamp", "0x99"), ("parentHash", "0x" + "94" * 32),
                             ("stateRoot", "0x"+"95"*32), ("transactionsRoot", "0x"+"96"*32),
                             ("receiptsRoot", "0x"+"97"*32)):
            captures = copy.deepcopy(self.captures)
            for capture in captures:
                capture["evidence"]["source_evidence"]["canonical_block"][field] = value
            comparison, _, anchors = _context(self.manifest, captures)
            candidate = dict(self.evidence, comparisonCanonicalSha256=canonical_sha256(comparison), anchors=anchors)
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.verify(captures=captures, evidence=candidate)

    def test_invalid_envelopes_reject_without_starting_verifier(self):
        for change in ("unknown", "missing", "oversized", "float"):
            candidate = copy.deepcopy(self.evidence)
            if change == "unknown":
                candidate["activate"] = True
            elif change == "missing":
                del candidate["headers"]
            elif change == "oversized":
                candidate["headers"][0] = "0x" + "01" * 1025
            else:
                candidate["anchors"][0]["timestamp"] = 1.5
            with patch("custody_deployment_ancestry.run_verifier") as runner:
                with self.subTest(change=change), self.assertRaises(ValueError):
                    self.verify(evidence=candidate)
                runner.assert_not_called()

    def test_rust_protocol_rejects_wrong_domain_duplicates_extra_fields_and_args(self):
        encoded = json.dumps(self.evidence, separators=(",", ":")).encode()
        duplicate = encoded.replace(b'"schema":', b'"schema":"wrong","schema":', 1)
        for payload in (encoded, DOMAIN + duplicate, DOMAIN + b"{}", b"x" * (1024 * 1024 + 1)):
            result = subprocess.run([str(self.executable)], input=payload,
                                    capture_output=True, timeout=10, check=False)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stdout, b"")
        result = subprocess.run([str(self.executable), "--activate"], input=DOMAIN + encoded,
                                capture_output=True, timeout=10, check=False)
        self.assertEqual(result.returncode, 1)

    def test_a_group_or_other_writable_verifier_is_refused(self):
        # The rule itself, pinned (agent 403, round 19): what cargo leaves under umask 002 (0775), and any other
        # group- or other-writable mode, IS refused by the library and by the CLI; only the mode differs from the
        # accepted case (same bytes, same pin), shown by the 0755 and 0500 controls.
        for mode in (0o775, 0o757, 0o777, 0o520, 0o502):
            with self.subTest(mode=oct(mode)):
                loose = private_copy(type(self), self.built, mode)
                with self.assertRaises(Invalid) as refused:
                    verify_custody_deployment_ancestry(self.manifest, self.captures, self.evidence,
                                                       executable=str(loose), expected_verifier_sha256=self.pin)
                self.assertIn("immutable regular settlement verifier required", str(refused.exception))
        old = os.umask(0o002)
        try:
            with tempfile.TemporaryDirectory() as directory:
                made = Path(directory) / "verifier"
                descriptor = os.open(made, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o777)  # as a linker creates it
                with os.fdopen(descriptor, "wb") as handle:
                    handle.write(self.built.read_bytes())
                self.assertEqual(made.stat().st_mode & 0o777, 0o775)
                with self.assertRaises(Invalid):
                    verify_custody_deployment_ancestry(self.manifest, self.captures, self.evidence,
                                                       executable=str(made), expected_verifier_sha256=self.pin)
                paths = {}
                for name, value in (("manifest", self.manifest), ("ancestry", self.evidence),
                                    ("a", self.captures[0]["evidence"]), ("b", self.captures[1]["evidence"])):
                    paths[name] = Path(directory) / (name + ".json")
                    paths[name].write_text(json.dumps(value))
                command = [sys.executable, str(SCRIPTS / "check-custody-deployment-ancestry.py"), str(paths["manifest"]),
                           "--ancestry", str(paths["ancestry"]), "--capture", "node-0=" + str(paths["a"]),
                           "--capture", "node-1=" + str(paths["b"]), "--verifier-sha256", self.pin, "--verifier"]
                result = subprocess.run(command + [str(made)], capture_output=True, text=True, timeout=15, check=False)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, "")
                self.assertEqual(json.loads(result.stderr)["error"], "custody-ancestry-verification-refused")
                made.chmod(0o755)  # the same file, only its mode changed: accepted
                result = subprocess.run(command + [str(made)], capture_output=True, text=True, timeout=15, check=False)
                self.assertEqual(result.returncode, 0, result.stderr)
        finally:
            os.umask(old)
        for mode in (0o755, 0o500):
            with self.subTest(control=oct(mode)):
                report = verify_custody_deployment_ancestry(
                    self.manifest, self.captures, self.evidence,
                    executable=str(private_copy(type(self), self.built, mode)), expected_verifier_sha256=self.pin)
                self.assertTrue(report["rawHeaderAncestryVerified"])

    def test_offline_cli_outputs_non_authorizing_report_and_safe_refusal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = {}
            for name, value in (("manifest", self.manifest), ("ancestry", self.evidence),
                                ("a", self.captures[0]["evidence"]), ("b", self.captures[1]["evidence"])):
                paths[name] = root / (name + ".json")
                paths[name].write_text(json.dumps(value))
            command = [sys.executable, str(SCRIPTS / "check-custody-deployment-ancestry.py"), str(paths["manifest"]),
                       "--ancestry", str(paths["ancestry"]), "--capture", "node-0=" + str(paths["a"]),
                       "--capture", "node-1=" + str(paths["b"]), "--verifier", str(self.executable),
                       "--verifier-sha256", self.pin]
            before = {path.name: path.read_bytes() for path in root.iterdir()}
            result = subprocess.run(command, capture_output=True, text=True, timeout=15, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout)
            self.assertTrue(report["rawHeaderAncestryVerified"])
            self.assertTrue(report["capturedHeaderRootsVerified"])
            self.assert_inert(report)
            self.assertEqual(before, {path.name: path.read_bytes() for path in root.iterdir()})
            paths["ancestry"].write_text('{"private-details":"DO-NOT-ECHO","private-details":1}')
            result = subprocess.run(command, capture_output=True, text=True, timeout=15, check=False)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stdout, "")
            self.assertNotIn("DO-NOT-ECHO", result.stderr)
            self.assertNotIn(str(root), result.stderr)
            self.assertFalse(json.loads(result.stderr)["rawHeaderAncestryVerified"])


class AncestryCollectorCliTest(unittest.TestCase):
    def test_loopback_cli_uses_raw_rpc_and_emits_no_verification_claim(self):
        manifest, captures, blocks = ancestry_fixture()
        source = SyntheticRpc(manifest, blocks)

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                result = source.eth(request["method"], request["params"])
                encoded = json.dumps({"jsonrpc": "2.0", "id": 1, "result": result}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)

            def log_message(self, *_):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                manifest_path = root / "manifest.json"
                manifest_path.write_text(json.dumps(manifest))
                command = [sys.executable, str(SCRIPTS / "collect-custody-deployment-ancestry.py"), str(manifest_path),
                           "--endpoint", "http://127.0.0.1:" + str(server.server_port)]
                for index, capture in enumerate(captures):
                    path = root / (str(index) + ".json")
                    path.write_text(json.dumps(capture["evidence"]))
                    command.extend(["--capture", capture["source"] + "=" + str(path)])
                result = subprocess.run(command, capture_output=True, text=True, timeout=15, check=False)
                self.assertEqual(result.returncode, 0, result.stderr)
                evidence = json.loads(result.stdout)
                self.assertEqual(evidence["headers"], [row["raw"] for row in VECTORS])
                self.assertNotIn("rawHeaderAncestryVerified", evidence)
                self.assertEqual(len(list(root.iterdir())), 3)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
