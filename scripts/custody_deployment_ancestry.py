"""Collect and check raw header links without authenticating Ethereum finality."""
import hashlib
import json
import re
import subprocess

from custody_deployment_compare import (
    MAX_CAPTURES,
    NON_AUTHORIZING,
    _bounded_copy,
    compare_custody_deployment_evidence,
)
from custody_deployment_manifest import canonical_sha256
from usdt_observer.common import MAX_JSON, load_json, quantity, require, word
from usdt_observer.l2_settlement import _stage_verifier
from usdt_observer.verifier_process import run_verifier


MAX_HEADERS = 256
MAX_HEADER_BYTES = 1024
DOMAIN = b"BLOCH-ETHEREUM-HEADER-ANCESTRY-v1\0"
SCHEMA = "postern.custody-deployment-ancestry.v1"


def load_captures(arguments):
    require(type(arguments) is list and 2 <= len(arguments) <= MAX_CAPTURES,
            "two to eight labelled captures required")
    result = []
    for argument in arguments:
        source, separator, path = argument.partition("=")
        require(separator and path, "capture label and path required")
        result.append({"source": source, "evidence": load_json(path)})
    return result


def _context(manifest, captures):
    comparison = compare_custody_deployment_evidence(manifest, captures)
    blocks = {}
    for capture in captures:
        source = capture["evidence"]["source_evidence"]
        for block in (source["canonical_block"], source["finalized_block"]):
            blocks[quantity(block["number"])] = block
    ordered = sorted(blocks)
    require(ordered[-1] - ordered[0] + 1 <= MAX_HEADERS,
            "deployment-to-checkpoint span exceeds header limit")
    anchors = [{
        "blockNumber": str(number), "blockHash": _hash(blocks[number]["hash"]),
        "parentHash": _hash(blocks[number]["parentHash"]) if "parentHash" in blocks[number] else None,
        "timestamp": str(quantity(blocks[number]["timestamp"])) if "timestamp" in blocks[number] else None,
    } for number in ordered]
    return comparison, blocks, anchors


def _hash(value):
    decoded = word(value, 32)
    require(any(decoded), "nonzero block hash required")
    return "0x" + decoded.hex()


def _raw(value):
    require(type(value) is str and 4 <= len(value) <= 2 + 2 * MAX_HEADER_BYTES
            and len(value) % 2 == 0 and re.fullmatch(r"0x[0-9a-f]+", value),
            "bounded raw RLP header required")
    return value


def collect_custody_deployment_ancestry(manifest, captures, source):
    """Retain exact raw bytes by hash; a separate verifier must check their RLP.

    The bounded walk is guided by RPC parent hashes, never by mutable latest
    selectors. Canonical anchor objects must equal the retained captures both
    before and after collection. This is observation consistency, not finality.
    """
    comparison, blocks, anchors = _context(manifest, captures)
    require(quantity(source.eth("eth_chainId", [])) == 1, "wrong Ethereum chain")
    genesis = source.eth("eth_getBlockByNumber", ["0x0", False])
    require(type(genesis) is dict and quantity(genesis.get("number")) == 0
            and _hash(genesis.get("hash")) == _hash(manifest["source"]["genesis_hash"]),
            "wrong Ethereum genesis")

    def recheck():
        for number, expected in sorted(blocks.items()):
            actual = source.eth("eth_getBlockByNumber", [hex(number), False])
            require(type(actual) is dict and actual == expected,
                    "captured canonical anchor changed")

    recheck()
    lower, upper = min(blocks), max(blocks)
    expected_hash = _hash(blocks[upper]["hash"])
    seen, descending = set(), []
    for number in range(upper, lower - 1, -1):
        require(expected_hash not in seen, "repeated RPC block hash")
        seen.add(expected_hash)
        block = source.eth("eth_getBlockByHash", [expected_hash, False])
        require(type(block) is dict and quantity(block.get("number")) == number
                and _hash(block.get("hash")) == expected_hash,
                "RPC parent walk changed identity or height")
        if number in blocks:
            require(block == blocks[number], "RPC parent walk missed a captured anchor")
        descending.append(_raw(source.eth("debug_getRawHeader", [expected_hash])))
        expected_hash = _hash(block.get("parentHash"))
    recheck()
    evidence = {
        "schema": SCHEMA,
        "manifestCanonicalSha256": comparison["manifestCanonicalSha256"],
        "comparisonCanonicalSha256": canonical_sha256(comparison),
        "anchors": anchors,
        "headers": list(reversed(descending)),
    }
    return _bounded_copy(evidence)


def _request(manifest, captures, evidence):
    comparison, _, anchors = _context(manifest, captures)
    evidence = _bounded_copy(evidence)
    require(type(evidence) is dict and set(evidence) == {
        "schema", "manifestCanonicalSha256", "comparisonCanonicalSha256", "anchors", "headers",
    } and evidence["schema"] == SCHEMA, "exact ancestry evidence required")
    require(evidence["manifestCanonicalSha256"] == comparison["manifestCanonicalSha256"]
            and evidence["comparisonCanonicalSha256"] == canonical_sha256(comparison)
            and evidence["anchors"] == anchors,
            "ancestry evidence is for different captures or anchors")
    headers = evidence["headers"]
    require(type(headers) is list and len(headers) == int(anchors[-1]["blockNumber"])
            - int(anchors[0]["blockNumber"]) + 1, "complete bounded header range required")
    for header in headers:
        _raw(header)
    encoded = json.dumps(evidence, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=True, allow_nan=False).encode("ascii")
    request = DOMAIN + encoded
    require(len(request) <= MAX_JSON, "ancestry verifier request exceeds limit")
    return request, comparison, evidence


def verify_custody_deployment_ancestry(manifest, captures, evidence, *,
                                     executable, expected_verifier_sha256):
    """Recompare original captures, then check their exact raw-header anchors.

    The executable pin must be selected independently of the evidence. It is a
    caller-supplied byte identity, not authentication of the verifier's author.
    """
    request, comparison, evidence = _request(manifest, captures, evidence)
    expected = word(expected_verifier_sha256, 32)
    require(any(expected) and expected_verifier_sha256 == "0x" + expected.hex(),
            "canonical nonzero verifier pin required")
    temporary = None
    try:
        temporary, staged, actual = _stage_verifier(executable)
        require(actual == expected, "ancestry verifier checksum mismatch")
        result = run_verifier([str(staged)], input=request, timeout=10,
                              max_input_bytes=MAX_JSON)
        commitment = hashlib.sha256(request).hexdigest()
        require(result.returncode == 0 and result.stdout == (commitment + "\n").encode("ascii"),
                "raw header ancestry verifier refused")
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError("ancestry verifier unavailable") from exc
    finally:
        if temporary is not None:
            temporary.cleanup()
    return {
        "schema": "postern.custody-deployment-ancestry-verification.v1",
        "manifestCanonicalSha256": comparison["manifestCanonicalSha256"],
        "comparisonCanonicalSha256": evidence["comparisonCanonicalSha256"],
        "ancestryEvidenceCanonicalSha256": canonical_sha256(evidence),
        "verifierRequestSha256": "0x" + commitment,
        "callerSuppliedVerifierSha256": expected_verifier_sha256,
        "anchors": evidence["anchors"],
        "headerCount": len(evidence["headers"]),
        "captureComparisonRevalidated": True,
        "rawHeaderAncestryVerified": True,
        "anchorAuthenticationVerified": False,
        "verifierIdentityAuthenticated": False,
        "consensusRulesVerified": False,
        "receiptInclusionVerified": False,
        "capturedStateProofsVerified": False,
        **NON_AUTHORIZING,
    }
