"""Bind exact creation/receipt trie proofs to original public deployment captures."""
import hashlib
import json
import subprocess

from custody_deployment_ancestry import _request as ancestry_request
from custody_deployment_compare import NON_AUTHORIZING, _bounded_copy
from custody_deployment_manifest import canonical_sha256
from usdt_observer.common import MAX_JSON, quantity, require, word
from usdt_observer.l2_settlement import _stage_verifier
from usdt_observer.verifier_process import run_verifier


DOMAIN = b"BLOCH-ETHEREUM-DEPLOYMENT-INCLUSION-v1\0"
SCHEMA = "postern.custody-deployment-inclusion.v1"


def _canonical_word(value, length):
    decoded = word(value, length)
    require(value == "0x" + decoded.hex(), "canonical lowercase bytes required")
    return value


def _request(manifest, captures, ancestry, inclusion):
    # Freeze the caller's complete public inputs before validation/subprocess IO.
    manifest, captures = _bounded_copy(manifest), _bounded_copy(captures)
    ancestry, inclusion = _bounded_copy(ancestry), _bounded_copy(inclusion)
    _, comparison, ancestry = ancestry_request(manifest, captures, ancestry)
    require(type(inclusion) is dict and set(inclusion) == {
        "schema", "manifestCanonicalSha256", "comparisonCanonicalSha256",
        "ancestryEvidenceCanonicalSha256", "transaction", "transactionProof", "receipt", "receiptProof",
    } and inclusion["schema"] == SCHEMA, "exact deployment inclusion evidence required")
    require(inclusion["manifestCanonicalSha256"] == comparison["manifestCanonicalSha256"]
            and inclusion["comparisonCanonicalSha256"] == canonical_sha256(comparison)
            and inclusion["ancestryEvidenceCanonicalSha256"] == canonical_sha256(ancestry),
            "inclusion is for different source captures or raw headers")
    captured = captures[0]["evidence"]
    receipt = captured["source_evidence"]["receipt"]
    require(receipt["logs"] == [] and quantity(receipt["status"]) == 1
            and _canonical_word(receipt.get("logsBloom"), 256) == "0x" + "00" * 256,
            "successful empty constructor receipt required")
    kind, cumulative = quantity(receipt.get("type")), quantity(receipt.get("cumulativeGasUsed"))
    require(kind in (0, 1, 2) and cumulative > 0, "supported receipt type and gas required")
    require(ancestry["anchors"][0]["blockNumber"] == comparison["blockNumber"]
            and ancestry["anchors"][0]["blockHash"] == comparison["blockHash"],
            "ancestry must begin at the selected deployment")
    value = {
        "schema": "postern.custody-deployment-inclusion-request.v1",
        "ancestry": ancestry,
        "transactionIndex": str(quantity(receipt["transactionIndex"])),
        "transactionHash": _canonical_word(comparison["transactionHash"], 32),
        "sender": _canonical_word(captured["transaction"]["from"], 20),
        "contractAddress": _canonical_word(manifest["source"]["vault_address"], 20),
        "creationInputSha256": _canonical_word(manifest["source"]["vault_creation_input_sha256"], 32),
        "receiptType": str(kind), "cumulativeGasUsed": str(cumulative),
        **{key: inclusion[key] for key in ("transaction", "transactionProof", "receipt", "receiptProof")},
    }
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")
    require(len(DOMAIN) + len(encoded) <= MAX_JSON, "inclusion request exceeds limit")
    return DOMAIN + encoded, comparison, ancestry, inclusion, value


def verify_custody_deployment_inclusion(manifest, captures, ancestry, inclusion, *,
                                      executable, expected_verifier_sha256):
    request, comparison, ancestry, inclusion, expected_fields = _request(manifest, captures, ancestry, inclusion)
    expected = word(expected_verifier_sha256, 32)
    require(any(expected) and expected_verifier_sha256 == "0x" + expected.hex(), "canonical nonzero verifier pin required")
    temporary = None
    try:
        temporary, staged, actual = _stage_verifier(executable)
        require(actual == expected, "inclusion verifier checksum mismatch")
        result = run_verifier([str(staged)], input=request, timeout=10, max_input_bytes=MAX_JSON)
        commitment = hashlib.sha256(request).hexdigest()
        require(result.returncode == 0 and result.stdout == (commitment + "\n").encode("ascii"),
                "deployment inclusion verifier refused")
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError("inclusion verifier unavailable") from exc
    finally:
        if temporary is not None:
            temporary.cleanup()
    return {
        "schema": "postern.custody-deployment-inclusion-verification.v1",
        "manifestCanonicalSha256": comparison["manifestCanonicalSha256"],
        "comparisonCanonicalSha256": canonical_sha256(comparison),
        "ancestryEvidenceCanonicalSha256": canonical_sha256(ancestry),
        "inclusionEvidenceCanonicalSha256": canonical_sha256(inclusion),
        "verifierRequestSha256": "0x" + commitment,
        "callerSuppliedVerifierSha256": expected_verifier_sha256,
        "blockHash": comparison["blockHash"], "blockNumber": comparison["blockNumber"],
        **{key: expected_fields[key] for key in ("transactionIndex", "transactionHash", "sender", "contractAddress", "receiptType", "cumulativeGasUsed")},
        "captureComparisonRevalidated": True,
        "rawHeaderAncestryVerified": True, "capturedHeaderRootsVerified": True,
        "transactionInclusionVerified": True, "receiptInclusionVerified": True,
        "creationSignatureVerified": True, "creationInputVerified": True, "createAddressDerived": True,
        "anchorAuthenticationVerified": False, "verifierIdentityAuthenticated": False,
        "consensusRulesVerified": False, "completeBlockContentsVerified": False,
        "capturedStateProofsVerified": False, "runtimeExecutionReplayed": False,
        **NON_AUTHORIZING,
    }
