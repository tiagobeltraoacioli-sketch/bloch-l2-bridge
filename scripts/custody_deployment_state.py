"""Collect and verify limited account/code/USDC implementation-slot evidence."""
import hashlib
import json
import re
import subprocess

from custody_deployment_compare import NON_AUTHORIZING, _bounded_copy
from custody_deployment_inclusion import _canonical_word, _request as inclusion_request
from custody_deployment_manifest import canonical_sha256
from usdt_observer.common import MAX_JSON, quantity, require, word
from usdt_observer.l2_settlement import _stage_verifier
from usdt_observer.verifier_process import run_verifier


DOMAIN = b"BLOCH-ETHEREUM-DEPLOYMENT-STATE-v1\0"
SCHEMA = "postern.custody-deployment-state.v1"
IMPLEMENTATION_SLOT = "0x7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3"
USDC_PROXY = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"


def _quantity(value, maximum_bytes):
    require(type(value) is str and re.fullmatch(r"0x(?:0|[1-9a-f][0-9a-f]*)", value)
            and len(value) <= 2 + maximum_bytes * 2, "bounded canonical quantity required")
    return int(value, 16)


def _nodes(nodes):
    require(type(nodes) is list and 1 <= len(nodes) <= 65, "bounded state proof required")
    total = 0
    for node in nodes:
        require(type(node) is str and 4 <= len(node) <= 2 + 65536 * 2 and len(node) % 2 == 0
                and re.fullmatch(r"0x[0-9a-f]+", node), "canonical bounded proof node required")
        total += (len(node) - 2) // 2
    require(total <= 262144, "state proof byte limit")


def _proof(proof, address, implementation, proxy):
    require(type(proof) is dict and set(proof) == {
        "address", "nonce", "balance", "codeHash", "storageHash", "accountProof", "storageProof",
    }, "exact EIP-1186 response required")
    require(_canonical_word(proof["address"], 20) == address, "proof address substitution")
    _quantity(proof["nonce"], 8)
    _quantity(proof["balance"], 32)
    for key in ("codeHash", "storageHash"):
        require(any(word(_canonical_word(proof[key], 32), 32)), "nonzero account hash required")
    _nodes(proof["accountProof"])
    storage = proof["storageProof"]
    require(type(storage) is list and len(storage) == int(proxy), "exact storage proof coverage required")
    if proxy:
        slot = storage[0]
        require(type(slot) is dict and set(slot) == {"key", "value", "proof"}
                and slot["key"] == IMPLEMENTATION_SLOT, "exact implementation-slot proof required")
        require(_quantity(slot["value"], 32) == int(implementation, 16) != 0,
                "proxy implementation value mismatch")
        _nodes(slot["proof"])


def _context(manifest, captures, ancestry, inclusion):
    # Freeze every public input before source IO, including the raw inclusion.
    manifest, captures, ancestry, inclusion = map(_bounded_copy, (manifest, captures, ancestry, inclusion))
    _, comparison, ancestry, inclusion, native = inclusion_request(manifest, captures, ancestry, inclusion)
    source, captured = manifest["source"], captures[0]["evidence"]
    token, vault = captured["token_runtime"], captured["vault_runtime"]
    require(source["token_address"] == USDC_PROXY, "canonical mainnet USDC proxy required")
    contracts = [
        {"role": "vault", "address": source["vault_address"], "code": vault["code"],
         "runtimeSha256": source["vault_runtime_sha256"]},
        {"role": "usdcProxy", "address": source["token_address"], "code": token["proxy_code"],
         "runtimeSha256": source["token_proxy_runtime_sha256"]},
        {"role": "usdcImplementation", "address": source["token_implementation_address"],
         "code": token["implementation_code"], "runtimeSha256": source["token_implementation_runtime_sha256"]},
    ]
    for contract in contracts:
        _canonical_word(contract["address"], 20)
        _canonical_word(contract["runtimeSha256"], 32)
    require(len({c["address"] for c in contracts}) == 3, "distinct contract addresses required")
    bindings = {
        "schema": SCHEMA, "manifestCanonicalSha256": comparison["manifestCanonicalSha256"],
        "comparisonCanonicalSha256": canonical_sha256(comparison),
        "ancestryEvidenceCanonicalSha256": canonical_sha256(ancestry),
        "inclusionEvidenceCanonicalSha256": canonical_sha256(inclusion),
    }
    return manifest, captured, comparison, native, contracts, bindings


def _request(manifest, captures, ancestry, inclusion, state):
    state = _bounded_copy(state)
    _, _, comparison, native, contracts, bindings = _context(manifest, captures, ancestry, inclusion)
    require(type(state) is dict and set(state) == {*bindings, "proofs"}
            and all(state[key] == value for key, value in bindings.items()),
            "state evidence is for different source captures, headers or inclusion")
    proofs = state["proofs"]
    require(type(proofs) is list and len(proofs) == 3, "three ordered account proofs required")
    for index, (contract, proof) in enumerate(zip(contracts, proofs)):
        _proof(proof, contract["address"], contracts[2]["address"], index == 1)
        contract["proof"] = proof
    value = {"schema": "postern.custody-deployment-state-request.v1", "inclusion": native, "contracts": contracts}
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")
    require(len(DOMAIN) + len(encoded) <= MAX_JSON, "state request exceeds limit")
    return DOMAIN + encoded, comparison, state, value


def collect_custody_deployment_state(manifest, captures, ancestry, inclusion, source):
    """Read only, at one captured block hash, with no selector fallback.

    This validates shape and collection consistency; the separate offline
    verifier must check trie paths, code commitments and the inclusion evidence.
    """
    manifest, captured, _, _, contracts, bindings = _context(manifest, captures, ancestry, inclusion)
    expected_block = captured["source_evidence"]["canonical_block"]
    expected_genesis = word(manifest["source"]["genesis_hash"], 32)

    def recheck():
        require(quantity(source.eth("eth_chainId", [])) == 1, "wrong Ethereum chain")
        genesis = _bounded_copy(source.eth("eth_getBlockByNumber", ["0x0", False]))
        require(type(genesis) is dict and quantity(genesis.get("number")) == 0
                and word(genesis.get("hash"), 32) == expected_genesis, "wrong Ethereum genesis")
        block = _bounded_copy(source.eth("eth_getBlockByNumber", [expected_block["number"], False]))
        require(block == expected_block, "captured deployment block changed")

    recheck()
    proofs = []
    for index, contract in enumerate(contracts):
        selector = {"blockHash": expected_block["hash"], "requireCanonical": True}
        slots = [IMPLEMENTATION_SLOT] if index == 1 else []
        proof = _bounded_copy(source.eth("eth_getProof", [contract["address"], slots, selector]))
        _proof(proof, contract["address"], contracts[2]["address"], index == 1)
        proofs.append(proof)
    recheck()
    return _bounded_copy({**bindings, "proofs": proofs})


def verify_custody_deployment_state(manifest, captures, ancestry, inclusion, state, *,
                                   executable, expected_verifier_sha256):
    request, comparison, state, native = _request(manifest, captures, ancestry, inclusion, state)
    expected = word(expected_verifier_sha256, 32)
    require(any(expected) and expected_verifier_sha256 == "0x" + expected.hex(), "canonical nonzero verifier pin required")
    temporary = None
    try:
        temporary, staged, actual = _stage_verifier(executable)
        require(actual == expected, "state verifier checksum mismatch")
        result = run_verifier([str(staged)], input=request, timeout=10, max_input_bytes=MAX_JSON)
        commitment = hashlib.sha256(request).hexdigest()
        require(result.returncode == 0 and result.stdout == (commitment + "\n").encode("ascii"),
                "deployment state verifier refused")
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError("state verifier unavailable") from exc
    finally:
        if temporary is not None:
            temporary.cleanup()
    return {
        "schema": "postern.custody-deployment-state-verification.v1",
        **{key: value for key, value in state.items() if key.endswith("CanonicalSha256")},
        "stateEvidenceCanonicalSha256": canonical_sha256(state),
        "verifierRequestSha256": "0x" + commitment, "callerSuppliedVerifierSha256": expected_verifier_sha256,
        "blockHash": comparison["blockHash"], "blockNumber": comparison["blockNumber"],
        "stateRoot": native["inclusion"]["ancestry"]["anchors"][0]["stateRoot"],
        "contracts": [{key: c[key] for key in ("role", "address", "runtimeSha256")} for c in native["contracts"]],
        "implementationSlot": IMPLEMENTATION_SLOT,
        "captureComparisonRevalidated": True, "rawHeaderAncestryVerified": True, "capturedHeaderRootsVerified": True,
        "transactionInclusionVerified": True, "receiptInclusionVerified": True,
        "creationSignatureVerified": True, "creationInputVerified": True, "createAddressDerived": True,
        "accountProofsVerified": True, "runtimeCodeStateProofsVerified": True, "proxyImplementationStorageVerified": True,
        "anchorAuthenticationVerified": False, "verifierIdentityAuthenticated": False,
        "consensusRulesVerified": False, "completeBlockContentsVerified": False,
        "capturedStateProofsVerified": False, "vaultControlsStorageVerified": False,
        "tokenBalanceStorageVerified": False, "runtimeExecutionReplayed": False,
        **NON_AUTHORIZING,
    }
