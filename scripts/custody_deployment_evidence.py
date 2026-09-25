"""Strict offline consistency checks for one paused Ethereum vault deployment.

Inputs are captured public JSON. This module performs no RPC, signing,
broadcast, deployment, funding, activation or consensus authentication.
"""
import hashlib

from custody_deployment_manifest import (
    canonical_sha256,
    validate_custody_deployment_manifest,
)
from usdt_observer.common import abi_uint, quantity, require, word
from usdt_observer.ethereum import validate_events
from usdt_observer.runtime import MAX_CODE, validate_runtime


MAX_CREATION_INPUT = 262144
USDC_IMPLEMENTATION_SLOT = bytes.fromhex(
    "7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3"
)
EVIDENCE_FIELDS = {
    "schema",
    "manifest_canonical_sha256",
    "source_evidence",
    "transaction",
    "token_runtime",
    "vault_runtime",
}
TRANSACTION_FIELDS = {
    "hash",
    "block_hash",
    "block_number",
    "transaction_index",
    "from",
    "to",
    "input",
}
TOKEN_RUNTIME_FIELDS = {
    "block_hash",
    "block_number",
    "proxy_address",
    "proxy_code",
    "implementation_address",
    "implementation_code",
    "implementation_slot_key",
    "implementation_slot",
    "implementation_getter",
}


def _route_id(source, native, cap):
    return hashlib.sha256(
        b"BLOCH-USDT-ROUTE-v1".ljust(32, b"\0")
        + word(source["source_domain"], 32)
        + word(native["domain"], 32)
        + word(native["asset_id"], 32)
        + word(source["token_address"], 20).rjust(32, b"\0")
        + word(source["vault_address"], 20).rjust(32, b"\0")
        + abi_uint(6)
        + abi_uint(cap)
    ).digest()


def _route(manifest, deployment_height):
    source = manifest["source"]
    native = manifest["native"]
    custody = manifest["custody"]
    cap = manifest["cap"]["base_units"]
    return {
        "network": source["network"],
        "genesis_hash": source["genesis_hash"].lower(),
        "source_domain": source["source_domain"].lower(),
        "native_domain": native["domain"].lower(),
        "native_asset": native["asset_id"].lower(),
        "token_vm_hex": source["token_address"].lower(),
        "vault_vm_hex": source["vault_address"].lower(),
        "cap": cap,
        "transfer_mode": source["transfer_mode"],
        "committee_signers": tuple(
            member["ethereum_signer"].lower() for member in custody["custodians"]
        ),
        "committee_threshold": custody["threshold"],
        "route_id": "0x" + _route_id(source, native, cap).hex(),
        "vault_runtime_sha256": source["vault_runtime_sha256"].lower(),
        "vault_deployment_height": deployment_height,
    }


def _creation_input(value):
    require(
        type(value) is str
        and value.startswith("0x")
        and len(value) % 2 == 0
        and 2 < len(value) <= 2 + 2 * MAX_CREATION_INPUT,
        "bounded creation input required",
    )
    return word(value, (len(value) - 2) // 2)


def _runtime_code(value, label):
    require(type(value) is str and value.startswith("0x") and len(value) % 2 == 0
            and 6 <= len(value) <= 2 + 2 * MAX_CODE, label + " runtime required")
    return word(value, (len(value) - 2) // 2)


def _validate_token_runtime(manifest, receipt, evidence):
    require(type(evidence) is dict and set(evidence) == TOKEN_RUNTIME_FIELDS,
            "exact USDC runtime evidence required")
    require(word(evidence["block_hash"], 32) == word(receipt["blockHash"], 32)
            and quantity(evidence["block_number"]) == quantity(receipt["blockNumber"]),
            "USDC runtime is from another block")
    source = manifest["source"]
    proxy = word(source["token_address"], 20)
    implementation = word(source["token_implementation_address"], 20)
    require(word(evidence["proxy_address"], 20) == proxy
            and word(evidence["implementation_address"], 20) == implementation,
            "USDC runtime address mismatch")
    proxy_code = _runtime_code(evidence["proxy_code"], "USDC proxy")
    implementation_code = _runtime_code(
        evidence["implementation_code"], "USDC implementation")
    proxy_digest = hashlib.sha256(proxy_code).digest()
    implementation_digest = hashlib.sha256(implementation_code).digest()
    require(proxy_digest == word(source["token_proxy_runtime_sha256"], 32),
            "USDC proxy runtime mismatch")
    require(implementation_digest == word(
        source["token_implementation_runtime_sha256"], 32),
        "USDC implementation runtime mismatch")
    encoded_implementation = implementation.rjust(32, b"\0")
    require(word(evidence["implementation_slot_key"], 32) == USDC_IMPLEMENTATION_SLOT,
            "unexpected USDC implementation slot")
    require(word(evidence["implementation_slot"], 32) == encoded_implementation,
            "USDC proxy implementation slot mismatch")
    require(word(evidence["implementation_getter"], 32) == encoded_implementation,
            "USDC proxy implementation getter mismatch")
    return proxy_digest, implementation_digest


def validate_custody_deployment_evidence(manifest, evidence):
    """Validate exact finalized, empty and paused deployment evidence."""
    validate_custody_deployment_manifest(manifest)
    require(type(evidence) is dict and set(evidence) == EVIDENCE_FIELDS,
            "exact custody deployment evidence required")
    require(evidence["schema"] == "postern.custody-deployment-evidence.v1",
            "unsupported custody deployment evidence schema")
    manifest_digest = canonical_sha256(manifest)
    require(word(evidence["manifest_canonical_sha256"], 32) == word(manifest_digest, 32),
            "deployment evidence is for another manifest")

    source_evidence = evidence["source_evidence"]
    require(type(source_evidence) is dict, "source evidence required")
    receipt = source_evidence.get("receipt")
    require(type(receipt) is dict, "deployment receipt required")
    deployment_height = quantity(receipt.get("blockNumber"))
    route = _route(manifest, deployment_height)
    # Deployment transactions have no vault events. Reuse the finalized block,
    # transaction-inclusion and source identity checks without decoding deposits.
    validate_events(route, source_evidence, lambda _route, _logs: [])

    vault = word(manifest["source"]["vault_address"], 20)
    require(receipt.get("to") is None, "contract creation receipt required")
    require(word(receipt.get("contractAddress"), 20) == vault,
            "deployment receipt contract mismatch")
    require(receipt.get("logs") == [], "vault constructor must emit no logs")

    transaction = evidence["transaction"]
    require(type(transaction) is dict and set(transaction) == TRANSACTION_FIELDS,
            "exact deployment transaction required")
    require(transaction["to"] is None, "contract creation transaction required")
    sender = word(transaction["from"], 20)
    require(any(sender), "zero deployment sender")
    require(word(receipt.get("from"), 20) == sender, "deployment sender mismatch")
    for tx_key, receipt_key, size in (
        ("hash", "transactionHash", 32),
        ("block_hash", "blockHash", 32),
    ):
        require(word(transaction[tx_key], size) == word(receipt[receipt_key], size),
                "deployment transaction binding mismatch")
    require(quantity(transaction["block_number"]) == deployment_height
            and quantity(transaction["transaction_index"])
            == quantity(receipt["transactionIndex"]),
            "deployment transaction position mismatch")
    creation = _creation_input(transaction["input"])
    creation_digest = hashlib.sha256(creation).digest()
    require(creation_digest == word(
        manifest["source"]["vault_creation_input_sha256"], 32),
        "vault creation input mismatch")

    proxy_digest, implementation_digest = _validate_token_runtime(
        manifest, receipt, evidence["token_runtime"])

    runtime = evidence["vault_runtime"]
    report = validate_runtime(route, source_evidence, runtime)
    configuration = runtime["configuration"]
    zero = abi_uint(0)
    require(word(configuration["controls"]["controlNonce"], 32) == zero
            and word(configuration["controls"]["depositsEnabled"], 32) == zero
            and word(configuration["controls"]["releasesEnabled"], 32) == zero,
            "new vault must remain paused with unused controls")
    require(word(configuration["counters"]["depositCount"], 32) == zero,
            "new vault must have zero deposits")
    require(word(runtime["reserves"]["total_locked"], 32) == zero
            and word(runtime["reserves"]["token_balance"], 32) == zero,
            "new vault must be empty")

    return {
        "schema": "postern.custody-deployment-verification.v1",
        "manifestCanonicalSha256": manifest_digest,
        "transactionHash": "0x" + word(receipt["transactionHash"], 32).hex(),
        "blockHash": "0x" + word(receipt["blockHash"], 32).hex(),
        "blockNumber": str(deployment_height),
        "vaultAddress": "0x" + vault.hex(),
        "routeId": route["route_id"],
        "creationInputSha256": "0x" + creation_digest.hex(),
        "tokenProxyRuntimeSha256": "0x" + proxy_digest.hex(),
        "tokenImplementationRuntimeSha256": "0x" + implementation_digest.hex(),
        "vaultRuntimeSha256": report["runtime_sha256"],
        "finalizedReceiptConsistent": True,
        "constructorStateMatched": True,
        "committeeMatched": True,
        "tokenProxyImplementationMatched": True,
        "paused": True,
        "empty": True,
        "sourceRpcAuthenticated": False,
        "deploymentAuthenticated": False,
        "activationAuthorized": False,
        "broadcastAllowed": False,
    }
