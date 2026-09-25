"""Bounded read-only collection for custody deployment verification."""

from custody_deployment_evidence import (
    USDC_IMPLEMENTATION_SLOT,
    _route,
    validate_custody_deployment_evidence,
)
from custody_deployment_manifest import (
    canonical_sha256,
    validate_custody_deployment_manifest,
)
from usdt_observer.collect import collect
from usdt_observer.common import quantity, require, word
from usdt_observer.runtime import collect_runtime


IMPLEMENTATION_SELECTOR = "0x5c60da1b"
CALL_GAS = "0x186a0"


def collect_custody_deployment_evidence(manifest, tx_hash, source):
    """Collect one exact finalized view; never authenticate or authorize it."""
    validate_custody_deployment_manifest(manifest)
    requested = "0x" + word(tx_hash, 32).hex()
    source_evidence = collect({
        "network": manifest["source"]["network"],
        "genesis_hash": manifest["source"]["genesis_hash"],
    }, requested, source)
    receipt = source_evidence["receipt"]
    deployment_height = quantity(receipt["blockNumber"])
    route = _route(manifest, deployment_height)
    block_hash = "0x" + word(receipt["blockHash"], 32).hex()
    block_number = hex(deployment_height)
    block = {"blockHash": block_hash, "requireCanonical": True}

    raw_transaction = source.eth("eth_getTransactionByHash", [requested])
    require(type(raw_transaction) is dict, "deployment transaction unavailable")
    transaction = {
        "hash": raw_transaction.get("hash"),
        "block_hash": raw_transaction.get("blockHash"),
        "block_number": raw_transaction.get("blockNumber"),
        "transaction_index": raw_transaction.get("transactionIndex"),
        "from": raw_transaction.get("from"),
        "to": raw_transaction.get("to"),
        "input": raw_transaction.get("input"),
    }

    source_config = manifest["source"]
    proxy = source_config["token_address"].lower()
    implementation = source_config["token_implementation_address"].lower()
    token_runtime = {
        "block_hash": block_hash,
        "block_number": block_number,
        "proxy_address": proxy,
        "proxy_code": source.eth("eth_getCode", [proxy, block]),
        "implementation_address": implementation,
        "implementation_code": source.eth("eth_getCode", [implementation, block]),
        "implementation_slot_key": "0x" + USDC_IMPLEMENTATION_SLOT.hex(),
        "implementation_slot": source.eth(
            "eth_getStorageAt", [proxy, "0x" + USDC_IMPLEMENTATION_SLOT.hex(), block]
        ),
        "implementation_getter": source.eth(
            "eth_call",
            [{"to": proxy, "data": IMPLEMENTATION_SELECTOR, "gas": CALL_GAS}, block],
        ),
    }
    vault_runtime = collect_runtime(route, source_evidence, source)
    evidence = {
        "schema": "postern.custody-deployment-evidence.v1",
        "manifest_canonical_sha256": canonical_sha256(manifest),
        "source_evidence": source_evidence,
        "transaction": transaction,
        "token_runtime": token_runtime,
        "vault_runtime": vault_runtime,
    }
    validate_custody_deployment_evidence(manifest, evidence)
    canonical = source.eth("eth_getBlockByNumber", [block_number, False])
    require(type(canonical) is dict and canonical == source_evidence["canonical_block"],
            "canonical block changed during deployment collection")
    return evidence
