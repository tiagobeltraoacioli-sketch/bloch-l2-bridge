"""Read-only, block-pinned deployment evidence collection tests."""
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock


SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))

from custody_deployment_collect import (  # noqa: E402
    IMPLEMENTATION_SELECTOR,
    collect_custody_deployment_evidence,
)
from test_custody_deployment_evidence import fixture  # noqa: E402


def rpc_values(evidence):
    source = evidence["source_evidence"]
    transaction = evidence["transaction"]
    token = evidence["token_runtime"]
    vault = evidence["vault_runtime"]
    configuration = vault["configuration"]
    raw_transaction = {
        "hash": transaction["hash"],
        "blockHash": transaction["block_hash"],
        "blockNumber": transaction["block_number"],
        "transactionIndex": transaction["transaction_index"],
        "from": transaction["from"],
        "to": transaction["to"],
        "input": transaction["input"],
    }
    configuration_reads = [
        value for key, value in configuration.items()
        if key not in ("signers", "memberships", "controls", "counters")
    ]
    configuration_reads.extend(configuration["controls"].values())
    configuration_reads.extend(configuration["counters"].values())
    for signer, membership in zip(
        configuration["signers"], configuration["memberships"]
    ):
        configuration_reads.extend([signer, membership])
    return [
        source["chain_id"],
        source["genesis"],
        source["receipt"],
        source["canonical_block"],
        source["finalized_block"],
        source["finalized_block"],
        source["canonical_block"],
        raw_transaction,
        token["proxy_code"],
        token["implementation_code"],
        token["implementation_slot"],
        token["implementation_getter"],
        vault["code"],
        *configuration_reads,
        vault["reserves"]["total_locked"],
        vault["reserves"]["token_balance"],
        source["canonical_block"],
        source["canonical_block"],
    ]


class CustodyDeploymentCollectTest(unittest.TestCase):
    def test_collection_is_exact_block_pinned_and_self_validating(self):
        manifest, expected = fixture()
        transport = Mock()
        transport.eth.side_effect = rpc_values(expected)
        actual = collect_custody_deployment_evidence(
            manifest, expected["transaction"]["hash"], transport
        )
        self.assertEqual(actual, expected)
        block = {
            "blockHash": expected["transaction"]["block_hash"],
            "requireCanonical": True,
        }
        calls = transport.eth.call_args_list
        self.assertEqual(calls[7].args, (
            "eth_getTransactionByHash", [expected["transaction"]["hash"]]
        ))
        self.assertEqual(calls[8].args, (
            "eth_getCode", [manifest["source"]["token_address"], block]
        ))
        self.assertEqual(calls[9].args, (
            "eth_getCode", [manifest["source"]["token_implementation_address"], block]
        ))
        self.assertEqual(calls[10].args[0], "eth_getStorageAt")
        self.assertEqual(calls[10].args[1][-1], block)
        self.assertEqual(calls[11].args, (
            "eth_call",
            [{"to": manifest["source"]["token_address"],
              "data": IMPLEMENTATION_SELECTOR, "gas": "0x186a0"}, block],
        ))
        self.assertEqual(calls[-1].args, (
            "eth_getBlockByNumber", [expected["transaction"]["block_number"], False]
        ))

    def test_final_reorg_and_malformed_transaction_are_refused(self):
        manifest, expected = fixture()
        for mutate in ("reorg", "transaction"):
            values = rpc_values(expected)
            if mutate == "reorg":
                values[-1] = dict(values[-1], hash="0x" + "91" * 32)
            else:
                values[7] = dict(values[7], input="0x6002")
            transport = Mock()
            transport.eth.side_effect = values
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                collect_custody_deployment_evidence(
                    manifest, expected["transaction"]["hash"], transport
                )

    def test_rpc_failure_has_no_fallback_or_retry(self):
        manifest, expected = fixture()
        transport = Mock()
        transport.eth.side_effect = ValueError("offline")
        with self.assertRaises(ValueError):
            collect_custody_deployment_evidence(
                manifest, expected["transaction"]["hash"], transport
            )
        self.assertEqual(transport.eth.call_count, 1)


if __name__ == "__main__":
    unittest.main()
