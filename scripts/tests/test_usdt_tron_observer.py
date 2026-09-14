"""Offline adversarial fixtures for native TRON receipt evidence; no node calls."""
import copy
import hashlib
import json
import sys
from pathlib import Path
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from usdt_observer import tron
from usdt_observer.common import DEPOSIT_TOPIC, TRANSFER_TOPIC, deposit_digest, normalized_route


def block_id(height, suffix=0x23):
    return height.to_bytes(8, "big").hex() + bytes([suffix] * 24).hex()


def fixture():
    txid = "ab" * 32
    owner, vault = "12" * 20, "34" * 20
    transaction = {
        "txID": txid, "ret": [{"contractRet": "SUCCESS"}],
        "raw_data": {"contract": [{
            "type": "TriggerSmartContract", "parameter": {
                "type_url": "type.googleapis.com/protocol.TriggerSmartContract",
                "value": {"owner_address": "41" + owner, "contract_address": "41" + vault,
                          "data": "12345678"}
            }
        }]}
    }
    route = {"network": "tron-mainnet", "genesis_hash": "0x" + block_id(0),
             "vault_vm_hex": "0x" + vault}
    def block(height):
        return {"blockID": block_id(height), "block_header": {"raw_data": {"number": height}}}
    canonical = block(42)
    canonical["transactions"] = [copy.deepcopy(transaction)]
    evidence = {"genesis": block(0), "transaction": transaction,
                "transaction_info": {"id": txid, "blockNumber": 42, "receipt": {"result": "SUCCESS"},
                                     "log": [{"address": owner}, {"address": vault, "topics": ["56" * 32], "data": "789a"}]},
                "canonical_block": canonical, "solidified_block": block(43)}
    return route, evidence


def deposit_fixture():
    """Two real event encodings using only the explicitly synthetic manifest."""
    _, evidence = fixture()
    manifest = json.loads((Path(__file__).resolve().parents[1] / "usdt-routes.synthetic.json").read_text())
    source = manifest["routes"][1]
    source["genesis_hash"] = "0x" + block_id(0)
    source["source_domain"] = "0x" + hashlib.sha256(
        b"BLOCH-USDT-SOURCE-CONFIG-v1\0tron-mainnet\0" + bytes.fromhex(block_id(0))).hexdigest()
    route = normalized_route(manifest, "tron-mainnet", allow_synthetic=True)
    vault, token = route["vault_vm_hex"][2:], route["token_vm_hex"][2:]
    sender, recipient = bytes.fromhex("12" * 20), bytes.fromhex("67" * 32)
    route_id = bytes.fromhex(route["route_id"][2:])
    deposit_id = deposit_digest(route_id, 7, sender, 55, recipient)
    for transaction in (evidence["transaction"], evidence["canonical_block"]["transactions"][0]):
        transaction["raw_data"]["contract"][0]["parameter"]["value"]["contract_address"] = "41" + vault
    evidence["transaction_info"]["log"] = [
        {"address": "12" * 20},  # Preserve the original ordinal of both following logs.
        {"address": token, "topics": [TRANSFER_TOPIC.hex(), sender.rjust(32, b"\0").hex(), "00" * 12 + vault],
         "data": (55).to_bytes(32, "big").hex()},
        {"address": vault, "topics": [DEPOSIT_TOPIC.hex(), deposit_id.hex(), route_id.hex()],
         "data": ((7).to_bytes(32, "big") + sender.rjust(32, b"\0") + (55).to_bytes(32, "big") + recipient).hex()}
    ]
    return route, evidence


class TronObserverTest(unittest.TestCase):
    def setUp(self):
        self.route, self.evidence = fixture()

    def rejected(self, change):
        evidence = copy.deepcopy(self.evidence)
        change(evidence)
        with patch.object(tron, "decode_deposits") as decoder:
            with self.assertRaises(ValueError):
                tron.validate(self.route, evidence)
            decoder.assert_not_called()

    def test_normalization_preserves_unfiltered_ordinal_and_provenance(self):
        with patch.object(tron, "decode_deposits", return_value=[{"log_index": 1}]) as decoder:
            output = tron.validate(self.route, self.evidence)
        logs = decoder.call_args.args[1]
        self.assertEqual(logs, [
            {"address": bytes.fromhex("12" * 20), "topics": [], "data": b"", "log_index": 0},
            {"address": bytes.fromhex("34" * 20), "topics": [bytes.fromhex("56" * 32)], "data": bytes.fromhex("789a"), "log_index": 1}
        ])
        self.assertEqual(output, [{"log_index": 1, "network": "tron-mainnet", "tx_hash": "0x" + "ab" * 32,
                                   "block_hash": "0x" + block_id(42), "block_number": 42}])
        self.assertEqual(self.evidence, fixture()[1])

    def test_success_defaults_and_same_height_solidified_block(self):
        self.evidence["transaction_info"]["result"] = "SUCCESS"
        self.evidence["genesis"]["block_header"]["raw_data"].pop("number")
        self.evidence["solidified_block"] = copy.deepcopy(self.evidence["canonical_block"])
        with patch.object(tron, "decode_deposits", return_value=[]):
            self.assertEqual(tron.validate(self.route, self.evidence), [])

    def test_wrong_network_genesis_height_and_finalized_branch_rejected(self):
        bad_route = dict(self.route, network="ethereum-mainnet")
        with self.assertRaises(ValueError):
            tron.validate(bad_route, self.evidence)
        mutations = [
            lambda e: e["genesis"].update(blockID=block_id(0, 0x45)),
            lambda e: e["genesis"]["block_header"]["raw_data"].update(number=1),
            lambda e: e["canonical_block"].update(blockID=block_id(43)),
            lambda e: e["canonical_block"]["block_header"]["raw_data"].pop("number"),
            lambda e: e["transaction_info"].update(blockNumber=41),
            lambda e: e["transaction_info"].update(blockNumber=True),
            lambda e: e["transaction_info"].update(blockID=block_id(42, 0x45)),
            lambda e: e["solidified_block"].update(blockID=block_id(41), block_header={"raw_data": {"number": 41}}),
            lambda e: e["solidified_block"].update(blockID=block_id(42, 0x45), block_header={"raw_data": {"number": 42}}),
        ]
        for mutation in mutations:
            self.rejected(mutation)

    def test_failed_missing_or_conflicting_transaction_receipts_rejected(self):
        mutations = [
            lambda e: e["transaction_info"].update(result="FAILED"),
            lambda e: e["transaction_info"].update(result=False),
            lambda e: e["transaction_info"].update(receipt={"result": "REVERT"}),
            lambda e: e["transaction_info"].pop("receipt"),
            lambda e: e["transaction"]["ret"][0].update(contractRet="OUT_OF_ENERGY"),
            lambda e: e["transaction"].update(ret=[]),
            lambda e: e["transaction_info"].update(id="cd" * 32),
            lambda e: e["canonical_block"].update(transactions=[]),
            lambda e: e["canonical_block"]["transactions"].append(copy.deepcopy(e["transaction"])),
            lambda e: e["canonical_block"]["transactions"][0]["raw_data"].update(expiration=123),
            lambda e: e["transaction"].update(raw_data_hex="1234"),
            lambda e: e.update(untrusted_network="mainnet"),
        ]
        for mutation in mutations:
            self.rejected(mutation)

    def test_call_types_address_formats_and_selectors_rejected(self):
        mutations = [
            lambda e: e["transaction"].update(visible=True),
            lambda e: e["transaction"]["raw_data"]["contract"][0].update(type="TransferContract"),
            lambda e: e["transaction"]["raw_data"]["contract"][0]["parameter"].update(type_url="other"),
            lambda e: e["transaction"]["raw_data"]["contract"][0]["parameter"]["value"].update(contract_address="42" + "34" * 20),
            lambda e: e["transaction"]["raw_data"]["contract"][0]["parameter"]["value"].update(owner_address="T" * 34),
            lambda e: e["transaction"]["raw_data"]["contract"][0]["parameter"]["value"].update(data="0x12345678"),
            lambda e: e["transaction"]["raw_data"]["contract"][0]["parameter"]["value"].update(data="1234"),
        ]
        for mutation in mutations:
            self.rejected(mutation)

    def test_logs_reject_jsonrpc_shape_indices_and_oversized_records(self):
        mutations = [
            lambda e: e["transaction_info"]["log"][0].update(address="0x" + "12" * 20),
            lambda e: e["transaction_info"]["log"][0].update(address="41" + "12" * 20),
            lambda e: e["transaction_info"]["log"][0].update(log_index=100),
            lambda e: e["transaction_info"]["log"][0].update(topics=["56" * 32] * 5),
            lambda e: e["transaction_info"]["log"][0].update(topics=["0x" + "56" * 32]),
            lambda e: e["transaction_info"]["log"][0].update(data="g0"),
            lambda e: e["transaction_info"]["log"][0].update(data="12" * (tron.MAX_DATA_BYTES + 1)),
            lambda e: e["transaction_info"].update(log=[{"address": "12" * 20}] * (tron.MAX_LOGS + 1)),
            lambda e: e["transaction_info"].update(log=[{"address": "12" * 20, "data": "12" * tron.MAX_DATA_BYTES}] * 33),
            lambda e: e["canonical_block"].update(transactions=[e["transaction"]] * (tron.MAX_TRANSACTIONS + 1)),
        ]
        for mutation in mutations:
            self.rejected(mutation)

    def test_deposit_decoder_rejections_propagate_and_never_emit_partial_result(self):
        with patch.object(tron, "decode_deposits", side_effect=ValueError("reordered token Transfer")):
            with self.assertRaises(ValueError):
                tron.validate(self.route, self.evidence)

    def test_real_deposit_and_token_transfer_are_bound_with_original_indices(self):
        route, evidence = deposit_fixture()
        result = tron.validate(route, evidence)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["amount"], 55)
        self.assertEqual(result[0]["nonce"], 7)
        self.assertEqual(result[0]["route_id"], route["route_id"])
        self.assertEqual(result[0]["log_index"], 2)
        self.assertEqual(result[0]["transfer_log_index"], 1)
        self.assertEqual(result[0]["block_number"], 42)

    def test_real_logs_reordered_missing_wrong_amount_and_duplicate_fail(self):
        route, original = deposit_fixture()
        mutations = [
            lambda logs: logs.reverse(),
            lambda logs: logs.pop(1),
            lambda logs: logs[1].update(data=(54).to_bytes(32, "big").hex()),
            lambda logs: logs[2]["topics"].__setitem__(1, "89" * 32),
            lambda logs: logs[2]["topics"].__setitem__(2, "89" * 32),
            lambda logs: logs.extend(copy.deepcopy(logs[1:])),
        ]
        for mutation in mutations:
            evidence = copy.deepcopy(original)
            mutation(evidence["transaction_info"]["log"])
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                tron.validate(route, evidence)


if __name__ == "__main__":
    unittest.main()
