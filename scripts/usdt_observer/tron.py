"""Pure checks for captured TRON walletsolidity responses (visible:false).

RPC-reported block inclusion/solidification is not consensus verification. This
module performs no HTTP calls, signature checks, minting or release authorization.
Schemas: https://developers.tron.network/docs/block and
https://tronprotocol.github.io/documentation-en/api/http/block-and-tx-query/gettransactioninfobyid/
"""
import re

from .common import decode_deposits, integer, require, word

MAX_TRANSACTIONS = 4096
MAX_LOGS = 2048
MAX_DATA_BYTES = 65536
MAX_TOTAL_LOG_BYTES = 1024 * 1024
HEX = re.compile(r"(?:[0-9a-fA-F]{2})*\Z")


def object_value(value, label):
    require(isinstance(value, dict), label + " must be an object")
    require(value.get("visible", False) is False, "only visible:false TRON responses are supported")
    require("Error" not in value, label + " contains an RPC error")
    return value


def data_bytes(value, maximum=MAX_DATA_BYTES):
    require(isinstance(value, str) and len(value) <= maximum * 2 and HEX.fullmatch(value),
            "invalid or oversized unprefixed TRON hex data")
    return bytes.fromhex(value)


def block_identity(value, *, genesis=False):
    value = object_value(value, "block")
    header = object_value(value.get("block_header"), "block header")
    raw = object_value(header.get("raw_data"), "block header raw_data")
    # Protobuf JSON may omit the default zero number at genesis. No other
    # missing height is accepted, and the embedded height and pinned ID agree.
    height = integer(raw.get("number", 0) if genesis else raw.get("number"))
    block_id = word(value.get("blockID"), 32, prefix=False)
    require(any(block_id) and int.from_bytes(block_id[:8], "big") == height,
            "TRON block ID height does not match its header")
    if genesis:
        require(height == 0, "genesis must be block zero")
    return height, block_id


def transaction_identity(value, *, inspect_call=False):
    value = object_value(value, "transaction")
    txid = word(value.get("txID"), 32, prefix=False)
    require(any(txid), "zero transaction ID")
    if not inspect_call:
        return txid
    results = value.get("ret")
    require(isinstance(results, list) and len(results) == 1 and isinstance(results[0], dict)
            and results[0].get("contractRet") == "SUCCESS", "transaction execution did not succeed")
    raw = object_value(value.get("raw_data"), "transaction raw_data")
    contracts = raw.get("contract")
    require(isinstance(contracts, list) and len(contracts) == 1,
            "exactly one TriggerSmartContract is required")
    contract = object_value(contracts[0], "transaction contract")
    require(contract.get("type") == "TriggerSmartContract", "unsupported TRON transaction type")
    parameter = object_value(contract.get("parameter"), "contract parameter")
    require(parameter.get("type_url") == "type.googleapis.com/protocol.TriggerSmartContract",
            "contract parameter type mismatch")
    call = object_value(parameter.get("value"), "contract call")
    for name in ("owner_address", "contract_address"):
        address = word(call.get(name), 21, prefix=False)
        require(address[0] == 0x41 and any(address[1:]), "invalid visible:false TRON call address")
    require(len(data_bytes(call.get("data"))) >= 4, "contract call selector is missing")
    # The top-level call may be a router. Deposits are identified from the
    # pinned vault event and matching source-token Transfer, never a selector.
    return txid


def validate(route, evidence):
    """Validate one captured transaction; return common decoded observations."""
    require(isinstance(route, dict) and route.get("network") == "tron-mainnet", "wrong source network")
    require(isinstance(evidence, dict) and set(evidence) == {
        "genesis", "transaction", "transaction_info", "canonical_block", "solidified_block"
    }, "invalid TRON evidence fields")
    _, genesis_id = block_identity(evidence["genesis"], genesis=True)
    require(genesis_id == word(route.get("genesis_hash"), 32), "source genesis mismatch")
    transaction = evidence["transaction"]
    txid = transaction_identity(transaction, inspect_call=True)
    info = object_value(evidence["transaction_info"], "transaction info")
    require(word(info.get("id"), 32, prefix=False) == txid, "transaction/receipt ID mismatch")
    receipt = object_value(info.get("receipt"), "execution receipt")
    require(receipt.get("result") == "SUCCESS" and info.get("result", "SUCCESS") == "SUCCESS",
            "receipt execution did not succeed")
    height = integer(info.get("blockNumber"))
    require(height > 0, "deposit cannot be in genesis")
    block_height, block_id = block_identity(evidence["canonical_block"])
    require(block_height == height, "receipt/canonical block height mismatch")
    # Native TransactionInfo normally omits a block ID. If an adapter returns
    # one, it must not contradict the separately supplied canonical block.
    for name in ("blockID", "blockHash"):
        if name in info:
            require(word(info[name], 32, prefix=False) == block_id, "receipt block ID mismatch")
    transactions = evidence["canonical_block"].get("transactions")
    require(isinstance(transactions, list) and 0 < len(transactions) <= MAX_TRANSACTIONS,
            "missing or oversized canonical transaction list")
    ids = [transaction_identity(item) for item in transactions]
    require(len(set(ids)) == len(ids) and txid in ids, "duplicate or missing canonical transaction")
    included = transactions[ids.index(txid)]
    transaction_identity(included, inspect_call=True)
    require(included["raw_data"] == transaction["raw_data"] and included["ret"] == transaction["ret"],
            "canonical transaction body mismatch")
    if "raw_data_hex" in included or "raw_data_hex" in transaction:
        require(data_bytes(included.get("raw_data_hex")) == data_bytes(transaction.get("raw_data_hex")),
                "canonical serialized transaction mismatch")
    solid_height, solid_id = block_identity(evidence["solidified_block"])
    require(solid_height >= height, "receipt is above the reported solidified block")
    require(solid_height != height or solid_id == block_id, "solidified/canonical block disagreement")
    logs = info.get("log")
    require(isinstance(logs, list) and len(logs) <= MAX_LOGS, "missing or oversized receipt logs")
    normalized = []
    total_bytes = 0
    for index, log in enumerate(logs):
        require(isinstance(log, dict) and {"address"} <= set(log) <= {"address", "topics", "data"},
                "malformed native receipt log")
        topics = log.get("topics", [])
        require(isinstance(topics, list) and len(topics) <= 4, "invalid receipt log topics")
        data = data_bytes(log.get("data", ""))
        total_bytes += len(data) + 32 * len(topics) + 20
        require(total_bytes <= MAX_TOTAL_LOG_BYTES, "receipt log data exceeds total limit")
        normalized.append({"address": word(log["address"], 20, prefix=False),
                           "topics": [word(topic, 32, prefix=False) for topic in topics],
                           "data": data, "log_index": index})
    observations = decode_deposits(route, normalized)
    return [dict(item, network="tron-mainnet", tx_hash="0x" + txid.hex(),
                 block_hash="0x" + block_id.hex(), block_number=height) for item in observations]
