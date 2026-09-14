"""Pure Ethereum receipt consistency checks for the federated USDT observer.

Inputs are JSON-RPC result objects collected from authenticated source nodes.
This module performs no I/O, consensus verification, signing or minting.
"""
from .common import decode_deposits, quantity, require, word

MAX_LOGS = 4096
MAX_TRANSACTIONS = 16384
MAX_LOG_DATA_BYTES = 65536
MAX_TOTAL_LOG_BYTES = 1048576
EVIDENCE_KEYS = {'chain_id', 'genesis', 'receipt', 'canonical_block', 'finalized_block'}


def _object(value, name):
    require(isinstance(value, dict), name + ' must be an object')
    return value


def _hash(value):
    result = word(value, 32)
    require(any(result), 'zero hash is not mined evidence')
    return result


def validate(route: dict, evidence: dict) -> list[dict]:
    """Validate finalized receipt evidence, returning candidate deposit observations.

    `finalized_block` must be collected using the explicit finalized selector.
    Result JSON alone cannot prove which selector was used or prove consensus.
    Canonical blocks must be fetched with full_transactions=false.
    """
    _object(route, 'route')
    _object(evidence, 'evidence')
    require(set(evidence) == EVIDENCE_KEYS, 'explicit finalized evidence fields required')
    require(route.get('network') == 'ethereum-mainnet', 'Ethereum mainnet route required')
    require(quantity(evidence.get('chain_id')) == 1, 'Ethereum mainnet chain ID required')
    genesis = _object(evidence.get('genesis'), 'genesis')
    require(quantity(genesis.get('number')) == 0, 'genesis must be block zero')
    require(_hash(genesis.get('hash')) == _hash(route.get('genesis_hash')), 'genesis identity mismatch')
    receipt = _object(evidence.get('receipt'), 'receipt')
    require(quantity(receipt.get('status')) == 1, 'successful receipt required')
    block_number = quantity(receipt.get('blockNumber'))
    require(block_number > 0, 'genesis cannot contain a bridge deposit')
    block_hash = _hash(receipt.get('blockHash'))
    tx_hash = _hash(receipt.get('transactionHash'))
    tx_index = quantity(receipt.get('transactionIndex'))
    canonical = _object(evidence.get('canonical_block'), 'canonical block')
    require(quantity(canonical.get('number')) == block_number, 'canonical block height mismatch')
    require(_hash(canonical.get('hash')) == block_hash, 'canonical block hash mismatch')
    transactions = canonical.get('transactions')
    require(isinstance(transactions, list) and 0 < len(transactions) <= MAX_TRANSACTIONS,
            'bounded transaction hash list required')
    hashes = [_hash(value) for value in transactions]
    require(len(set(hashes)) == len(hashes), 'duplicate block transaction hash')
    require(tx_index < len(hashes) and hashes[tx_index] == tx_hash, 'receipt transaction inclusion mismatch')
    finalized = _object(evidence.get('finalized_block'), 'finalized block')
    final_number = quantity(finalized.get('number'))
    final_hash = _hash(finalized.get('hash'))
    require(final_number >= block_number, 'receipt block is not finalized')
    if final_number == block_number:
        require(final_hash == block_hash, 'finalized block hash mismatch')
    logs = receipt.get('logs')
    require(isinstance(logs, list) and len(logs) <= MAX_LOGS, 'bounded receipt log list required')
    normalized = []
    previous_index = -1
    total_bytes = 0
    for entry in logs:
        _object(entry, 'receipt log')
        require(entry.get('removed') is False, 'explicit nonremoved log required')
        require(_hash(entry.get('transactionHash')) == tx_hash, 'log transaction hash mismatch')
        require(quantity(entry.get('transactionIndex')) == tx_index, 'log transaction index mismatch')
        require(_hash(entry.get('blockHash')) == block_hash, 'log block hash mismatch')
        require(quantity(entry.get('blockNumber')) == block_number, 'log block height mismatch')
        index = quantity(entry.get('logIndex'))
        require(index > previous_index, 'receipt log indices must be unique and ordered')
        previous_index = index
        topics = entry.get('topics')
        require(isinstance(topics, list) and len(topics) <= 4, 'invalid log topic count')
        topics = [word(topic, 32) for topic in topics]
        data = entry.get('data')
        require(isinstance(data, str) and len(data) <= 2 + 2 * MAX_LOG_DATA_BYTES,
                'log data exceeds limit')
        data = word(data, (len(data) - 2) // 2)
        total_bytes += len(data) + 32 * len(topics) + 20
        require(total_bytes <= MAX_TOTAL_LOG_BYTES, 'receipt log bytes exceed limit')
        normalized.append({'address': word(entry.get('address'), 20), 'topics': topics,
                           'data': data, 'log_index': index})
    observations = decode_deposits(route, normalized)
    return [dict(observation, tx_hash='0x' + tx_hash.hex(), block_hash='0x' + block_hash.hex(),
                 block_number=block_number, network=route['network']) for observation in observations]
