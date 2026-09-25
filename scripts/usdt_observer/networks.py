"""Explicit EVM source profiles. Chain ID alone never establishes finality."""
import hashlib

EVM_CHAIN_IDS = {'ethereum-mainnet': 1, 'base-mainnet': 8453}
BASE_GENESIS = '0xf712aa9241cc24369b143cf6dce85f0902a9731e70d66818a3a5845b296c73dd'
BASE_USDC = '0x833589fcd6edb6e08f4c7c32d4f71b54bda02913'
BASE_SOURCE_DOMAIN = '0x' + hashlib.sha256(
    b'BLOCH-USDT-SOURCE-CONFIG-v1\0base-mainnet\0' + bytes.fromhex(BASE_GENESIS[2:])
).hexdigest()
