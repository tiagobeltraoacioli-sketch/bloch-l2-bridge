"""Block-local source reserve consistency, not native liability reconciliation."""
from .common import integer, require, word


def validate_reserves(route, reserves):
    require(type(reserves) is dict and set(reserves) == {'total_locked', 'token_balance'},
            'exact source reserve evidence required')
    locked = integer(int.from_bytes(word(reserves['total_locked'], 32), 'big'))
    # ERC-20 balances are uint256; donated surplus may exceed a uint64 route cap.
    balance = int.from_bytes(word(reserves['token_balance'], 32), 'big')
    cap = integer(route['cap'])
    require(0 < cap and locked <= cap, 'source liability exceeds route cap')
    require(balance >= locked, 'source reserve deficit')
    return {'validation': 'source-rpc-reserve-consistency-only',
            'source_reserve_policy_satisfied': True,
            'total_locked': str(locked), 'token_balance': str(balance),
            'uncredited_surplus': str(balance - locked),
            'native_liabilities_reconciled': False, 'backing_verified': False,
            'mint_authorized': False}


def collect_reserves(route, block_hash, source):
    block = '0x' + word(block_hash, 32).hex()
    vault = '0x' + word(route['vault_vm_hex'], 20).hex()
    token = '0x' + word(route['token_vm_hex'], 20).hex()

    def call(address, data):
        return source.eth('eth_call', [{'to': address, 'data': data, 'gas': '0x186a0'},
                                     {'blockHash': block, 'requireCanonical': True}])

    # Keccak selectors: totalLocked() and balanceOf(address).
    locked = call(vault, '0x56891412')
    integer(int.from_bytes(word(locked, 32), 'big'))
    balance = call(token, '0x70a08231' + word(vault, 20).rjust(32, b'\0').hex())
    result = {'total_locked': locked, 'token_balance': balance}
    validate_reserves(route, result)
    return result
