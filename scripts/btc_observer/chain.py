"""Read-only Bitcoin Core evidence; trust the selected node, never authorize minting."""
from .proof import hash_bytes, verify_branch
from .transaction import Invalid, inspect_deposit

# Bitcoin Core v30.0 src/kernel/chainparams.cpp. Custom signets are not accepted.
CHAINS = {
    'bitcoin-mainnet': ('main', '000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f'),
    'bitcoin-testnet4': ('testnet4', '00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043'),
    'bitcoin-signet': ('signet', '00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6'),
    'bitcoin-regtest': ('regtest', '0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206'),
}
SIGNET_CHALLENGE = ('512103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be43'
                    '0210359ef5021964fe22d6f8e05b2463c9540ce96883fe3b278760f048f5189f2e6c452ae')
MAX_HEIGHT = 2_147_483_647


def require(condition, message):
    if not condition:
        raise Invalid(message)


def integer(value, low, high):
    require(type(value) is int and low <= value <= high, 'Invalid node integer')
    return value


def snapshot(info, network):
    require(type(info) is dict, 'Invalid chain information')
    require(info.get('chain') == CHAINS[network][0], 'Wrong Bitcoin network')
    if network == 'bitcoin-signet':
        require(info.get('signet_challenge') == SIGNET_CHALLENGE, 'Custom signet refused')
    height = integer(info.get('blocks'), 0, MAX_HEIGHT)
    require(integer(info.get('headers'), 0, MAX_HEIGHT) == height,
            'Node has not validated all known headers')
    require(info.get('initialblockdownload') is False, 'Node is synchronizing')
    require(info.get('warnings') in ([], ''), 'Node warning or missing warning status')
    tip, work = info.get('bestblockhash'), info.get('chainwork')
    hash_bytes(tip)
    hash_bytes(work)
    require(int(work, 16) > 0, 'Invalid chainwork')
    return height, tip, work


def assess_deposit(rpc, deposit, proof, *, expected_block_hash, min_confirmations):
    """Check one output and its proof against a stable pair of node tip reads.

    rpc(method, params) must be an authenticated, bounded operator-selected
    Bitcoin Core connection. Matching snapshots are not an atomic chain lock,
    protection against a lying node, or a durable reorg monitor.
    """
    integer(min_confirmations, 1, 100_000)
    require(type(deposit) is dict and set(deposit) ==
            {'raw', 'network', 'expected_txid', 'vout', 'script_pubkey'}, 'Invalid deposit request')
    require(type(proof) is dict and set(proof) ==
            {'header', 'tx_index', 'tx_count', 'siblings'}, 'Invalid membership request')
    observation = inspect_deposit(**deposit)
    membership = verify_branch(deposit['raw'], expected_block_hash=expected_block_hash, **proof)
    network = deposit['network']
    before = snapshot(rpc('getblockchaininfo', []), network)
    require(rpc('getblockhash', [0]) == CHAINS[network][1], 'Wrong genesis block')
    metadata = rpc('getblockheader', [expected_block_hash, True])
    require(type(metadata) is dict and metadata.get('hash') == expected_block_hash,
            'Node returned a different block')
    height = integer(metadata.get('height'), 1, before[0])
    confirmations = integer(metadata.get('confirmations'), 1, MAX_HEIGHT)
    require(confirmations == before[0] - height + 1, 'Inconsistent confirmation count')
    count = integer(metadata.get('nTx'), 1, 100_000)
    require(count == proof['tx_count'], 'Node transaction count differs from proof')
    require(metadata.get('merkleroot') == proof['header'][36:68][::-1].hex(),
            'Node Merkle root differs from proof')
    require(rpc('getblockheader', [expected_block_hash, False]) == proof['header'].hex(),
            'Node header differs from proof')
    require(rpc('getblockhash', [height]) == expected_block_hash, 'Block is not in active chain')
    after = snapshot(rpc('getblockchaininfo', []), network)
    require(before == after, 'Chain tip changed during observation; retry from fresh evidence')
    observation['proof'] = membership
    observation['chain'] = {
        'schema': 'bloch-btc-node-assessment-v1',
        'trust_model': 'operator-selected-bitcoin-core',
        'block_hash': expected_block_hash, 'block_height': height,
        'tip_hash': before[1], 'tip_height': before[0], 'tip_chainwork': before[2],
        'confirmations': confirmations, 'required_confirmations': min_confirmations,
        'confirmation_policy_met': confirmations >= min_confirmations,
        'node_active_chain_observed': True,
        'header_chain_verified': False, 'inclusion_verified': False,
        'finality_verified': False, 'custody_verified': False,
        'mint_authorized': False, 'bridge_ready': False,
    }
    return observation
