#!/usr/bin/env python3
"""bBTC deployment helper: from the key ceremony's public inventory to the vault, its addresses and the token arguments.

Offline unless a node is named. It never reads a key, a keystore or a password, and sends nothing.

  keys     --inventory INVENTORY.json [--role eth-release-signer | btc-vault-signer]
           The 7 compressed public keys of the committee, recovered from proof-of-possession signatures.
           eth-release-signer: the keys of the bUSDC ceremony (docs/BRIDGE-V3-KEY-CEREMONY.md 4.1), no new step.
           btc-vault-signer: a separate Bitcoin key per operator, attested with the same text and tool, listed in an
           inventory file of its own (deployments/bitcoin/bbtc-keys.inventory.json).
  message  --index N --operator NAME --address 0x.. --date YYYY-MM-DD
           The text an operator signs (`cast wallet sign`) for a separate btc-vault-signer key.
  thread   --config VAULT.json
           The thread (bare 5-of-7) address to fund once: that payment is the vault's anchor. Works before the anchor is set.
  vault    --config VAULT.json [--btc-rpc URL --btc-cookie PATH]
           Everything derived from the config: vault id, source chain id / vault / route for the L2 token, policy hash,
           charge sizes. With a node: the anchor exists, pays the thread script, is confirmed and (before the token is
           deployed) unspent.
  address  --config VAULT.json --recipient 0xL2ADDRESS
  token    --config VAULT.json --token-config TOKEN.json --artifact out/BridgedStablecoinV3.sol/BridgedStablecoinV3.json
           The constructor arguments and init code of the L2 token (BridgedStablecoinV3, frozen creation code), after the
           policy checks: creation keccak equals the freeze, T = 0, 5 of 7, 3 guardians, 6-of-7 switch, burn limits that
           fit the vault policy. Prints the exact `cast send --create` data; the owner's deployer sends it.
  verify   --config VAULT.json --token-config TOKEN.json --l2-rpc URL --token 0x...
           Reads the deployed token back and compares every immutable with the plan.
UNAUDITED.
"""
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / 'deploy-pontes'))
import btc_core as c  # noqa: E402
import btc_l2  # noqa: E402
import btc_policy as pol  # noqa: E402

FROZEN_CREATION = 'e560441f37e247e387cebd23bb3dd798a29d34174a9fb19a4bb3877c6c721de7'
MAINNET_POLICY = {'signers': 7, 'threshold': 5, 'guardians': 3, 'switchThreshold': 6}


def refuse(reason, **detail):
    print(json.dumps({'decision': 'refused', 'reason': reason, **detail}, indent=2))
    raise SystemExit(1)


def option(args, name, default=None):
    if name in args:
        return args[args.index(name) + 1]
    if default is None:
        raise SystemExit(f'{name} is required\n{__doc__}')
    return default


def personal_digest(text):
    data = text.encode()
    return c.keccak256(b'\x19Ethereum Signed Message:\n' + str(len(data)).encode() + data)


def recover_key(text, signature, address):
    sig = bytes.fromhex(signature.removeprefix('0x'))
    key = c.recover(personal_digest(text), *c.parse_rsv(sig))
    if c.eth_address(key) != address.lower():
        refuse('an attestation does not recover to its address', address=address)
    return key


BTC_ROLE = 'btc-vault-signer'


def attestation_text(key_inventory, role, index, operator, address, date):
    """The ceremony's attestation text. `btc-vault-signer` is a role of this bridge only: a separate Bitcoin key per
    operator (same tool, same text format), kept in its own inventory file so the frozen bUSDC inventory tool and its
    role list do not change."""
    if role != BTC_ROLE:
        return key_inventory.message(role, index, operator, address, date)
    template = key_inventory.message('eth-release-signer', index, operator, address, date)
    return template.replace('role=eth-release-signer ', f'role={BTC_ROLE} ')


def cmd_keys(args):
    import key_inventory  # the ceremony's own message format (tools/deploy-pontes)
    role = option(args, '--role', 'eth-release-signer')
    inv = json.loads(Path(option(args, '--inventory')).read_text())
    out = []
    for k in inv['keys']:
        if k['role'] != role:
            continue
        if not k.get('address') or not k.get('attestation') or not k.get('date'):
            refuse('the inventory has an unfilled key of this role', index=k.get('index'))
        text = attestation_text(key_inventory, role, k['index'], k['operator'], k['address'], k['date'])
        out.append({'index': k['index'], 'operator': k['operator'], 'address': k['address'].lower(),
                    'pubkey': recover_key(text, k['attestation'], k['address']).hex()})
    if len(out) != MAINNET_POLICY['signers']:
        refuse(f"expected {MAINNET_POLICY['signers']} keys of role {role}, found {len(out)}")
    print(json.dumps({'decision': 'ok', 'role': role, 'keys': sorted(out, key=lambda x: x['index'])}, indent=2))


def load(args, need_anchor=True):
    cfg = json.loads(Path(option(args, '--config')).read_text())
    for field in ('network', 'threshold', 'keys', 'owner_address', 'policy'):
        if field not in cfg or cfg[field] in (None, 'TBD-owner', 'TBD-deploy'):
            refuse(f'vault config: {field} is undecided')
    if any(not isinstance(k, str) or len(k) != 66 for k in cfg['keys']):
        refuse('vault config: keys must be 33-byte compressed public keys in hex (btc_deploy.py keys)')
    anchor = cfg.get('anchor') or {}
    if not isinstance(anchor.get('txid'), str) or len(anchor.get('txid', '')) != 64 or type(anchor.get('vout')) is not int:
        if need_anchor:
            refuse('vault config: the anchor is undecided (fund the thread address once, then name that output)')
        cfg = {**cfg, 'anchor': {'txid': '00' * 32, 'vout': 0}}
    try:
        vault = pol.Vault.from_config(cfg)
    except (pol.PolicyError, c.BadKey, c.BadAddress, ValueError) as e:
        refuse(f'vault config: {getattr(e, "reason", e)}')
    if cfg['network'] == 'bitcoin-mainnet':
        if (len(vault.keys), vault.threshold) != (MAINNET_POLICY['signers'], MAINNET_POLICY['threshold']):
            refuse('mainnet policy is 5 of 7')
        if not c.is_standard_payout(vault.owner_spk):
            refuse('the owner fee address must be P2WPKH')
    return cfg, vault


def cmd_token(args, verify=False):
    cfg, vault = load(args)
    tok = json.loads(Path(option(args, '--token-config')).read_text())
    lim, signers, guardians = tok['limits'], tok['signers'], tok['guardians']
    addr = lambda v: isinstance(v, str) and len(v) == 42 and v.startswith('0x')
    if not all(addr(a) for a in signers['set'] + guardians['set']):
        refuse('token config: a signer or guardian address is undecided')
    mainnet = cfg['network'] == 'bitcoin-mainnet'
    if mainnet and (len(signers['set']), signers['threshold'], len(guardians['set']), tok['mintSwitch']['threshold']) != (7, 5, 3, 6):
        refuse('mainnet policy: 7 signers, threshold 5, 3 guardians, switch threshold 6')
    if set(a.lower() for a in signers['set']) & set(a.lower() for a in guardians['set']):
        refuse('a guardian is also a signer')
    if lim['largeMintThreshold'] != 0:
        refuse('T = 0 is a hard rule: every mint queues and stays cancellable')
    unit, p = vault.policy['unitSats'], vault.policy
    if lim['bucketCapacity'] < 10 or not 1 <= lim['refillPerSecond'] <= lim['bucketCapacity'] <= lim['supplyCap']:
        refuse('token limits out of range')
    # a burn must be payable: its 10% miner-charge cap must cover at least 1 sat/vB, and its payout must clear dust
    try:
        pol.release_payout(vault, lim['minBurn'], 1)
    except pol.PolicyError as e:
        refuse(f'token minBurn is too small for the vault policy: {e.reason}')
    if p['maxDepositSats'] > lim['bucketCapacity'] * unit:
        refuse('a deposit of maxDepositSats would not fit the token mint bucket: its mint could never queue and would block every later one')
    if p['capSats'] != lim['supplyCap'] * unit:
        refuse('the vault cap must equal the token supply cap', capSats=p['capSats'], supplyCap=lim['supplyCap'])
    if lim['bucketCapacity'] * unit > p['windowLimitSats']:
        refuse('one burn (at most bucketCapacity) must fit the vault release window', window=p['windowLimitSats'])
    if not p['windowLimitSats'] <= lim['supplyCap'] * unit:
        refuse('the release window exceeds the supply cap')
    plan = {'name': tok['token']['name'], 'symbol': tok['token']['symbol'], 'decimals': 6,
            'sourceChainId': str(vault.chain_id), 'sourceVault': '0x' + vault.source_vault.hex(),
            'sourceRoute': '0x' + vault.route.hex(), 'signers': [a.lower() for a in signers['set']],
            'threshold': signers['threshold'], 'limits': lim, 'guardians': [a.lower() for a in guardians['set']],
            'pauseDuration': guardians['pauseDuration'], 'pauseCooldown': guardians['pauseCooldown'],
            'mintSwitch': tok['mintSwitch']}
    if verify:
        return cfg, vault, plan
    art = json.loads(Path(option(args, '--artifact')).read_text())
    creation = bytes.fromhex(art['bytecode']['object'].removeprefix('0x'))
    if c.keccak256(creation).hex() != FROZEN_CREATION:
        refuse('the artifact is not the frozen BridgedStablecoinV3 creation code', got=c.keccak256(creation).hex())
    enc = abi_constructor(plan)
    init = creation + enc
    print(json.dumps({'decision': 'ok', 'plan': plan, 'creationCodeKeccak': '0x' + FROZEN_CREATION,
                      'constructorArgs': '0x' + enc.hex(), 'initCodeKeccak': '0x' + c.keccak256(init).hex(),
                      'initCodeBytes': len(init),
                      'deploy': 'cast send --create <initCode> with the l2-token-deployer wallet at nonce 0 (see docs/BTC-BRIDGE-DEPLOYMENT.md)'},
                     indent=2))
    out = option(args, '--out', '')
    if out:
        Path(out).write_text('0x' + init.hex() + '\n')


def abi_constructor(plan):
    """abi.encode of BridgedStablecoinV3's constructor arguments (dynamic: 2 strings, 2 address arrays inside tuples)."""
    w = c.abi_word

    def dyn_bytes(b):
        return w(len(b)) + b.ljust((len(b) + 31) // 32 * 32, b'\0')

    def addr_array(a):
        return w(len(a)) + b''.join(w(bytes.fromhex(x[2:])) for x in a)

    lim = plan['limits']
    limits = b''.join(w(lim[k]) for k in ('supplyCap', 'bucketCapacity', 'refillPerSecond', 'largeMintThreshold',
                                          'largeMintDelay', 'minBurn'))
    guard = w(0x60) + w(plan['pauseDuration']) + w(plan['pauseCooldown']) + addr_array(plan['guardians'])
    switch = w(plan['mintSwitch']['threshold']) + w(plan['mintSwitch']['delay'])
    name, symbol, signers = dyn_bytes(plan['name'].encode()), dyn_bytes(plan['symbol'].encode()), addr_array(plan['signers'])
    head_words = 6 + 1 + 6 + 1 + 2  # name, symbol, chain, vault, route, signers, threshold, limits(6), guard, switch(2)
    off_name = 32 * head_words
    off_symbol = off_name + len(name)
    off_signers = off_symbol + len(symbol)
    off_guard = off_signers + len(signers)
    head = (w(off_name) + w(off_symbol) + w(int(plan['sourceChainId'])) + w(bytes.fromhex(plan['sourceVault'][2:]))
            + bytes.fromhex(plan['sourceRoute'][2:]) + w(off_signers) + w(plan['threshold']) + limits + w(off_guard) + switch)
    return head + name + symbol + signers + guard


def cmd_verify(args):
    cfg, vault, plan = cmd_token(args, verify=True)
    token = btc_l2.Token(option(args, '--l2-rpc'), option(args, '--token'))
    lim = plan['limits']
    want = {'decimals()': 6, 'sourceChainId()': int(plan['sourceChainId']), 'threshold()': plan['threshold'],
            'supplyCap()': lim['supplyCap'], 'bucketCapacity()': lim['bucketCapacity'], 'refillPerSecond()': lim['refillPerSecond'],
            'largeMintThreshold()': 0, 'largeMintDelay()': lim['largeMintDelay'], 'minBurn()': lim['minBurn'],
            'pauseDuration()': plan['pauseDuration'], 'pauseCooldown()': plan['pauseCooldown'],
            'switchThreshold()': plan['mintSwitch']['threshold'], 'switchDelay()': plan['mintSwitch']['delay'],
            'cancelQuorum()': len(plan['guardians']) // 2 + 1, 'instantCapacity()': 0, 'totalSupply()': 0, 'nextSlot()': 0}
    bad = {k: token.uint(k) for k, v in want.items() if token.uint(k) != v}
    if token.word('sourceRoute()') != vault.route or token.word('sourceVault()')[12:] != vault.source_vault:
        bad['source'] = 'route or vault differs'
    for a in plan['signers']:
        if not token.uint('isSigner(address)', bytes.fromhex(a[2:])):
            bad[a] = 'not a signer'
    for a in plan['guardians']:
        if not token.uint('isGuardian(address)', bytes.fromhex(a[2:])):
            bad[a] = 'not a guardian'
    head = token.word('mintHead()')
    if head != c.mint_chain_genesis(vault.chain_id, vault.source_vault, vault.route):
        bad['mintHead'] = 'not the genesis of this vault'
    code = token.rpc('eth_getCode', [token.token, 'latest'])
    print(json.dumps({'decision': 'refused' if bad else 'ok', 'differences': bad, 'token': token.token,
                      'runtimeCodeKeccak': '0x' + c.keccak256(bytes.fromhex(code[2:])).hex()}, indent=2))
    raise SystemExit(1 if bad else 0)


def main():
    args = sys.argv[1:]
    if not args or args[0] in ('-h', '--help'):
        raise SystemExit(__doc__)
    cmd = next((a for a in args if a in ('keys', 'message', 'thread', 'vault', 'address', 'token', 'verify')), None)
    if cmd == 'keys':
        return cmd_keys(args)
    if cmd == 'message':
        import key_inventory
        print(attestation_text(key_inventory, BTC_ROLE, int(option(args, '--index')), option(args, '--operator'),
                               option(args, '--address'), option(args, '--date')))
        return
    if cmd == 'token':
        return cmd_token(args)
    if cmd == 'verify':
        return cmd_verify(args)
    if cmd == 'thread':
        cfg, vault = load(args, need_anchor=False)
        print(json.dumps({'decision': 'ok', 'thread_address': vault.thread_address(), 'witness_script': vault.thread_script.hex(),
                          'keys_in_script_order': [k.hex() for k in vault.keys],
                          'fund': 'send the fee-pool seed (>= poolTargetSats) to thread_address ONCE; that output is the anchor'}, indent=2))
        return
    cfg, vault = load(args)
    if cmd == 'address':
        recipient = bytes.fromhex(option(args, '--recipient').lower().removeprefix('0x'))
        print(json.dumps({'decision': 'ok', 'recipient': '0x' + recipient.hex(), 'deposit_address': vault.deposit_address(recipient),
                          'witness_script': vault.deposit_script(recipient).hex()}, indent=2))
        return
    if cmd == 'vault':
        out = {'decision': 'ok', **vault.summary(), 'policy': vault.policy}
        if '--btc-rpc' in args:
            import btc_vault
            node = btc_vault.Node(option(args, '--btc-rpc'), option(args, '--btc-cookie'), vault.network)
            node.check_network()
            got = node.tx(vault.anchor[0])
            if got is None or got['confirmations'] < 1 or vault.anchor[1] >= len(got['tx'].outputs) \
                    or got['tx'].outputs[vault.anchor[1]][1] != vault.thread_spk:
                refuse('the anchor is not a confirmed output paying the thread script')
            out['anchor_check'] = {'confirmations': got['confirmations'], 'sats': got['tx'].outputs[vault.anchor[1]][0],
                                   'unspent': node.unspent(*vault.anchor) is not None}
        print(json.dumps(out, indent=2))
        return
    raise SystemExit(__doc__)


if __name__ == '__main__':
    main()
