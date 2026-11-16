#!/usr/bin/env python3
"""Deployment path of the L2 token of the Solana bridge (`bUSDC.sol`): tools/deploy-pontes/deploy_pontes.py,
unchanged, over a Solana source vault.

  sol_deploy_token.py translate --token-config T --vault-config V [--program-id ID] --write PONTES.json
  sol_deploy_token.py source  --config PONTES.json --vault-config V [--program-id ID] --source-rpc SOLANA_URL
  sol_deploy_token.py pontes <validate|plan|run|record|verify> --vault-config V [--program-id ID]
                             <the arguments of deploy_pontes.py, with --config PONTES.json>

`source` is the read-only source check alone (pins, and deploy_pontes' own "the vault was never used" rule), for
the owner to run before the plan; `pontes run` repeats it.

deploy_pontes.py is not edited and its behaviour for an Ethereum vault is untouched: this file imports it and,
for the duration of one command in this process only, replaces two things.

  1. Its source-chain reader. `--source-rpc` names this operator's own Solana RPC; every question deploy_pontes
     asks an Ethereum vault is answered from the Solana vault's accounts, after the same pins the signers apply
     (cluster genesis hash, program owned by the upgradeable loader with NO upgrade authority and equal to the
     pinned ELF, vault at the address the configuration derives and equal to the file):
       chain id            the 256-bit source chain id of the cluster
       code hash           keccak256 of the 32-byte sha256 of the program image on chain (`ethereum.vaultCodeHash`
                           in the translated config is keccak256 of `program.elfSha256`)
       depositCount, totalLocked, controlNonce   the vault state: `run` refuses a vault that was ever used
       routeId, cap, guardians, pauseDuration, pauseCooldown   the vault's immutable configuration
       provenanceMode      1 (the Solana vault always checks the mint chain)
       chainHeadAt(n)      the vault's deposit chain after n deposits (genesis, or the head in record n - 1)
     `latest` reads are at `confirmed`, `finalized` reads at `finalized`.
  2. Its policy constant "the source chain of a mainnet token is Ethereum (1)" becomes "is Solana mainnet-beta"
     (the chain id derived from genesis hash 5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d).

`translate` writes the deploy_pontes config from the two reviewed files of deployments/solana: the token file
(names, signers, guardians, limits, deployer, network) and the vault file (the source side, derived, never
typed). It refuses undecided values and any `solana.*` value of the token file that differs from what the vault
file derives. Every other rule (5-of-7, 6-of-7 switch, 3 guardians, T = 0, the legacy-address list, the
deterministic plan, one signed creation, record, verify at `finalized`) is deploy_pontes' own code.

Not covered here: the SolanaRecipientRegistry (a contract without constructor arguments or roles; deploy it with
`forge create` and record its address), and Solana operator templates (deploy_pontes checks the committed
Ethereum bridge templates on chain 700770; they are not this bridge's). UNAUDITED tooling.
"""
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / 'deploy-pontes'))
import solana_lib as S  # noqa: E402
from sol_half import Node, elf_digest  # noqa: E402
import deploy_pontes as P  # noqa: E402

MAINNET_GENESIS = '5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d'
UNDECIDED = (None, 'TBD-owner', 'TBD-deploy')


def opt(args, name, default=None):
    return args[args.index(name) + 1] if name in args[:-1] else default


def without(args, name):
    i = args.index(name)
    return args[:i] + args[i + 2:]


def vault_identity(vault_path, program_id=None):
    doc = json.loads(Path(vault_path).read_text())
    config = S.Config.from_json(doc)
    program_id = program_id or (doc.get('program') or {}).get('id')
    pin = (doc.get('program') or {}).get('elfSha256')
    P.refuse(program_id not in UNDECIDED and pin not in UNDECIDED, 'the vault file has no program.id or program.elfSha256 yet')
    P.refuse(len(pin) == 64, 'program.elfSha256 is not a sha256')
    a = S.Addresses(S.pubkey(program_id), config)
    return doc, config, a, pin.lower()


def code_hash_of(pin):
    return S.hx(S.keccak256(bytes.fromhex(pin)))


def translate(token_path, vault_path, program_id=None):
    token = json.loads(Path(token_path).read_text())
    doc, config, a, pin = vault_identity(vault_path, program_id)
    P.refuse(token.get('domain') == 'bloch.bridge.solana-token-deploy.v1' and token.get('bridge') == 'stable',
             'not a Solana token deployment file')
    tok = dict(token['token'])
    P.refuse(tok.pop('decimals', 6) == 6, 'the token has 6 decimals (fixed in BridgedStablecoinV3)')
    chain_id = int.from_bytes(config.source_chain_id, 'big')
    derived = {'genesisHash': doc['solana']['genesisHash'], 'sourceChainId': str(chain_id),
               'sourceChainIdHex': S.hx(config.source_chain_id), 'programId': S.b58encode(a.program_id),
               'vaultAddress': S.b58encode(a.vault), 'vault20': S.hx(a.vault20), 'route': S.hx(a.route),
               'vaultCap': config.cap}
    guardians = [S.hx(g) for g in config.guardians]
    sol = token.get('solana') or {}
    for key, want in derived.items():
        got = sol.get(key)
        P.refuse(got in UNDECIDED or str(got).lower() == str(want).lower(),
                 f'solana.{key} in the token file is {got}, the vault file derives {want}')
    guard = sol.get('vaultGuard') or {}
    P.refuse(guard.get('guardians') in UNDECIDED or [str(g).lower() for g in guard['guardians']] == guardians,
             'solana.vaultGuard.guardians differ from the vault file')
    for key, want in (('pauseDuration', config.pause_duration), ('pauseCooldown', config.pause_cooldown)):
        P.refuse(guard.get(key) in (None, want), f'solana.vaultGuard.{key} differs from the vault file')
    limits = token['limits']
    for ours, theirs in (('cap', 'supplyCap'), ('window_limit', 'bucketCapacity'), ('l2_min_burn', 'minBurn')):
        P.refuse(limits.get(theirs) == getattr(config, ours),
                 f'token limits.{theirs} {limits.get(theirs)} differs from the vault {ours} {getattr(config, ours)}')
    notes = {k: v for k, v in (token.get('notes') or {}).items() if isinstance(v, str)}
    notes['sourceSide'] = ('Solana vault. In this file `ethereum` is the Solana source: chainId is the 256-bit source chain id, '
                           'vault the 20-byte vault id, vaultCodeHash keccak256 of the 32-byte sha256 ELF pin. Generated by '
                           'tools/signatario-solana/sol_deploy_token.py translate; use it only through `sol_deploy_token.py pontes`')
    return {'domain': P.DOMAIN, 'bridge': 'stable', 'notes': notes, 'network': token['network'], 'source': token['source'],
            'deployer': token['deployer'], 'token': tok, 'signers': token['signers'], 'guardians': token['guardians'],
            'limits': limits, 'tx': token['tx'], 'mintSwitch': token['mintSwitch'],
            'ethereum': {'chainId': chain_id, 'vault': S.hx(a.vault20), 'route': S.hx(a.route), 'vaultCodeHash': code_hash_of(pin),
                         'vaultCap': config.cap,
                         'vaultGuard': {'guardians': guardians, 'pauseDuration': config.pause_duration,
                                        'pauseCooldown': config.pause_cooldown}}}


class SolanaVaultView:
    """What deploy_pontes reads from an Ethereum vault, answered from the Solana vault's accounts (see the header)."""

    def __init__(self, url, vault_path, program_id=None):
        self.cfg = {'sol_rpc': url, 'vault_config': str(vault_path), 'program_id': program_id}
        self.nodes = {}

    def node(self, tag):
        commitment = 'finalized' if tag == 'finalized' else 'confirmed'
        P.refuse(tag in ('finalized', 'latest'), f'unsupported block tag {tag} for the Solana source')
        if commitment not in self.nodes:
            try:
                self.nodes[commitment] = Node(self.cfg, commitment=commitment)
            except S.Refused as e:
                raise P.Refused(f'Solana source: {e.reason} {e.detail}')
            except S.RpcError as e:
                raise P.Refused(f'Solana RPC unreachable or failing: {e}')
        return self.nodes[commitment]

    def guarded(self, read):
        try:
            return read()
        except S.Refused as e:
            raise P.Refused(f'Solana source: {e.reason} {e.detail}')
        except S.RpcError as e:
            raise P.Refused(f'Solana RPC unreachable or failing: {e}')

    def __call__(self, method, params):
        if method == 'eth_chainId':
            return hex(int.from_bytes(self.node('latest').config.source_chain_id, 'big'))
        if method == 'eth_getCode':
            n = self.node(params[1])
            P.refuse(str(params[0]).lower() == S.hx(n.a.vault20), 'the plan names another vault than the vault file')
            _, _, data = self.guarded(lambda: n.account(n.a.program_data))
            return '0x' + elf_digest(data[45:])  # Node already refused an upgrade authority and another image
        raise P.Refused(f'the Solana source does not answer {method}')

    def call(self, to, sig, *args, block='latest', returns=None):
        n = self.node(block)
        P.refuse(str(to).lower() == S.hx(n.a.vault20), 'the plan names another vault than the vault file')
        v, c = n.vault, n.config
        fixed = {'depositCount()': v['deposit_count'], 'totalLocked()': v['total_locked'], 'controlNonce()': v['control_nonce'],
                 'routeId()': S.hx(n.a.route), 'cap()': c.cap, 'guardianCount()': len(c.guardians),
                 'pauseDuration()': c.pause_duration, 'pauseCooldown()': c.pause_cooldown, 'provenanceMode()': 1}
        if sig in fixed:
            value = fixed[sig]
        elif sig == 'guardians(uint256)':
            value = S.hx(c.guardians[int(args[0])])
        elif sig == 'chainHeadAt(uint64)':
            count = int(args[0])
            P.refuse(count <= v['deposit_count'], f'the token credited {count} mints, the vault has {v["deposit_count"]} deposits')
            record = self.guarded(lambda: n.deposit(count - 1)) if count else None
            P.refuse(count == 0 or record is not None, f'deposit record {count - 1} is absent at {block}')
            value = S.hx(record['head_after'] if count else n.a.genesis)
        else:
            raise P.Refused(f'the Solana source does not answer {sig}')
        return json.dumps([value])

    def summary(self):
        n = self.node('finalized')
        return {'cluster': n.doc['solana'].get('cluster'), 'genesisHash': n.doc['solana']['genesisHash'],
                'programId': S.b58encode(n.a.program_id), 'programUpgradeAuthority': None, 'programElfSha256': n.elf_pin,
                'vault': S.b58encode(n.a.vault), 'vault20': S.hx(n.a.vault20), 'contextSlot': n.vault['context_slot'],
                'depositCount': n.vault['deposit_count'], 'depositsEnabled': n.vault['deposits_enabled'],
                'releasesEnabled': n.vault['releases_enabled']}


def pontes(argv):
    vault_path = opt(argv, '--vault-config')
    P.refuse(vault_path, '--vault-config is required')
    program_id = opt(argv, '--program-id')
    argv = without(argv, '--vault-config')
    if program_id:
        argv = without(argv, '--program-id')
    command = argv[0] if argv else None
    cfg_path = opt(argv, '--config')
    P.refuse(cfg_path, '--config is required (the file written by translate)')
    cfg = json.loads(Path(cfg_path).read_text())
    doc, config, a, pin = vault_identity(vault_path, program_id)
    eth = cfg.get('ethereum') or {}
    want = (int.from_bytes(config.source_chain_id, 'big'), S.hx(a.vault20), S.hx(a.route), code_hash_of(pin))
    P.refuse((eth.get('chainId'), str(eth.get('vault')).lower(), str(eth.get('route')).lower(),
              str(eth.get('vaultCodeHash')).lower()) == want,
             'the config was not translated from this vault file (chain id, vault id, route or program pin differ)')
    rehearsal = bool(cfg.get('network', {}).get('rehearsal'))
    P.refuse(rehearsal == bool(doc['solana'].get('rehearsal')), 'one file is a rehearsal and the other is not')
    P.refuse(rehearsal or doc['solana']['genesisHash'] == MAINNET_GENESIS, 'a mainnet token needs the mainnet-beta vault file')
    source_url = opt(argv, '--source-rpc')
    P.refuse(command not in ('run', 'verify', 'source') or source_url, 'pass --source-rpc (this operator\'s own Solana RPC)')
    view = SolanaVaultView(source_url, vault_path, program_id) if source_url else None
    ethereum_rpc, ethereum_policy = P.Rpc, P.ETH_MAINNET
    P.Rpc = lambda url: view if view is not None and url == source_url else ethereum_rpc(url)
    P.ETH_MAINNET = int.from_bytes(S.chain_id_of(S.b58decode(MAINNET_GENESIS, 32)), 'big')
    try:
        if command == 'source':
            P.validate(cfg, rehearsal)
            result = {'decision': 'source-ok', **P.unused_vault({'sourceVault': {
                'chainId': eth['chainId'], 'address': eth['vault'].lower(), 'codeHash': eth['vaultCodeHash'].lower()}}, source_url)}
        else:
            result = P.main(argv)
    finally:
        P.Rpc, P.ETH_MAINNET = ethereum_rpc, ethereum_policy
    if view is not None and command in ('run', 'verify', 'source'):
        result['solanaSource'] = view.summary()
    return result


def main(argv):
    if not argv or argv[0] in ('-h', '--help'):
        raise SystemExit(__doc__)
    if argv[0] == 'translate':
        out = translate(opt(argv, '--token-config'), opt(argv, '--vault-config'), opt(argv, '--program-id'))
        write = opt(argv, '--write')
        if write:
            P.write_new(write, out)
        return {'decision': 'translated', 'configSha256': P.config_sha256(out), 'written': write, 'ethereum': out['ethereum']}
    if argv[0] == 'source':
        return pontes(argv)
    if argv[0] == 'pontes':
        return pontes(argv[1:])
    raise SystemExit(__doc__)


if __name__ == '__main__':
    try:
        print(json.dumps(main(sys.argv[1:]), indent=2))
    except (P.Refused, S.Refused) as e:
        print(json.dumps({'decision': 'refused', 'reason': str(e), **getattr(e, 'detail', {})}, default=str, indent=2))
        raise SystemExit(1)
    except (OSError, ValueError, KeyError, TypeError) as e:  # fail closed, with a reason
        print(json.dumps({'decision': 'refused', 'reason': f'{type(e).__name__}: {e}'}, indent=2))
        raise SystemExit(1)
