#!/usr/bin/env python3
"""Every bridge route of the tree, for the deploy tool (integration of the six bridge lines, agent 355, round 17).

  deploy_pontes.py routes                       one line per route: launch status, L2 token, config, how it is deployed
  deploy_pontes.py route NETWORK COMMAND ...    COMMAND of that route's deployment path, with its committed config

One tool deploys the L2 token of every route; the L2 token is always the frozen BridgedStablecoinV3.

  ethereum                        deploy_pontes.py itself, exactly as at the freeze (source chain id 1)
  arbitrum-one, op-mainnet, linea deploy_pontes.py; the source chain id is accepted from the EVM launch registry
                                  (tools/evm-nets/launch.py + networks.json), under that network's token name only
  base, bnb                       refused: not launchable in v1 (the registry's reason is printed); no flag lifts it
  tron                            deploy_pontes.py; the config's `ethereum` section describes the TRON vault and the
                                  source chain id is accepted from DATA (`source_refusal` below); `--source-rpc` is the
                                  operator's tools/signatario-tron/tron_rpc_shim.py
  stellar                         deploy_pontes.py; a `stellar` section takes tools/deploy-pontes/source_stellar.py
  solana                          tools/signatario-solana/sol_deploy_token.py (translate, source, then deploy_pontes'
                                  own validate / plan / run / record / verify over the Solana vault's accounts)
  bitcoin                         tools/signatario-btc/btc_deploy.py (token, verify): it derives the constructor
                                  arguments from the vault policy and prints the creation data; it has no
                                  plan / run / record of its own (gap listed in docs/BRIDGE-ALLNETS.md)

`source_refusal` is the single data-driven rule proposed by agent 323 (cross-area log, 2026-11-16 21:05 UTC): a source
chain id that is neither 1 nor an EVM registry network is accepted only when exactly one
`deployments/<network>/bridge.network.json` (a) passes the schema check, (b) is of a kind whose vault is read through the
Ethereum-shaped `ethereum` section (`tvm`), (c) has `network.chainId` equal to the id as a decimal string, (d) names the
config's token name and symbol in `l2`, and (e) does not say `launch.v1: false`. An `evm` network is never opened by
data: only the launch registry opens one (so a hand-written file cannot open Base or BNB Smart Chain).
Standard library only. UNAUDITED tooling.
"""
import json
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
DEPLOYMENTS = ROOT / 'deployments'
# Kinds whose L2 token config uses deploy_pontes' own `ethereum` section for a non-Ethereum source vault.
DATA_KINDS = ('tvm',)
COMMANDS = ('validate', 'plan', 'run', 'record', 'verify')

# network id -> how its L2 token is deployed. `path`: native = deploy_pontes.py itself; adapter = a route tool.
ROUTES = {
    'ethereum': {'path': 'native', 'config': 'deployments/mainnet/busdc-mainnet.config.json',
                 'sourceRpc': 'own Ethereum node', 'doc': 'docs/BUSDC-MAINNET-V2.md'},
    'arbitrum-one': {'path': 'native', 'config': 'deployments/arbitrum-one/busdc-token.config.json',
                     'sourceRpc': 'own Arbitrum One node', 'doc': 'docs/BRIDGE-EVM-NETWORKS.md'},
    'op-mainnet': {'path': 'native', 'config': 'deployments/op-mainnet/busdc-token.config.json',
                   'sourceRpc': 'own OP Mainnet node', 'doc': 'docs/BRIDGE-EVM-NETWORKS.md'},
    'linea': {'path': 'native', 'config': 'deployments/linea/busdc-token.config.json',
              'sourceRpc': 'own Linea node', 'doc': 'docs/BRIDGE-EVM-NETWORKS.md'},
    'base': {'path': 'refused', 'doc': 'docs/BRIDGE-EVM-NETWORKS.md'},
    'bnb': {'path': 'refused', 'doc': 'docs/BRIDGE-EVM-NETWORKS.md'},
    'tron': {'path': 'native', 'config': 'deployments/tron/busdt-trx-token.config.json',
             'sourceRpc': 'tools/signatario-tron/tron_rpc_shim.py over the operator\'s own java-tron node',
             'doc': 'docs/BRIDGE-TRON-USDT.md'},
    'stellar': {'path': 'native', 'config': 'deployments/stellar/busdc-xlm-token.config.json',
                'sourceRpc': 'own Stellar RPC', 'doc': 'docs/STELLAR-BRIDGE-DEPLOY.md'},
    'solana': {'path': 'adapter', 'tool': 'tools/signatario-solana/sol_deploy_token.py',
               'config': 'deployments/solana/busdc-sol-token.config.json',
               'vaultConfig': 'deployments/solana/busdc-sol-vault.config.json',
               'commands': ('translate', 'source') + COMMANDS, 'sourceRpc': 'own Solana RPC',
               'doc': 'docs/SOLANA-BRIDGE-DEPLOY-CEREMONY.md'},
    'bitcoin': {'path': 'adapter', 'tool': 'tools/signatario-btc/btc_deploy.py',
                'config': 'deployments/bitcoin/bbtc-token-mainnet.config.json',
                'vaultConfig': 'deployments/bitcoin/bbtc-vault-mainnet.config.json',
                'commands': ('keys', 'message', 'thread', 'vault', 'address', 'token', 'verify', 'router', 'router-verify'),
                'sourceRpc': 'own bitcoind', 'doc': 'docs/BTC-BRIDGE-DEPLOYMENT.md'},
}


EVM_NETS = HERE.parent / 'evm-nets'  # the tools of this tree, whatever ROOT a test points the data at


def _checker():
    if str(EVM_NETS) not in sys.path:
        sys.path.insert(0, str(EVM_NETS))
    import network_json
    return network_json


def _launch():
    if str(EVM_NETS) not in sys.path:
        sys.path.insert(0, str(EVM_NETS))
    import launch
    return launch


def network_files():
    """{network id: (path, document or None, [errors])} of every deployments/<network>/bridge.network.json."""
    out = {}
    check = _checker().check
    for path in sorted(DEPLOYMENTS.glob('*/bridge.network.json')):
        try:
            found, doc = check(path), json.loads(path.read_text())
        except (OSError, ValueError) as e:
            found, doc = [f'{type(e).__name__}: {e}'], None
        out[path.parent.name] = (path, doc, found)
    return out


def source_refusal(chain_id, name, symbol):
    """None when a non-Ethereum, non-EVM-registry source chain id may be the source of a mainnet token named
    (name, symbol); otherwise the reason. See the module text for the rule."""
    want = str(int(chain_id))
    looked, matches = [], []
    for net, (path, doc, found) in network_files().items():
        rel = path.relative_to(ROOT)
        if doc is None or not isinstance(doc.get('network'), dict) or str(doc['network'].get('chainId')) != want:
            continue
        looked.append(str(rel))
        if found:
            return f'{rel} names source chain {want} but fails the schema check: {found[0]}'
        if doc['network'].get('kind') not in DATA_KINDS:
            return (f'{rel} names source chain {want}, but a network of kind {doc["network"].get("kind")!r} is not opened by a '
                    'data file (an EVM network is opened only by the launch registry of tools/evm-nets)')
        if isinstance(doc.get('launch'), dict) and doc['launch'].get('v1') is False:
            return f'{rel}: this route is not launchable in v1 ({doc["launch"].get("state")}): {doc["launch"].get("reason")}'
        if (doc['l2'].get('name'), doc['l2'].get('symbol')) != (name, symbol):
            return (f'the L2 token of source chain {want} is {doc["l2"].get("symbol")} ("{doc["l2"].get("name")}"), one token per '
                    f'network ({rel}); the config names {symbol} ("{name}")')
        matches.append(net)
    if len(matches) == 1:
        return None
    if matches:
        return f'source chain {want} is named by more than one route: {sorted(matches)}'
    return (f'source chain {want} is not the source of any route: no deployments/<network>/bridge.network.json has '
            f'network.chainId "{want}"')


def status(net):
    """(state, reason) of a route: launchable | held | out | undeclared, from the EVM launch registry for the EVM
    networks and from the file's own `launch` block otherwise; Ethereum is launchable (the frozen bridge)."""
    if net == 'ethereum':
        return 'launchable', 'the Ethereum bridge (bUSDC V3), freeze cc2511a'
    files = network_files()
    doc = files[net][1] if net in files else None
    if doc and doc['network'].get('kind') == 'evm':
        launch = _launch()
        try:
            spec = launch.registry()['networks'].get(net)
        except launch.LaunchError as e:
            return 'held', f'the launch registry cannot be trusted: {e}'
        if spec is None:
            return 'out', 'an EVM network that the launch registry does not name'
        return spec['launch']['state'], spec['launch']['reason']
    if doc and isinstance(doc.get('launch'), dict):
        return doc['launch']['state'], doc['launch']['reason']
    return 'undeclared', 'the route\'s bridge.network.json carries no `launch` block'


def table():
    rows = []
    files = network_files()
    for net, how in ROUTES.items():
        doc = files[net][1] if net in files else None
        state, reason = status(net)
        if net == 'ethereum':
            symbol = json.loads((ROOT / how['config']).read_text())['token']['symbol']
        else:
            symbol = doc['l2']['symbol'] if doc else None
        rows.append({'network': net, 'l2Symbol': symbol, 'launch': state, 'reason': reason, 'path': how['path'],
                     'tool': how.get('tool', 'tools/deploy-pontes/deploy_pontes.py') if how['path'] != 'refused' else None,
                     'config': how.get('config'), 'vaultConfig': how.get('vaultConfig'), 'sourceRpc': how.get('sourceRpc'),
                     'commands': list(how.get('commands', COMMANDS)) if how['path'] != 'refused' else [],
                     'document': how['doc']})
    extra = sorted(set(files) - set(ROUTES))
    return rows, extra


def cli(argv, dp):
    """`routes` and `route NETWORK COMMAND ...`. `dp` is the deploy_pontes module that was started."""
    if argv[0] == 'routes':
        rows, extra = table()
        dp.refuse(not extra, f'deployments/ holds routes this tool does not know: {extra}')
        return {'decision': 'routes', 'routes': rows}
    dp.refuse(len(argv) >= 3, 'usage: deploy_pontes.py route NETWORK COMMAND [arguments]')
    net, command, rest = argv[1], argv[2], argv[3:]
    dp.refuse(net in ROUTES, f'unknown route {net}; routes: {sorted(ROUTES)}')
    how = ROUTES[net]
    state, reason = status(net)
    dp.refuse(how['path'] != 'refused' and state not in ('held', 'out'), f'route {net} is not launchable in v1 ({state}): {reason}')
    dp.refuse(command in how.get('commands', COMMANDS), f'route {net} has the commands {list(how.get("commands", COMMANDS))}')
    if how['path'] == 'native':
        if '--config' not in rest:
            rest = ['--config', str(ROOT / how['config']), *rest]
        return dp.main([command, *rest])
    # An adapter runs as its own process: its output and exit code are the result, unchanged.
    tool = ROOT / how['tool']
    if net == 'solana':
        if '--vault-config' not in rest:
            rest = ['--vault-config', str(ROOT / how['vaultConfig']), *rest]
        if command == 'translate' and '--token-config' not in rest:
            rest = ['--token-config', str(ROOT / how['config']), *rest]
        args = [command, *rest] if command in ('translate', 'source') else ['pontes', command, *rest]
    else:
        if command in ('thread', 'vault', 'address', 'token', 'verify', 'router', 'router-verify') and '--config' not in rest:
            rest = ['--config', str(ROOT / how['vaultConfig']), *rest]
        if command in ('token', 'verify') and '--token-config' not in rest:
            rest = ['--token-config', str(ROOT / how['config']), *rest]
        args = [command, *rest]
    done = subprocess.run([sys.executable, str(tool), *args])
    raise SystemExit(done.returncode)
