#!/usr/bin/env python3
"""Reserves monitor for the Stellar route: the vault's books against the asset it really holds, against the L2 token's
supply, and against the issuer's powers and the ledger's rent. Read-only; no key.

  reservas_stellar.py --config R.json check

Exit 0: ok. Exit 2: at least one hard alert (print and page). Findings:
  shortfall      the vault's balance is below (total_locked + fees_accrued) * 10 stroops: the asset left the vault from
                 outside its code (an issuer clawback). Deposits, releases and the sweep already fail on-chain; the L2
                 token is under-backed by the difference and its guardians should pause it.
  frozen         the vault's balance entry is not authorized (the issuer revoked it): no transfer in or out works.
  clawback-on    the vault's balance entry carries the clawback flag (set when the entry was created under an issuer
                 with clawback enabled; it never changes afterwards). A warning, reported once per run.
  oversupply     the L2 token's totalSupply + pendingSupply exceeds the vault's total_locked: a mint without a deposit.
  rent           the vault instance, its Wasm, or its balance entry in the asset contract lives fewer than
                 `min_ttl_ledgers` more ledgers (default 259,200, about 15 days): extend it (anyone can).
  archived       one of those entries is already archived: the vault cannot be called until it is restored.
  paused / closed   informational.

  wrong-asset    the vault's asset contract is not the pinned one (`asset_contract`, required).
Config: `stellar_rpc`, `network_passphrase`, `vault`, `view_account`, `asset_contract`; optional `l2_rpc` + `token`
(read over JSON-RPC in this process), `min_ttl_ledgers`, `stellar_cli`.
"""
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import stellar_net as sn  # noqa: E402


def check(cfg):
    net = sn.Net(cfg)
    alerts, warnings, info = [], [], {}
    latest = net.latest()
    min_ttl = int(cfg.get('min_ttl_ledgers', 259200))
    try:
        wasm, live_until, _ = net.wasm_hash()
    except sn.StellarError as e:
        return {'ok': False, 'alerts': [{'kind': 'archived', 'what': 'vault instance', 'detail': str(e)}],
                'warnings': [], 'info': {'latest': latest}}
    info['wasm'] = wasm
    code_key = {'contract_code': {'hash': wasm}}
    config = net.view('config')
    pinned = cfg.get('asset_contract')
    if pinned is None or config['token'] != pinned:
        # Without the pin the monitor would measure whatever asset the vault names; with another asset it is an alert.
        return {'ok': False, 'alerts': [{'kind': 'wrong-asset', 'vault': config['token'], 'pinned': pinned,
                                         'detail': 'the vault\'s asset contract is not the one pinned in `asset_contract`'}],
                'warnings': [], 'info': {'latest': latest}}
    state = net.view('state')
    backing = net.view('backing')
    balance_key = net.data_key({'vec': [{'symbol': 'Balance'}, {'address': net.vault}]}, config['token'])
    _, (code, bal) = net.entries([code_key, balance_key])
    ttls = {'instance': live_until, 'wasm': code and code.get('liveUntilLedgerSeq'),
            'balance': bal and bal.get('liveUntilLedgerSeq')}
    for what, until in ttls.items():
        if until is None:
            if what != 'balance' or int(state['deposit_count']):
                alerts.append({'kind': 'archived', 'what': what})
        elif int(until) < latest['sequence']:
            alerts.append({'kind': 'archived', 'what': what, 'live_until': until})
        elif int(until) - latest['sequence'] < min_ttl:
            warnings.append({'kind': 'rent', 'what': what, 'ledgers_left': int(until) - latest['sequence']})
    info.update(ttl={k: (v and int(v) - latest['sequence']) for k, v in ttls.items()}, latest=latest['sequence'],
                total_locked=int(state['total_locked']), fees_accrued=int(state['fees_accrued']),
                deposit_count=int(state['deposit_count']), balance=int(backing['balance']),
                required=int(backing['required']))
    if int(backing['balance']) < int(backing['required']):
        alerts.append({'kind': 'shortfall', 'balance': int(backing['balance']), 'required': int(backing['required']),
                       'missing_stroops': int(backing['required']) - int(backing['balance'])})
    if bal is not None:
        value = sn.scval(bal['dataJson']['contract_data']['val'])
        info['balance_entry'] = value
        if value.get('authorized') is False:
            alerts.append({'kind': 'frozen', 'detail': 'the issuer revoked the vault\'s authorization'})
        if value.get('clawback') is True:
            warnings.append({'kind': 'clawback-on', 'detail': 'the vault\'s balance can be clawed back by the issuer'})
    if latest['close_time'] < int(state['paused_until']):
        warnings.append({'kind': 'paused', 'until': int(state['paused_until'])})
    if not state['deposits_enabled'] or not state['releases_enabled']:
        warnings.append({'kind': 'closed', 'deposits': state['deposits_enabled'], 'releases': state['releases_enabled']})
    if cfg.get('l2_rpc') and cfg.get('token'):
        l2 = sn.L2(cfg['l2_rpc'])
        head = l2.block('latest')

        def call(sig):
            return l2.call_word(cfg['token'], sn.selector(sig.split(')')[0] + ')'), head['number'])

        supply, pending = call('totalSupply()(uint256)'), call('pendingSupply()(uint256)')
        info.update(l2_supply=supply, l2_pending=pending)
        if supply + pending > int(state['total_locked']):
            alerts.append({'kind': 'oversupply', 'l2_supply': supply, 'l2_pending': pending,
                           'total_locked': int(state['total_locked'])})
    return {'ok': not alerts, 'alerts': alerts, 'warnings': warnings, 'info': info}


def main():
    argv = sys.argv[1:]
    if 'check' not in argv or '--config' not in argv:
        raise SystemExit(__doc__)
    cfg = json.loads(Path(argv[argv.index('--config') + 1]).read_text())
    try:
        result = check(cfg)
    except sn.StellarError as e:
        result = {'ok': False, 'alerts': [{'kind': 'unreadable', 'detail': str(e)[-600:]}], 'warnings': [], 'info': {}}
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result['ok'] else 2)


if __name__ == '__main__':
    main()
