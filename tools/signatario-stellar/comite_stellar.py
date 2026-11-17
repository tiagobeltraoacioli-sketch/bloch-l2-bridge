#!/usr/bin/env python3
"""Committee acts on the Stellar vault that are not releases: opening or closing deposits and releases
(`set_controls`, `threshold` signers) and ending a guardian pause early (`unpause`, `switch_threshold` signers).
Each signer runs `sign` on its own host against its own Stellar RPC; anyone combines and relays.

  comite_stellar.py --config XLM.json sign controls --deposits true --releases true [--valid-until T] --out PART.json
  comite_stellar.py --config XLM.json sign unpause [--valid-until T] --out PART.json
  comite_stellar.py --config XLM.json combine --sig A.json --sig B.json [...] --out CALL.json

`sign` reads the vault's current control nonce or pause count, computes the digest here, requires it to equal the
vault's own view, and signs it with this signer's keystore. The first signer picks `valid_until` (ledger time +
`valid_seconds`, default 1800); the others pass the same value with `--valid-until`, so the partials share one digest.
Config: as stellar_half.py (`stellar_rpc`, `network_passphrase`, `vault`, `vault_wasm_hash`, `view_account`,
`keystore`, `password_file`).
"""
import json
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import stellar_net as sn  # noqa: E402


def fail(msg, **detail):
    print(json.dumps({'ok': False, 'reason': msg, **detail}, indent=2))
    raise SystemExit(1)


def flag(args, name):
    v = args.get(name)
    if v not in ('true', 'false'):
        fail(f'{name} must be true or false')
    return v == 'true'


def sign(cfg, argv, args):
    net = sn.Net(cfg)
    cast = cfg.get('cast', str(Path.home() / '.foundry/bin/cast'))
    wasm, _, _ = net.wasm_hash()
    if wasm != cfg['vault_wasm_hash'].replace('0x', '').lower():
        fail('the vault runs another Wasm than the pinned one', got=wasm)
    d, c, st, latest = net.view('derived'), net.view('config'), net.view('state'), net.latest()
    given = args.get('--valid-until')
    if given is not None and not str(given).isdigit():
        fail('--valid-until is a ledger time in seconds')
    valid_until = int(given or latest['close_time'] + int(cfg.get('valid_seconds', 1800)))
    if not latest['close_time'] < valid_until <= latest['close_time'] + sn.MAX_VALIDITY:
        fail('valid_until is outside (ledger time, ledger time + 1 day]', valid_until=valid_until)
    if 'controls' in argv:
        deposits, releases = flag(args, '--deposits'), flag(args, '--releases')
        nonce = int(st['control_nonce'])
        digest = sn.control_digest(net.passphrase, net.vault, d['route'], deposits, releases, nonce, valid_until)
        view = net.view('control_digest', deposits=deposits, releases=releases, nonce=nonce, valid_until=valid_until)
        body = {'action': 'controls', 'deposits': deposits, 'releases': releases, 'nonce': nonce}
        required = int(c['threshold'])
    elif 'unpause' in argv:
        if latest['close_time'] >= int(st['paused_until']):
            fail('the vault is not paused')
        count = int(st['pause_count'])
        digest = sn.unpause_digest(net.passphrase, net.vault, d['route'], count, valid_until)
        view = net.view('unpause_digest', pause_count=count, valid_until=valid_until)
        body = {'action': 'unpause', 'pause_count': count}
        required = int(c['switch_threshold'])
    else:
        fail('sign what? controls or unpause')
    if view != digest.hex():
        fail('the digest computed here differs from the vault\'s', local=digest.hex(), vault=view)
    ks = ['--keystore', cfg['keystore'], '--password-file', cfg['password_file']]
    # An Ethereum personal message over the vault's digest (EIP-191; no `--no-hash`).
    # The key stays in the keystore and `cast` signs; what it printed counts only if it is a well-formed signature
    # that recovers, in this process, to one of the vault's signers.
    done = subprocess.run([cast, 'wallet', 'sign'] + ks + ['--', '0x' + digest.hex()], capture_output=True, text=True)
    signature = done.stdout.strip().lower()
    who = sn.recover_personal(digest, signature)
    if done.returncode or who is None or who[2:] not in c['signers']:
        fail('signing failed, or this keystore is not one of the vault\'s signers', signer=who)
    part = {'kind': 'stellar-committee', 'vault': net.vault, **body, 'valid_until': valid_until, 'required': required,
            'digest': digest.hex(), 'signer': who, 'signature': signature}
    Path(args['--out']).write_text(json.dumps(part, indent=2) + '\n')
    print(json.dumps(part, indent=2))


def combine(argv, args):
    parts = [json.loads(Path(argv[i + 1]).read_text()) for i, a in enumerate(argv[:-1]) if a == '--sig']
    same = ('kind', 'vault', 'action', 'valid_until', 'digest', 'required')
    if not parts or any({k: p.get(k) for k in same} != {k: parts[0].get(k) for k in same} for p in parts):
        fail('the partials are for different messages')
    first = parts[0]
    try:
        if first['kind'] != 'stellar-committee' or first['action'] not in ('controls', 'unpause'):
            fail('not partials of a committee act')
        by = {}
        for part in parts:   # every signature is recovered here; a partial that does not recover to its signer is out
            who = sn.recover_personal(bytes.fromhex(part['digest']), part['signature'])
            if who is None or who != str(part['signer']).lower():
                fail('a partial signature does not recover to the signer it names', signer=part.get('signer'))
            by[who] = part['signature'].lower()
        sn.strkey_decode(first['vault'])
    except (KeyError, TypeError, ValueError, sn.StellarError) as e:
        fail('malformed partial', error=str(e))
    if len(by) < first['required']:
        fail(f"need {first['required']} distinct signers, have {len(by)}")
    chosen = sorted(by, key=lambda a: int(a, 16))[:first['required']]
    sigs = [by[a][2:] for a in chosen]
    if first['action'] == 'controls':
        call = {'fn': 'set_controls', 'args': {'deposits': first['deposits'], 'releases': first['releases'],
                                               'nonce': first['nonce'], 'valid_until': first['valid_until'],
                                               'signatures': sigs}}
    else:
        call = {'fn': 'unpause', 'args': {'pause_count': first['pause_count'], 'valid_until': first['valid_until'],
                                          'signatures': sigs}}
    result = {'kind': 'stellar-committee-call', 'to': first['vault'], 'signers': chosen, 'call': call}
    Path(args['--out']).write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


def main():
    argv = sys.argv[1:]
    if not argv or '-h' in argv or '--help' in argv:
        raise SystemExit(__doc__)
    args = {a: argv[i + 1] for i, a in enumerate(argv[:-1]) if a.startswith('--')}
    try:
        if 'combine' in argv:
            combine(argv, args)
        elif 'sign' in argv:
            sign(json.loads(Path(args['--config']).read_text()), argv, args)
        else:
            raise SystemExit(__doc__)
    except sn.StellarError as e:
        fail('the Stellar node could not be read', error=str(e))


if __name__ == '__main__':
    main()
