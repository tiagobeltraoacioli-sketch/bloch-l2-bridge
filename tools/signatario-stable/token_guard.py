#!/usr/bin/env python3
"""The token guard of a bridge route: is the asset contract still in the state the route pins? (round 20)

A stablecoin is somebody else's contract. Its issuer or its admin can switch on a transfer fee, pause it, replace it,
upgrade the code behind a proxy or block the vault. The vault refuses what it can see (it never credits more than it
received); the SIGNERS must stop minting as soon as the token is no longer the contract that was reviewed, because a
deposit attested after such a change is backed by a token nobody examined. So, before attesting a deposit, each signer
reads at its own finalized block:

  codes   keccak256 of the code at an address              (the token; behind a proxy, the implementation too)
  slots   a storage slot of an address                      (EIP-1967 implementation and admin)
  calls   one ABI word answered by a zero- or one-argument getter, the one argument being the route's vault
          (fee rate and ceiling zero, not paused, not deprecated, the vault not blocked, owner and minter unchanged)

and attests nothing while any of them differs or cannot be read (a revert, a short or long answer and an RPC error
are differences: the guard fails closed). The pins of a route are in tools/evm-nets/asset-routes.json (`guard`);
tools/signatario-stable/eth_half.py applies them in `deposit`. Releases are NOT gated here: an exit that the token
refuses reverts in the token with no state change and is paid when the token allows it again, and an exit must not be
stopped by a monitor.

  token_guard.py check --rpc URL --guard GUARD.json --vault ADDRESS [--block finalized]

Standard library only, plus `cast keccak` for the code hash (FOUNDRY_BIN or ~/.foundry/bin). Reads only.
"""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import urllib.request

HEX = re.compile(r'0x[0-9a-fA-F]*\Z')


def _addr(value):
    v = str(value).lower()
    if not (HEX.match(v) and len(v) == 42):
        raise ValueError(f'not a 20-byte address: {str(value)[:50]!r}')
    return v


def check(rpc, keccak, guard, vault, block):
    """Differences between the token's state at `block` and the route's pins: [] when the token is as reviewed.

    rpc(method, params) -> result, raising on a transport or RPC error; keccak(hex) -> hex. `block` is a tag or a
    block number as the caller's node takes it. Every failure to read is a difference."""
    vault = _addr(vault)
    ref = hex(block) if isinstance(block, int) else block
    found = []

    def differ(kind, what, where, got, want):
        found.append({'kind': kind, 'what': what, 'where': where, 'got': got, 'pinned': want})

    for pin in guard['codes']:
        try:
            code = rpc('eth_getCode', [_addr(pin['address']), ref])
            got = keccak(code).lower() if isinstance(code, str) and HEX.match(code) and len(code) > 2 else 'no code'
        except Exception as e:  # noqa: BLE001  (fail closed on anything)
            got = f'unreadable: {type(e).__name__}: {str(e)[:120]}'
        if got != pin['keccak'].lower():
            differ('code', pin['what'], pin['address'], got, pin['keccak'].lower())
    for pin in guard['slots']:
        try:
            got = str(rpc('eth_getStorageAt', [_addr(pin['address']), pin['slot'], ref])).lower()
            got = '0x' + got[2:].rjust(64, '0') if HEX.match(got) else got
        except Exception as e:  # noqa: BLE001
            got = f'unreadable: {type(e).__name__}: {str(e)[:120]}'
        if got != pin['value'].lower():
            differ('slot', pin['what'], f'{pin["address"]} slot {pin["slot"]}', got, pin['value'].lower())
    for pin in guard['calls']:
        data = pin['selector'] + (vault[2:].rjust(64, '0') if pin['arg'] == 'vault' else '')
        try:
            out = str(rpc('eth_call', [{'to': _addr(pin['to']), 'data': data}, ref])).lower()
            got = hex(int(out, 16)) if HEX.match(out) and len(out) == 66 else f'not one ABI word: {out[:80]}'
        except Exception as e:  # noqa: BLE001
            got = f'unreadable: {type(e).__name__}: {str(e)[:120]}'
        if got != hex(int(pin['word'], 16)):
            differ('call', pin['what'], f'{pin["to"]} {pin["sig"]}', got, hex(int(pin['word'], 16)))
    return found


def url_rpc(url, timeout=60):
    def rpc(method, params):
        body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode()
        with urllib.request.urlopen(urllib.request.Request(url, body, {'content-type': 'application/json'}), timeout=timeout) as r:
            out = json.loads(r.read())
        if 'error' in out:
            raise RuntimeError(f'{method}: {out["error"]}')
        return out['result']
    return rpc


def cast_keccak(cast=None):
    cast = cast or str(Path(os.environ.get('FOUNDRY_BIN', Path.home() / '.foundry/bin')) / 'cast')

    def keccak(hexdata):
        if not isinstance(hexdata, str) or not re.fullmatch(r'0x(?:[0-9a-fA-F]{2})*', hexdata):
            raise ValueError('code to hash is not 0x-prefixed hex')  # never an option of `cast` (agent 374's class)
        return subprocess.run([cast, 'keccak', hexdata], capture_output=True, text=True, check=True).stdout.strip().lower()
    return keccak


def check_url(url, guard, vault, block='finalized', cast=None):
    return check(url_rpc(url), cast_keccak(cast), guard, vault, block)


def main(argv):
    opt = lambda n, d=None: argv[argv.index(n) + 1] if n in argv else d  # noqa: E731
    if not argv or argv[0] != 'check' or not opt('--rpc') or not opt('--guard') or not opt('--vault'):
        raise SystemExit(__doc__)
    found = check_url(opt('--rpc'), json.loads(Path(opt('--guard')).read_text()), opt('--vault'), opt('--block', 'finalized'))
    print(json.dumps({'decision': 'token-state-differs' if found else 'token-state-pinned', 'differences': found}, indent=2))
    return 1 if found else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
