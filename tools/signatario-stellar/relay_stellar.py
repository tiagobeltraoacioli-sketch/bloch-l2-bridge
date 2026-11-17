#!/usr/bin/env python3
"""Relayer for the Stellar vault: submits calls anyone may submit (a combined release, a queued release that is due,
the fee sweep, committee controls, a guardian's signed pause, an unpause). It holds no bridge key:
only a Stellar account that pays the fee. The certificate inside the call is what the vault checks.

  relay_stellar.py --config RELAY.json submit --call CALL.json [--key NAME]
  relay_stellar.py --config RELAY.json status --key NAME

`CALL.json` is {"call": {"fn": ..., "args": {...}}} (what signatario_stellar.py combine and guardiao_stellar.py write).

Reservation before publication (the rule of tools/signatario-stable/release_submission.py, in Stellar's terms): the
transaction is built and simulated against the relayer's own RPC, signed, and its envelope and hash are written to
the journal BEFORE it is sent. A Stellar transaction is identified by its hash and can be applied at most once (its
sequence number), so resending the journaled envelope is always safe, and a new one is built only when the journaled
one is known dead: applied and failed, or its sequence number consumed by something else. For a release, a new
transaction is never built while the vault counts the burn (`burn_status` 1 queued or 2 paid: done) or counts its
nonce or id for another release (3: refused). A release that a guardian pause voided is open again (0), and its new
certificate, signed under the new pause count, is journaled under its own key.

A call file is data from someone else. Only the six calls anyone may submit are accepted, each with exactly its
argument names (stellar_net.RELAYABLE); every value must be a number, a boolean, a hexadecimal string or a Stellar
address (stellar_net.cli_value), so nothing in it can be read as an option by the `stellar` CLI; a journal key is
letters, digits, `-` and `_` only. What the CLI prints is accepted only as a transaction envelope or a hash.

Config: `stellar_rpc`, `network_passphrase`, `vault`, `relayer` (the G... address that pays), `relayer_identity`
(the `stellar` CLI identity that signs for it), `journal` (directory); optional `stellar_cli`, `stellar_config_dir`.
"""
import json
import os
import re
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import stellar_net as sn  # noqa: E402


KEY = re.compile(r'[A-Za-z0-9_-]{1,80}')


def out(ok, **fields):
    print(json.dumps({'ok': ok, **fields}, indent=2))
    raise SystemExit(0 if ok else 1)


def write_json(path, obj):
    tmp = path.with_suffix('.tmp')
    with open(tmp, 'w') as f:
        f.write(json.dumps(obj, indent=2) + '\n')
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def wait(net, tx_hash, seconds=60):
    deadline = time.time() + seconds
    while True:
        st = net.transaction(tx_hash)
        if st['status'] in ('SUCCESS', 'FAILED') or time.time() > deadline:
            return st
        time.sleep(1)


def submit(cfg, call, key):
    net = sn.Net({**cfg, 'view_account': cfg['relayer']})
    journal = Path(cfg['journal'])
    journal.mkdir(parents=True, exist_ok=True)
    fn, args = call.get('fn'), call.get('args')
    if fn not in sn.RELAYABLE or not isinstance(args, dict) or set(args) != sn.RELAYABLE[fn]:
        out(False, status='REFUSED', error='not a call a relayer submits, or not exactly its arguments')
    try:
        for value in args.values():
            sn.cli_value(value)
        if key is None:
            key = f"release-{int(args['item']['nonce'])}-p{int(args['context']['pause_count'])}" if fn == 'release' \
                else f'{fn}-{int(time.time())}'
    except (sn.StellarError, KeyError, TypeError, ValueError) as e:
        out(False, status='REFUSED', error=f'malformed call: {e}')
    if not isinstance(key, str) or not KEY.fullmatch(key):
        out(False, status='REFUSED', error='a journal key is 1 to 80 letters, digits, - or _')
    path = journal / f'{key}.json'
    entry = json.loads(path.read_text()) if path.exists() else None

    if entry is not None:
        st = net.transaction(entry['hash'])
        if st['status'] == 'SUCCESS':
            out(True, key=key, hash=entry['hash'], status='SUCCESS', ledger=st['ledger'], note='already applied')
        if st['status'] == 'NOT_FOUND':
            # Not applied as far as this node knows: send the SAME envelope again. If its sequence number is gone the
            # network refuses it, and only then is a new one built.
            try:
                net.send(entry['envelope'])
            except sn.StellarError as e:
                entry['resend_error'] = str(e)[-400:]
            st = wait(net, entry['hash'])
            if st['status'] == 'SUCCESS':
                out(True, key=key, hash=entry['hash'], status='SUCCESS', ledger=st['ledger'], note='resent')
            if st['status'] == 'NOT_FOUND' and 'resend_error' not in entry:
                out(False, key=key, hash=entry['hash'], status='PENDING', note='sent again; not yet in a ledger')
        entry['dead'] = st['status']
        write_json(path, entry)

    if fn == 'release':
        status = net.burn_status(args['item']['nonce'], args['item']['native_burn'])
        if status in (1, 2):
            out(True, key=key, status='DONE', note='the vault already records this burn ('
                + ('queued' if status == 1 else 'paid') + ')')
        if status != 0:
            out(False, key=key, status='REFUSED', error='the vault counts this nonce or burn id for another release')
    try:
        envelope = net.sign(net.build(cfg['relayer'], fn, **args), cfg['relayer_identity'])
    except sn.StellarError as e:
        out(False, key=key, status='REFUSED', error=str(e)[:1700])
    tx_hash = net.tx_hash(envelope)
    write_json(path, {'key': key, 'fn': fn, 'args': args, 'hash': tx_hash, 'envelope': envelope,
                      'reserved_at': int(time.time()), 'previous': entry})
    try:
        net.send(envelope)
    except sn.StellarError as e:
        st = wait(net, tx_hash, 10)
        if st['status'] != 'SUCCESS':
            out(False, key=key, hash=tx_hash, status=st['status'], error=str(e)[:1700])
    st = wait(net, tx_hash)
    out(st['status'] == 'SUCCESS', key=key, hash=tx_hash, status=st['status'], ledger=st['ledger'])


def main():
    argv = sys.argv[1:]
    if not argv or '-h' in argv or '--help' in argv:
        raise SystemExit(__doc__)
    args = {a: argv[i + 1] for i, a in enumerate(argv[:-1]) if a.startswith('--')}
    cfg = json.loads(Path(args['--config']).read_text())
    try:
        if 'submit' in argv:
            call = json.loads(Path(args['--call']).read_text())
            if not isinstance(call, dict) or not isinstance(call.get('call', call), dict):
                out(False, status='REFUSED', error='the call file holds no call object')
            submit(cfg, call.get('call', call), args.get('--key'))
        elif 'status' in argv:
            if not KEY.fullmatch(args['--key']):
                out(False, status='REFUSED', error='a journal key is 1 to 80 letters, digits, - or _')
            path = Path(cfg['journal']) / f"{args['--key']}.json"
            if not path.exists():
                out(False, key=args['--key'], status='UNKNOWN')
            entry = json.loads(path.read_text())
            st = sn.Net({**cfg, 'view_account': cfg['relayer']}).transaction(entry['hash'])
            out(st['status'] == 'SUCCESS', key=args['--key'], hash=entry['hash'], **st)
        else:
            raise SystemExit(__doc__)
    except sn.StellarError as e:
        out(False, status='ERROR', error=str(e)[:1700])


if __name__ == '__main__':
    main()
