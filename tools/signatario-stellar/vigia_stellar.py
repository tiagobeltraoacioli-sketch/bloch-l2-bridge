#!/usr/bin/env python3
"""Automatic signer and relayer for the Stellar route: tools/signatario-stable/vigia.py with the source network replaced.

  vigia_stellar.py --config CFG.json sign  [--once] [--interval 60]
  vigia_stellar.py --config CFG.json relay [--once] [--interval 60]

This is vigia.py itself, imported and subclassed; vigia.py is not edited, so an Ethereum configuration runs the same
code as before. Everything about the L2 (burn discovery up to the finalized level, the mint relay in slot order, the
drain, the relayer's L2 nonces and gas ceiling, roles and backups, the hourly signing budget, rounds and their
directories) is that module's code. Replaced, because it reads or writes the source network:

  deposits     the vault's own chain of deposits in ledger state, not an event feed: the fields of deposit n (from the
               vault's `deposited` events, or from a file in `deposit_hints`) count only if the id recomputes from
               them and keccak(head[n], id, amount, recipient) equals the stored head[n + 1], and only once that
               entry's ledger is `finality_ledgers` behind the node. Discovery only: signatario_stellar.py and
               stellar_half.py decide again before anything is signed.
  released     the vault's own `burn_status` of the burn's nonce and id: queued or paid is done. A burn whose queued
               release a guardian pause voided is open again and is signed again like any other, with no operator
               step. A burn whose nonce or id the vault counts for another release (a forgery took it) is parked
               with an alert until a pause voids that one.
  certificates a partial counts if its signature (an Ethereum personal message) recovers to one of the vault's
               signers, its digest is the vault's release digest of its fields (computed here; the vault's code is
               pinned by `vault_wasm_hash`), and it was signed under the vault's CURRENT pause count: a round from
               before a pause is dead and a new one is opened.
  anchor       a round can be joined if this node holds the same hash for the round's anchor ledger.
  relay        a release with `vault_threshold` certificates goes to relay_stellar.py (journal before publication);
               a queued release that is due is executed the same way.

NOT adapted: the authenticated feed (bridge_feed.py) checks EVM vault digests and signer sets, so this watcher runs
only in the shared-directory mode and refuses a config with a `feed` block or `l2_pins`. That transport must be
adapted and reviewed before chain 700770 (docs/STELLAR-BRIDGE.md, "Not done").

Config: the signer's signatario_stellar.py config plus `shared_dir`, `stellar_rpc`, `view_account`,
`vault_wasm_hash`; optional `stellar_config_dir`, `vault_from_ledger`, `finality_ledgers` (12), `anchor_max_age`
(ledgers, default 160), `deposit_hints` (directory of JSON files named by the deposit nonce); for `relay` also
`l2_chain_id`, the L2 gas key as in vigia.py, and relay_stellar.py's keys `relayer`, `relayer_identity`, `journal`.
"""
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / 'signatario-stable'))
import bridge_feed  # noqa: E402
import stellar_net as sn  # noqa: E402
import vigia as V  # noqa: E402


class VigiaStellar(V.Vigia):
    def __init__(self, cfg_path):
        super().__init__(cfg_path)
        c = self.cfg
        if c.get('feed') or c.get('l2_pins'):
            raise SystemExit('the Stellar watcher runs only in the shared-directory mode: the authenticated feed '
                             'verifies EVM vault digests and is not adapted to the Stellar vault')
        if not self.provenance:
            raise SystemExit('the Stellar route needs "provenance": true')
        self.net = sn.Net(c)
        self.vault_contract = c['vault']
        if '0x' + sn.vault20(self.vault_contract).hex() != self.vault:
            raise SystemExit('source_vault is not the low 20 bytes of the vault contract id')
        self.finality = int(c.get('finality_ledgers', 12))
        self.known_deposits = {}   # nonce -> verified fields, for this process only
        self.queued = set()        # release ids seen queued, for this process only
        self.queue_cursor = None
        self.burn_nonce = {}       # burn id -> nonce, from this process's own L2 reads and verified partials

    # ── the source network's clock and identity ──────────────────────────────
    def latest(self):
        return self.chain_read('stellar-latest', self.net.latest)

    def eth_now(self):
        """The vault compares `valid_until` with the ledger close time, so rounds are judged on it."""
        return self.latest()['close_time']

    def vault_config(self):
        return self.chain_read('stellar-config', lambda: self.net.view('config'))

    def check_design(self):
        if self.design_checked:
            return
        head = self.call(self.cfg['l2_rpc'], self.token, 'mintHead()')
        if head in ('0x', '') or len(head) != 66:
            raise SystemExit('the L2 token does not answer mintHead(): not a BridgedStablecoinV3')
        wasm, _, _ = self.net.wasm_hash()
        if wasm != str(self.cfg['vault_wasm_hash']).replace('0x', '').lower():
            raise SystemExit(f'the vault runs another Wasm than the pinned one ({wasm})')
        d = self.net.view('derived')
        if '0x' + d['route'] != self.route or bytes.fromhex(d['network_id']) != sn.network_id(self.net.passphrase):
            raise SystemExit('the vault reports another route or network than the config')
        self.design_checked = True

    def check_signer_sets(self):
        raise SystemExit('the feed is not adapted to the Stellar vault')

    def check_chain_ids(self):
        if self.chains_checked:
            return
        for name, url in (('l2_rpc', self.cfg['l2_rpc']), ('l2_tx_rpc', self.l2_tx)):
            got, want = int(self.rpc(url, 'eth_chainId', []), 16), self.cfg.get('l2_chain_id')
            if want is None or got != int(str(want), 0):
                raise SystemExit(f'{name} answers chain id {got}, the config says {want}: refusing to relay')
        if self.net.rpc('getNetwork').get('passphrase') != self.net.passphrase:
            raise SystemExit('the Stellar RPC serves another network than network_passphrase: refusing to relay')
        self.chains_checked = True

    # ── deposits: the vault's chain in ledger state ──────────────────────────
    def head(self, n, derived):
        """(head after n deposits, the ledger that wrote it), or None when the entry is not live."""
        if n == 0:
            return bytes.fromhex(derived['genesis']), 0
        state, entry, _ = self.net.record_state('Head', n)
        if state != 'live':
            return None
        return bytes.fromhex(sn.scval(entry['dataJson']['contract_data']['val'])), int(entry['lastModifiedLedgerSeq'])

    def candidate_fields(self, count):
        """Unverified fields by nonce, from hint files and from the vault's events in the RPC's retained window."""
        found = {}
        hints = self.cfg.get('deposit_hints')
        for n in range(count):
            if n not in self.known_deposits and hints and (Path(hints) / f'{n}.json').exists():
                try:
                    found[n] = json.loads((Path(hints) / f'{n}.json').read_text())
                except (OSError, ValueError):
                    pass
        if all(n in self.known_deposits or n in found for n in range(count)):
            return found
        start = max(int(self.cfg.get('vault_from_ledger', 0)), int(self.net.health().get('oldestLedger', 1)))
        while True:
            events, latest, _ = self.net.events(start)
            for e in events:
                if e['name'] == 'deposited' and e['topics']:
                    d = e['data']
                    found.setdefault(int(d['nonce']), {'sender': d['sender'], 'amount': int(d['amount']),
                                                       'l2_recipient': d['l2_recipient']})
            if not events or events[-1]['ledger'] >= latest:
                return found
            start = events[-1]['ledger'] + 1

    def deposits(self):
        derived = self.net.view('derived')
        count = int(self.net.view('state')['deposit_count'])
        final = self.latest()['sequence'] - self.finality
        route = bytes.fromhex(derived['route'])
        candidates = None
        ids, self.deposit_fields = [], {}
        for n in range(count):
            known = self.known_deposits.get(n)
            if known is None:
                if candidates is None:
                    candidates = self.candidate_fields(count)
                f = candidates.get(n)
                before, after = self.head(n, derived), self.head(n + 1, derived)
                if f is None or before is None or after is None:
                    V.log(kind='alert', severity='warning', id='stellar-deposit-fields-missing', nonce=n,
                          reason='no fields for this deposit in the RPC window, or a chain head is archived; supply '
                                 'deposit_hints or restore the entry')
                    break  # mints credit in nonce order: later deposits wait behind this one
                try:
                    amount, l2 = int(f['amount']), sn.b20(f['l2_recipient'])
                    dep = sn.deposit_id(route, n, f['sender'], amount, l2)
                    if sn.next_head(before[0], dep, amount, l2) != after[0]:
                        raise sn.StellarError('the fields are not the ones in the vault\'s chain')
                except (sn.StellarError, KeyError, ValueError, TypeError) as e:
                    V.log(kind='alert', severity='warning', id='stellar-deposit-fields-wrong', nonce=n, reason=str(e))
                    break
                known = {'id': '0x' + dep.hex(), 'amount': amount, 'l2': '0x' + l2.hex(), 'ledger': after[1]}
                self.known_deposits[n] = known
            if known['ledger'] > final:
                break  # closed, not yet past the margin
            ids.append(known['id'])
            self.deposit_fields[known['id']] = (known['amount'], known['l2'])
        self.deposits_read = True
        return ids

    # ── releases ─────────────────────────────────────────────────────────────
    def burns(self):
        burns = super().burns()
        for b in burns:
            self.burn_nonce[b['burn_id']] = b['nonce']
        return burns

    def pause_count(self):
        return self.chain_read('stellar-pause-count', lambda: int(self.net.view('state')['pause_count']))

    def status(self, burn_id):
        """The vault's burn_status for a burn id, or None while this process does not know the burn's nonce."""
        nonce = self.burn_nonce.get(burn_id)
        if nonce is None:
            # relay mode without an L2 scan: the nonce stated by the certificates in SHARED (untrusted; a wrong nonce
            # only makes the vault answer for another pair, and the vault checks every release again).
            for f in (self.shared / 'release' / burn_id[2:]).glob('r-*/*.json'):
                try:
                    rec = json.loads(f.read_text())
                    if str(rec['release']['nativeBurn']).lower() == burn_id:
                        nonce = int(rec['release']['nonce'])
                        break
                except (OSError, ValueError, KeyError, TypeError):
                    continue
        if nonce is None:
            return None
        return self.chain_read(('stellar-burn-status', burn_id), lambda: self.net.burn_status(nonce, burn_id))

    def released(self, burn_id):
        return self.status(burn_id) in (1, 2)

    def release_finished(self, burn_id):
        # Stellar does not reorganise: the answer of a closed ledger is final. Nothing is cached across passes. A
        # queued release counts as done here; if a pause voids it, the vault answers "open" again and it is redone.
        return self.released(burn_id)

    def burn_done(self, d, burn_id):
        """As vigia.py, without the `done` marker: on this route a queued release can become open again."""
        return 'known' if self.release_finished(burn_id) else None

    def unpayable(self, b):
        if 'mint_head' not in b:
            return False
        state, head = self.net.record_value('Head', b['mint_count']) if b['mint_count'] else ('absent', None)
        if state == 'live' and '0x' + head != b['mint_head']:
            if b['burn_id'] not in self.parked_logged:
                V.log(kind='alert', severity='critical', id='release-held-provenance', burn=b['burn_id'],
                      mint_count=b['mint_count'], mint_head=b['mint_head'],
                      reason='the burn was made under a mint chain the vault deposits do not back')
            return True
        self.burn_nonce[b['burn_id']] = b['nonce']
        if self.status(b['burn_id']) == 3:
            # The vault counts this nonce or this burn id for another release: a forgery took it. A guardian pause
            # voids that one; nothing is signed until then.
            if b['burn_id'] not in self.parked_logged:
                V.log(kind='alert', severity='critical', id='release-held-nonce-or-id-taken', burn=b['burn_id'],
                      nonce=b['nonce'])
            return True
        return False

    def round_fits(self, b, rec):
        try:
            rel, ctx = rec['release'], rec['context']
            if 'amount' in b and ((int(rel['nonce']), str(rel['recipient']).lower(), int(rel['amount']),
                                   str(rel['route']).lower()) != (b['nonce'], b['recipient'], b['amount'], self.route)
                                  or int(ctx['nativeFinalizedNumber']) != b['block']
                                  or str(ctx['nativeFinalizedHash']).lower() != b['block_hash']):
                return False
            if (int(rel['mintCount']), int(rel['mintedTotal']), str(rel['mintHead']).lower()) != \
                    (b['mint_count'], b['minted_total'], b['mint_head']):
                return False
            number = int(ctx['sourceAnchorNumber'])
            if not 0 <= self.latest()['sequence'] - number <= self.anchor_max_age:
                return False
            return '0x' + self.net.ledger(number)['hash'] == str(ctx['sourceAnchorHash']).lower()
        except (KeyError, ValueError, TypeError, AttributeError, sn.StellarError):
            return False

    def verified(self, path, url, to):
        if to != self.vault:
            return super().verified(path, url, to)
        try:
            rec = json.loads(path.read_text())
            signer, digest, sig = rec['signer'], rec['digest'], rec['signature']
            if not (V.ADDRESS.fullmatch(signer) and V.WORD.fullmatch(digest) and V.SIGNATURE.fullmatch(sig)):
                return None
            rc, _, _ = self.run([self.cast, 'wallet', 'verify', '--no-hash', '--address', signer, digest, sig])
            return rec if rc == 0 and signer[2:].lower() in self.vault_config()['signers'] else None
        except (OSError, ValueError, KeyError, TypeError, RuntimeError, sn.StellarError):
            return None

    def release_partial(self, path, burn_id, rnd):
        rec = self.verified(path, None, self.vault)
        if rec is None or rec.get('kind') != 'stable-release' or str(rec.get('source_vault')).lower() != self.vault:
            return None
        try:
            rel, c, half = rec['release'], rec['context'], rec.get('eth') or {}
            if str(rel['nativeBurn']).lower() != burn_id or rnd.name != bridge_feed.round_name(rec):
                return None
            recipient, count = half['stellar_recipient'], int(half['pause_count'])
            if count != self.pause_count():
                return None  # signed before a pause: dead
            if '0x' + sn.recipient_commitment(recipient).hex() != str(rel['recipient']).lower() and not half.get('claim'):
                return None  # (a claim is verified by signatario_stellar.py when the certificates are combined)
            item = {'route': rel['route'], 'nonce': rel['nonce'], 'recipient': recipient, 'amount': rel['amount'],
                    'native_burn': rel['nativeBurn'], 'mint_count': rel['mintCount'],
                    'minted_total': rel['mintedTotal'], 'mint_head': rel['mintHead']}
            ctx = {'valid_until': c['validUntil'], 'pause_count': count, 'native_finalized_number': c['nativeFinalizedNumber'],
                   'native_finalized_hash': c['nativeFinalizedHash']}
            want = '0x' + sn.personal(sn.release_digest(self.net.passphrase, self.vault_contract, item, ctx)).hex()
            self.burn_nonce.setdefault(burn_id, int(rel['nonce']))
        except (KeyError, ValueError, TypeError, sn.StellarError):
            return None
        return rec if want == rec['digest'].lower() else None

    def signatario(self, *args):
        rc, out, err = self.run([sys.executable, HERE / 'signatario_stellar.py', '--config', self.cfg_path, *args])
        try:
            return rc, json.loads(out)
        except ValueError:
            return rc, {'reason': 'no JSON from signatario_stellar.py: ' + err.strip()[-300:]}

    # ── relay ────────────────────────────────────────────────────────────────
    def relay_stellar(self, call, key=None):
        path = self.shared / '.calls'
        path.mkdir(parents=True, exist_ok=True)
        f = path / f"{key or call['fn']}.json"
        f.write_text(json.dumps({'call': call}))
        argv = [sys.executable, HERE / 'relay_stellar.py', '--config', self.cfg_path, 'submit', '--call', f]
        if key:
            argv += ['--key', key]
        rc, out, err = self.run(argv)
        try:
            return rc, json.loads(out)
        except ValueError:
            return rc, {'status': 'ERROR', 'error': err.strip()[-300:]}

    def relay_release(self, d):
        burn_id = '0x' + d.name
        if not V.WORD.fullmatch(burn_id):
            return
        if self.burn_done(d, burn_id):
            return
        live = self.quorum_release(d, burn_id)
        if live is None or not self.backup_due('eth', f'release:{burn_id}'):
            return
        rnd, call = live
        # relay_stellar.py journals the signed envelope before it is sent and never builds a second transaction for
        # a nonce the vault records, so a second round reaching quorum cannot become a second payment.
        rc, sent = self.relay_stellar(call)
        if rc == 0:
            self.queued.add(sn.release_id(call['args']['item']).hex())
        V.log(kind='relay-release', burn=burn_id, round=rnd.name, tx=sent.get('hash'), status=sent.get('status'),
              error=sent.get('error'))

    def execute_due(self):
        """Queued releases whose delay has passed are paid by anyone: here. Ids come from this process's own relays and
        from the vault's `release_queued` events; the vault decides (queued, due, not paused, open, the bucket)."""
        start = self.queue_cursor or max(int(self.cfg.get('vault_from_ledger', 0)),
                                         int(self.net.health().get('oldestLedger', 1)))
        while True:
            events, latest, _ = self.net.events(start)
            for e in events:
                if e['name'] == 'release_queued' and e['topics']:
                    self.queued.add(e['topics'][0])
            if not events or events[-1]['ledger'] >= latest:
                self.queue_cursor = (events[-1]['ledger'] if events else start)
                break
            start = events[-1]['ledger'] + 1
        st = self.net.view('state')
        now = self.latest()['close_time']
        if now < int(st['paused_until']) or not st['releases_enabled']:
            return
        for rid in sorted(self.queued):
            pending = self.net.view('pending', id=rid)
            if pending is None or int(pending['pause_count']) != int(st['pause_count']):
                self.queued.discard(rid)   # paid, or voided by a pause (its burn is certified again by the signers)
                continue
            if now < int(pending['ready_at']) or int(pending['amount']) > int(self.net.view('available_to_release')):
                continue
            if not self.backup_due('eth', f'execute:{rid}'):
                continue
            rc, sent = self.relay_stellar({'fn': 'execute_release', 'args': {'id': rid}}, key=f'execute-{rid[:24]}')
            V.log(kind='relay-execute-release', release=rid, nonce=pending['nonce'], tx=sent.get('hash'),
                  status=sent.get('status'), error=sent.get('error'))

    def relay_round(self):
        super().relay_round()
        self.isolated('relay-execute-release', 'queue', self.execute_due)


def main():
    args = sys.argv[1:]
    mode = 'sign' if 'sign' in args else 'relay' if 'relay' in args else None
    if mode is None or '-h' in args or '--help' in args:
        raise SystemExit(__doc__)
    v = VigiaStellar(V.option(args, '--config'))
    interval = int(V.option(args, '--interval', '60'))
    if mode == 'relay':  # fail at start, not at the first send
        v.relayer_wallet('l2')
        for key in ('relayer', 'relayer_identity', 'journal'):
            if not v.cfg.get(key):
                raise SystemExit(f'relay needs `{key}` (relay_stellar.py)')
    while True:
        try:
            v.sign_round() if mode == 'sign' else v.relay_round()
        except Exception as e:  # noqa: BLE001 - a daemon keeps running; the next round retries
            V.log(kind=mode, error=f'{type(e).__name__}: {e}')
        if '--once' in args:
            break
        V.time.sleep(interval)


if __name__ == '__main__':
    main()
