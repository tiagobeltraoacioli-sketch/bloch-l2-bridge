#!/usr/bin/env python3
"""Guardian watch of the Solana bridge: tools/guardiao/guardiao.py with a Solana source side.

  python3 sol_guardiao.py --config CFG.json check [--dry-run]
  python3 sol_guardiao.py --config CFG.json watch [--interval 60] [--dry-run]

A subclass of `Guardian` (kind `stable`, `provenance: true`). The L2 side, the findings, their grace periods,
the state file, alerts, the token pause and the queued-mint cancel votes are the parent's code, unchanged. What the
parent reads from an Ethereum vault is read here from the vault's accounts on this guardian's own Solana node at
`finalized` (program final and equal to the pinned image, cluster, vault equal to the configuration file):

  RESERVES            backing = min(total_locked, vault token balance - fees_accrued)
  MINT PROVENANCE     the deposit records (nonce 0 up to the deposit count, each checked against the vault's hash
                      chain) in the shape the parent's `eth_provenance` expects; `mint-chain` against the record
                      heads
  RELEASE MATCH       every release record of the vault (`getProgramAccounts`, filtered by size and vault):
                      a PAID record without a matching L2 burn -> `release-unknown:<nonce>`; one that differs from
                      its burn -> `release-mismatch:<nonce>`; a burn not final on this guardian's L2 ->
                      `release-before-final:<nonce>`.
                      A paid record closed after the retention leaves its bit in a paid page: the nonce must
                      still belong to a burn (`release-unknown:<nonce>`); its amount and recipient were checked
                      while the record existed, so a guardian must run at least once per `record_retention`.
                      Review 330, R330-SOL-3: outside a rehearsal the vault's retention must be at least
                      solana_lib.retention_floor (4,320 watch rounds, never less than a pause) and `watch` refuses
                      an `--interval` so slow that 4,320 rounds of it exceed the vault's retention; a gap between
                      two verified rounds longer than the retention is alerted (`watch-gap-exceeds-retention`):
                      records closed inside that gap were not compared with their burns by this guardian.
  APPROVALS (new)     a STANDING approval (not paid, not voided) without a matching L2 burn ->
                      `release-unknown:approval-<nonce>-<seq>`; one that differs from its burn ->
                      `release-mismatch:approval-<nonce>-<seq>`. The Solana vault pays in two steps, so a wrong
                      approval of a large release is visible for `release_delay` before any token moves, and a
                      guardian pause voids it. The ids keep the parent's prefixes, so the parent pauses the vault.

  DESTINATIONS (new)  every approval and every payment is also held against the recipient rule of sol_recipient.py
                      (round 17; review 330, R330-SOL-3P-2), read from this guardian's own L2 and Solana nodes:
                      - its recipient must be the burn's own destination or the destination of the burner's latest
                        `redirectHeldBurn`, each with a VALID PROOF of the destination key in the router's log.
                        Otherwise `release-mismatch:unproven-<tag>`, hard: only signers who skipped the rule can
                        produce it, and a pause voids an approval that is not paid yet.
                      - the wallet behind it must be a wallet on Solana at `finalized` (absent, or a System account
                        without data). Otherwise `release-destination:<tag>`. This one is SOFT (an alert to the
                        operator, no pause) unless `pause_on_destination` is true: the holder of a destination's
                        key can turn its own address into a mint AFTER the signers read it, at no cost, and a hard
                        finding would let anyone buy a 72 h pause of the vault and the token that way.

Vault pause (`vault_pause: true`): this guardian signs the pause authorization for pause number `pause_count + 1`
with its secp256k1 keystore (`sol_keystore` / `sol_password_file`, default the L2 guardian keystore) and delivers
it with `sol_fee_payer`, an Ed25519 key that only pays the fee. Both steps are sol_vault.py commands; the pause
counts only when the vault account shows it.

A pause voids unpaid approvals; it never loses an exit. The burn stays on the L2, the vault has no paid record
for its nonce, and the signers certify it again after the pause (see docs/SOLANA-VAULT.md, section 3.5).

Config: the parent's keys for the L2 side (`kind: "stable"`, `provenance: true`, `l2_rpc`, `l2_chain_id`, `token`,
`keystore`, `password_file`, `state`, ...) plus `vault` (the vault's 20-byte id, `sourceVault` of the token),
`sol_rpc`, `vault_config`, `burn_router` and `burn_router_code_keccak` (the pinned router), optional
`router_from_block`, `pause_on_destination` (false), and for `vault_pause` the keys above. `eth_rpc` and `eth_chain_id` are not used.

Independence: unlike the parent, this file shares solana_lib.py and sol_half.Node (encodings, account layouts,
the pin checks) with the signer tools. It does not call the signer or the relayer. Development tool; UNAUDITED.
"""
import base64
import json
from pathlib import Path
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / 'guardiao'))
import solana_lib as S  # noqa: E402
from sol_half import Node  # noqa: E402
import sol_recipient  # noqa: E402
import guardiao  # noqa: E402
from guardiao import Guardian, Unverifiable, addr, b32, uint  # noqa: E402


class SolGuardian(Guardian):
    def __init__(self, cfg_path, dry_run=False):
        super().__init__(cfg_path, dry_run)
        if self.kind != 'stable' or not self.provenance:
            raise SystemExit('the Solana guardian needs kind "stable" and `provenance: true`')
        self.sol_cfg = {'sol_rpc': self.cfg['sol_rpc'], 'vault_config': self.cfg['vault_config']}
        if not (self.cfg.get('burn_router') and self.cfg.get('burn_router_code_keccak')):
            raise SystemExit('the Solana guardian needs `burn_router` and `burn_router_code_keccak`: approvals and payments '
                             'are compared with the proofs in the router\'s log')
        self.router_cfg = {'l2_rpc': self.cfg['l2_rpc'], 'burn_router': str(self.cfg['burn_router']).lower(),
                           'burn_router_code_keccak': self.cfg['burn_router_code_keccak'],
                           'l2_chain_id': int(str(self.cfg['l2_chain_id']), 0), 'token': str(self.cfg['token']).lower(),
                           'router_from_block': self.cfg.get('router_from_block') or 0}
        self._nodes, self._records, self._senders, self._paid_checked = {}, [], None, {}

    # ── this guardian's Solana node ─────────────────────────────────────────
    def node(self, commitment='finalized'):
        if commitment not in self._nodes:
            try:
                self._nodes[commitment] = Node(self.sol_cfg, commitment=commitment)
            except S.Refused as e:
                raise Unverifiable(f'Solana vault: {e.reason} {e.detail}') from e
            except S.RpcError as e:
                raise Unverifiable(f'Solana RPC: {e}') from e
        return self._nodes[commitment]

    def sol(self, read):
        try:
            return read()
        except S.Refused as e:
            raise Unverifiable(f'Solana vault: {e.reason} {e.detail}') from e
        except S.RpcError as e:
            raise Unverifiable(f'Solana RPC: {e}') from e

    def round(self):
        self._nodes, self._senders = {}, None
        self.check_retention()
        return super().round()

    def check_retention(self):
        """R330-SOL-3. A paid record is compared with its burn only while it exists, so this watch must complete a
        round at least once per `record_retention`. Outside a rehearsal: refuse a vault whose retention is below
        the floor, refuse a watch interval the retention does not cover with the margin, and say so when the last
        verified round is further back than the retention."""
        n = self.node()
        retention, floor = n.config.record_retention, S.retention_floor(n.config.pause_duration)
        if n.rehearsal:
            return
        if retention < floor:
            raise SystemExit(f'the vault\'s recordRetention {retention} s is below the floor {floor} s: paid records could be '
                             'closed before this watch reads them (review 330, R330-SOL-3)')
        if WATCH_INTERVAL is not None and S.RETENTION_WATCH_ROUNDS * WATCH_INTERVAL > retention:
            raise SystemExit(f'--interval {WATCH_INTERVAL} is too slow for a recordRetention of {retention} s: at most '
                             f'{retention // S.RETENTION_WATCH_ROUNDS} s ({S.RETENTION_WATCH_ROUNDS} rounds per retention)')
        last = self.state.get('verified_t')
        if isinstance(last, int) and time.time() - last > retention:
            self.log(kind='alert', severity='soft', id='watch-gap-exceeds-retention', last_verified=last, retention=retention,
                     reason='this guardian completed no round for longer than the record retention: release records paid '
                            'and closed in that time were not compared with their burns here; check them from the '
                            'transaction history (docs/SOLANA-BRIDGE-OPERATOR-RUNBOOK-DELTA.md)')

    def eth_me(self):
        if self._eth_me is None:
            self._eth_me = self.cast_out('wallet', 'address', '--keystore', self.cfg.get('sol_keystore', self.cfg['keystore']),
                                         '--password-file', self.cfg.get('sol_password_file', self.cfg['password_file'])).lower()
        return self._eth_me

    def setup(self):
        chain = int(self.rpc(self.l2, 'eth_chainId', []), 16)
        if chain != int(self.cfg['l2_chain_id']):
            raise Unverifiable(f'L2 chain id {chain} != {self.cfg["l2_chain_id"]}')
        pin = self.cfg.get('l2_genesis_hash')
        if pin:
            g = self.block(self.l2, 0)[2].lower().removeprefix('0x')
            if g != str(pin).lower().removeprefix('0x'):
                raise Unverifiable(f'L2 genesis {g} != pinned {pin}')
        if not uint(self.call(self.l2, self.token, 'isGuardian(address)', self.me())[0]):
            raise Unverifiable(f'{self.me()} is not a guardian of {self.token}')
        n = self.node()
        a = n.a
        if addr(self.call(self.l2, self.token, 'sourceVault()')[0]) != self.cfg['vault'].lower() or S.hx(a.vault20) != self.cfg['vault'].lower():
            raise Unverifiable('the token sourceVault, the configured vault and the vault configuration file differ')
        self.route = b32(self.call(self.l2, self.token, 'sourceRoute()')[0])
        if self.route != S.hx(a.route):
            raise Unverifiable(f'token sourceRoute {self.route} != vault route {S.hx(a.route)}')
        if uint(self.call(self.l2, self.token, 'sourceChainId()')[0]) != int.from_bytes(n.config.source_chain_id, 'big'):
            raise Unverifiable('the token sourceChainId is not this Solana cluster')
        if self.vault_pause and S.unhex(self.eth_me(), 20) not in n.config.guardians:
            raise Unverifiable(f'{self.eth_me()} is not a guardian of the Solana vault')
        if not self.design_checked:
            self.check_design()

    def check_design(self):
        if len(self.call(self.l2, self.token, 'mintHead()')) != 1:
            raise SystemExit('the L2 token does not answer mintHead(): the Solana vault needs BridgedStablecoinV3')
        self.design_checked = True

    # ── the source side ─────────────────────────────────────────────────────
    def records(self):
        """Deposit records at `finalized`, each one checked against the vault hash chain up to the vault head."""
        n = self.node()
        count = n.vault['deposit_count']
        kept = self._records[:count]
        last = self.sol(lambda: n.deposit(len(kept) - 1)) if kept else None
        if kept and (last is None or last['head_after'] != kept[-1]['head_after']):
            self.log(kind='alert', severity='soft', id='deposit-record-changed',
                     reason='a deposit record read in an earlier round is no longer on this node (a rollback or another node)')
            kept = []
        head = kept[-1]['head_after'] if kept else n.a.genesis
        for nonce in range(len(kept), count):
            d = self.sol(lambda nonce=nonce: n.deposit(nonce))
            if d is None or S.chain_step(head, d['id'], d['amount'], d['l2_recipient']) != d['head_after']:
                raise Unverifiable(f'deposit record {nonce} is absent or does not extend the vault hash chain')
            head = d['head_after']
            kept.append(d)
        if head != n.vault['head']:
            self._records = []
            raise Unverifiable('the deposit records do not end at the vault head')
        self._records = kept
        return kept

    def release_records(self):
        n = self.node()
        rows = self.sol(lambda: n.rpc.call('getProgramAccounts', [S.b58encode(n.a.program_id), {
            'encoding': 'base64', 'commitment': 'finalized',
            'filters': [{'dataSize': S.RELEASE_LEN}, {'memcmp': {'offset': 4, 'bytes': S.b58encode(n.a.vault)}}]}]))
        out = []
        for row in rows or []:
            r = self.sol(lambda row=row: S.decode_release(base64.b64decode(row['account']['data'][0])))
            if r['vault'] != n.a.vault or n.a.release_record(r['nonce']) != S.pubkey(row['pubkey']):
                raise Unverifiable('a release record is not at the address of its nonce')
            r['key'] = row['pubkey']
            out.append(r)
        # Releases paid and closed after the retention: only their bit in a paid page is left.
        pages = self.sol(lambda: n.rpc.call('getProgramAccounts', [S.b58encode(n.a.program_id), {
            'encoding': 'base64', 'commitment': 'finalized',
            'filters': [{'dataSize': S.PAGE_LEN}, {'memcmp': {'offset': 3, 'bytes': S.b58encode(n.a.vault)}}]}]))
        for row in pages or []:
            page = self.sol(lambda row=row: S.decode_page(base64.b64decode(row['account']['data'][0])))
            if page['vault'] != n.a.vault or n.a.paid_page(page['page'] * S.PAGE_NONCES) != S.pubkey(row['pubkey']):
                raise Unverifiable('a paid page is not at the address of its range')
            have = {r['nonce'] for r in out}
            out += [{'nonce': nonce, 'state': 2, 'closed': True, 'seq': 0, 'key': row['pubkey']}
                    for nonce in S.page_nonces(page) if nonce not in have]
        return sorted(out, key=lambda r: r['nonce'])

    def eth_source(self, burns, fin=None):
        n = self.node()
        v = n.vault
        tokens = self.sol(lambda: n.token_balance(n.a.tokens))
        if tokens is None or tokens['mint'] != n.config.mint or tokens['owner'] != n.a.vault:
            raise Unverifiable('the vault token account is missing or not the vault\'s')
        backing = min(v['total_locked'], tokens['amount'] - v['fees_accrued'])
        self.deposits = {S.hx(d['id']): {'route': self.route, 'nonce': d['nonce'], 'sender': S.hx(d['sender20']),
                                         'amount': d['amount'], 'pq': '0x' + '00' * 12 + d['l2_recipient'].hex()}
                         for d in self.records()}
        by_nonce = {b['nonce']: b for b in burns}
        released, findings = {}, []
        for r in self.release_records():
            b = by_nonce.get(r['nonce'])
            paid = r['state'] == 2
            if not paid and r['seq'] <= v['void_through_seq']:
                continue  # voided by a guardian pause: it can never be paid
            if r.get('closed'):
                # Paid, then closed after the retention: the record's fields were checked while it existed; what
                # is left to check for good is that the nonce belongs to a burn.
                if b is None:
                    findings.append(('hard', f'release-unknown:{r["nonce"]}', self.provenance_grace,
                                     {'reason': 'vault release (closed record) without a matching L2 burn', 'nonce': r['nonce']}))
                else:
                    released[b['burn_id']] = r['key']
                continue
            shown = {'nonce': r['nonce'], 'recipient': S.hx(r['recipient']), 'amount': r['amount'],
                     'burn_id': S.hx(r['native_burn']), 'record': r['key'], 'paid': paid, 'ready_at': r['ready_at']}
            tag = str(r['nonce']) if paid else f"approval-{r['nonce']}-{r['seq']}"
            if b is None:
                findings.append(('hard', f'release-unknown:{tag}', self.provenance_grace,
                                 {'reason': 'vault release without a matching L2 burn' if paid else
                                  'vault approval without a matching L2 burn (not paid yet: a pause voids it)', **shown}))
                continue
            if (shown['burn_id'], shown['amount']) != (b['burn_id'], b['amount']):
                findings.append(('hard', f'release-mismatch:{tag}', 0,
                                 {'reason': 'vault release differs from its L2 burn' if paid else
                                  'vault approval differs from its L2 burn (not paid yet: a pause voids it)',
                                  'release': shown, 'burn': b}))
                continue
            if fin is not None and b['block'] > fin:
                # Round 18 (review 376, R330-SOL-4P-9): a burn past THIS guardian's L2 finalized head is judged first
                # as early, with the parent's severity and grace; its recipient is judged in the first round whose
                # head covers it (the router's logs up to this head cannot show it yet).
                findings.append((self.release_before_final, f'release-before-final:{tag}', self.provenance_grace,
                                 {'reason': 'vault release of a burn not finalized on this guardian\'s L2',
                                  'release': shown, 'burn_block': b['block'], 'l2_finalized': fin}))
                if paid:
                    released[b['burn_id']] = r['key']
                continue
            # The recipient rule (sol_recipient.py). A paid record that passed is not read again; an approval is
            # judged every round until it is paid or voided.
            kind, why = self.judged_recipient(b, r, paid, fin)
            if kind == 'pending-final':
                findings.append((self.release_before_final, f'release-before-final:{tag}', self.provenance_grace,
                                 {'reason': 'vault release for a redirect not yet finalized on this guardian\'s L2: ' + why,
                                  'release': shown, 'burn_block': b['block'], 'l2_finalized': fin}))
                continue
            if kind == 'mismatch':
                findings.append(('hard', f'release-mismatch:{tag}', 0,
                                 {'reason': ('vault release' if paid else 'vault approval (not paid yet: a pause voids it)')
                                  + ' names a recipient that is neither its L2 burn\'s nor its burner\'s redirect',
                                  'release': shown, 'burn': b}))
                continue
            if kind == 'unproven':
                findings.append(('hard', f'release-mismatch:unproven-{tag}', 0,
                                 {'reason': ('vault release' if paid else 'vault approval (not paid yet: a pause voids it)')
                                  + ' for a destination without a valid proof of its key in the router log: ' + why,
                                  'release': shown, 'burn': b}))
                continue
            if kind == 'destination':
                hard = bool(self.cfg.get('pause_on_destination')) and not paid
                findings.append(('hard' if hard else 'soft', ('release-mismatch:destination-' if hard else 'release-destination:') + tag,
                                 0, {'reason': ('vault release was paid' if paid else 'vault approval stands (a guardian pause '
                                     'voids it; anyone may send the payment)') + ' for a destination that is not a wallet on '
                                     'Solana: ' + why, 'release': shown, 'burn': b}))
            if paid:
                released[b['burn_id']] = r['key']
            if fin is None:  # no finalized head known: judged on the router's `finalized` logs above, and early as before
                findings.append((self.release_before_final, f'release-before-final:{tag}', self.provenance_grace,
                                 {'reason': 'vault release of a burn not finalized on this guardian\'s L2',
                                  'release': shown, 'burn_block': b['block'], 'l2_finalized': fin}))
        return backing, released, findings

    def judged_recipient(self, b, r, paid, fin):
        """The verdict of `recipient_verdict` for the release record `r` of burn `b`, with the cache of paid records:
        only a verdict READ from the L2 and found 'ok' is remembered. A round without the L2 judges nothing
        ('unjudged'), and what it could not judge is judged in the next round that reads the L2 (round 18: before,
        the blind round's answer was cached as 'ok', and a payment first seen in a blind round was never judged)."""
        key = (r['nonce'], r['seq'])
        if paid and key in self._paid_checked:
            return self._paid_checked[key]
        verdict = self.recipient_verdict(b, r['recipient'], fin)
        if paid and verdict == ('ok', None):
            self._paid_checked[key] = verdict
        return verdict

    def recipient_verdict(self, b, recipient20, fin):
        """('ok', None), ('mismatch', None), ('unproven', why), ('destination', why), or ('unjudged', why) in a round
        without the L2, for a release recipient of the burn `b`, by the rule of sol_recipient.py on this guardian's
        own nodes."""
        if self.blind:  # the L2 does not answer this round: the router's log cannot be read, and the round must go on
            return 'unjudged', 'the L2 did not answer this round: the recipient rule is judged in the next round that reads it'
        def read():
            if self._senders is None:
                sol_recipient.check_router(self.router_cfg, self.node().a)
                self._senders = {x['burn_id']: x['from'] for x in sol_recipient.l2_burns(
                    self.l2, self.token, self.cfg.get('token_from_block', 0), 'latest')}
            burn = {'burn_id': b['burn_id'], 'nonce': b['nonce'], 'amount': b['amount'], 'recipient': b['eth_recipient'],
                    'from': self._senders.get(b['burn_id'])}
            view = sol_recipient.exit_view(self.router_cfg, self.node().a, burn, hex(fin) if fin is not None else 'finalized')
            wallet = sol_recipient.wallet_for_recipient(view, burn, recipient20)
            if wallet is None and fin is not None:
                # R330-SOL-4P-9: a redirect past this guardian's finalized head is not in its view yet. When the logs
                # up to `latest` accept the recipient, the record is early, not wrong: release-before-final, its grace.
                later = sol_recipient.exit_view(self.router_cfg, self.node().a, burn, 'latest')
                if sol_recipient.wallet_for_recipient(later, burn, recipient20) is not None:
                    return 'pending-final', 'the router log that names this recipient is past the finalized head'
            if wallet is None:
                if S.hx(recipient20) != b['eth_recipient']:
                    return 'mismatch', None
                original = view['original']
                return 'unproven', (original['reason'] if original is not None else
                                    'the burn was made directly on the token and its burner has not claimed it')
            dest = sol_recipient.destination([self.node().rpc], wallet, self.node().a)
            return ('destination', dest['hold']) if dest['hold'] else ('ok', None)
        return self.sol(read)

    def chain_findings(self, b):
        n = self.node()
        count = uint(self.call(self.l2, self.token, 'mintCount()', block=b)[0])
        head = b32(self.call(self.l2, self.token, 'mintHead()', block=b)[0])
        records = self.records()
        detail = {'mint_count': count, 'mint_head': head, 'deposit_count': len(records), 'l2_block': b,
                  'sol_finalized': n.vault['context_slot']}
        if count > len(records):
            latest = self.node('confirmed').vault['deposit_count']
            ahead = count > latest
            return [('hard', 'mint-chain', 0 if ahead else self.provenance_grace, {
                'reason': 'the token credited more mints than the vault has deposits, even at confirmed: credited forgeries'
                          if ahead else 'the token credited more mints than the vault has finalized deposits (a lagging '
                          'Solana view, or credited forgeries)', 'deposit_count_latest': latest, **detail})]
        want = S.hx(records[count - 1]['head_after'] if count else n.a.genesis)
        if want != head:
            return [('hard', 'mint-chain', self.provenance_grace, {
                'reason': 'a credited L2 mint has no deposit behind it: the vault refuses every burn made from now on '
                          '(held, not lost) until the owner settles', 'vault_head': want, **detail})]
        return []

    def head_deposit_ids(self):
        """(head slot, head time, deposit ids) at `confirmed`: the freshest view, for the parent's cancel-vote rule."""
        if getattr(self, '_head_deposits', None) is None:
            n = self.node('confirmed')
            ids = set()
            for nonce in range(n.vault['deposit_count']):
                d = self.sol(lambda nonce=nonce: n.deposit(nonce))
                if d is not None:
                    ids.add(S.hx(d['id']))
            slot = n.vault['context_slot']
            self._head_deposits = (slot, int(self.sol(lambda: n.rpc.block_time(slot))), ids)
        return self._head_deposits

    def watch_switch(self):
        """The Solana vault has no verifier switch: nothing to watch."""

    # ── the vault pause ─────────────────────────────────────────────────────
    def vault_view(self):
        n = self.node('confirmed')
        return n, n.vault, int(self.sol(lambda: n.rpc.block_time(n.vault['context_slot'])))

    def vault_unpaused_at(self):
        _, v, _ = self.vault_view()
        return v['guardian_blocked_until'] - v['config'].pause_cooldown if v['guardian_blocked_until'] else 0

    def vault_paused_now(self):
        try:
            self._nodes.pop('confirmed', None)
            _, v, now = self.vault_view()
            return now < v['paused_until']
        except Unverifiable:
            return False

    def sol_vault(self, command, *argv):
        rc, out, err = self.run([sys.executable, HERE / 'sol_vault.py', command, '--config', self.cfg['vault_config'],
                                 '--rpc', self.cfg['sol_rpc'], *argv])
        try:
            return json.loads(out)
        except ValueError:
            return {'ok': False, 'reason': (err or out).strip()[-300:]}

    def pause_vault(self, reasons):
        n, v, now = self.vault_view()
        count = v['pause_count']
        me = n.config.guardians.index(S.unhex(self.eth_me(), 20))
        chain_ended = count == 0 or now >= v['paused_until'] + v['config'].pause_cooldown
        why = ('already paused' if now < v['paused_until'] else
               'cooldown after a committee unpause' if now < v['guardian_blocked_until'] else
               'this guardian already paused in this chain' if not chain_ended and v['guardian_last_chain'][me] == v['pause_chain']
               else None)
        if why:
            self.clear_problem('vault-pause-failed')
            note = f'{why}:{count}'
            if self.state.get('vault_skip') != note:
                self.state['vault_skip'] = note
                self.log(kind='vault-pause-skip', reason=why, until=max(v['paused_until'], v['guardian_blocked_until']),
                         pause_count=count, violations=reasons)
            return
        if self.dry_run:
            self.log(kind='vault-pause-dry-run', violations=reasons)
            return
        with tempfile.TemporaryDirectory() as tmp:
            cert = str(Path(tmp) / 'pause.json')
            signed = self.sol_vault('pause-sign', '--keystore', self.cfg.get('sol_keystore', self.cfg['keystore']),
                                    '--password-file', self.cfg.get('sol_password_file', self.cfg['password_file']),
                                    '--cast', self.cast, '--out', cert)
            sent = self.sol_vault('pause-submit', '--cert', cert, '--fee-payer', self.cfg['sol_fee_payer']) \
                if signed.get('ok') else signed
        ok = bool(sent.get('ok'))
        entry = {'chain_time': now, 'tx': sent.get('signature'), 'ok': ok, 'violations': reasons, 'slot': sent.get('slot'),
                 'units': sent.get('units'), 'pause_count': sent.get('pauseCount'), 'paused_until': sent.get('pausedUntil')}
        self.state.setdefault('vault_pauses', []).append(entry)
        self.log(kind='vault-pause', **entry, error=None if ok else str(sent.get('reason') or sent.get('error_name'))[-300:])
        if ok:
            self.clear_problem('vault-pause-failed')
        elif self.vault_paused_now():
            self.log(kind='vault-pause-skip', reason='another guardian paused first', violations=reasons)
            self.clear_problem('vault-pause-failed')
        else:
            self.problem('vault-pause-failed', str(sent.get('reason') or sent.get('error_name'))[-200:])


WATCH_INTERVAL = None  # seconds between rounds of `watch` (None for a single `check`)


def main():
    global WATCH_INTERVAL
    args = sys.argv[1:]
    if 'watch' in args:
        WATCH_INTERVAL = int(args[args.index('--interval') + 1]) if '--interval' in args else S.GUARDIAN_WATCH_INTERVAL
        if WATCH_INTERVAL < 1:
            raise SystemExit('--interval must be at least 1 second')
    guardiao.Guardian = SolGuardian  # the parent's main loop, with this class
    guardiao.main()


if __name__ == '__main__':
    main()
