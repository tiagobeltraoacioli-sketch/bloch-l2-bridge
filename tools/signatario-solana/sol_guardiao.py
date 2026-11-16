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
  APPROVALS (new)     a STANDING approval (not paid, not voided) without a matching L2 burn ->
                      `release-unknown:approval-<nonce>-<seq>`; one that differs from its burn ->
                      `release-mismatch:approval-<nonce>-<seq>`. The Solana vault pays in two steps, so a wrong
                      approval of a large release is visible for `release_delay` before any token moves, and a
                      guardian pause voids it. The ids keep the parent's prefixes, so the parent pauses the vault.

Vault pause (`vault_pause: true`): this guardian signs the pause authorization for pause number `pause_count + 1`
with its secp256k1 keystore (`sol_keystore` / `sol_password_file`, default the L2 guardian keystore) and delivers
it with `sol_fee_payer`, an Ed25519 key that only pays the fee. Both steps are sol_vault.py commands; the pause
counts only when the vault account shows it.

A pause voids unpaid approvals; it never loses an exit. The burn stays on the L2, the vault has no paid record
for its nonce, and the signers certify it again after the pause (see docs/SOLANA-VAULT.md, section 3.5).

Config: the parent's keys for the L2 side (`kind: "stable"`, `provenance: true`, `l2_rpc`, `l2_chain_id`, `token`,
`keystore`, `password_file`, `state`, ...) plus `vault` (the vault's 20-byte id, `sourceVault` of the token),
`sol_rpc`, `vault_config`, and for `vault_pause` the keys above. `eth_rpc` and `eth_chain_id` are not used.

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
import guardiao  # noqa: E402
from guardiao import Guardian, Unverifiable, addr, b32, uint  # noqa: E402


class SolGuardian(Guardian):
    def __init__(self, cfg_path, dry_run=False):
        super().__init__(cfg_path, dry_run)
        if self.kind != 'stable' or not self.provenance:
            raise SystemExit('the Solana guardian needs kind "stable" and `provenance: true`')
        self.sol_cfg = {'sol_rpc': self.cfg['sol_rpc'], 'vault_config': self.cfg['vault_config']}
        self._nodes, self._records = {}, []

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
        self._nodes = {}
        return super().round()

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
            shown = {'nonce': r['nonce'], 'recipient': S.hx(r['recipient']), 'amount': r['amount'],
                     'burn_id': S.hx(r['native_burn']), 'record': r['key'], 'paid': paid, 'ready_at': r['ready_at']}
            tag = str(r['nonce']) if paid else f"approval-{r['nonce']}-{r['seq']}"
            if b is None:
                findings.append(('hard', f'release-unknown:{tag}', self.provenance_grace,
                                 {'reason': 'vault release without a matching L2 burn' if paid else
                                  'vault approval without a matching L2 burn (not paid yet: a pause voids it)', **shown}))
                continue
            if (shown['burn_id'], shown['recipient'], shown['amount']) != (b['burn_id'], b['eth_recipient'], b['amount']):
                findings.append(('hard', f'release-mismatch:{tag}', 0,
                                 {'reason': 'vault release differs from its L2 burn' if paid else
                                  'vault approval differs from its L2 burn (not paid yet: a pause voids it)',
                                  'release': shown, 'burn': b}))
                continue
            if paid:
                released[b['burn_id']] = r['key']
            if fin is None or b['block'] > fin:
                findings.append((self.release_before_final, f'release-before-final:{tag}', self.provenance_grace,
                                 {'reason': 'vault release of a burn not finalized on this guardian\'s L2',
                                  'release': shown, 'burn_block': b['block'], 'l2_finalized': fin}))
        return backing, released, findings

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


def main():
    guardiao.Guardian = SolGuardian  # the parent's main loop, with this class
    guardiao.main()


if __name__ == '__main__':
    main()
