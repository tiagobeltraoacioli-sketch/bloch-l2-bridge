#!/usr/bin/env python3
"""Automatic signer and relayer of the Solana bridge: tools/signatario-stable/vigia.py with a Solana source side.

  python3 sol_vigia.py --config CFG.json sign  [--once] [--interval 60]
  python3 sol_vigia.py --config CFG.json relay [--once] [--interval 60]

This is a subclass of `Vigia`. Everything on the L2 side and everything about files, rounds, feeds, budgets,
relay roles, L2 nonces and completion from canonical observations is the parent's code, unchanged. Only what the
parent reads from or sends to an Ethereum JSON-RPC is replaced by the same thing on the operator's own Solana
node, through sol_half.Node (program pin, cluster, vault equal to the configuration file) and sol_vault.py:

  deposits      the vault's deposit records at `finalized`, nonce 0 up to the vault's deposit count, each one
                checked against the vault's hash chain (the last head equals the vault's). Account state, not logs.
  a partial     a release certificate counts when its signature recovers to a signer in the vault configuration
                and its digest is the one recomputed here from its fields.
  released      the release record of the burn's nonce is PAID at `finalized` and names this burn.
  held burns    a burn made under a mint chain the vault's deposits do not back is parked and alerted
                (`release-held-provenance`), as in the parent.
  the recipient a burn is signed, and later paid, only when a WALLET is known for its 20-byte recipient
                (sol_recipient.py: the burn router's log, a registry announcement or a hint). A burn without one
                is parked and alerted (`release-held-no-wallet`).
  rent          a release record this relayer paid for is closed once it has been paid for the vault's
                `record_retention`; its rent comes back and the paid page keeps the nonce spent.
  relay         two steps, as the vault has them: `approve` (the threshold certificate, any fee payer), then
                `execute` once the approval is ready (large-release delay), the vault is not paused and the
                release bucket allows it. The wallet to pay is read from the SolanaRecipientRegistry on the L2
                (`recipient_registry`) and checked against the burn's 20-byte commitment here and by the vault.
                A guardian pause voids approvals that were not paid: the signers then certify the burn again by
                themselves (their Solana half refuses only a paid release or a standing approval), and the
                relayer approves and pays with the new certificate. Nothing is kept in a `sent` file for Solana:
                a transaction either confirms within its blockhash lifetime or never lands, and the release
                record is read back.

Config: the signer's signatario.py config plus the parent's keys (`shared_dir`, `token_from_block`, relayer keys
for the L2 side, `feed`, relay role ...) and
  `sol_half_config`      this operator's sol_half.py config (its `sol_rpc` and `vault_config` are used here)
  `sol_fee_payer`        relay only: an Ed25519 keypair file that pays Solana fees and rent; no power over the vault
  `burn_router`, `recipient_registry`, `router_from_block`, `registry_from_block`, `recipient_hints`
                         where a burn's wallet is looked for (also read from the Solana half's config)
  `sol_close_records`    relay only, default true: close paid records this fee payer paid for, after the retention
  `sol_create_recipient_account`  relay only, default false: pay the rent of a recipient's missing associated
                         token account (about 0.002 SOL each); otherwise the release waits and is alerted
  `anchor_max_age`       slots, default 9000 (as the Solana half)
`eth_rpc`, `eth_chain_id`, `vault_from_block` and the `eth_relayer_*` keys are not used. Development tool; UNAUDITED.
"""
import json
from pathlib import Path
import sys
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / 'signatario-stable'))
import solana_lib as S  # noqa: E402
from sol_half import Node  # noqa: E402
import bridge_feed  # noqa: E402
import sol_recipient  # noqa: E402
import vigia  # noqa: E402
from vigia import Vigia, WORD, log, option  # noqa: E402



class SolVigia(Vigia):
    def __init__(self, cfg_path):
        super().__init__(cfg_path)
        self.sol_cfg = json.loads(Path(self.cfg['sol_half_config']).read_text())
        self.anchor_max_age = int(self.cfg.get('anchor_max_age', 9000))
        self._nodes, self._records, self._wallets, self._burns_pass = {}, [], {}, None

    # ── this operator's Solana node ─────────────────────────────────────────
    def node(self, commitment='finalized'):
        """One pinned view per pass and commitment (program final and pinned, cluster, vault equal to the file)."""
        if commitment not in self._nodes:
            self._nodes[commitment] = Node(self.sol_cfg, commitment=commitment)
        return self._nodes[commitment]

    def new_pass(self):
        super().new_pass()
        self._nodes, self._burns_pass = {}, None

    def rounds(self, d, margin):
        """The parent's live rounds, without those the vault would refuse as older than its last guardian pause
        (R325-SOL-2): after a pause the signers open a new round at once instead of waiting for the old to expire."""
        v, limit = self.node().vault, self.node().config.max_valid_seconds
        return [(valid_until, r) for valid_until, r in super().rounds(d, margin)
                if not v['last_pause_at'] or valid_until > v['last_pause_at'] + limit]

    def eth_now(self):
        if self.cfg.get('eth_clock') == 'chain':
            n = self.node()
            return int(n.rpc.block_time(n.vault['context_slot']))
        return int(time.time())

    def check_design(self):
        """The config, the L2 token and the vault on this node name one route; the token is a BridgedStablecoinV3."""
        if self.design_checked:
            return
        if not self.provenance:
            raise SystemExit('the Solana vault always checks provenance: set `provenance: true`')
        a = self.node().a
        url = self.cfg['l2_rpc']
        head = self.call(url, self.token, 'mintHead()')
        if not WORD.fullmatch(head):
            raise SystemExit('the L2 token does not answer mintHead(): not a BridgedStablecoinV3')
        chain_id = int.from_bytes(self.node().config.source_chain_id, 'big')
        want = (S.hx(a.vault20), S.hx(a.route), chain_id)
        if (self.vault, self.route, int(str(self.cfg['source_chain_id']), 0)) != want:
            raise SystemExit(f'the config names another vault, route or cluster than the vault configuration file: {want}')
        token = ('0x' + self.call(url, self.token, 'sourceVault()')[-40:].lower(),
                 self.call(url, self.token, 'sourceRoute()').lower(), int(self.call(url, self.token, 'sourceChainId()'), 16))
        if token != want:
            raise SystemExit(f'the L2 token was deployed for another vault, route or cluster: {token}')
        self.design_checked = True

    def check_signer_sets(self):
        if self.signers_checked:
            return
        for a in self.feed.mint_signers:
            if not self.flag(self.cfg['l2_rpc'], self.token, 'isSigner(address)', a):
                raise RuntimeError(f'feed signer {a} is not a signer of {self.token}')
        members = {S.hx(s) for s in self.node().config.signers}
        for a in self.feed.release_signers:
            if a.lower() not in members:
                raise RuntimeError(f'feed signer {a} is not a signer of the Solana vault')
        self.signers_checked = True

    def check_chain_ids(self):
        if self.chains_checked:
            return
        for name, url in (('l2_rpc', self.cfg['l2_rpc']), ('l2_tx_rpc', self.l2_tx)):
            got, want = int(self.rpc(url, 'eth_chainId', []), 16), self.cfg.get('l2_chain_id')
            if want is None or got != int(str(want), 0):
                raise SystemExit(f'{name} answers chain id {got}, the config says {want}: refusing to relay')
        self.node()  # refuses another cluster, another program image or another vault
        self.chains_checked = True

    def check_relay_role(self):
        others = self.cfg.get('relay_other_gas_addresses')
        self.cfg['relay_other_gas_addresses'] = []  # the parent would ask for an Ethereum gas key
        try:
            super().check_relay_role()
        finally:
            self.cfg['relay_other_gas_addresses'] = others
        named = {str(a) for a in others or []}
        if named:
            l2 = self.cast_out('wallet', 'address', *self.relayer_wallet('l2')).lower()
            sol = S.b58encode(S.Keypair(self.cfg['sol_fee_payer']).public)
            if l2 in {a.lower() for a in named} or sol in named:
                raise SystemExit('a gas key of this relayer is listed in relay_other_gas_addresses: every relayer needs '
                                 'its own gas keys and nonce record')

    # ── discovery ───────────────────────────────────────────────────────────
    def deposits(self):
        """Deposit ids of the vault at `finalized` (discovery only; the Solana half verifies each again, with its
        margin). Records already read are kept while the hash chain still joins them to the vault's head."""
        n = self.node()
        a, count = n.a, n.vault['deposit_count']
        kept = self._records[:count]
        last = n.deposit(len(kept) - 1) if kept else None
        if kept and (last is None or last['head_after'] != kept[-1]['head_after']):
            log(kind='scan-rescan', scan='deposits', reason='a deposit record read earlier is no longer on this node')
            kept = []
        head = kept[-1]['head_after'] if kept else a.genesis
        for nonce in range(len(kept), count):
            d = n.deposit(nonce)
            if d is None:
                raise RuntimeError(f'deposit record {nonce} is below the deposit count but absent at finalized')
            if S.chain_step(head, d['id'], d['amount'], d['l2_recipient']) != d['head_after']:
                raise RuntimeError(f'deposit record {nonce} does not extend the vault hash chain')
            head = d['head_after']
            kept.append(d)
        if head != n.vault['head']:
            self._records = []
            raise RuntimeError('the deposit records do not end at the vault head; read again on the next pass')
        self._records = kept
        self.deposit_fields = {S.hx(d['id']): (d['amount'], S.hx(d['l2_recipient'])) for d in kept}
        self.deposits_read = True
        return [S.hx(d['id']) for d in kept]

    def burns(self):
        found = super().burns()
        self._burns_pass = {b['burn_id']: b for b in found}
        return found

    def burn_of(self, burn_id):
        if self._burns_pass is None:
            self.burns()
        return self._burns_pass.get(burn_id)

    def eth_block(self, tag):
        """The parent's anchor pre-check (`round_fits`), on slots: 'latest' is the finalized slot of this node."""
        def read():
            n = self.node()
            if tag == 'latest':
                return {'number': hex(n.rpc.slot('finalized'))}
            block_hash = n.rpc.block_hash(int(tag, 16), 'finalized')
            return None if block_hash is None else {'number': tag, 'hash': S.hx(block_hash)}
        return self.chain_read(('block', tag), read)

    def recipient_cfg(self):
        """Where a burn's wallet is looked for: the Solana half's keys, or this config's (the relayer has no half)."""
        return {k: self.cfg.get(k, self.sol_cfg.get(k)) if k != 'l2_rpc' else (self.sol_cfg.get(k) or self.cfg.get(k))
                for k in ('l2_rpc', 'burn_router', 'router_from_block', 'recipient_registry', 'registry_from_block',
                          'recipient_hints')}

    def wallet_for(self, b):
        """The wallet behind a burn's 20-byte recipient (sol_recipient.py), or None: looked up once per burn."""
        key = b['burn_id']
        if self._wallets.get(key) is None:
            self._wallets[key] = sol_recipient.find_wallet(self.recipient_cfg(), S.unhex(b['recipient'], 20), key)[0]
        return self._wallets[key]

    def unpayable(self, b):
        """Held, not lost. (1) The burn was made under a mint chain this vault's deposits do not back: the vault
        refuses it (ProvenanceMismatch) whatever is signed. (2) No wallet is known for the burn's 20-byte recipient
        (R325-SOL-1): the Solana half would refuse it. Neither costs a rebuild or a certificate; both are alerted."""
        if 'mint_head' not in b:
            return False
        n = self.node()
        backing = n.deposit(b['mint_count'] - 1) if 1 <= b['mint_count'] <= n.vault['deposit_count'] else None
        if backing is not None and S.hx(backing['head_after']) == b['mint_head']:
            if self.wallet_for(b) is not None:
                return False
            if b['burn_id'] not in self.parked_logged:
                log(kind='alert', severity='critical', id='release-held-no-wallet', burn=b['burn_id'], nonce=b.get('nonce'),
                    recipient=b['recipient'], reason=sol_recipient.HELD)
            return True
        if b['burn_id'] not in self.parked_logged:
            log(kind='alert', severity='critical', id='release-held-provenance', burn=b['burn_id'], mint_count=b['mint_count'],
                mint_head=b['mint_head'], reason='the burn was made under a mint chain the vault deposits do not back')
        return True

    # ── completion: the vault's accounts decide ─────────────────────────────
    def release_state(self, burn_id, commitment='finalized'):
        """(burn, release record or None) for a burn this node's L2 shows; (None, None) when the burn is not known."""
        b = self.burn_of(burn_id)
        if b is None:
            return None, None
        return b, self.node(commitment).release(b['nonce'])

    def released(self, burn_id):
        """Paid at `finalized`: the record says so and names this burn, or the record was closed after the retention
        and the paid page holds the nonce's bit (the nonce is the vault's replay key)."""
        b, r = self.release_state(burn_id)
        return bool(r and r['state'] == 2 and (r.get('closed') or S.hx(r['native_burn']) == burn_id))

    def release_finished(self, burn_id):
        """Paid at `finalized`, read every pass: the parent's finished-item cache is an Ethereum block anchor and is
        not used for Solana (one account read per open or past burn and pass)."""
        return self.released(burn_id)

    # ── partials ────────────────────────────────────────────────────────────
    def release_partial(self, path, burn_id, rnd):
        try:
            rec = json.loads(path.read_text())
            signer, digest, sig = rec['signer'], rec['digest'], rec['signature']
            if not (vigia.ADDRESS.fullmatch(signer) and WORD.fullmatch(digest) and vigia.SIGNATURE.fullmatch(sig)):
                return None
            a, config = self.node().a, self.node().config
            if rec.get('kind') != 'stable-release' or str(rec.get('source_vault')).lower() != self.vault \
                    or S.unhex(signer, 20) not in config.signers:
                return None
            rel, c = rec['release'], rec['context']
            if str(rel['nativeBurn']).lower() != burn_id or rnd.name != bridge_feed.round_name(rec):
                return None
            item = {'route': S.unhex(rel['route'], 32), 'nonce': int(rel['nonce']), 'recipient': S.unhex(rel['recipient'], 20),
                    'amount': int(rel['amount']), 'nativeBurn': S.unhex(rel['nativeBurn'], 32), 'mintCount': int(rel['mintCount']),
                    'mintedTotal': int(rel['mintedTotal']), 'mintHead': S.unhex(rel['mintHead'], 32)}
            ctx = {'validUntil': int(c['validUntil']), 'sourceAnchorNumber': int(c['sourceAnchorNumber']),
                   'sourceAnchorHash': S.unhex(c['sourceAnchorHash'], 32),
                   'nativeFinalizedNumber': int(c['nativeFinalizedNumber']),
                   'nativeFinalizedHash': S.unhex(c['nativeFinalizedHash'], 32)}
            if item['route'] != a.route:
                return None
            want = S.hx(S.eip191(S.release_authorization(config.source_chain_id, a.vault20, item, ctx)))
            if want != digest.lower():
                return None
            rc, _, _ = self.run([self.cast, 'wallet', 'verify', '--no-hash', '--address', signer, digest, sig])
            return rec if rc == 0 else None
        except (OSError, ValueError, KeyError, TypeError, RuntimeError, S.Refused, S.RpcError):
            return None

    # ── relay: approve, then execute ────────────────────────────────────────
    def sol_vault(self, command, *argv):
        rc, out, err = self.run([sys.executable, HERE / 'sol_vault.py', command, '--config', self.sol_cfg['vault_config'],
                                 '--rpc', self.sol_cfg['sol_rpc'], '--fee-payer', self.cfg['sol_fee_payer'], *argv])
        try:
            return json.loads(out)
        except ValueError:
            return {'ok': False, 'reason': 'no JSON from sol_vault.py: ' + err.strip()[-300:]}

    def relay_release(self, d):
        burn_id = '0x' + d.name
        if not WORD.fullmatch(burn_id):
            return
        state = self.burn_done(d, burn_id)
        if state:
            if state == 'new':
                log(kind='relay-release', burn=burn_id, done=True)
            b, record = self.release_state(burn_id, 'confirmed')
            if b is not None and record is not None:
                self.close_if_due(burn_id, b, record)
            return
        b, record = self.release_state(burn_id, 'confirmed')
        if b is None:
            return  # not a burn of this relayer's finalized L2: a directory alone is no reason to act
        if record is not None and record['state'] == 2:
            self.close_if_due(burn_id, b, record)
            return  # paid at `confirmed`; `burn_done` records it once it is final
        if record is None or not record['standing']:
            live = self.quorum_release(d, burn_id)
            if live is None or not self.backup_due('eth', f'release:{burn_id}'):
                return
            rnd, _ = live
            res = self.sol_vault('approve', '--cert', rnd / 'release.call')
            log(kind='relay-approve', burn=burn_id, nonce=b['nonce'], round=rnd.name, ok=res.get('ok'),
                tx=res.get('signature'), units=res.get('units'), ready_at=res.get('readyAt'),
                reason=res.get('reason') or res.get('error_name'), reapproved=record is not None)
            if not res.get('ok'):
                return
            self._nodes.pop('confirmed', None)
            b, record = self.release_state(burn_id, 'confirmed')
            if record is None or not record['standing']:
                return
        if (S.hx(record['native_burn']), S.hx(record['recipient']), record['amount']) != (burn_id, b['recipient'], b['amount']):
            log(kind='alert', severity='critical', id='approval-mismatch', burn=burn_id, nonce=b['nonce'],
                reason='the vault holds an approval under this burn nonce that differs from the L2 burn: not paid by this '
                       'relayer, left to the guardians\' pause', approved_amount=record['amount'],
                approved_recipient=S.hx(record['recipient']))
            return
        self.execute(burn_id, b, record)

    def close_if_due(self, burn_id, b, record):
        """A record this relayer's fee payer paid for, paid longer ago than the retention: closing it returns its rent
        (review 325, R325-SOL-4). The paid page keeps the nonce spent. Other relayers' records are left to them."""
        if record.get('closed') or self.cfg.get('sol_close_records') is False:
            return
        n = self.node('confirmed')
        if record['payer'] != S.Keypair(self.cfg['sol_fee_payer']).public:
            return
        now = int(n.rpc.block_time(n.vault['context_slot']))
        if now < record['paid_at'] + n.config.record_retention:
            return
        res = self.sol_vault('close', '--nonce', str(b['nonce']))
        log(kind='relay-close', burn=burn_id, nonce=b['nonce'], ok=res.get('ok'), tx=res.get('signature'), units=res.get('units'),
            reason=res.get('reason') or res.get('error_name'))

    def execute(self, burn_id, b, record):
        n = self.node('confirmed')
        now = int(n.rpc.block_time(n.vault['context_slot']))
        wait = ('the vault is paused' if now < n.vault['paused_until'] else
                'the large-release delay has not passed' if now < record['ready_at'] else
                'the release bucket has not refilled' if record['amount'] > S.available_to_release(n.vault, now) else None)
        if wait:
            log(kind='relay-execute', burn=burn_id, nonce=b['nonce'], waiting=True, reason=wait, ready_at=record['ready_at'])
            return
        wallet = self.wallet_for(b)
        if wallet is None:
            log(kind='alert', severity='critical', id='approved-without-wallet', burn=burn_id, commitment=b['recipient'],
                reason='the vault holds an approval for a burn with no known wallet: honest signers do not certify one. '
                       'Not paid by this relayer')
            return
        argv = ['--nonce', str(b['nonce']), '--owner', S.b58encode(wallet)]
        if n.token_balance(S.associated_token_address(wallet, n.config.mint)) is None:
            if not self.cfg.get('sol_create_recipient_account'):
                log(kind='alert', severity='soft', id='recipient-account-missing', burn=burn_id, wallet=S.b58encode(wallet),
                    reason='the wallet has no associated token account for the mint: its owner creates it, or set '
                           'sol_create_recipient_account')
                return
            argv.append('--create-account')
        if not self.backup_due('eth', f'execute:{burn_id}'):
            return
        res = self.sol_vault('execute', *argv)
        log(kind='relay-execute', burn=burn_id, nonce=b['nonce'], ok=res.get('ok'), tx=res.get('signature'),
            units=res.get('units'), paid=res.get('paidAmount'), reason=res.get('reason') or res.get('error_name'))
        self._nodes.pop('confirmed', None)


def main():
    args = sys.argv[1:]
    v = SolVigia(option(args, '--config'))
    mode = 'sign' if 'sign' in args else 'relay' if 'relay' in args else None
    if mode is None:
        raise SystemExit(__doc__)
    interval = int(option(args, '--interval', '60'))
    if mode == 'relay':  # fail at start, not at the first send
        v.relayer_wallet('l2')
        S.Keypair(v.cfg['sol_fee_payer'])
    while True:
        try:
            v.sign_round() if mode == 'sign' else v.relay_round()
        except (S.Refused, S.RpcError) as e:
            log(kind=mode, error=f'{type(e).__name__}: {e}', detail={k: str(x) for k, x in getattr(e, 'detail', {}).items()})
        except Exception as e:  # noqa: BLE001 - a daemon keeps running; the next round retries
            log(kind=mode, error=f'{type(e).__name__}: {e}')
        if '--once' in args:
            break
        time.sleep(interval)


if __name__ == '__main__':
    main()
