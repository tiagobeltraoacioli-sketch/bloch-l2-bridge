#!/usr/bin/env python3
"""Stellar half of the bridge signer: the "Ethereum-half interface" of tools/signatario-stable/README.md, answered
from a Stellar RPC and the Soroban vault (stellar/vault) instead of an Ethereum node and ProvenanceSourceVault.

  stellar_half.py --config XLM.json deposit --deposit-id 0xID [--fields FILE]
  stellar_half.py --config XLM.json release --intent INTENT.json

It prints one JSON object: {"ok": true, ...} with exit 0, or {"ok": false, "reason": ...} with exit 1. It reads only
this signer's own Stellar RPC (and, when configured, further RPCs that must agree) and signs only what it checked.

deposit  Stellar closes a ledger by consensus and never reorganises, so the rule is: the ledger is closed, it is at
         least `finality_ledgers` (default 12, about a minute) behind this node's latest ledger, the node is fresh
         (latest close time within `max_ledger_age` seconds of the wall clock), and every configured RPC reports the
         same hash for that ledger. The deposit is taken from the vault's STATE, not from an event feed: the id
         carries its nonce n, and the vault keeps the deposit-chain head after every deposit, so the fields (from the
         `deposited` event, or from `--fields`, any source) are accepted only if the id recomputes from them and
         keccak(head[n], id, amount, recipient) equals the stored head[n + 1]. An RPC that has pruned the event
         (the default retention is about 7 days) can therefore not make this half sign something else; it can only
         make it wait for the fields. The vault's code is pinned by its Wasm hash. Signs nothing.
release  the pinned Wasm; the route; releases enabled; no pause; the vault's `burn_status` of the burn nonce and burn
         id is 0 (open): the vault reads its own records, restored if archived, and a read error is never "open";
         amount within `total_locked` and the release bucket; the burn's chain head
         equals the vault's head at its mint count; the Stellar recipient is the one the signer read from its
         own final L2 by the route's one rule (stellar_net.burn_destination, in the intent as `l2.stellar`): for a
         router burn it must hash to the burn's 20-byte recipient, checked here again (and if the exit is HELD,
         that address cannot receive the asset on this node's ledger, the latest redirect by the exit's own burner,
         final at that block, is paid instead); for a burn made directly on the token it is its burner's LATEST
         claim on the router at that final block, which this half reads again from its own `l2_rpc` and requires
         to be the same; the vault's balance covers its books. `validUntil` in (ledger time, ledger time + max_valid_seconds], never above the vault's
         MAX_VALIDITY. The anchor is a recent closed ledger of this node; a proposed anchor is accepted only if this
         node holds the same hash for that ledger (the signers then share one ledger history). The anchor is not part
         of the signed digest (the vault cannot check a ledger hash); it travels with the certificate so the k
         partials agree. The digest is computed here and must equal the vault's `release_digest`. A local database
         refuses two different releases for one nonce or one burn.
         The certificate names the vault's pause count: a guardian pause voids every certificate signed before it and
         every release still queued. A burn whose queued release was voided is simply open again (`burn_status` 0),
         and this half signs it again like any other burn: no operator step. A burn whose nonce or id counts for
         another release (`burn_status` 3: a forgery took it) is refused until a guardian pause voids that one.
         The signature is an Ethereum personal message (EIP-191) over the vault's digest.
direct   A burn made directly on the token is NEVER paid to the 20 bytes it names. It is paid to the latest address
         its burner claimed with `StellarBurnRouter.claimDirectBurn` on the L2, read from the final L2. There are
         no claim files and no hint files. This half remembers the release it signed for a nonce and for a burn
         and signs another one only once its earlier signature is dead for the vault (validUntil passed on the
         ledger clock, or a pause moved the count) and the burn is still open: it never holds two live signatures
         for one burn, so the latest naming before the vault records a release wins and none after.
asset    `asset_contract` (the Stellar Asset Contract the vault must hold; on the public network Circle's USDC,
         stellar_net.CIRCLE_USDC) is REQUIRED: the route this half signs for is recomputed from that pinned asset,
         never from the asset the deployed vault reports.

Config (one JSON per signer): `stellar_rpc`, `network_passphrase`, `vault`, `vault_wasm_hash`, `view_account`,
`keystore`, `password_file`, `db`, `asset_contract`; optional `stellar_cli`, `stellar_config_dir`, `cast`, `stellar_rpc_others` (list),
`vault_from_ledger`, `finality_ledgers` (12), `max_ledger_age` (60), `valid_seconds` (1800), `max_valid_seconds`
(3600), `l2_rpc` (this operator's L2 RPC: when given, a claimed recipient or a redirect is read from it again and
must agree), `asset_code` and `asset_issuer` (REQUIRED for a release: the classic asset of `asset_contract`;
the half never signs for an address that cannot receive it, R331-XLM-4P-1).
"""
import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import stellar_net as sn  # noqa: E402


def answer(ok, **fields):
    print(json.dumps({'ok': ok, **fields}, indent=2))
    raise SystemExit(0 if ok else 1)


def refuse(reason, **detail):
    answer(False, reason=reason, **detail)


def hx(b):
    return '0x' + bytes(b).hex()


def unhex(s):
    return s[2:] if isinstance(s, str) and s.startswith('0x') else s


class Half:
    def __init__(self, cfg_path):
        self.cfg = json.loads(Path(cfg_path).read_text())
        c = self.cfg
        self.net = sn.Net(c)
        self.others = [sn.Net({**c, 'stellar_rpc': u}) for u in c.get('stellar_rpc_others', [])]
        self.cast = c.get('cast', str(Path.home() / '.foundry/bin/cast'))
        try:
            if sn.strkey_decode(c.get('asset_contract'))[0] != 'contract':
                raise sn.StellarError('not a contract address')
        except sn.StellarError as e:
            refuse('config: `asset_contract` (the asset contract the vault must hold) is missing or invalid', error=str(e))
        if self.net.passphrase == sn.PUBLIC_PASSPHRASE and c['asset_contract'] != sn.CIRCLE_USDC['contract']:
            refuse('on the public network the asset contract is Circle\'s USDC', pinned=sn.CIRCLE_USDC['contract'],
                   config=c['asset_contract'])
        self.finality = int(c.get('finality_ledgers', 12))
        self.max_age = int(c.get('max_ledger_age', 60))
        self.db_path = Path(c['db'])

    # ── shared checks ────────────────────────────────────────────────────────
    def fresh_latest(self):
        latest = self.net.latest()
        age = int(time.time()) - latest['close_time']
        if age > self.max_age:
            refuse('the Stellar node is stale: its latest ledger is old', age=age, max=self.max_age, latest=latest)
        return latest

    def check_code(self):
        wasm, live_until, latest = self.net.wasm_hash()
        if wasm != unhex(self.cfg['vault_wasm_hash']).lower():
            refuse('the vault runs another Wasm than the pinned one', got=wasm, pinned=self.cfg['vault_wasm_hash'])
        return live_until, latest

    def derived(self):
        d = self.net.view('derived')
        c = self.net.view('config')
        nid = sn.network_id(self.net.passphrase)
        if bytes.fromhex(d['network_id']) != nid or bytes.fromhex(d['vault_id']) != sn.strkey_decode(self.net.vault)[1]:
            refuse('the vault reports another network or contract id than this node and config', derived=d)
        if c['token'] != self.cfg['asset_contract']:
            refuse('the vault holds another asset contract than the pinned one: nothing is signed for it',
                   vault=c['token'], pinned=self.cfg['asset_contract'])
        route = sn.route_id(self.net.passphrase, c['source_domain'], c['native_domain'], c['asset'],
                            self.cfg['asset_contract'], self.net.vault, c['cap'])
        if route.hex() != d['route'] or bytes.fromhex(d['vault20']) != sn.vault20(self.net.vault):
            refuse('the route recomputed from the pinned asset and the vault configuration differs from the stored one',
                   derived=d)
        return d, c

    def same_ledger_everywhere(self, sequence, own_hash):
        for other in self.others:
            try:
                theirs = other.ledger(sequence)['hash']
            except sn.StellarError as e:
                refuse('another configured Stellar RPC cannot confirm the ledger', rpc=other.url, error=str(e))
            if theirs != own_hash:
                refuse('the configured Stellar RPCs disagree on a closed ledger: holding', ledger=sequence,
                       own=own_hash, other=theirs, rpc=other.url)

    # ── deposit ──────────────────────────────────────────────────────────────
    def find_fields(self, deposit_id, hint):
        if hint:
            f = json.loads(Path(hint).read_text())
            return {'sender': f['sender'], 'amount': int(f['amount']), 'l2_recipient': unhex(f['l2_recipient']),
                    'tx': f.get('tx'), 'ledger': f.get('ledger')}
        start = int(self.cfg.get('vault_from_ledger', 0))
        health = self.net.health()
        start = max(start, int(health.get('oldestLedger', 1)))
        while True:
            events, latest, _ = self.net.events(start)
            for e in events:
                if e['name'] == 'deposited' and e['topics'] and e['topics'][0] == deposit_id.hex():
                    d = e['data']
                    return {'sender': d['sender'], 'amount': int(d['amount']), 'l2_recipient': d['l2_recipient'],
                            'tx': e['tx'], 'ledger': e['ledger']}
            if not events or events[-1]['ledger'] >= latest:
                return None
            start = events[-1]['ledger'] + 1

    def deposit(self, args):
        deposit_id = sn.b32(args['--deposit-id'])
        latest = self.fresh_latest()
        self.check_code()
        derived, _ = self.derived()
        route = bytes.fromhex(derived['route'])
        nonce = int.from_bytes(deposit_id[:8], 'big')
        try:
            fields = self.find_fields(deposit_id, args.get('--fields'))
        except (KeyError, ValueError, OSError) as e:
            refuse('the deposit fields could not be read', error=str(e))
        if fields is None:
            refuse('no `deposited` event for this id in the RPC\'s retained history; supply --fields or wait',
                   deposit_id=hx(deposit_id))
        sender, amount, l2 = fields['sender'], fields['amount'], sn.b20(fields['l2_recipient'])
        if amount <= 0 or l2 == b'\0' * 20:
            refuse('the deposit has a zero amount or a zero L2 recipient')
        if sn.deposit_id(route, nonce, sender, amount, l2) != deposit_id:
            refuse('the deposit id recomputed from the fields differs', fields=fields)
        # The canonical observation: the vault's own chain of deposits, in ledger state.
        if nonce == 0:
            previous = bytes.fromhex(derived['genesis'])
        else:
            state, entry, _ = self.net.record_state('Head', nonce)
            if state != 'live':
                refuse(f'the previous chain head is {state} in ledger state', nonce=nonce)
            previous = bytes.fromhex(sn.scval(entry['dataJson']['contract_data']['val']))
        state, entry, entry_latest = self.net.record_state('Head', nonce + 1)
        if state != 'live':
            refuse(f'the chain head of this deposit is {state} in ledger state: the deposit is not there (or needs a '
                   'restore)', nonce=nonce)
        stored = bytes.fromhex(sn.scval(entry['dataJson']['contract_data']['val']))
        if sn.next_head(previous, deposit_id, amount, l2) != stored:
            refuse('the vault\'s deposit chain does not hold this deposit with these fields', nonce=nonce,
                   stored=hx(stored))
        ledger = int(entry['lastModifiedLedgerSeq'])
        if fields.get('ledger') is not None and int(fields['ledger']) > ledger:
            refuse('the event is newer than the vault state it describes', event=fields['ledger'], state=ledger)
        final_number = min(latest['sequence'], entry_latest) - self.finality
        if ledger > final_number:
            refuse('the deposit ledger is closed but not yet past the margin', ledger=ledger, latest=latest['sequence'],
                   margin=self.finality)
        own = self.net.ledger(ledger)
        self.same_ledger_everywhere(ledger, own['hash'])
        for other in self.others:
            s2, e2, _ = other.record_state('Head', nonce + 1)
            if s2 != 'live' or bytes.fromhex(sn.scval(e2['dataJson']['contract_data']['val'])) != stored:
                refuse('another configured Stellar RPC does not show this deposit: holding', rpc=other.url)
        answer(True, source_chain_id=int.from_bytes(sn.network_id(self.net.passphrase), 'big'),
               vault=hx(sn.vault20(self.net.vault)), vault_contract=self.net.vault, route=hx(route),
               deposit_id=hx(deposit_id), nonce=nonce, sender=sender, amount=amount, pq_recipient_hash=hx(b'\0' * 12 + l2),
               tx_hash=fields.get('tx'), log_index=0, block_number=ledger, block_hash='0x' + own['hash'],
               finalized=True, finalized_number=final_number)

    def sign(self, digest, members):
        """This signer's signature over `digest` as an Ethereum personal message. The key stays in the keystore and
        `cast` signs; what it printed is accepted only if it is a well-formed signature that recovers, in this
        process, to one of the vault's signers. Returns (signature, address without 0x)."""
        done = subprocess.run([self.cast, 'wallet', 'sign', '--keystore', str(self.cfg['keystore']),
                               '--password-file', str(self.cfg['password_file']), '--', hx(sn.b32(digest))],
                              capture_output=True, text=True)
        signature = done.stdout.strip().lower()
        who = sn.recover_personal(digest, signature)
        if done.returncode or who is None:
            refuse('signing failed', stderr=done.stderr.strip()[-500:])
        if who[2:] not in members:
            refuse('this keystore is not one of the vault\'s signers', signer=who)
        return signature, who[2:]

    # ── release ──────────────────────────────────────────────────────────────
    def stellar_recipient(self, intent, commitment):
        """The recipient the signer read from its final L2 (`l2.stellar` of the intent), checked again here."""
        l2 = intent.get('l2') or {}
        named = l2.get('stellar') or {}
        recipient, via = named.get('recipient'), named.get('via')
        try:
            sn.strkey_decode(recipient)
            if via == 'router':
                if sn.recipient_commitment(recipient) != commitment:
                    refuse('the recipient does not hash to the burn\'s recipient commitment', recipient=recipient)
                redirect = named.get('redirect')
                if redirect is not None:
                    sn.strkey_decode(redirect)
                    if self.cfg.get('l2_rpc'):
                        own = sn.redirects_of(sn.L2(self.cfg['l2_rpc']), named['router'], intent['release']['nonce'],
                                              l2['finalized_number'])
                        if (own[-1] if own else None) != redirect:
                            refuse('this operator\'s L2 RPC holds another redirect (or none) for this exit at that '
                                   'final block: holding', intent=redirect, own=own[-1:] or None)
                    # The redirect is paid INSTEAD only while the exit is held: the address given to burnTo cannot
                    # receive the asset on this node's ledger. Otherwise the exit is paid where burnTo said.
                    if self.cannot_receive(recipient):
                        problems = self.cannot_receive(redirect)
                        if problems:
                            refuse('the exit is held (its address cannot receive the asset) and the redirect cannot '
                                   'receive it either: holding', problems=problems)
                        return redirect, 'redirect'
                # R331-XLM-4P-1: never sign for an address that cannot receive. With a release delay the vault
                # QUEUES a release and pins its recipient, so a certificate for such an address would queue an exit
                # that can never execute and that no redirect or newer claim could change until a pause. Holding
                # here keeps the burn open: the burner redirects it (router exit), claims again (direct burn), or
                # the account adds its trustline, and the ordinary rule pays it.
                problems = self.cannot_receive(recipient)
                if problems:
                    refuse('held: the address this exit is paid to cannot receive the asset on this ledger; the exit\'s '
                           'burner may redirect it with StellarBurnRouter.redirectHeldBurn, or the account may add its '
                           'trustline', recipient=recipient, problems=problems)
            elif via == 'claim':
                if self.cfg.get('l2_rpc'):
                    again = sn.claim_of(sn.L2(self.cfg['l2_rpc']), named['router'], l2['from'],
                                        intent['release']['nonce'], l2['finalized_number'])
                    if again != recipient:
                        refuse('this operator\'s L2 RPC holds another claim (or none) for this burn at that final '
                               'block: holding', intent=recipient, own=again)
                problems = self.cannot_receive(recipient)   # R331-XLM-4P-1, as for a router exit
                if problems:
                    refuse('held: the address the burner claimed cannot receive the asset on this ledger; the burner '
                           'may claim again with StellarBurnRouter.claimDirectBurn, or the account may add its '
                           'trustline', recipient=recipient, problems=problems)
            else:
                refuse('the intent does not say how the recipient was read (router or claim)')
        except (sn.StellarError, KeyError, TypeError, ValueError) as e:
            refuse('the intent names no usable Stellar recipient', error=str(e))
        return recipient, via

    def cannot_receive(self, address):
        """[] when `address` can receive the vault's asset on this node's latest ledger; otherwise what is missing.
        A contract (`C...`) holds the asset without a trustline. An account needs to exist and to hold a trustline
        for `asset_code:asset_issuer` that the issuer authorized. Needs `asset_code` and `asset_issuer`, whose asset
        contract must be the pinned `asset_contract`; without them nothing is signed (fail closed)."""
        c = self.cfg
        try:
            code, issuer = c['asset_code'], c['asset_issuer']
            if sn.asset_contract_id(self.net.passphrase, code, issuer) != c['asset_contract']:
                raise ValueError('asset_code:asset_issuer is not the pinned asset_contract')
        except (KeyError, TypeError, ValueError, sn.StellarError) as e:
            refuse('a release needs `asset_code` and `asset_issuer` of the pinned asset to tell whether the address '
                   'paid can receive it: holding', error=str(e))
        if sn.strkey_decode(address)[0] == 'contract':
            return []
        return sn.fee_account_problems(self.net, address, code, issuer)

    def release(self, args):
        intent = json.loads(Path(args['--intent']).read_text())
        rel = intent['release']
        native = intent['native']
        latest = self.fresh_latest()
        self.check_code()
        derived, config = self.derived()
        state = self.net.view('state')
        if unhex(rel['route']).lower() != derived['route']:
            refuse('the release is for another route', release=rel['route'], vault=derived['route'])
        if int(intent.get('source_chain_id', -1)) != int.from_bytes(sn.network_id(self.net.passphrase), 'big'):
            refuse('the intent names another source network')
        if unhex(intent.get('vault', '')).lower() != sn.vault20(self.net.vault).hex():
            refuse('the intent names another vault')
        if not state['releases_enabled']:
            refuse('releases are not enabled on the vault')
        now = latest['close_time']
        if now < int(state['paused_until']):
            refuse('the vault is paused by a guardian', paused_until=state['paused_until'])
        nonce, amount = int(rel['nonce']), int(rel['amount'])
        burn = sn.b32(rel['nativeBurn'])
        status = self.net.burn_status(nonce, burn)
        if status in (1, 2):
            refuse('this burn is already recorded by the vault (' + ('queued' if status == 1 else 'paid') + ')', nonce=nonce)
        if status != 0:
            refuse('the vault counts this nonce or this burn id for another release: held until a guardian pause '
                   'voids that one', nonce=nonce, status=status)
        if amount <= 0 or amount > int(state['total_locked']):
            refuse('the amount is zero or above the vault\'s locked total', amount=amount, locked=state['total_locked'])
        if amount > int(self.net.view('available_to_release')):
            refuse('the release bucket does not allow this amount now; retry later', amount=amount)
        mint_count = int(rel['mintCount'])
        if mint_count == 0 or mint_count > int(state['deposit_count']):
            refuse('the burn states a mint count the vault has no deposits for', mint_count=mint_count,
                   deposits=state['deposit_count'])
        head_state, entry, _ = self.net.record_state('Head', mint_count)
        if head_state != 'live':
            refuse(f'the vault\'s chain head at the burn\'s mint count is {head_state}; restore it first',
                   mint_count=mint_count)
        if sn.scval(entry['dataJson']['contract_data']['val']) != unhex(rel['mintHead']).lower():
            refuse('the burn was made under another mint chain than the vault\'s deposits: nothing is signed',
                   mint_count=mint_count)
        backing = self.net.view('backing')
        if int(backing['balance']) < int(backing['required']):
            refuse('the vault holds less than its books need (clawback?): nothing is signed', backing=backing)
        commitment = sn.b20(rel['recipient'])
        recipient, via = self.stellar_recipient(intent, commitment)
        if recipient in (self.net.vault, config['token']):
            refuse('the recipient is the vault or the asset contract')
        if int(native['nativeFinalizedHash'], 16) == 0:
            refuse('zero L2 block hash in the context')

        max_valid = min(int(self.cfg.get('max_valid_seconds', 3600)), sn.MAX_VALIDITY)
        proposed = intent.get('proposed_context')
        if proposed:
            valid_until = int(proposed['validUntil'])
            anchor = int(proposed['sourceAnchorNumber'])
            if not now < valid_until <= now + max_valid:
                refuse('the proposed validUntil is outside (ledger time, ledger time + max_valid_seconds]',
                       validUntil=valid_until, now=now)
            if anchor > latest['sequence']:
                refuse('the proposed anchor ledger is ahead of this node', anchor=anchor, latest=latest['sequence'])
            own = self.net.ledger(anchor)
            if own['hash'] != unhex(proposed['sourceAnchorHash']).lower():
                refuse('this node holds another hash for the proposed anchor ledger: another ledger history',
                       anchor=anchor, own=own['hash'], proposed=proposed['sourceAnchorHash'])
        else:
            valid_until = now + min(int(self.cfg.get('valid_seconds', 1800)), max_valid)
            anchor = latest['sequence'] - 1
            own = self.net.ledger(anchor)
        self.same_ledger_everywhere(anchor, own['hash'])

        item = {'route': derived['route'], 'nonce': nonce, 'recipient': recipient, 'amount': amount,
                'native_burn': burn.hex(), 'mint_count': mint_count, 'minted_total': int(rel['mintedTotal']),
                'mint_head': unhex(rel['mintHead']).lower()}
        ctx = {'valid_until': valid_until, 'pause_count': int(state['pause_count']), 'native_finalized_number': int(native['nativeFinalizedNumber']),
               'native_finalized_hash': unhex(native['nativeFinalizedHash']).lower()}
        digest = sn.release_digest(self.net.passphrase, self.net.vault, item, ctx)
        onchain = self.net.view('release_digest', item=item, context=ctx)
        if onchain != digest.hex():
            refuse('the digest computed here differs from the vault\'s', local=hx(digest), vault=onchain)

        # Equivocation guard, under a lock: one release per nonce and per burn, whatever the vault would accept later.
        core = {'nonce': nonce, 'recipient': recipient, 'amount': amount, 'burn': burn.hex(),
                'mint_count': mint_count, 'mint_head': item['mint_head']}
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with open(str(self.db_path) + '.lock', 'w') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            db = json.loads(self.db_path.read_text()) if self.db_path.exists() else {'nonces': {}, 'burns': {}}
            # A burn's destination may change before the vault records a release (the burner's latest claim, a
            # held exit's redirect): see `resign_allowed`.
            for table, key in (('nonces', str(nonce)), ('burns', burn.hex())):
                prior = db[table].get(key)
                if prior is not None and not resign_allowed(prior, core, now, int(state['pause_count'])):
                    refuse('this signer already signed another release for this nonce or burn, and that signature is '
                           'still live for the vault', prior=prior, now=core)
            record = {'core': core, 'valid_until': valid_until, 'pause_count': int(state['pause_count'])}
            db['nonces'][str(nonce)] = record
            db['burns'][burn.hex()] = record
            tmp = self.db_path.with_suffix('.tmp')
            tmp.write_text(json.dumps(db, indent=2) + '\n')
            os.replace(tmp, self.db_path)

        # An Ethereum personal message over the vault's 32-byte digest (no `--no-hash`: cast applies EIP-191).
        signature = self.sign(digest, config['signers'])
        signer = '0x' + signature[1]
        signature = signature[0]
        answer(True, signer=signer, release=rel, stellar_recipient=recipient, vault_contract=self.net.vault,
               pause_count=ctx['pause_count'], via=via, vault_digest=hx(digest),
               context={'validUntil': valid_until, 'sourceAnchorNumber': anchor, 'sourceAnchorHash': '0x' + own['hash'],
                        'nativeFinalizedNumber': ctx['native_finalized_number'],
                        'nativeFinalizedHash': native['nativeFinalizedHash']},
               digest=hx(sn.personal(digest)), signature=signature)


def resign_allowed(prior, core, now, pause_count):
    """May this signer sign `core` for a burn it already signed `prior` for? Yes for the same release (a renewal).
    For another one only if (1) it differs in the recipient alone (a newer claim of a direct burn's burner, or the
    redirect of a held router exit: nonce, amount, burn id and mint chain never change), and (2) the earlier signature
    is DEAD for the vault: its validUntil is before this ledger's close time, or a guardian pause moved the count
    since. The caller has checked that the vault still shows the burn open (burn_status 0: never recorded, or voided
    by a pause), so no release for it is queued or paid. So a signer never holds two live signatures for one burn,
    and two addresses can never both gather a quorum. A record without validUntil and pause count (an older
    database) counts as live."""
    old = prior.get('core', prior) if isinstance(prior, dict) else None
    if old == core:
        return True
    if not isinstance(old, dict) or {k: v for k, v in old.items() if k != 'recipient'} != \
            {k: v for k, v in core.items() if k != 'recipient'}:
        return False
    vu, pc = prior.get('valid_until'), prior.get('pause_count')
    if not all(isinstance(x, int) and not isinstance(x, bool) for x in (vu, pc)):
        return False
    return vu < now or pc != pause_count


def main():
    argv = sys.argv[1:]
    if not argv or '-h' in argv or '--help' in argv:
        raise SystemExit(__doc__)
    args = {a: argv[i + 1] for i, a in enumerate(argv[:-1]) if a.startswith('--')}
    try:
        half = Half(args['--config'])
        if 'deposit' in argv:
            half.deposit(args)
        elif 'release' in argv:
            half.release(args)
        else:
            raise SystemExit(__doc__)
    except sn.StellarError as e:
        # A node that cannot be read is never a reason to sign.
        refuse('the Stellar node could not be read', error=str(e))


if __name__ == '__main__':
    main()
