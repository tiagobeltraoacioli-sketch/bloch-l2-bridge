#!/usr/bin/env python3
"""Stellar half of the bridge signer: the "Ethereum-half interface" of tools/signatario-stable/README.md, answered
from a Stellar RPC and the Soroban vault (stellar/vault) instead of an Ethereum node and ProvenanceSourceVault.

  stellar_half.py --config XLM.json deposit --deposit-id 0xID [--fields FILE]
  stellar_half.py --config XLM.json release --intent INTENT.json
  stellar_half.py --config XLM.json claim-text --burn-id 0xID --to G...

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
         equals the vault's head at its mint count; the Stellar recipient (from `stellar_recipient` in the intent, a
         hint file, or the L2 router's log: any source) hashes to the burn's 20-byte recipient; the vault's balance
         covers its books. `validUntil` in (ledger time, ledger time + max_valid_seconds], never above the vault's
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
claim    A burn made directly on the token names 20 bytes that may commit to no Stellar address (an Ethereum
         address, as on bUSDC). It is paid by this stated rule only: the account that burned signs, as an Ethereum
         personal message, the text printed by `claim-text` (it names the L2 chain, the token, the burn id and one
         Stellar address), and the signed claim is placed in `recipient_claims/<burn id>.json` as
         {"stellar_address": "G...", "signature": "0x..."}: exactly these two fields, the signature exactly 65 bytes
         of hex with v 27 or 28 and a low s. The signature is recovered IN THIS PROCESS (stellar_net.verify_claim:
         the repository's own secp256k1 and Keccak code) and the address it gives must be the burner; no part of a
         claim is ever handed to another program. The burner is taken from the L2 burn that signatario.py
         read from its own L2, never from the claim. A burn made through the router has the router as its burner,
         and a contract cannot sign: router burns are paid only to the address the router committed to. A burner
         that is a contract cannot claim.
         One claim per burn. This half remembers the release it signed for a burn and refuses another, with one
         stated exception: for a direct burn paid on a claim, once the signature it gave is dead (its `validUntil`
         has passed on the ledger clock, or the vault's pause count moved) and the vault still shows the burn open,
         it may sign for the address of another claim of the same burner. A signer therefore never has two live
         signatures for one burn, so two addresses can never both reach the threshold, and operators who were
         handed different claim files converge on one file without editing a database.
asset    `asset_contract` (the Stellar Asset Contract the vault must hold; on the public network Circle's USDC,
         stellar_net.CIRCLE_USDC) is REQUIRED: the route this half signs for is recomputed from that pinned asset,
         never from the asset the deployed vault reports.

Config (one JSON per signer): `stellar_rpc`, `network_passphrase`, `vault`, `vault_wasm_hash`, `view_account`,
`keystore`, `password_file`, `db`, `asset_contract`; optional `stellar_cli`, `stellar_config_dir`, `cast`, `stellar_rpc_others` (list),
`vault_from_ledger`, `finality_ledgers` (12), `max_ledger_age` (60), `valid_seconds` (1800), `max_valid_seconds`
(3600), `recipient_hints` (directory of files named by the commitment hex), `l2_rpc` + `router` (StellarBurnRouter),
`recipient_claims` (directory of signed claims, see above) with `l2_chain_id` and `l2_token`.
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
        candidates = []
        if intent.get('stellar_recipient'):
            candidates.append(intent['stellar_recipient'])
        hints = self.cfg.get('recipient_hints')
        if hints and (Path(hints) / commitment.hex()).exists():
            candidates.append((Path(hints) / commitment.hex()).read_text().strip())
        if self.cfg.get('l2_rpc') and self.cfg.get('router'):
            candidates += self.router_recipients(intent)
        for c in candidates:
            try:
                if sn.recipient_commitment(c) == commitment:
                    return c, None
            except sn.StellarError:
                continue
        claim = self.claim(intent)
        if claim is not None:
            return claim['stellar_address'], claim
        refuse('no Stellar address is known for the burn\'s recipient commitment; publish it (router log or hint)',
               commitment=hx(commitment))

    def claim_text(self, burn_id, to):
        sn.strkey_decode(to)
        c = self.cfg
        return sn.claim_text(c['l2_chain_id'], c['l2_token'], burn_id, to)

    def claim(self, intent):
        """A claim signed by the account that burned, for a burn whose 20 bytes commit to no known address.
        Verified in this process; see stellar_net.verify_claim."""
        claims = self.cfg.get('recipient_claims')
        burn = sn.b32(intent['release']['nativeBurn']).hex()
        if not claims:
            return None
        l2 = intent.get('l2') or {}
        burner = str(l2.get('from', '')).lower()
        router = str(self.cfg.get('router') or '').lower()
        try:
            claim = sn.load_claim(Path(claims) / f'{burn}.json')
            if claim is None:
                return None
            if not sn.ADDRESS_RE.fullmatch(burner) or burner == router:
                refuse('a claim is accepted only from the account that burned, and never for a router burn', burner=burner)
            to = sn.verify_claim(claim, burner, l2['chain_id'], l2['token'], burn)
            text = sn.claim_text(l2['chain_id'], l2['token'], burn, to)
        except (KeyError, TypeError, ValueError, sn.StellarError) as e:
            refuse('the claim for this burn is refused: ' + str(e), burner=burner)
        return {'stellar_address': to, 'signature': claim['signature'].lower(), 'burner': burner, 'text': text}

    def router_recipients(self, intent):
        """Strings the L2 router logged for this burn id, read over JSON-RPC in this process. Untrusted: only the
        commitment decides."""
        out = []
        try:
            burn = '0x' + sn.b32(intent['release']['nativeBurn']).hex()
            l2 = sn.L2(self.cfg['l2_rpc'])
            head = l2.block('latest')
            logs = l2.logs(self.cfg['router'], [sn.STELLAR_EXIT_TOPIC, burn], int(self.cfg.get('router_from_block', 0)),
                           head['number'])
            for log in logs:
                text = sn.abi_string(log['data'], 2)   # data: (uint64 amount, bytes20 commitment, string address)
                if text:
                    out.append(text)
        except (sn.StellarError, KeyError, TypeError, ValueError):
            return []
        return out

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
        recipient, claim = self.stellar_recipient(intent, commitment)
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
        live = {'valid_until': valid_until, 'pause_count': ctx['pause_count'], 'claimed': claim is not None}
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with open(str(self.db_path) + '.lock', 'w') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            db = json.loads(self.db_path.read_text()) if self.db_path.exists() else {'nonces': {}, 'burns': {}}
            db.setdefault('live', {})
            for table, key in (('nonces', str(nonce)), ('burns', burn.hex())):
                prior = db[table].get(key)
                if prior is not None and prior != core \
                        and not repin_allowed(prior, core, db['live'].get(burn.hex()), live, now):
                    refuse('this signer already signed another release for this nonce or burn', prior=prior, now=core)
            db['nonces'][str(nonce)] = core
            db['burns'][burn.hex()] = core
            db['live'][burn.hex()] = live
            tmp = self.db_path.with_suffix('.tmp')
            tmp.write_text(json.dumps(db, indent=2) + '\n')
            os.replace(tmp, self.db_path)

        # An Ethereum personal message over the vault's 32-byte digest (no `--no-hash`: cast applies EIP-191).
        signature = self.sign(digest, config['signers'])
        signer = '0x' + signature[1]
        signature = signature[0]
        answer(True, signer=signer, release=rel, stellar_recipient=recipient, vault_contract=self.net.vault,
               pause_count=ctx['pause_count'], claim=claim, vault_digest=hx(digest),
               context={'validUntil': valid_until, 'sourceAnchorNumber': anchor, 'sourceAnchorHash': '0x' + own['hash'],
                        'nativeFinalizedNumber': ctx['native_finalized_number'],
                        'nativeFinalizedHash': native['nativeFinalizedHash']},
               digest=hx(sn.personal(digest)), signature=signature)


def repin_allowed(prior, core, prior_live, live, now):
    """May a signer that pinned `prior` for a burn now sign `core`? Only for a direct burn paid on a claim, only when
    nothing but the Stellar recipient differs, and only once the signature it gave for `prior` is dead: its
    `valid_until` has passed on the ledger clock (`now`), or the vault's pause count has moved since. The caller has
    already read the vault's `burn_status` as open."""
    if not isinstance(prior_live, dict) or not prior_live.get('claimed') or not live.get('claimed'):
        return False
    if {k: v for k, v in prior.items() if k != 'recipient'} != {k: v for k, v in core.items() if k != 'recipient'}:
        return False
    try:
        return int(prior_live['valid_until']) < int(now) or int(prior_live['pause_count']) < int(live['pause_count'])
    except (KeyError, TypeError, ValueError):
        return False


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
        elif 'claim-text' in argv:
            print(half.claim_text(hx(sn.b32(args['--burn-id'])), args['--to']))
        else:
            raise SystemExit(__doc__)
    except sn.StellarError as e:
        # A node that cannot be read is never a reason to sign.
        refuse('the Stellar node could not be read', error=str(e))


if __name__ == '__main__':
    main()
