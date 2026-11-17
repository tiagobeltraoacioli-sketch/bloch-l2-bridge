#!/usr/bin/env python3
"""Solana half of the stablecoin bridge signer: the source-chain half of tools/signatario-stable/signatario.py
for a vault on Solana (solana/bloch-sol-vault).

  sol_half.py --config SOL.json deposit --deposit-id 0xID
  sol_half.py --config SOL.json release --intent INTENT.json

It speaks the "Ethereum-half interface" of tools/signatario-stable/README.md, so `signatario.py` runs unchanged
with `"provenance": true` and these two argv templates as `eth_half_deposit` / `eth_half_release`. It answers one
JSON object on stdout: {"ok": true, ...} with exit 0, or {"ok": false, "reason": ...} with exit 1. It reads only
this signer's own Solana node, at `finalized` commitment, and signs only what it checked there.

Every check, both commands:
  the node's genesis hash is the configured cluster (the source chain id is derived from it); the program
  account is owned by the upgradeable loader, its program data account has NO upgrade authority and holds
  exactly the pinned ELF (sha256); the vault account is at the address the configuration file derives, is owned
  by the program, and every immutable field equals the file.

deposit  the deposit record account of the id's nonce (top 8 bytes) exists at `finalized`, is owned by the
         program, belongs to this vault and carries this id; the id is recomputed from its fields; the nonce is
         below the vault's deposit count; the record's slot is at least `finality_margin_slots` below the node's
         finalized slot. Account state is the observation: no log is parsed, so a truncated log or a skipped
         slot cannot hide or invent a deposit. Signs nothing (the Bloch half signs the mint).
release  route, chain and vault of the intent are this vault's; releases enabled; no guardian pause; the burn
         nonce has no paid release and no standing approval; amount <= totalLocked and within what the release
         bucket allows now; recipient not zero; provenance: the deposit record of nonce `mintCount - 1` exists at
         `finalized` and its head equals `mintHead` (otherwise the burn is HELD: a mint the deposits do not back,
         for example a deposit that a cluster restart rolled back after it was attested). Anchor: the newest
         finalized block of this node (slot and blockhash), or the proposed one when this node has the same
         blockhash at that slot at `finalized` and it is at most `anchor_max_age_slots` old. `validUntil` in
         (now, now + max_valid_seconds], with the cluster clock within `max_clock_skew` of this host's. A local
         database refuses to sign two different releases for one nonce or one burn.

Review 325: `deposit` is answered only when EVERY configured endpoint shows the same record (R325-SOL-3);
`release` only when a wallet is known for the burn's 20-byte recipient (R325-SOL-1, sol_recipient.py), no paid
page marks the nonce as paid, and the certificate could not predate the vault's last guardian pause (R325-SOL-2).

Review 330 and the coordinator's decisions of round 17 (the whole rule: sol_recipient.py). `release` is
answered only for a target that is a wallet address, WITH A PROOF OF ITS KEY in the burn router's log (a signature
by the destination over the exit message, verified here in process), and that is a wallet on Solana at
`finalized` on every configured endpoint. The target is the burn's own destination, or, for a HELD burn, the
destination its own burner named with `redirectHeldBurn`; the release then carries the new wallet's commitment
and its partial is written by this half (the unchanged Bloch half only accepts a release equal to the burn).
Holds are LATCHED in this signer's database: a destination once refused for a burn stays refused whatever the
chain shows later (`holds`, `release-hold --burn 0x.. --note TEXT`). The router is pinned by address AND code
(`burn_router_code_keccak`), mint, route and token. `solana.rehearsal: true` is refused, not obeyed, when the
genesis hash is a public cluster's or an endpoint is not on loopback. The policy of the vault configuration (the
retention floor included) is applied to the vault this half serves.

Config (one JSON per signer): `sol_rpc` (one URL, or a list of URLs of different operators; a deposit needs
`sol_rpc_min` of them, default 2 on a public cluster and 1 in a rehearsal, and all listed must agree),
`vault_config` (the deployments/solana/*.config.json file, with `program.id` and `program.elfSha256` filled),
`keystore`, `password_file` (the secp256k1 release key, the same keystore format as the Ethereum half), `db`;
for releases `l2_rpc`, `burn_router`, `burn_router_code_keccak`, `l2_chain_id`, `token` (all required),
`router_from_block`, `redirect_dir` (where partials of redirected releases are written; default next to `db`);
optional `cast`, `finality_margin_slots` (150),
`valid_seconds` (1800), `max_valid_seconds` (3600), `anchor_max_age_slots` (9000), `max_clock_skew` (120).
"""
import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import solana_lib as S  # noqa: E402
import sol_recipient  # noqa: E402


def answer(ok, **fields):
    print(json.dumps({'ok': ok, 'signed': ok and 'signature' in fields, **fields}, indent=2))
    raise SystemExit(0 if ok else 1)


def refuse(reason, **detail):
    answer(False, reason=reason, **detail)


def elf_digest(data):
    """sha256 of a program image without trailing zero bytes (the loader may pad the data account)."""
    return S.sha256(bytes(data).rstrip(b'\0')).hex()


def endpoints(cfg):
    """`sol_rpc` is one URL or a list of URLs (each a different operator's node or provider)."""
    urls = cfg['sol_rpc'] if isinstance(cfg['sol_rpc'], (list, tuple)) else [cfg['sol_rpc']]
    if not urls or len(set(urls)) != len(urls) or not all(isinstance(u, str) and u for u in urls):
        raise S.Refused('sol_rpc must be one URL or a list of distinct URLs')
    return list(urls)


class Node:
    """This operator's view of the vault on its own node, pinned to the configuration file."""

    def __init__(self, cfg, commitment='finalized', check_pins=True, url=None):
        self.cfg = cfg
        self.url = url or endpoints(cfg)[0]
        self.rpc = S.Rpc(self.url)
        self.commitment = commitment
        doc = json.loads(Path(cfg['vault_config']).read_text())
        self.doc = doc
        self.config = S.Config.from_json(doc)
        program_id = cfg.get('program_id') or (doc.get('program') or {}).get('id')
        if not program_id:
            raise S.Refused('the program id is undecided (program.id in the vault configuration file)')
        self.a = S.Addresses(S.pubkey(program_id), self.config)
        self.elf_pin = (cfg.get('program_elf_sha256') or (doc.get('program') or {}).get('elfSha256') or '').lower()
        genesis = self.rpc.genesis_hash()
        if S.chain_id_of(genesis) != self.config.source_chain_id:
            raise S.Refused('this Solana node serves another cluster', node=S.b58encode(genesis),
                            config=doc['solana']['genesisHash'])
        # R330-SOL-2: a rehearsal is decided by the cluster this node serves, not by the flag in the file.
        self.rehearsal = S.rehearsal(doc, [self.url, *endpoints(cfg)], genesis)
        # R330-SOL-3P-4: the policy (the retention floor included) holds for the vault this tool serves, whoever
        # initialized it: a vault below it is not signed for, relayed for or watched.
        problems = self.config.problems(mainnet=not self.rehearsal)
        if problems:
            raise S.Refused('the vault configuration is refused by the policy', problems=problems)
        self.floor = None
        if check_pins:
            self.check_program()
        self.vault = self.read_vault()

    def account(self, key, commitment=None):
        slot, owner, data, lamports = self.rpc.account(key, commitment or self.commitment, self.floor)
        if (commitment or self.commitment) == self.commitment:
            self.floor = slot if self.floor is None else max(self.floor, slot)
        return slot, owner, data

    def check_program(self):
        if len(self.elf_pin) != 64:
            raise S.Refused('the program ELF pin is undecided (program.elfSha256)')
        _, owner, data = self.account(self.a.program_id)
        if data is None:
            raise S.Refused('the program account does not exist at this commitment', commitment=self.commitment)
        if owner != S.UPGRADEABLE_LOADER or data is None or data[:4] != b'\x02\0\0\0' or data[4:36] != self.a.program_data:
            raise S.Refused('the program account is not an upgradeable-loader program at the expected address')
        _, owner, pd = self.account(self.a.program_data)
        if owner != S.UPGRADEABLE_LOADER or pd is None or len(pd) < 45 or pd[:4] != b'\x03\0\0\0':
            raise S.Refused('the program data account is missing or malformed')
        if pd[12] != 0:
            raise S.Refused('the program still has an upgrade authority', authority=S.b58encode(pd[13:45]))
        if elf_digest(pd[45:]) != self.elf_pin:
            raise S.Refused('the program on chain is not the pinned build', chain=elf_digest(pd[45:]), pin=self.elf_pin)

    def read_vault(self):
        slot, owner, data = self.account(self.a.vault)
        if data is None:
            raise S.Refused('the vault account does not exist at this commitment', vault=S.b58encode(self.a.vault))
        if owner != self.a.program_id:
            raise S.Refused('the vault account is not owned by the program')
        v = S.decode_vault(data)
        a = self.a
        if (v['config'].encode() != self.config.encode() or v['config_hash'] != a.config_hash or v['vault20'] != a.vault20
                or v['route'] != a.route or v['genesis'] != a.genesis or v['token_account'] != a.tokens
                or v['fee_token_account'] != a.fee_account or v['mint20'] != a.mint20):
            raise S.Refused('the vault on chain differs from the configuration file')
        v['context_slot'] = slot
        return v

    def deposit(self, nonce):
        key = self.a.deposit_record(nonce)
        slot, owner, data = self.account(key)
        if data is None:
            return None
        if owner != self.a.program_id:
            raise S.Refused('the deposit record is not owned by the program', nonce=nonce)
        d = S.decode_deposit(data)
        if d['vault'] != self.a.vault or d['nonce'] != nonce:
            raise S.Refused('the deposit record belongs to another vault or nonce', nonce=nonce)
        if S.deposit_id(self.a.route, nonce, d['sender20'], d['amount'], d['l2_recipient']) != d['id']:
            raise S.Refused('the deposit id recomputed from the record differs', nonce=nonce)
        if S.account_id(d['depositor']) != d['sender20']:
            raise S.Refused('the deposit record names a sender that is not its depositor', nonce=nonce)
        d['key'] = key
        return d

    def page(self, nonce):
        """The paid page that covers `nonce`, or None while nobody approved a release in its range."""
        _, owner, data = self.account(self.a.paid_page(nonce))
        if data is None or owner != self.a.program_id:
            return None
        page = S.decode_page(data)
        if page['vault'] != self.a.vault or page['page'] != nonce // S.PAGE_NONCES:
            raise S.Refused('the paid page belongs to another vault or range', nonce=nonce)
        return page

    def release(self, nonce):
        """The release record of a burn nonce. A release that was paid and whose record was closed after the
        retention is reported from its bit in the paid page: state 2, `closed`, and no other field."""
        _, owner, data = self.account(self.a.release_record(nonce))
        if data is None or owner != self.a.program_id or not any(data[:2]):
            page = self.page(nonce)
            if page is not None and S.page_bit(page, nonce):
                return {'state': 2, 'closed': True, 'standing': True, 'nonce': nonce, 'vault': self.a.vault}
            return None
        r = S.decode_release(data)
        if r['vault'] != self.a.vault or r['nonce'] != nonce:
            raise S.Refused('the release record belongs to another vault or nonce', nonce=nonce)
        r['standing'] = r['state'] == 2 or r['seq'] > self.vault['void_through_seq']
        return r

    def token_balance(self, key):
        _, owner, data = self.account(key)
        if data is None:
            return None
        if owner != S.TOKEN_PROGRAM:
            raise S.Refused('not a classic token account', account=S.b58encode(key))
        return S.decode_token_account(data)


def observe_deposit(cfg, url, dep_id):
    """One endpoint's answer for a deposit id: its record at `finalized`, old enough, or a refusal."""
    node = Node(cfg, url=url)
    nonce = int.from_bytes(dep_id[:8], 'big')
    v = node.vault
    if nonce >= v['deposit_count']:
        raise S.Refused('no such deposit at finalized commitment', nonce=nonce, deposit_count=v['deposit_count'])
    d = node.deposit(nonce)
    if d is None:
        raise S.Refused('the deposit record is not on this node at finalized commitment', nonce=nonce)
    if d['id'] != dep_id:
        raise S.Refused('the deposit of that nonce has another id', nonce=nonce, chain=S.hx(d['id']))
    finalized = node.rpc.slot('finalized')
    margin = int(cfg.get('finality_margin_slots', 150))
    if d['slot'] + margin > finalized:
        raise S.Refused('the deposit is finalized but younger than the margin', slot=d['slot'], finalized=finalized, margin=margin)
    return node, d, finalized


def cmd_deposit(cfg, deposit_id):
    """Every configured endpoint must show the same deposit record at `finalized` (review 325, R325-SOL-3): a mint
    is attested on the word of at least `sol_rpc_min` endpoints (default 2 on a public cluster, 1 in a rehearsal),
    and one endpoint that fails, lags or disagrees stops the signature. Fail closed."""
    dep_id = S.unhex(deposit_id, 32, 'deposit id')
    urls = endpoints(cfg)
    # R330-SOL-2: `rehearsal: true` is refused for a public cluster's genesis hash and for any endpoint that is not
    # on loopback (here from the file; every Node below repeats it against the genesis hash its node reports).
    rehearsal = S.rehearsal(json.loads(Path(cfg['vault_config']).read_text()), urls)
    need = int(cfg.get('sol_rpc_min', 1 if rehearsal else 2))
    if need < 1 or (not rehearsal and need < 2):
        refuse('sol_rpc_min below 2 on a public cluster: mint signing needs two independent endpoints')
    if len(urls) < need:
        refuse('mint signing needs agreement of independent Solana endpoints', configured=len(urls), needed=need)
    seen = []
    for url in urls:
        try:
            seen.append(observe_deposit(cfg, url, dep_id))
        except S.Refused as e:
            refuse('an endpoint does not show this deposit as final: ' + e.reason, endpoint=urls.index(url),
                   **{k: (S.hx(v) if isinstance(v, bytes) else v) for k, v in e.detail.items()})
        except S.RpcError as e:
            refuse('an endpoint failed; every configured endpoint must answer', endpoint=urls.index(url), error=str(e))
    node, d, finalized = seen[0]
    fields = ('id', 'vault', 'nonce', 'depositor', 'sender20', 'l2_recipient', 'amount', 'fee', 'head_after', 'slot', 'timestamp')
    for i, (_, other, _) in enumerate(seen[1:], 1):
        if any(other[f] != d[f] for f in fields):
            refuse('the endpoints disagree about this deposit', endpoint=i,
                   differ=[f for f in fields if other[f] != d[f]])
    finalized = min(f for _, _, f in seen)
    nonce = d['nonce']
    sigs = []
    try:
        sigs = node.rpc.signatures_for(d['key'], 'finalized', 5) or []
    except S.RpcError:
        pass  # history may be pruned on this node; the account is the evidence
    block_hash = None
    try:
        block_hash = node.rpc.block_hash(d['slot'], 'finalized')
    except S.RpcError:
        pass
    answer(True, source_chain_id=int.from_bytes(node.config.source_chain_id, 'big'), vault=S.hx(node.a.vault20),
           route=S.hx(node.a.route), deposit_id=S.hx(dep_id), nonce=nonce, sender=S.hx(d['sender20']),
           amount=d['amount'], pq_recipient_hash=S.hx(d['l2_recipient'].rjust(32, b'\0')),
           tx_hash=sigs[-1]['signature'] if sigs else None, log_index=0, block_number=d['slot'],
           block_hash=S.hx(block_hash) if block_hash else None, finalized=True, finalized_number=finalized,
           solana={'vault': S.b58encode(node.a.vault), 'record': S.b58encode(d['key']),
                   'depositor': S.b58encode(d['depositor']), 'fee': d['fee'], 'timestamp': d['timestamp'],
                   'endpoints_agreeing': len(seen)})


def cmd_release(cfg, intent_path):
    intent = json.loads(Path(intent_path).read_text())
    node = Node(cfg)
    v, a = node.vault, node.a
    if int(intent.get('source_chain_id', -1)) != int.from_bytes(node.config.source_chain_id, 'big'):
        refuse('the intent is for another source chain')
    if S.unhex(intent.get('vault', ''), 20, 'vault') != a.vault20:
        refuse('the intent is for another vault')
    got = intent['release']
    rel = {'route': S.unhex(got['route'], 32, 'route'), 'nonce': int(got['nonce']),
           'recipient': S.unhex(got['recipient'], 20, 'recipient'), 'amount': int(got['amount']),
           'nativeBurn': S.unhex(got['nativeBurn'], 32, 'nativeBurn'), 'mintCount': int(got['mintCount']),
           'mintedTotal': int(got['mintedTotal']), 'mintHead': S.unhex(got['mintHead'], 32, 'mintHead')}
    native = intent['native']
    ctx = {'nativeFinalizedNumber': int(native['nativeFinalizedNumber']),
           'nativeFinalizedHash': S.unhex(native['nativeFinalizedHash'], 32, 'nativeFinalizedHash')}
    if rel['route'] != a.route:
        refuse('route differs from the vault', route=got['route'])
    if not v['releases_enabled']:
        refuse('releases are disabled in the vault')
    cluster_now = node.rpc.block_time(v['context_slot'])
    now = int(time.time())
    if cluster_now is None or abs(int(cluster_now) - now) > int(cfg.get('max_clock_skew', 120)):
        refuse('the cluster clock and this host disagree', cluster=cluster_now, host=now)
    if int(cluster_now) < v['paused_until']:
        refuse('the vault is paused by a guardian', paused_until=v['paused_until'])
    if rel['amount'] == 0 or not any(rel['recipient']) or not any(rel['nativeBurn']) or not any(ctx['nativeFinalizedHash']):
        refuse('zero amount, recipient, burn or L2 block hash')
    if rel['amount'] > v['total_locked']:
        refuse('amount above the locked backing', amount=rel['amount'], locked=v['total_locked'])
    if rel['amount'] > S.available_to_release(v, int(cluster_now)):
        refuse('amount above what the release bucket allows now', available=S.available_to_release(v, int(cluster_now)))
    standing = node.release(rel['nonce'])
    if standing is not None and standing['standing']:
        refuse('this burn nonce already has a release', state=standing['state'], closed=bool(standing.get('closed')),
               release_id=S.hx(standing['release_id']) if 'release_id' in standing else None)
    # Provenance: HOLD unless the burn's mint chain is this vault's deposit chain after the same count.
    if not 1 <= rel['mintCount'] <= v['deposit_count']:
        refuse('provenance: the burn names more mints than this vault has deposits (held)', mintCount=rel['mintCount'],
               deposit_count=v['deposit_count'])
    backing = node.deposit(rel['mintCount'] - 1)
    if backing is None or backing['head_after'] != rel['mintHead']:
        refuse('provenance: the burn was made under a mint chain the deposits do not back (held)',
               mintHead=got['mintHead'], vault=S.hx(backing['head_after']) if backing else None)

    # Who may be paid (sol_recipient.py): the burn's own destination, or its burner's redirect when the burn is
    # held; a wallet address, with a proof of its key in the router's log, that is a wallet on Solana at
    # `finalized` on every endpoint. Holds are latched in this signer's database.
    l2 = intent.get('l2') or {}
    if not (cfg.get('l2_rpc') and cfg.get('burn_router') and cfg.get('l2_chain_id') is not None and cfg.get('token')):
        refuse('`l2_rpc`, `burn_router`, `burn_router_code_keccak`, `l2_chain_id` and `token` are required: without the '
               'router log no destination can be checked')
    if (l2.get('chain_id') is not None and int(l2['chain_id']) != int(str(cfg['l2_chain_id']), 0)) or \
            (l2.get('token') is not None and str(l2['token']).lower() != str(cfg['token']).lower()):
        refuse('the intent is for another L2 chain or token than this half is configured for')
    sol_recipient.check_router(cfg, a)
    burn = {'burn_id': got['nativeBurn'], 'nonce': rel['nonce'], 'amount': rel['amount'], 'recipient': got['recipient'],
            'from': l2.get('from')}
    # The logs are read up to the L2 block the Bloch half verified as final for this burn, when it names one.
    to_block = hex(int(l2['finalized_number'])) if l2.get('finalized_number') is not None else 'finalized'
    view = sol_recipient.exit_view(cfg, a, burn, to_block)
    rpcs = [S.Rpc(u) for u in endpoints(cfg)]
    verdict = sol_recipient.decide(view, S.hx(rel['nativeBurn']), sol_recipient.Holds(cfg['db']),
                                   lambda wallet: sol_recipient.destination(rpcs, wallet, a))
    if verdict['hold']:
        refuse(verdict['reason'], hold=verdict['hold'], latched=verdict['latched'], recipient=got['recipient'],
               burn=got['nativeBurn'], burner=view['burner'], direct_burn=view['direct'], redirect=verdict['redirect'],
               destination=verdict['destination'])
    paid_to, dest, redirected = verdict['wallet'], verdict['destination'], verdict['target'] == 'redirect'
    if redirected:
        # The burner sent its held burn elsewhere (redirectHeldBurn): the release names the new wallet's commitment.
        rel['recipient'] = S.account_id(paid_to)

    # Anchor and validity.
    finalized = node.rpc.slot('finalized')
    proposed = intent.get('proposed_context')
    max_valid = int(cfg.get('max_valid_seconds', 3600))
    if proposed:
        slot, want = int(proposed['sourceAnchorNumber']), S.unhex(proposed['sourceAnchorHash'], 32, 'sourceAnchorHash')
        if slot > finalized or finalized - slot > int(cfg.get('anchor_max_age_slots', 9000)):
            refuse('the proposed anchor is not a recent finalized slot of this node', slot=slot, finalized=finalized)
        if node.rpc.block_hash(slot, 'finalized') != want:
            refuse('the proposed anchor is not a block of this node', slot=slot)
        valid_until = int(proposed['validUntil'])
        anchor = (slot, want)
    else:
        anchor = node.rpc.last_block('finalized', finalized)
        # Round 18 (agent 371; rehearsal run 3): the vault measures validity on the CLUSTER clock (validUntil at most
        # maxValidSeconds after it). A cluster clock behind this host's by more than maxValidSeconds - valid_seconds
        # made the first signer propose a certificate the window rule below then refused. Capped to what the vault
        # accepts; every check below is unchanged.
        valid_until = min(now + int(cfg.get('valid_seconds', 1800)), int(cluster_now) + node.config.max_valid_seconds)
    if not now < valid_until <= now + max_valid or valid_until - int(cluster_now) > node.config.max_valid_seconds:
        refuse('validUntil outside the allowed window', validUntil=valid_until, now=now)
    # The vault refuses a certificate that could have been signed before its last guardian pause (R325-SOL-2).
    if v['last_pause_at'] and valid_until <= v['last_pause_at'] + node.config.max_valid_seconds:
        refuse('the vault would refuse this certificate as older than its last guardian pause; signing resumes at '
               'the time given', resumes_at=v['last_pause_at'] + node.config.max_valid_seconds - (valid_until - now) + 1,
               validUntil=valid_until, last_pause_at=v['last_pause_at'])
    ctx.update(validUntil=valid_until, sourceAnchorNumber=anchor[0], sourceAnchorHash=anchor[1])
    digest = S.eip191(S.release_authorization(node.config.source_chain_id, a.vault20, rel, ctx))

    # Equivocation guard: one release per nonce and per burn, whatever the vault would accept later.
    # A redirect changes the recipient of a burn's release. This signer signs a release that differs from one it
    # signed before for the same nonce or burn ONLY when the new one follows a newer redirect of the burner AND the
    # earlier certificate can no longer be approved (its validUntil has passed on the cluster clock, with the skew
    # margin): two certificates for one burn are then never live together.
    core = {'nonce': rel['nonce'], 'recipient': S.hx(rel['recipient']), 'amount': rel['amount'],
            'nativeBurn': S.hx(rel['nativeBurn']), 'mintCount': rel['mintCount'], 'mintedTotal': rel['mintedTotal'],
            'mintHead': S.hx(rel['mintHead'])}
    stamp = {'redirect': verdict['redirect'] if redirected else None, 'validUntil': ctx['validUntil']}
    db_path = Path(cfg['db'])
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with open(str(db_path) + '.lock', 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        db = json.loads(db_path.read_text()) if db_path.exists() else {}
        db.setdefault('by_nonce', {})
        db.setdefault('by_burn', {})
        for table, key in (('by_nonce', str(rel['nonce'])), ('by_burn', core['nativeBurn'])):
            prior = db[table].get(key)
            if prior is None:
                continue
            before = {k: prior.get(k) for k in core}
            if before == core:
                stamp['validUntil'] = max(stamp['validUntil'], int(prior.get('validUntil') or 0))
                continue
            newer = stamp['redirect'] is not None and (prior.get('redirect') is None or stamp['redirect'] > prior['redirect'])
            expired = int(cluster_now) > int(prior.get('validUntil') or 2**62) + int(cfg.get('max_clock_skew', 120))
            if not (newer and expired):
                refuse('this signer already signed a different release for that nonce or burn'
                       + ('; the release for the newer redirect is signed once the earlier certificate has expired' if newer else ''),
                       prior=prior, now=dict(core, **stamp), earlier_certificate_expires=prior.get('validUntil'))
        db['by_nonce'][str(rel['nonce'])] = dict(core, **stamp)
        db['by_burn'][core['nativeBurn']] = dict(core, **stamp)
        tmp = db_path.with_suffix('.tmp')
        tmp.write_text(json.dumps(db, indent=2) + '\n')
        os.replace(tmp, db_path)

    cast = cfg.get('cast', str(Path.home() / '.foundry/bin/cast'))
    wallet = ['--keystore', cfg['keystore'], '--password-file', cfg['password_file']]
    try:
        signer = subprocess.run([cast, 'wallet', 'address', *wallet], capture_output=True, text=True)
    except OSError as e:
        refuse('cast cannot be run', error=str(e))
    if signer.returncode:
        refuse('cast wallet address failed', stderr=signer.stderr.strip()[-800:])
    signer = signer.stdout.strip().lower()
    if S.unhex(signer, 20) not in node.config.signers:
        refuse('this keystore is not one of the vault signers', signer=signer)
    done = subprocess.run([cast, 'wallet', 'sign', '--no-hash', *wallet, S.hx(digest)], capture_output=True, text=True)
    if done.returncode:
        refuse('cast wallet sign failed', stderr=done.stderr.strip()[-800:])
    # What the signing tool printed is checked here, in process, before it is handed on: it must be a signature of
    # this digest by this keystore's key (the parent then asks `cast wallet verify`, whose exit code alone says little).
    try:
        made = S.secp256k1_recover(digest, S.unhex(done.stdout.strip(), 65, 'signature'))
    except S.Refused:
        made = None
    if made is None or made != S.unhex(signer, 20):
        refuse('the signing tool did not return a signature of this digest by this keystore')
    shown = {'signer': signer, 'release': {k: (S.hx(rel[k]) if isinstance(rel[k], bytes) else rel[k]) for k in S.RELEASE_FIELDS},
             'context': {'validUntil': ctx['validUntil'], 'sourceAnchorNumber': ctx['sourceAnchorNumber'],
                         'sourceAnchorHash': S.hx(ctx['sourceAnchorHash']),
                         'nativeFinalizedNumber': ctx['nativeFinalizedNumber'],
                         'nativeFinalizedHash': S.hx(ctx['nativeFinalizedHash'])},
             'digest': S.hx(digest), 'signature': done.stdout.strip().lower()}
    if redirected:
        # The unchanged Bloch half accepts only a release that is exactly the burn's (it would answer "the Ethereum
        # half signed another release"), so the partial of a redirected release is written HERE, in the shape of the
        # partials it writes, and this half answers "refused: redirected". The Bloch half has by then verified the
        # burn on the L2 at finality and built the intent; that part of its work is used, its output is not.
        partial = dict(shown, kind='stable-release', source_chain_id=int.from_bytes(node.config.source_chain_id, 'big'),
                       source_vault=S.hx(a.vault20), redirect=verdict['redirect'], wallet=S.b58encode(paid_to))
        out_dir = (Path(cfg.get('redirect_dir') or db_path.parent / 'redirect-partials') / S.hx(rel['nativeBurn'])[2:]
                   / f"n{verdict['redirect']}-{ctx['validUntil']}-{ctx['sourceAnchorNumber']}")
        out_dir.mkdir(parents=True, exist_ok=True)
        path = out_dir / f'{signer[2:]}.json'
        tmp = path.with_suffix('.tmp')
        tmp.write_text(json.dumps(partial, indent=2) + '\n')
        os.replace(tmp, path)
        refuse('redirected: the burner sent this held burn to another wallet (redirectHeldBurn); the partial signature '
               'of the redirected release was written by this half', redirected=True, partial=str(path),
               redirect=verdict['redirect'], wallet=S.b58encode(paid_to), context=shown['context'],
               release=shown['release'], destination=dest)
    answer(True, **shown, finalized_slot=finalized, wallet=S.b58encode(paid_to), destination=dest)


def cmd_release_hold(cfg, args):
    """An operator's explicit action: this signer forgets that it held one destination of one burn. The burn is then
    judged afresh by what the chains show. It names the burn (and the redirect nonce, for a redirect's hold), needs
    a note, and is recorded in the database (`released_holds`) and in this answer, which the operator keeps.
    Releasing a hold whose destination was closed and is now "absent" lets the burn be paid to that address:
    the note says who asked and why that address is a wallet after all."""
    burn = S.hx(S.unhex(args[args.index('--burn') + 1], 32, 'burn id'))
    note = args[args.index('--note') + 1] if '--note' in args else ''
    if len(note.strip()) < 10:
        refuse('release-hold needs --note: who asked for it and why (at least 10 characters)')
    key = burn + (f":r{int(args[args.index('--redirect') + 1])}" if '--redirect' in args else '')
    entry = sol_recipient.Holds(cfg['db']).release(key, note.strip())
    if entry is None:
        refuse('this signer holds no latch under that key', key=key)
    answer(True, released=key, was=entry, note=note.strip(), at=int(time.time()))


def main():
    args = sys.argv[1:]
    try:
        cfg = json.loads(Path(args[args.index('--config') + 1]).read_text())
        if 'deposit' in args:
            cmd_deposit(cfg, args[args.index('--deposit-id') + 1])
        elif 'release-hold' in args:
            cmd_release_hold(cfg, args)
        elif 'holds' in args:
            answer(True, held=sol_recipient.Holds(cfg['db']).all())
        elif 'release' in args:
            cmd_release(cfg, args[args.index('--intent') + 1])
        else:
            refuse('usage: sol_half.py --config SOL.json deposit --deposit-id 0xID | release --intent FILE | holds | '
                   'release-hold --burn 0xID [--redirect N] --note TEXT')
    except S.Refused as e:
        refuse(e.reason, **{k: (S.hx(v) if isinstance(v, bytes) else v) for k, v in e.detail.items()})
    except S.RpcError as e:
        refuse('Solana RPC failed', error=str(e))
    except (KeyError, ValueError, IndexError) as e:
        refuse('malformed input', error=repr(e))


if __name__ == '__main__':
    main()
