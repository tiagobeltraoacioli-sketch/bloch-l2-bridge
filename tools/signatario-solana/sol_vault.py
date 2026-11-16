#!/usr/bin/env python3
"""Operator and owner tool of the Bloch bridge vault on Solana (solana/bloch-sol-vault).

  sol_vault.py <command> --config deployments/solana/busdc-sol-vault.config.json [--program-id ID] [--rpc URL] ...

Offline:
  address              every address and identity that follows from (program id, configuration)
  validate             the configuration against the program's rules and the mainnet policy
  elf-sha256 --file F  the pin of a built program image (program.elfSha256)
Read-only (own node):
  verify               program final and pinned, vault equals the file, token account, mint, fee account
  show                 the vault's state            deposits [--from N]   deposit records at `finalized`
  reserves --l2-rpc URL --token 0x..   backing against the L2 token's supply (exit 1 when broken)
Transactions (need --fee-payer KEYPAIR.json, an Ed25519 key that only pays fees and rent):
  init                 create the vault (permissionless: its address is a function of the configuration)
  create-fee-account   create the fee owner's associated token account
  deposit --keypair USER.json --amount N --l2-recipient 0x..   (a user's deposit; reference client and rehearsal)
  approve --cert CERT.json             CERT = `signatario.py combine` output for a release
  execute --nonce N --owner WALLET     pay an approved release to the wallet the burn committed to
  close --nonce N                      close a release record paid longer ago than the retention: its rent returns
                                       to the account that paid it, and the nonce stays spent in the paid page
  pause-submit --cert F  controls-submit --sig F [--sig F ...]  unpause-submit --sig F [--sig F ...]
  sweep                pay accrued fees to the fee owner's associated token account
Signatures (need --keystore and --password-file, a `cast` keystore of a committee or guardian secp256k1 key):
  pause-sign --out F                   a guardian's pause (bound to the next pause number, valid 10 minutes)
  controls-sign --deposits on|off --releases on|off --valid-until T --out F
  unpause-sign --valid-until T --out F

The effect of a transaction is always read back from the vault's accounts; an RPC answer is never the proof.
"""
import json
from pathlib import Path
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import solana_lib as S  # noqa: E402
from sol_half import Node, elf_digest  # noqa: E402


def opt(args, name, default=None, many=False):
    found = [args[i + 1] for i, a in enumerate(args[:-1]) if a == name]
    if many:
        return found
    return found[-1] if found else default


def out(ok, /, **fields):
    fields.pop('ok', None)  # a transaction result carries its own 'ok'; the verdict is the first argument

    def clean(v):
        if isinstance(v, (bytes, bytearray)):
            return S.hx(v)
        if isinstance(v, dict):
            return {k: clean(x) for k, x in v.items()}
        if isinstance(v, (list, tuple)):
            return [clean(x) for x in v]
        return v
    print(json.dumps({'ok': bool(ok), **clean(fields)}, indent=2))
    raise SystemExit(0 if ok else 1)


def need(args, name):
    value = opt(args, name)
    if value is None:
        raise S.Refused(f'missing {name}')
    return value


def node_of(args, check_pins=None, commitment='confirmed'):
    doc = json.loads(Path(need(args, '--config')).read_text())
    cfg = {'sol_rpc': need(args, '--rpc'), 'vault_config': need(args, '--config'), 'program_id': opt(args, '--program-id')}
    pinned = bool((doc.get('program') or {}).get('elfSha256'))
    return Node(cfg, commitment=commitment, check_pins=pinned if check_pins is None else check_pins)


def offline(args, allow_undecided=False):
    doc = json.loads(Path(need(args, '--config')).read_text())
    config = S.Config.from_json(doc, allow_undecided=allow_undecided)
    program_id = opt(args, '--program-id') or (doc.get('program') or {}).get('id')
    return doc, config, program_id


def send(args, node, instructions, extra=(), fee_payer=None):
    payer = fee_payer or S.Keypair(need(args, '--fee-payer'))
    res = S.send_and_confirm(node.rpc, payer, instructions, extra_signers=extra,
                             commitment=opt(args, '--commitment', 'confirmed'))
    code = S.custom_error(res['err'])
    res['error_name'] = S.VAULT_ERRORS.get(code) if code is not None else None
    res['ok'] = res['err'] is None
    return res


def cast_sign(args, digest):
    cast = opt(args, '--cast', str(Path.home() / '.foundry/bin/cast'))
    wallet = ['--keystore', need(args, '--keystore'), '--password-file', need(args, '--password-file')]
    who = subprocess.run([cast, 'wallet', 'address', *wallet], capture_output=True, text=True)
    done = subprocess.run([cast, 'wallet', 'sign', '--no-hash', *wallet, S.hx(digest)], capture_output=True, text=True)
    if who.returncode or done.returncode:
        raise S.Refused('cast failed', stderr=(who.stderr + done.stderr).strip()[-800:])
    return who.stdout.strip().lower(), done.stdout.strip().lower()


def pairs(records, members, what):
    """(address, signature) pairs of partial signatures, each from a distinct member of the set."""
    by = {}
    for r in records:
        address = S.unhex(r['signer'], 20, 'signer')
        if address not in members:
            raise S.Refused(f'a partial is not signed by a {what}', signer=r['signer'])
        by[address] = S.unhex(r['signature'], 65, 'signature')
    return sorted(by.items())


def same(records, fields):
    first = {f: records[0][f] for f in fields}
    for r in records[1:]:
        if {f: r.get(f) for f in fields} != first:
            raise S.Refused('the partial signatures are for different messages')
    return first


# ── offline ─────────────────────────────────────────────────────────────────
def cmd_address(args):
    doc, config, program_id = offline(args)
    if not program_id:
        raise S.Refused('the program id is undecided: pass --program-id')
    a = S.Addresses(S.pubkey(program_id), config)
    out(True, **a.summary(), initializeDataBytes=len(config.encode()) + 1,
        feeOwnerOnCurve=S.on_curve(config.fee_owner),
        l2TokenConstructor={'sourceChainId_': a.summary()['sourceChainId'], 'sourceVault_': S.hx(a.vault20),
                            'sourceRoute_': S.hx(a.route)})


def cmd_validate(args):
    doc = json.loads(Path(need(args, '--config')).read_text())
    undecided = []
    v = doc['vault']
    for i, s in enumerate(v['signers']['set']):
        if s.get('address') in (None, 'TBD-owner') or s.get('operator') in (None, 'TBD-owner'):
            undecided.append(f'signer {i}')
    for i, g in enumerate(v['guard']['guardians']):
        if g.get('address') in (None, 'TBD-owner') or g.get('operator') in (None, 'TBD-owner'):
            undecided.append(f'guardian {i}')
    for path in (('program', 'id'), ('program', 'elfSha256'), ('source', 'revision'), ('deployer', 'address')):
        if (doc.get(path[0]) or {}).get(path[1]) in (None, 'TBD-owner', 'TBD-deploy'):
            undecided.append('.'.join(path))
    config = S.Config.from_json(doc, allow_undecided=True)
    mainnet = not doc['solana'].get('rehearsal')
    problems = [] if undecided else config.problems(mainnet=mainnet)
    if mainnet and doc['solana']['genesisHash'] != '5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d':
        problems.append('solana.genesisHash is not mainnet-beta while rehearsal is false')
    token_cfg = opt(args, '--token-config')
    if token_cfg:
        limits = json.loads(Path(token_cfg).read_text()).get('limits', {})
        for ours, theirs in (('cap', 'supplyCap'), ('window_limit', 'bucketCapacity'), ('l2_min_burn', 'minBurn')):
            if limits.get(theirs) != getattr(config, ours):
                problems.append(f'L2 token {theirs} {limits.get(theirs)} differs from the vault {ours} {getattr(config, ours)}')
    ok = not undecided and not problems
    out(ok, decision='ok' if ok else 'refused', undecided=undecided, problems=problems)


def cmd_elf_sha256(args):
    out(True, elfSha256=elf_digest(Path(need(args, '--file')).read_bytes()))


# ── read-only ───────────────────────────────────────────────────────────────
def cmd_verify(args):
    node = node_of(args, check_pins=True, commitment=opt(args, '--commitment', 'finalized'))
    a, v = node.a, node.vault
    tokens = node.token_balance(a.tokens)
    problems = []
    if tokens is None or tokens['mint'] != node.config.mint or tokens['owner'] != a.vault:
        problems.append('the vault token account is missing or not owned by the vault')
    elif tokens['delegate'] or tokens['close_authority'] or tokens['state'] != 1:
        problems.append('the vault token account has a delegate, a close authority or is frozen')
    _, owner, mint_data = node.account(node.config.mint)
    mint = S.decode_mint(mint_data) if mint_data is not None and owner == S.TOKEN_PROGRAM else None
    if mint is None or mint['decimals'] != 6:
        problems.append('the mint is not a classic 6-decimal mint')
    fee = node.token_balance(a.fee_account)
    if tokens and tokens['amount'] < v['total_locked'] + v['fees_accrued']:
        problems.append('backing broken: the token balance is below locked plus fees')
    out(not problems, decision='ok' if not problems else 'refused', problems=problems, **a.summary(),
        programUpgradeAuthority=None, programElfSha256=node.elf_pin, contextSlot=v['context_slot'],
        mintAuthority=S.b58encode(mint['mint_authority']) if mint and mint['mint_authority'] else None,
        freezeAuthority=S.b58encode(mint['freeze_authority']) if mint and mint['freeze_authority'] else None,
        feeAccountExists=fee is not None,
        feeAccountOwnerMatches=(fee['owner'] == node.config.fee_owner) if fee else None,
        depositsEnabled=v['deposits_enabled'], releasesEnabled=v['releases_enabled'])


def state_of(node):
    v = node.vault
    tokens = node.token_balance(node.a.tokens)
    return {'vault': S.b58encode(node.a.vault), 'contextSlot': v['context_slot'], 'depositCount': v['deposit_count'],
            'totalLocked': v['total_locked'], 'feesAccrued': v['fees_accrued'],
            'tokenBalance': tokens['amount'] if tokens else None, 'head': v['head'],
            'depositsEnabled': v['deposits_enabled'], 'releasesEnabled': v['releases_enabled'],
            'controlNonce': v['control_nonce'], 'releaseBucket': v['release_bucket'],
            'bucketUpdatedAt': v['bucket_updated_at'], 'pausedUntil': v['paused_until'], 'pauseCount': v['pause_count'],
            'guardianBlockedUntil': v['guardian_blocked_until'], 'pauseChain': v['pause_chain'],
            'approvalSeq': v['approval_seq'], 'voidThroughSeq': v['void_through_seq'], 'lastPauseAt': v['last_pause_at']}


def cmd_show(args):
    node = node_of(args, commitment=opt(args, '--commitment', 'finalized'))
    extra = {}
    if opt(args, '--release') is not None:
        r = node.release(int(opt(args, '--release')))
        extra['release'] = r
    out(True, **state_of(node), **extra)


def cmd_deposits(args):
    node = node_of(args, commitment='finalized')
    finalized = node.rpc.slot('finalized')
    rows, head = [], None
    start = int(opt(args, '--from', '0'))
    for nonce in range(start, node.vault['deposit_count']):
        d = node.deposit(nonce)
        if d is None:
            raise S.Refused('a deposit record below the deposit count is missing', nonce=nonce)
        rows.append({'nonce': nonce, 'depositId': d['id'], 'amount': d['amount'], 'fee': d['fee'],
                     'l2Recipient': d['l2_recipient'], 'depositor': S.b58encode(d['depositor']), 'slot': d['slot'],
                     'slotsBelowFinalized': finalized - d['slot'], 'headAfter': d['head_after']})
        head = d['head_after']
    if rows and head != node.vault['head']:
        raise S.Refused('the last record does not carry the vault head')
    out(True, finalizedSlot=finalized, depositCount=node.vault['deposit_count'], deposits=rows)


def cmd_reserves(args):
    node = node_of(args, commitment='finalized')
    s = state_of(node)
    cast = opt(args, '--cast', str(Path.home() / '.foundry/bin/cast'))
    token, l2 = need(args, '--token'), need(args, '--l2-rpc')

    def call(sig):
        done = subprocess.run([cast, 'call', token, sig, '--rpc-url', l2, '--block', opt(args, '--l2-block', 'finalized')],
                              capture_output=True, text=True)
        if done.returncode:
            raise S.Refused('the L2 call failed', call=sig, stderr=done.stderr.strip()[-400:])
        return int(done.stdout.split()[0], 0)
    supply, pending = call('totalSupply()(uint256)'), call('pendingSupply()(uint256)')
    problems = []
    if s['tokenBalance'] is None or s['tokenBalance'] < s['totalLocked'] + s['feesAccrued']:
        problems.append('the vault token balance is below locked plus fees')
    if supply > s['totalLocked']:
        problems.append('the L2 supply exceeds the locked backing')
    out(not problems, problems=problems, tokenBalance=s['tokenBalance'], totalLocked=s['totalLocked'],
        feesAccrued=s['feesAccrued'], l2Supply=supply, l2Pending=pending,
        lockedMinusSupply=s['totalLocked'] - supply, contextSlot=s['contextSlot'])


# ── transactions ────────────────────────────────────────────────────────────
def cmd_init(args):
    doc, config, program_id = offline(args)
    problems = config.problems(mainnet=not doc['solana'].get('rehearsal'))
    if problems:
        raise S.Refused('the configuration is refused', problems=problems)
    cfg = {'sol_rpc': need(args, '--rpc'), 'vault_config': need(args, '--config'), 'program_id': program_id}
    rpc = S.Rpc(cfg['sol_rpc'])
    a = S.Addresses(S.pubkey(program_id), config)
    _, owner, data, _ = rpc.account(a.vault, 'confirmed')
    if data is None:
        probe = Node.__new__(Node)  # the program pin and finality, before paying for anything
        probe.cfg, probe.rpc, probe.commitment, probe.a, probe.config, probe.floor = cfg, rpc, 'confirmed', a, config, None
        probe.elf_pin = ((doc.get('program') or {}).get('elfSha256') or '').lower()
        if S.chain_id_of(rpc.genesis_hash()) != config.source_chain_id:
            raise S.Refused('this Solana node serves another cluster')
        probe.check_program()
        payer = S.Keypair(need(args, '--fee-payer'))
        res = S.send_and_confirm(rpc, payer, [S.VaultIx(a).initialize(payer.public)])
        if res['err'] is not None:
            out(False, step='initialize', **res, error_name=S.VAULT_ERRORS.get(S.custom_error(res['err'])))
    node = Node(cfg, commitment='confirmed')
    out(True, created=data is None, **{**a.summary(), **state_of(node)})


def cmd_create_fee_account(args):
    node = node_of(args)
    payer = S.Keypair(need(args, '--fee-payer'))
    ix = S.create_ata_instruction(payer.public, node.config.fee_owner, node.config.mint)
    res = send(args, node, [ix], fee_payer=payer)
    out(res['ok'], feeTokenAccount=S.b58encode(node.a.fee_account), **res)


def cmd_deposit(args):
    node = node_of(args)
    user = S.Keypair(need(args, '--keypair'))
    amount = int(need(args, '--amount'))
    l2 = S.unhex(need(args, '--l2-recipient'), 20, 'L2 recipient')
    source = S.pubkey(opt(args, '--source')) if opt(args, '--source') else S.associated_token_address(user.public, node.config.mint)
    # The record address depends on the vault's deposit count when the deposit EXECUTES. The deposit names the
    # records of the next `--window` counts (default 4, at most 8); if more deposits than that land in between,
    # it fails without moving anything (InvalidAccount) and is sent again against the fresh count.
    window = int(opt(args, '--window', str(S.DEPOSIT_WINDOW)))
    res, nonce, attempts = None, None, 0
    for attempts in range(1, int(opt(args, '--attempts', '4')) + 1):
        node = node_of(args)
        nonce = node.vault['deposit_count']
        ix = S.VaultIx(node.a).deposit(user.public, source, nonce, amount, l2, window)
        res = S.send_and_confirm(node.rpc, user, [ix], commitment=opt(args, '--commitment', 'confirmed'))
        if S.custom_error(res['err']) != 101 or node_of(args).vault['deposit_count'] == nonce:
            break  # landed, or refused for a reason that another count does not change
    code = S.custom_error(res['err'])
    record = None
    if res['err'] is None:
        after = node_of(args)
        for n in range(nonce, min(nonce + window, after.vault['deposit_count'])):
            d = after.deposit(n)
            if d is not None and d['depositor'] == user.public and d['slot'] == res.get('slot'):
                record = {'nonce': n, 'depositId': d['id'], 'net': d['amount'], 'fee': d['fee'], 'slot': d['slot']}
    out(res['err'] is None and record is not None, deposit=record, attempts=attempts, error_name=S.VAULT_ERRORS.get(code), **res)


def cmd_approve(args):
    cert = json.loads(Path(need(args, '--cert')).read_text())
    if cert.get('kind') != 'stable-release':
        raise S.Refused('not a combined release certificate (signatario.py combine)')
    node = node_of(args)
    a = node.a
    if int(cert['source_chain_id']) != int.from_bytes(node.config.source_chain_id, 'big') or S.unhex(cert['source_vault'], 20) != a.vault20:
        raise S.Refused('the certificate is for another chain or vault')
    r, c = cert['release'], cert['context']
    rel = {'route': S.unhex(r['route'], 32), 'nonce': int(r['nonce']), 'recipient': S.unhex(r['recipient'], 20),
           'amount': int(r['amount']), 'nativeBurn': S.unhex(r['nativeBurn'], 32), 'mintCount': int(r['mintCount']),
           'mintedTotal': int(r['mintedTotal']), 'mintHead': S.unhex(r['mintHead'], 32)}
    ctx = {'validUntil': int(c['validUntil']), 'sourceAnchorNumber': int(c['sourceAnchorNumber']),
           'sourceAnchorHash': S.unhex(c['sourceAnchorHash'], 32), 'nativeFinalizedNumber': int(c['nativeFinalizedNumber']),
           'nativeFinalizedHash': S.unhex(c['nativeFinalizedHash'], 32)}
    authorization = S.release_authorization(node.config.source_chain_id, a.vault20, rel, ctx)
    if S.hx(S.eip191(authorization)) != cert['digest'].lower():
        raise S.Refused('the certificate digest differs from the one recomputed here')
    standing = node.release(rel['nonce'])
    if standing is not None and standing['standing']:
        out(True, already=True, state=standing['state'], closed=bool(standing.get('closed')),
            sameRelease=None if standing.get('closed') else standing['release_id'] == S.release_id(rel))
    if node.vault['last_pause_at'] and ctx['validUntil'] <= node.vault['last_pause_at'] + node.config.max_valid_seconds:
        raise S.Refused('this certificate is not newer than the last guardian pause: the vault refuses it for good '
                        '(StaleCertificate); the signers certify the burn again', validUntil=ctx['validUntil'],
                        lastPauseAt=node.vault['last_pause_at'])
    signers = [(S.unhex(addr, 20), S.unhex(sig, 65)) for addr, sig in zip(cert['signers'], cert['signatures'])]
    if any(addr not in node.config.signers for addr, _ in signers) or len(signers) < node.config.threshold:
        raise S.Refused('the certificate lacks a threshold of vault signers')
    signers = sorted(signers)[:node.config.threshold]
    payer = S.Keypair(need(args, '--fee-payer'))
    ixs = [S.secp_instruction(authorization, signers, 0), S.VaultIx(a).approve_release(payer.public, rel, ctx)]
    res = send(args, node, ixs, fee_payer=payer)
    after = node_of(args).release(rel['nonce']) if res['ok'] else None
    out(res['ok'] and after is not None, nonce=rel['nonce'], readyAt=after['ready_at'] if after else None, **res)


def cmd_execute(args):
    node = node_of(args)
    nonce, owner = int(need(args, '--nonce')), S.pubkey(need(args, '--owner'))
    record = node.release(nonce)
    if record is None:
        raise S.Refused('no approval for this burn nonce', nonce=nonce)
    if record['state'] == 2:
        out(True, already=True, closed=bool(record.get('closed')), paidAmount=record.get('paid_amount'), paidAt=record.get('paid_at'))
    if S.account_id(owner) != record['recipient']:
        raise S.Refused('this wallet is not the one the burn committed to', commitment=record['recipient'])
    payer = S.Keypair(need(args, '--fee-payer'))
    ixs = []
    if node.token_balance(S.associated_token_address(owner, node.config.mint)) is None:
        if '--create-account' not in args:
            raise S.Refused('the wallet has no associated token account for this mint; its owner creates it, or '
                            'pass --create-account to pay its rent', wallet=S.b58encode(owner))
        ixs.append(S.create_ata_instruction(payer.public, owner, node.config.mint))
    ixs.append(S.VaultIx(node.a).execute_release(nonce, owner))
    res = send(args, node, ixs, fee_payer=payer)
    after = node_of(args).release(nonce) if res['ok'] else None
    out(res['ok'] and after is not None and after['state'] == 2, nonce=nonce,
        paidAmount=after['paid_amount'] if after else None, **res)


def cmd_close(args):
    node = node_of(args)
    nonce = int(need(args, '--nonce'))
    record = node.release(nonce)
    if record is None:
        raise S.Refused('no release record for this burn nonce', nonce=nonce)
    if record.get('closed'):
        out(True, already=True, nonce=nonce)
    now = int(node.rpc.block_time(node.vault['context_slot']))
    if record['state'] != 2 or now < record['paid_at'] + node.config.record_retention:
        raise S.Refused('only a release paid longer ago than the retention can be closed', state=record['state'],
                        paidAt=record['paid_at'], retention=node.config.record_retention, now=now)
    res = send(args, node, [S.VaultIx(node.a).close_release(nonce, record['payer'])])
    after = node_of(args).release(nonce) if res['ok'] else None
    out(res['ok'] and bool(after and after.get('closed')), nonce=nonce, rentReturnedTo=S.b58encode(record['payer']), **res)


def cmd_pause_sign(args):
    node = node_of(args)
    count = node.vault['pause_count'] + 1
    valid_until = int(time.time()) + int(opt(args, '--valid-seconds', str(min(600, node.config.max_valid_seconds - 10))))
    auth = S.guardian_pause_authorization(node.config.source_chain_id, node.a.vault20, node.a.route, count, valid_until)
    signer, signature = cast_sign(args, S.eip191(auth))
    if S.unhex(signer, 20) not in node.config.guardians:
        raise S.Refused('this keystore is not one of the vault guardians', signer=signer)
    record = {'kind': 'svm-guardian-pause', 'vault': S.b58encode(node.a.vault), 'count': count,
              'validUntil': valid_until, 'signer': signer, 'signature': signature}
    Path(need(args, '--out')).write_text(json.dumps(record, indent=2) + '\n')
    out(True, **record)


def cmd_pause_submit(args):
    cert = json.loads(Path(need(args, '--cert')).read_text())
    node = node_of(args)
    if cert.get('kind') != 'svm-guardian-pause' or cert['vault'] != S.b58encode(node.a.vault):
        raise S.Refused('not a guardian pause for this vault')
    auth = S.guardian_pause_authorization(node.config.source_chain_id, node.a.vault20, node.a.route,
                                          int(cert['count']), int(cert['validUntil']))
    ixs = [S.secp_instruction(auth, pairs([cert], node.config.guardians, 'guardian'), 0),
           S.VaultIx(node.a).guardian_pause(int(cert['validUntil']))]
    res = send(args, node, ixs)
    after = node_of(args).vault
    out(res['ok'] and after['pause_count'] == int(cert['count']), pausedUntil=after['paused_until'],
        pauseCount=after['pause_count'], **res)


def cmd_controls_sign(args):
    node = node_of(args)
    deposits, releases = need(args, '--deposits') == 'on', need(args, '--releases') == 'on'
    nonce, valid_until = node.vault['control_nonce'], int(need(args, '--valid-until'))
    auth = S.controls_authorization(node.config.source_chain_id, node.a.vault20, node.a.route, deposits, releases, nonce, valid_until)
    signer, signature = cast_sign(args, S.eip191(auth))
    record = {'kind': 'svm-controls', 'vault': S.b58encode(node.a.vault), 'deposits': deposits, 'releases': releases,
              'nonce': nonce, 'validUntil': valid_until, 'signer': signer, 'signature': signature}
    Path(need(args, '--out')).write_text(json.dumps(record, indent=2) + '\n')
    out(True, **record)


def cmd_controls_submit(args):
    records = [json.loads(Path(p).read_text()) for p in opt(args, '--sig', many=True)]
    node = node_of(args)
    if not records or any(r.get('kind') != 'svm-controls' or r['vault'] != S.b58encode(node.a.vault) for r in records):
        raise S.Refused('not control partials for this vault')
    m = same(records, ('deposits', 'releases', 'nonce', 'validUntil'))
    auth = S.controls_authorization(node.config.source_chain_id, node.a.vault20, node.a.route, m['deposits'],
                                    m['releases'], int(m['nonce']), int(m['validUntil']))
    signers = pairs(records, node.config.signers, 'signer')[:node.config.threshold]
    if len(signers) < node.config.threshold:
        raise S.Refused('not enough distinct signers', have=len(signers), need=node.config.threshold)
    ixs = [S.secp_instruction(auth, signers, 0),
           S.VaultIx(node.a).set_controls(m['deposits'], m['releases'], int(m['nonce']), int(m['validUntil']))]
    res = send(args, node, ixs)
    after = node_of(args).vault
    out(res['ok'] and after['control_nonce'] == int(m['nonce']) + 1, depositsEnabled=after['deposits_enabled'],
        releasesEnabled=after['releases_enabled'], **res)


def cmd_unpause_sign(args):
    node = node_of(args)
    count, valid_until = node.vault['pause_count'], int(need(args, '--valid-until'))
    auth = S.unpause_authorization(node.config.source_chain_id, node.a.vault20, node.a.route, count, valid_until)
    signer, signature = cast_sign(args, S.eip191(auth))
    record = {'kind': 'svm-unpause', 'vault': S.b58encode(node.a.vault), 'count': count, 'validUntil': valid_until,
              'signer': signer, 'signature': signature}
    Path(need(args, '--out')).write_text(json.dumps(record, indent=2) + '\n')
    out(True, **record)


def cmd_unpause_submit(args):
    records = [json.loads(Path(p).read_text()) for p in opt(args, '--sig', many=True)]
    node = node_of(args)
    if not records or any(r.get('kind') != 'svm-unpause' or r['vault'] != S.b58encode(node.a.vault) for r in records):
        raise S.Refused('not unpause partials for this vault')
    m = same(records, ('count', 'validUntil'))
    auth = S.unpause_authorization(node.config.source_chain_id, node.a.vault20, node.a.route, int(m['count']), int(m['validUntil']))
    signers = pairs(records, node.config.signers, 'signer')[:node.config.switch_threshold]
    if len(signers) < node.config.switch_threshold:
        raise S.Refused('not enough distinct signers', have=len(signers), need=node.config.switch_threshold)
    ixs = [S.secp_instruction(auth, signers, 0), S.VaultIx(node.a).unpause(int(m['count']), int(m['validUntil']))]
    res = send(args, node, ixs)
    after = node_of(args).vault
    out(res['ok'], pausedUntil=after['paused_until'], guardianBlockedUntil=after['guardian_blocked_until'], **res)


def cmd_sweep(args):
    node = node_of(args)
    before = node.vault['fees_accrued']
    if node.token_balance(node.a.fee_account) is None:
        raise S.Refused('the fee owner has no associated token account yet: run create-fee-account',
                        account=S.b58encode(node.a.fee_account))
    res = send(args, node, [S.VaultIx(node.a).sweep_fees()])
    after = node_of(args)
    out(res['ok'], swept=before if res['ok'] else 0, feesAccrued=after.vault['fees_accrued'],
        feeAccountBalance=after.token_balance(after.a.fee_account)['amount'], **res)


COMMANDS = {'address': cmd_address, 'elf-sha256': cmd_elf_sha256, 'validate': cmd_validate, 'verify': cmd_verify, 'show': cmd_show,
            'deposits': cmd_deposits, 'reserves': cmd_reserves, 'init': cmd_init,
            'create-fee-account': cmd_create_fee_account, 'deposit': cmd_deposit, 'approve': cmd_approve,
            'execute': cmd_execute, 'close': cmd_close, 'pause-sign': cmd_pause_sign, 'pause-submit': cmd_pause_submit,
            'controls-sign': cmd_controls_sign, 'controls-submit': cmd_controls_submit,
            'unpause-sign': cmd_unpause_sign, 'unpause-submit': cmd_unpause_submit, 'sweep': cmd_sweep}


def main():
    args = sys.argv[1:]
    if not args or args[0] not in COMMANDS:
        print(__doc__)
        raise SystemExit(2)
    try:
        COMMANDS[args[0]](args[1:])
    except S.Refused as e:
        out(False, reason=e.reason, **e.detail)
    except S.RpcError as e:
        out(False, reason='Solana RPC failed', error=str(e))


if __name__ == '__main__':
    main()
