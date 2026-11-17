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
  reserves <L2 arguments>
                       backing against the L2 token's supply (exit 1 when broken), and every burn that is not
                       paid yet with its state; a HELD burn is listed with the reason it is held and how its
                       burner recovers it, a REDIRECTED one with its new wallet
  burn-status <L2 arguments> (--burn 0xID | --nonce N | --all)
                       the state of an L2 burn: paid, approved, waiting, or held and why
                       L2 arguments: --l2-rpc URL --token 0x.. --router 0x.. --router-code-keccak 0x.. --l2-chain-id N
                       [--from-block N] [--l2-block finalized|latest] [--holds DB: the operator's hold latch]
  router-pin --artifact out/SolanaBurnRouter.sol/SolanaBurnRouter.json --token 0x.. --program-id ID
                       offline: the code hash a deployed burn router of this route must have
  fee-account          the fee owner's address and associated token account at `finalized` (exit 1 unless the
                       account exists, is a USDC account of the classic token program and is owned by the fee owner)
Transactions (need --fee-payer KEYPAIR.json, an Ed25519 key that only pays fees and rent):
  init [--fee-owner-proof PROOF.json]  create the vault (permissionless: its address is a function of the
                       configuration). Refused without the fee owner's proof (default: fee-owner-proof.json next
                       to the configuration; one signature of the fee key, sol_proof.py, at most 30 days old). The
                       fee owner's associated token account is created here when absent (no owner key is needed;
                       this fee payer pays) and verified at `finalized`: canonical address, mint, owner
  create-fee-account   the same creation alone (anyone may run it; the vault need not exist)
  deposit --keypair USER.json --amount N --l2-recipient 0x..   (a user's deposit; reference client and rehearsal)
  approve --cert CERT.json <L2 arguments>   CERT = `signatario.py combine` output for a release (or the relayer's
                                       certificate of a redirected one). Its signatures are recovered here, and
                                       the recipient rule of sol_recipient.py is ALWAYS applied before anything is
                                       sent: the burn is read on the L2, the proof of the destination key is
                                       verified, the destination is read on Solana, the latch is consulted
  execute --nonce N --owner WALLET [--create-account]   pay an approved release to the wallet the burn committed
                                       to. Refused when the wallet is, at `finalized`, not absent and not a System
                                       account without data; --create-account only for a funded System account
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
import sol_proof  # noqa: E402
import sol_recipient  # noqa: E402


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
    signer, signature = who.stdout.strip().lower(), done.stdout.strip().lower()
    # What the signing tool printed is checked here, in process: it must be a signature of this digest by that key.
    if S.secp256k1_recover(digest, S.unhex(signature, 65, 'signature')) != S.unhex(signer, 20, 'signer'):
        raise S.Refused('the signing tool did not return a signature of this digest by this keystore')
    return signer, signature


def pairs(records, members, what, authorization):
    """(address, signature) pairs of partial signatures, each from a distinct member of the set and each a
    signature of `authorization` by that member: recovered in process from strictly parsed bytes."""
    by = {}
    for r in records:
        address = S.unhex(r['signer'], 20, 'signer')
        if address not in members:
            raise S.Refused(f'a partial is not signed by a {what}', signer=r['signer'])
        signature = S.unhex(r['signature'], 65, 'signature')
        if S.secp256k1_recover(S.eip191(authorization), signature) != address:
            raise S.Refused('a partial signature does not recover to the signer it names', signer=r['signer'])
        by[address] = signature
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
    problems = []
    try:  # R330-SOL-2: the flag is refused, not obeyed, with a public cluster's genesis hash or a remote endpoint
        mainnet = not S.rehearsal(doc, [opt(args, '--rpc')] if opt(args, '--rpc') else [])
    except S.Refused as e:
        mainnet = True
        problems.append(e.reason)
    if undecided:
        # The policy values that do not depend on what is undecided are judged now (R330-SOL-3: the retention floor).
        if mainnet and config.record_retention < S.retention_floor(config.pause_duration):
            problems.append(f'mainnet policy: recordRetention {config.record_retention} is below the floor '
                            f'{S.retention_floor(config.pause_duration)} s')
    else:
        problems += config.problems(mainnet=mainnet)
    if mainnet and doc['solana']['genesisHash'] != S.MAINNET_GENESIS:
        problems.append('solana.genesisHash is not mainnet-beta while rehearsal is false')
    token_cfg = opt(args, '--token-config')
    if token_cfg:
        limits = json.loads(Path(token_cfg).read_text()).get('limits', {})
        for ours, theirs in (('cap', 'supplyCap'), ('window_limit', 'bucketCapacity'), ('l2_min_burn', 'minBurn')):
            if limits.get(theirs) != getattr(config, ours):
                problems.append(f'L2 token {theirs} {limits.get(theirs)} differs from the vault {ours} {getattr(config, ours)}')
    ok = not undecided and not problems
    out(ok, decision='ok' if ok else 'refused', undecided=undecided, problems=problems,
        recordRetentionFloor=S.retention_floor(config.pause_duration) if mainnet else None)


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
    fee_state = fee_account_state(node.rpc, node.config, a, node.commitment)
    problems += fee_state['problems']
    problems += node.config.problems(mainnet=not node.rehearsal)  # the policy again, on the configuration ON CHAIN
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


def l2_uint(url, token, signature, block):
    """One uint256 view of the L2 token, asked over JSON-RPC in process (no command line)."""
    data = S.hx(S.keccak256(signature.encode())[:4])
    try:
        return int(sol_recipient.l2_call(url, token, data, block), 16)
    except ValueError:
        raise S.Refused('the L2 call failed', call=signature)


L2_ARGS = '--l2-rpc URL --token 0x.. --router 0x.. --router-code-keccak 0x.. --l2-chain-id N [--from-block N] [--holds DB]'


def recipient_cfg(args):
    """Where a burn's destination is checked (sol_recipient.py), from the command line. Every value is parsed
    strictly here; none is handed to another program."""
    cfg = {'l2_rpc': need(args, '--l2-rpc'), 'burn_router': S.hx(S.unhex(need(args, '--router'), 20, '--router')),
           'burn_router_code_keccak': S.hx(S.unhex(need(args, '--router-code-keccak'), 32, '--router-code-keccak')),
           'l2_chain_id': int(need(args, '--l2-chain-id')), 'token': S.hx(S.unhex(need(args, '--token'), 20, '--token')),
           'router_from_block': int(opt(args, '--from-block', '0'))}
    return cfg


def l2_block(args):
    block = opt(args, '--l2-block', 'finalized')
    if block not in ('finalized', 'latest', 'safe'):
        raise S.Refused('--l2-block is finalized, safe or latest')
    return block


def burns_of(args, node):
    """(config, every `Burned` log of the token up to `--l2-block`), after the router pin was checked."""
    cfg = recipient_cfg(args)
    sol_recipient.check_router(cfg, node.a)
    return cfg, sol_recipient.l2_burns(cfg['l2_rpc'], cfg['token'], cfg['router_from_block'], l2_block(args))


def burn_rows(args, node):
    """Every burn with its state on Solana; with `--holds DB` the operator's latch is applied (and written)."""
    cfg, burns = burns_of(args, node)
    holds = sol_recipient.Holds(opt(args, '--holds')) if opt(args, '--holds') else None
    return [sol_recipient.burn_status(node, cfg, b, holds=holds, to_block=l2_block(args)) for b in burns]


def cmd_reserves(args):
    node = node_of(args, commitment='finalized')
    s = state_of(node)
    token, l2, block = S.hx(S.unhex(need(args, '--token'), 20, '--token')), need(args, '--l2-rpc'), l2_block(args)
    supply, pending = l2_uint(l2, token, 'totalSupply()', block), l2_uint(l2, token, 'pendingSupply()', block)
    problems = []
    if s['tokenBalance'] is None or s['tokenBalance'] < s['totalLocked'] + s['feesAccrued']:
        problems.append('the vault token balance is below locked plus fees')
    if supply > s['totalLocked']:
        problems.append('the L2 supply exceeds the locked backing')
    # Burns that are not paid yet explain `lockedMinusSupply`; the held ones are named with their reason and with
    # how they are recovered (the burner's redirectHeldBurn). Nothing held is ever paid blind.
    rows = [r for r in burn_rows(args, node) if r['state'] != 'paid']
    held = [r for r in rows if r['state'] == 'held']
    redirected = [r for r in rows if r['state'] != 'held' and r.get('redirected')]
    keep = ('burn', 'nonce', 'amount', 'recipient', 'burner', 'direct', 'state', 'hold', 'latched', 'redirects', 'reason', 'recoverable')
    out(not problems, problems=problems, tokenBalance=s['tokenBalance'], totalLocked=s['totalLocked'],
        feesAccrued=s['feesAccrued'], l2Supply=supply, l2Pending=pending,
        lockedMinusSupply=s['totalLocked'] - supply, contextSlot=s['contextSlot'],
        unpaidBurns=len(rows), unpaidTotal=sum(r['amount'] for r in rows),
        heldBurns=len(held), heldTotal=sum(r['amount'] for r in held),
        redirectedBurns=len(redirected), redirectedTotal=sum(r['amount'] for r in redirected),
        held=[{k: r.get(k) for k in keep} for r in held],
        redirected=[{k: r.get(k) for k in ('burn', 'nonce', 'amount', 'burner', 'state', 'wallet', 'redirectNonce')} for r in redirected])


def cmd_burn_status(args):
    node = node_of(args, commitment='finalized')
    rows = burn_rows(args, node)
    if '--all' not in args:
        burn, nonce = opt(args, '--burn'), opt(args, '--nonce')
        if (burn is None) == (nonce is None):
            raise S.Refused('pass --burn 0xID, --nonce N or --all')
        want = S.hx(S.unhex(burn, 32, '--burn')) if burn is not None else None
        rows = [r for r in rows if (r['burn'] == want if want else r['nonce'] == int(nonce))]
        if not rows:
            raise S.Refused('no such burn in the token logs up to this L2 block', burn=want, nonce=nonce)
    out(True, burns=rows, held=sum(1 for r in rows if r['hold']))


def cmd_router_pin(args):
    """Offline: the code hash a deployed SolanaBurnRouter of this route must have (`burn_router_code_keccak`), from
    the compiler's artifact and the three constructor values, and the hash of its creation code."""
    doc, config, program_id = offline(args)
    if not program_id:
        raise S.Refused('the program id is undecided: pass --program-id')
    a = S.Addresses(S.pubkey(program_id), config)
    artifact = json.loads(Path(need(args, '--artifact')).read_text())
    token = S.hx(S.unhex(need(args, '--token'), 20, '--token'))
    out(True, token=token, solanaMint=S.hx(config.mint), route=S.hx(a.route),
        **sol_recipient.router_runtime_pin(artifact, token, S.hx(config.mint), S.hx(a.route)))


def fee_account_state(rpc, config, a, commitment='finalized'):
    """The fee owner's address and its associated token account as this node shows them. The fee owner is part of
    the vault's address for good and fees can only ever be swept to this one account, so `init` refuses unless
    the account exists, is a classic token account of the vault's mint, and is OWNED BY THE FEE OWNER."""
    problems = []
    owner = sol_recipient.destination([rpc], config.fee_owner) if commitment == 'finalized' else {'hold': None}
    if owner['hold']:
        problems.append('the fee owner is not a wallet address: ' + owner['hold'])
    if a.fee_account != S.associated_token_address(config.fee_owner, config.mint):
        problems.append('the fee account is not the canonical associated token address of the fee owner and the mint')
    info = rpc.account_info(a.fee_account, commitment)
    account = None
    if info is None:
        problems.append("the fee owner's associated token account does not exist: run create-fee-account "
                        f'({S.b58encode(a.fee_account)})')
    elif info['owner'] != S.TOKEN_PROGRAM or len(info['data']) != 165:
        problems.append("the account at the fee owner's associated token address is not a classic token account")
    else:
        account = S.decode_token_account(info['data'])
        if account['mint'] != config.mint:
            problems.append("the fee owner's associated token account is of another mint")
        if account['owner'] != config.fee_owner:
            problems.append("the fee owner's associated token account is not owned by the fee owner (its authority "
                            f"was changed to {S.b58encode(account['owner'])}): fees swept there would not be the owner's")
        if account['state'] != 1:
            problems.append("the fee owner's associated token account is frozen or not initialized")
    return {'problems': problems, 'feeOwner': S.b58encode(config.fee_owner), 'feeTokenAccount': S.b58encode(a.fee_account),
            'feeOwnerExists': owner.get('exists'), 'feeAccountExists': info is not None,
            'feeAccountOwner': S.b58encode(account['owner']) if account else None,
            'feeAccountBalance': account['amount'] if account else None}


def cmd_fee_account(args):
    doc, config, program_id = offline(args, allow_undecided=True)
    rpc = S.Rpc(need(args, '--rpc'))
    if S.chain_id_of(rpc.genesis_hash()) != config.source_chain_id:
        raise S.Refused('this Solana node serves another cluster')
    state = fee_account_state(rpc, config, FeeAddresses(config), opt(args, '--commitment', 'finalized'))
    out(not state['problems'], **state)


class FeeAddresses:
    """The one address of the fee side that does not need the program id (undecided before the ceremony)."""

    def __init__(self, config):
        self.fee_account = S.associated_token_address(config.fee_owner, config.mint)


# ── transactions ────────────────────────────────────────────────────────────
def cmd_init(args):
    doc, config, program_id = offline(args)
    cfg = {'sol_rpc': need(args, '--rpc'), 'vault_config': need(args, '--config'), 'program_id': program_id}
    rpc = S.Rpc(cfg['sol_rpc'])
    genesis = rpc.genesis_hash()
    if S.chain_id_of(genesis) != config.source_chain_id:
        raise S.Refused('this Solana node serves another cluster')
    rehearsal = S.rehearsal(doc, [cfg['sol_rpc']], genesis)  # R330-SOL-2: decided by the cluster, not by the flag
    problems = config.problems(mainnet=not rehearsal)
    if problems:
        raise S.Refused('the configuration is refused', problems=problems)
    a = S.Addresses(S.pubkey(program_id), config)
    _, owner, data, _ = rpc.account(a.vault, 'confirmed')
    if data is None:
        # The fee owner is in the vault's address for good. Before anything is paid for: its associated token
        # account exists at `finalized` and is the fee owner's, and (outside a rehearsal) a signature made with
        # the fee owner's key is shown: a fee address nobody holds a key for would collect every fee for nobody.
        # 1. One signature made with the fee owner's key (the committed proof file), checked offline, in process.
        proof = opt(args, '--fee-owner-proof', str(Path(need(args, '--config')).with_name('fee-owner-proof.json')))
        if not Path(proof).is_file():
            raise S.Refused('the fee owner\'s proof is missing: the owner signs the text of `sol_proof.py fee-owner-message` '
                            'with the fee key once, and `sol_proof.py verify --out` writes the file '
                            '(docs/SOLANA-BRIDGE-DEPLOY-CEREMONY.md 4.1)', looked_for=proof)
        sol_proof.check_fee_owner_proof(json.loads(Path(proof).read_text()), doc, program_id,
                                        max_age_days=sol_proof.FEE_PROOF_MAX_AGE_DAYS)
        # 2. Its token account needs no owner key: anyone may create the associated token account of any owner. It
        # is created here when absent (idempotent; this fee payer pays the rent) and then verified at `finalized`:
        # the canonical associated address, a classic token account of the mint, owned by the fee owner.
        fee = fee_account_state(rpc, config, a, 'finalized')
        if not fee['feeAccountExists'] and len(fee['problems']) == 1:
            payer = S.Keypair(need(args, '--fee-payer'))
            made = S.send_and_confirm(rpc, payer, [S.create_ata_instruction(payer.public, config.fee_owner, config.mint)])
            if made['err'] is not None:
                out(False, step='create the fee owner\'s token account', **made)
            for _ in range(120):
                fee = fee_account_state(rpc, config, a, 'finalized')
                if fee['feeAccountExists']:
                    break
                time.sleep(0.5)
            fee['created'] = True
        if fee['problems']:
            raise S.Refused('the fee account is refused', **fee)
        probe = Node.__new__(Node)  # the program pin and finality, before paying for anything
        probe.cfg, probe.rpc, probe.commitment, probe.a, probe.config, probe.floor = cfg, rpc, 'confirmed', a, config, None
        probe.elf_pin = ((doc.get('program') or {}).get('elfSha256') or '').lower()
        probe.check_program()
        payer = S.Keypair(need(args, '--fee-payer'))
        res = S.send_and_confirm(rpc, payer, [S.VaultIx(a).initialize(payer.public)])
        if res['err'] is not None:
            out(False, step='initialize', **res, error_name=S.VAULT_ERRORS.get(S.custom_error(res['err'])))
    node = Node(cfg, commitment='confirmed')
    out(True, created=data is None, **{**a.summary(), **state_of(node)})


def cmd_create_fee_account(args):
    """Before `init`: the vault need not exist and the program id may still be undecided."""
    doc, config, _ = offline(args, allow_undecided=True)
    rpc = S.Rpc(need(args, '--rpc'))
    if S.chain_id_of(rpc.genesis_hash()) != config.source_chain_id:
        raise S.Refused('this Solana node serves another cluster')
    a = FeeAddresses(config)
    before = fee_account_state(rpc, config, a, 'confirmed')
    if before['feeAccountExists']:
        out(not before['problems'], already=True, **before)
    owner = sol_recipient.destination([rpc], config.fee_owner)
    if owner['hold']:
        raise S.Refused('the fee owner is not a wallet address: ' + owner['hold'])
    payer = S.Keypair(need(args, '--fee-payer'))
    res = S.send_and_confirm(rpc, payer, [S.create_ata_instruction(payer.public, config.fee_owner, config.mint)],
                             commitment=opt(args, '--commitment', 'confirmed'))
    after = fee_account_state(rpc, config, a, 'confirmed')
    res.pop('ok', None)
    out(res['err'] is None and not after['problems'], created=res['err'] is None, **after, **res)


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
    # Every member of the committee the certificate names must have signed THIS digest: recovered in process.
    for addr, sig in zip(cert['signers'], cert['signatures']):
        if S.secp256k1_recover(S.eip191(authorization), S.unhex(sig, 65, 'signature')) != S.unhex(addr, 20, 'signer'):
            raise S.Refused('a signature of the certificate does not recover to the signer it names', signer=addr)
    # The recipient rule, ALWAYS (review 330, R330-SOL-3P-2): no flag delivers a certificate without it. The burn is
    # looked up on the L2, and the certificate must pay exactly what the rule allows for it now: the burn's own
    # destination with a valid proof of its key, or, for a held burn, its burner's latest redirect; a wallet on
    # Solana at `finalized`; not latched in the operator's database when one is given (--holds).
    cfg, burns = burns_of(args, node)
    burn = next((b for b in burns if b['burn_id'] == S.hx(rel['nativeBurn'])), None)
    if burn is None or (burn['nonce'], burn['amount']) != (rel['nonce'], rel['amount']):
        raise S.Refused('the certificate is for a burn the L2 token does not show at this block, or with other values',
                        burn=S.hx(rel['nativeBurn']))
    view = sol_recipient.exit_view(cfg, a, burn, l2_block(args))
    holds = sol_recipient.Holds(opt(args, '--holds')) if opt(args, '--holds') else sol_recipient.Holds(None)
    verdict = sol_recipient.decide(view, burn['burn_id'], holds, lambda wallet: sol_recipient.destination([node.rpc], wallet, a))
    if verdict['hold']:
        raise S.Refused(verdict['reason'], hold=verdict['hold'], latched=verdict['latched'], burn=burn['burn_id'])
    if S.account_id(verdict['wallet']) != rel['recipient']:
        raise S.Refused('the certificate pays another recipient than the rule allows for this burn now (the burn\'s own '
                        'destination, or its burner\'s latest redirect when the burn is held)', burn=burn['burn_id'],
                        certificate=S.hx(rel['recipient']), allowed=S.hx(S.account_id(verdict['wallet'])), target=verdict['target'])
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


def refuse_destination(node, owner, commitment):
    """The recipient rule of sol_recipient.py for a wallet named on the command line (R330-SOL-1): it hashes to
    the burn's 20 bytes, is not a small-order point or a known non-wallet, and at `finalized` the address is absent
    or a System account without data. Returns what the chain shows."""
    if not sol_recipient.is_wallet(owner, commitment):
        raise S.Refused('this address is not a wallet the burn committed to (another commitment, a point without a '
                        'key, or an address known not to be a wallet)', commitment=commitment)
    dest = sol_recipient.destination([node.rpc], owner, node.a)
    if dest['hold']:
        raise S.Refused('refused: the address is not a wallet on Solana. ' + dest['hold'], hold='destination-not-a-wallet',
                        wallet=S.b58encode(owner), destination=dest)
    return dest


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
    dest = refuse_destination(node, owner, record['recipient'])
    payer = S.Keypair(need(args, '--fee-payer'))
    ixs = []
    if node.token_balance(S.associated_token_address(owner, node.config.mint)) is None:
        if '--create-account' not in args:
            raise S.Refused('the wallet has no associated token account for this mint; its owner creates it, or '
                            'pass --create-account to pay its rent', wallet=S.b58encode(owner))
        if not dest['fundedSystemAccount']:
            raise S.Refused('--create-account is refused: the wallet is not a funded System account at finalized '
                            '(absent from the chain: a wallet never used, or an address nobody holds a key for). Its '
                            'owner creates the token account', wallet=S.b58encode(owner), destination=dest)
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
    ixs = [S.secp_instruction(auth, pairs([cert], node.config.guardians, 'guardian', auth), 0),
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
    signers = pairs(records, node.config.signers, 'signer', auth)[:node.config.threshold]
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
    signers = pairs(records, node.config.signers, 'signer', auth)[:node.config.switch_threshold]
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
            'deposits': cmd_deposits, 'reserves': cmd_reserves, 'burn-status': cmd_burn_status,
            'fee-account': cmd_fee_account, 'router-pin': cmd_router_pin, 'init': cmd_init,
            'create-fee-account': cmd_create_fee_account, 'deposit': cmd_deposit, 'approve': cmd_approve,
            'execute': cmd_execute, 'close': cmd_close, 'pause-sign': cmd_pause_sign, 'pause-submit': cmd_pause_submit,
            'controls-sign': cmd_controls_sign, 'controls-submit': cmd_controls_submit,
            'unpause-sign': cmd_unpause_sign, 'unpause-submit': cmd_unpause_submit, 'sweep': cmd_sweep}


def main_of(args):
    """One command with its arguments: prints one JSON object and exits 0 (accepted) or 1 (refused)."""
    try:
        COMMANDS[args[0]](args[1:])
    except S.Refused as e:
        out(False, reason=e.reason, **e.detail)
    except S.RpcError as e:
        out(False, reason='Solana RPC failed', error=str(e))


def main():
    args = sys.argv[1:]
    if not args or args[0] not in COMMANDS:
        print(__doc__)
        raise SystemExit(2)
    main_of(args)


if __name__ == '__main__':
    main()
