#!/usr/bin/env python3
"""End-to-end rehearsal of a FURTHER asset route of a network (round 20: USDT) on a LOCAL anvil fork, with the real token.

  python3 tools/evm-nets/rehearse_route.py ROUTE [--rpc URL] [--port BASE] [--keep]

ROUTE is a key of tools/evm-nets/asset-routes.json: ethereum-usdt, arbitrum-one-usdt, op-mainnet-usdt. The rig, the
daemons and steps 1 to 10 are those of rehearse_fork.py (deposit, no attestation before finality, credit after the
12 h delay, burn, release with the fee to the owner's address, replay, forged and under-quorum certificates, limits,
guardian pause and 6-of-7 unpause, a deposit that disappears after attestation), run with this route's vault contract
and transfer mode, its cap, window, fees and minimums, over the REAL asset contract of the forked network. A route
that is not launchable runs under a rehearsal chain id (900,000,000 + the network's id): every tool refuses its asset
on the network's own id, and nothing signed here is valid there. Every key is a throwaway; the fork source is a
read-only public endpoint and nothing is ever sent to it.

Step 11 is this file: what the token's issuer or admin can do, with the vault in each role, on the real contract.
For each state the real source half (tools/signatario-stable/eth_half.py, the command a signer runs before it signs a
mint) is asked to attest a finalized deposit: it must answer `ok` while the token is in the pinned state and refuse,
naming the difference, while it is not (the token guard: minting stops).

  tether-legacy (ethereum-usdt)   blacklisted release recipient (paid: this token checks the sender side only);
        the vault blacklisted (deposit refused by the vault, releases revert, the same burn is paid after the
        blacklist is lifted); a deposit sent while the issuer's transfer fee is on (refused: the vault never credits
        more than it received) and a release under the fee (paid, the recipient bears it, IssuerFeeKept); pause;
        `deprecate` (deposits refused for good, releases pay through the forwarder once the upgraded token holds the
        balance); and the stand-in token of the forge suites answers every probe call as the real contract does.
  usdt0 (arbitrum-one-usdt)       exactly which contract is the asset (proxy, implementation, admin, owner Safe);
        blocked release recipient (paid); a release the token refuses for good (recipient = the token contract): not
        paid, nothing consumed, the next burn is paid; the vault blocked; a blocked depositor; the implementation
        slot changed (minting stops; with code that reads no balances every path of the vault stops on its backing
        check); the stand-in compared with the real contract.
  op-bridged (op-mainnet-usdt)    which contract is the asset (plain token, l1Token, l2Bridge); the bridge burns part
        of the vault's balance (every path stops on the backing check; the reserves monitor reports the deficit) and
        mints it back; the bridge's implementation slot changed (minting stops); the stand-in compared.
"""
import json
from pathlib import Path
import sys
import time
import urllib.request

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import asset_routes  # noqa: E402
import rehearse_fork as rf  # noqa: E402

check, out, sh, CAST, FORGE, ROOT, STABLE = rf.check, rf.out, rf.sh, rf.CAST, rf.FORGE, rf.ROOT, rf.STABLE
RELEASE_SIG = 'release((bytes32,uint64,address,uint64,bytes32,uint64,uint64,bytes32),(uint256,uint256,bytes32,uint64,bytes32),bytes[])'


# ── helpers over the rig ────────────────────────────────────────────────────────
def owner_send(rig, who, to, *call):
    """A transaction of the token's owner / admin / bridge on the fork (impersonated; the fork is local)."""
    rig.impersonated(who, to, *call)


def half_deposit(rig, deposit_id):
    """The source half of signer 1 asked to attest a deposit: (ok, answer). This is the command signatario.py runs
    before it signs a mint; a refusal here is a mint that is not signed."""
    done = sh(sys.executable, STABLE / 'eth_half.py', '--config', rig.eth_cfgs[0], 'deposit', '--deposit-id', deposit_id, ok=False)
    try:
        answer = json.loads(done.stdout)
    except ValueError:
        answer = {'ok': False, 'reason': f'unreadable answer: {done.stdout[-300:]} {done.stderr[-300:]}'}
    return bool(answer.get('ok')) and done.returncode == 0, answer


def deposit_id_of(rig, receipt):
    topic0 = out(CAST, 'keccak', 'Deposited(bytes32,bytes32,uint64,address,uint64,bytes32)').lower()
    for log in receipt['logs']:
        if log['address'].lower() == rig.vault and log['topics'][0].lower() == topic0:
            return log['topics'][1]
    raise SystemExit('no Deposited log in the receipt')


def finalized_deposit(rig, amount):
    """A new deposit of the depositor, finalized on the source fork: its id."""
    did = deposit_id_of(rig, rig.deposit(amount))
    rig.finalize_source()
    return did


def differences(answer):
    return sorted(d.get('what', '') for d in answer.get('differences', []))


def guard_case(rig, label, did, flip, restore, expect):
    """With the token moved out of the pinned state by `flip`, the source half attests nothing and names `expect`;
    after `restore` it attests again. The state is read at the signer's FINALIZED block, so each change is finalized."""
    flip()
    rig.finalize_source()
    ok, a = half_deposit(rig, did)
    check(f'11 guard: {label}: the source half attests no deposit and names the difference (minting stops)',
          not ok and 'no deposit is attested' in str(a.get('reason')) and all(e in differences(a) for e in expect), a)
    if restore:
        restore()
        rig.finalize_source()
        ok, a = half_deposit(rig, did)
        check(f'11 guard: {label}: with the token back in the pinned state the same deposit is attested', ok, a)


def pay_round(rig, burn_nonce, tries=3):
    ev = []
    for _ in range(tries):
        ev += rig.sign_all()
        ev += rig.relay()
        if rig.released(rig.burn_id(burn_nonce)):
            break
        time.sleep(1)
    return ev


def next_burn(rig):
    """The nonce the next burn of the L2 token takes (the flow's burns are 1, 2, ...)."""
    rig.burns = getattr(rig, 'burns', 2) + 1
    return rig.burns


def books_exact(rig):
    return rig.bal(rig.held, rig.vault) == int(rig.vview('totalLocked()(uint64)')) + int(rig.vview('feesAccrued()(uint64)'))


def books_covered(rig):
    return rig.bal(rig.held, rig.vault) >= int(rig.vview('totalLocked()(uint64)')) + int(rig.vview('feesAccrued()(uint64)'))


def guard_now(rig, label, expect_clean=True):
    """The route's whole token guard read at the fork's head (asset_routes.py guard does the same at `finalized`)."""
    sys.path.insert(0, str(STABLE))
    import token_guard
    found = token_guard.check_url(rig.eth, rig.spec['guard'], rig.vault, 'latest', cast=CAST)
    check(f'11 asset: {label}', (not found) == expect_clean, found)
    return found


# ── the stand-in tokens of the forge suites against the real contracts ──────────────────────
def probe(rig, token, actor, sig, *args):
    """(reverts?, bytes of return data) of a call as `actor`, then the same call sent: its status."""
    data = out(CAST, 'calldata', sig, *args)
    body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'eth_call', 'params': [{'from': actor, 'to': token, 'data': data}, 'latest']})
    req = urllib.request.Request(rig.eth, body.encode(), {'content-type': 'application/json'})
    with urllib.request.urlopen(req, timeout=300) as h:
        r = json.loads(h.read())
    simulated = ('revert', 0) if 'error' in r else ('ok', (len(r['result']) - 2) // 2, r['result'][-2:] if len(r['result']) > 2 else '')
    sh(CAST, 'rpc', 'anvil_setBalance', actor, hex(10**20), '--rpc-url', rig.eth)
    sh(CAST, 'rpc', 'anvil_impersonateAccount', actor, '--rpc-url', rig.eth)
    done = sh(CAST, 'send', token, sig, *args, '--rpc-url', rig.eth, '--unlocked', '--from', actor, '--gas-limit', '600000', '--json', ok=False)
    sh(CAST, 'rpc', 'anvil_stopImpersonatingAccount', actor, '--rpc-url', rig.eth)
    status = 'reverted' if done.returncode or json.loads(done.stdout)['status'] != '0x1' else 'mined'
    return simulated, status


def compare_tokens(rig, name, real, real_admin, mock, mock_admin, script, fund_mock):
    """Runs `script` against the real contract and against the stand-in, with the same accounts in the same roles,
    and compares, call by call: does it revert, how many bytes it returns and the last one, and after each call the
    balances of the three accounts and the allowance between the first two. `admin` in the script is each token's own
    owner (or bridge)."""
    a = [rig.addr[f'x{i}'] for i in range(3)]
    amount = 1_000_000_000
    for who in a:
        rig.fund_asset(who, amount)
    fund_mock(a, amount)
    rows, same = [], 0
    for step in script:
        label, actor, sig, args = step[0], step[1], step[2], step[3:]
        seen = []
        for token, admin in ((real, real_admin), (mock, mock_admin)):
            who = admin if actor == 'admin' else a[actor]
            got = probe(rig, token, who, sig, *[a[x] if isinstance(x, int) and not isinstance(x, bool) and x < 3 else
                                                 (token if x == 'token' else str(x)) for x in args])
            state = tuple(int(rig.view(rig.eth, token, 'balanceOf(address)(uint256)', w)) for w in a) + (
                int(rig.view(rig.eth, token, 'allowance(address,address)(uint256)', a[0], a[1])),)
            seen.append((got, state))
        rows.append((label, seen[0] == seen[1], seen))
        same += seen[0] == seen[1]
    bad = [(label, seen) for label, eq, seen in rows if not eq]
    check(f'11 stand-in: the {name} stand-in of the forge suites answers {len(rows)} of {len(rows)} probe calls as the real contract '
          '(revert or not, bytes returned, balances and allowance after each call)', same == len(rows), bad[:3])
    print(f'INFO stand-in comparison ({name}): {same} of {len(rows)} calls identical', flush=True)


def amounts(*values):
    """Script amounts as strings (so they are never taken for account indexes)."""
    return [str(v) for v in values]


# ── tether-legacy: Tether's own contract on Ethereum ──────────────────────────────────
def tether_legacy(rig):
    A, U, t = rig.addr, rf.U, rig.asset
    owner = rig.view(rig.eth, t, 'owner()(address)')
    guard_now(rig, 'the real token is in the state this route pins (code, fee zero, not paused, not deprecated, vault not blacklisted, owner)')
    check('11 asset: the vault\'s own reading of the token: known, not blacklisted, not replaced',
          out(CAST, 'call', rig.vault, 'tokenState()(bool,bool,bool)', '--rpc-url', rig.eth).split() == ['true', 'false', 'false'])
    did = finalized_deposit(rig, 80 * U)
    ok, a = half_deposit(rig, did)
    check('11 guard: with the token as reviewed, the source half attests a finalized deposit (control)', ok, a)

    # a. a blacklisted RELEASE RECIPIENT: this token checks only the sender side, so the release is paid
    owner_send(rig, owner, t, 'addBlackList(address)', A['carol'])
    n_carol, n_bob = next_burn(rig), next_burn(rig)
    rig.burn(40 * U, A['carol'])
    rig.burn(60 * U, A['bob'])
    bob_before = rig.bal(t, A['bob'])
    pay_round(rig, n_carol)
    pay_round(rig, n_bob)
    check('11 issuer: a burn to a recipient the issuer BLACKLISTED is paid by this token (it checks the sender side only); '
          'the next burn is paid too', rig.released(rig.burn_id(n_carol)) and rig.bal(t, A['carol']) == rf.paid(40 * U)
          and rig.released(rig.burn_id(n_bob)) and rig.bal(t, A['bob']) == bob_before + rf.paid(60 * U),
          (rig.bal(t, A['carol']), rig.bal(t, A['bob']) - bob_before))
    owner_send(rig, owner, t, 'destroyBlackFunds(address)', A['carol'])
    check('11 issuer: the issuer can destroy what the blacklisted recipient received; the vault\'s books are untouched',
          rig.bal(t, A['carol']) == 0 and books_exact(rig))
    owner_send(rig, owner, t, 'removeBlackList(address)', A['carol'])

    # b. the VAULT blacklisted: deposits refused by the vault itself, releases revert in the token, nothing is lost
    n = next_burn(rig)
    rig.burn(40 * U, A['bob'])
    bob_before, locked = rig.bal(t, A['bob']), int(rig.vview('totalLocked()(uint64)'))

    def blacklist_vault():
        owner_send(rig, owner, t, 'addBlackList(address)', rig.vault)
        check('11 issuer: with the VAULT blacklisted the vault refuses a deposit itself (TokenUnsafe): the token alone would take it',
              rf.selector('TokenUnsafe()')[2:] in rig.deposit_reverts(100 * U)
              and rig.reverts(rig.eth, rig.vault, t, 'transferFrom(address,address,uint256)', A['alice'], rig.vault, str(100 * U)) == '')
        ev = pay_round(rig, n, tries=2)
        check('11 issuer: with the VAULT blacklisted a release is not paid, consumes nothing and the books are unchanged',
              not rig.released(rig.burn_id(n)) and rig.bal(t, A['bob']) == bob_before
              and int(rig.vview('totalLocked()(uint64)')) == locked and books_exact(rig), [e for e in ev if 'release' in str(e.get('kind'))][-2:])
    guard_case(rig, 'the vault blacklisted', did, blacklist_vault,
               lambda: owner_send(rig, owner, t, 'removeBlackList(address)', rig.vault), ['the vault is blacklisted'])
    pay_round(rig, n)
    check('11 issuer: once the blacklist is lifted the same burn is paid, exactly once',
          rig.released(rig.burn_id(n)) and rig.bal(t, A['bob']) == bob_before + rf.paid(40 * U) and books_exact(rig))

    # c. the issuer's transfer fee switched on
    n = next_burn(rig)
    rig.burn(40 * U, A['bob'])
    bob_before, vault_before = rig.bal(t, A['bob']), rig.bal(t, rig.vault)
    issuer_before = rig.bal(t, owner)

    def fee_on():
        owner_send(rig, owner, t, 'setParams(uint256,uint256)', '10', '5')
        locked0, count0 = rig.vview('totalLocked()(uint64)'), rig.vview('depositCount()(uint64)')
        check('11 issuer: with the transfer fee ON a deposit is refused (InvalidTransfer): the vault never credits more than it received',
              rf.selector('InvalidTransfer()')[2:] in rig.deposit_reverts(100 * U)
              and (rig.deposit(100 * U, ok=False) or {'status': '0x0'})['status'] != '0x1'
              and (rig.vview('totalLocked()(uint64)'), rig.vview('depositCount()(uint64)')) == (locked0, count0) and books_exact(rig))
        pay_round(rig, n)
        sent = rf.paid(40 * U)
        kept = min(sent * 10 // 10_000, 5_000_000)
        check('11 issuer: with the transfer fee ON a release still pays: the vault\'s balance falls by exactly what it sent and '
              'the recipient bears the issuer\'s fee',
              rig.released(rig.burn_id(n)) and rig.bal(t, A['bob']) == bob_before + sent - kept
              and rig.bal(t, rig.vault) == vault_before - sent and rig.bal(t, owner) == issuer_before + kept and books_exact(rig),
              (rig.bal(t, A['bob']) - bob_before, sent, kept))
    guard_case(rig, 'the issuer\'s transfer fee on', did, fee_on,
               lambda: owner_send(rig, owner, t, 'setParams(uint256,uint256)', '0', '0'),
               ['issuer transfer fee rate (must be zero)', 'issuer transfer fee ceiling (must be zero)'])

    # d. the issuer's pause
    n = next_burn(rig)
    rig.burn(40 * U, A['bob'])
    bob_before = rig.bal(t, A['bob'])

    def pause():
        owner_send(rig, owner, t, 'pause()')
        ev = pay_round(rig, n, tries=2)
        check('11 issuer: with the token PAUSED a deposit reverts and a release is not paid; nothing is consumed',
              rig.deposit_reverts(100 * U) != '' and not rig.released(rig.burn_id(n)) and rig.bal(t, A['bob']) == bob_before
              and books_exact(rig), [e for e in ev if 'release' in str(e.get('kind'))][-2:])
    guard_case(rig, 'the token paused', did, pause, lambda: owner_send(rig, owner, t, 'unpause()'), ['issuer pause'])
    pay_round(rig, n)
    check('11 issuer: after the unpause the waiting burn is paid and a deposit works again',
          rig.released(rig.burn_id(n)) and rig.bal(t, A['bob']) == bob_before + rf.paid(40 * U) and rig.deposit_reverts(100 * U) == '')

    # e. the stand-in of the forge suites against the real contract (before the token is replaced below)
    mock = rig.create(rig.eth, 'solidity-tests/harness/UsdtRouteTokens.sol:EthereumUSDTLike')
    script = [
        ('approve 0 -> 5', 0, 'approve(address,uint256)', 1, *amounts(5)),
        ('approve 5 -> 7', 0, 'approve(address,uint256)', 1, *amounts(7)),
        ('approve 5 -> 5', 0, 'approve(address,uint256)', 1, *amounts(5)),
        ('approve 5 -> 0', 0, 'approve(address,uint256)', 1, *amounts(0)),
        ('approve 0 -> 700', 0, 'approve(address,uint256)', 1, *amounts(700)),
        ('transfer', 0, 'transfer(address,uint256)', 2, *amounts(100)),
        ('transfer above the balance', 0, 'transfer(address,uint256)', 2, *amounts(10**12)),
        ('transferFrom', 1, 'transferFrom(address,address,uint256)', 0, 2, *amounts(300)),
        ('transferFrom above the allowance', 1, 'transferFrom(address,address,uint256)', 0, 2, *amounts(401)),
        ('blacklist the third account', 'admin', 'addBlackList(address)', 2),
        ('transfer BY a blacklisted account', 2, 'transfer(address,uint256)', 0, *amounts(1)),
        ('transfer TO a blacklisted account', 0, 'transfer(address,uint256)', 2, *amounts(50)),
        ('transferFrom TO a blacklisted account', 1, 'transferFrom(address,address,uint256)', 0, 2, *amounts(50)),
        ('destroy the blacklisted balance', 'admin', 'destroyBlackFunds(address)', 2),
        ('blacklist lifted', 'admin', 'removeBlackList(address)', 2),
        ('destroy a balance that is not blacklisted', 'admin', 'destroyBlackFunds(address)', 0),
        ('pause', 'admin', 'pause()'),
        ('transfer while paused', 0, 'transfer(address,uint256)', 2, *amounts(1)),
        ('transferFrom while paused', 1, 'transferFrom(address,address,uint256)', 0, 2, *amounts(1)),
        ('approve to zero while paused', 0, 'approve(address,uint256)', 1, *amounts(0)),
        ('approve from zero while paused', 0, 'approve(address,uint256)', 1, *amounts(900)),
        ('unpause', 'admin', 'unpause()'),
        ('fee 20 bps refused', 'admin', 'setParams(uint256,uint256)', *amounts(20, 49)),
        ('fee ceiling 50 refused', 'admin', 'setParams(uint256,uint256)', *amounts(19, 50)),
        ('fee 19 bps, ceiling 49', 'admin', 'setParams(uint256,uint256)', *amounts(19, 49)),
        ('transfer under the fee', 0, 'transfer(address,uint256)', 2, *amounts(1_000_000)),
        ('transferFrom under the fee', 1, 'transferFrom(address,address,uint256)', 0, 2, *amounts(500)),
        ('fee off', 'admin', 'setParams(uint256,uint256)', *amounts(0, 0)),
        ('transfer after the fee', 0, 'transfer(address,uint256)', 2, *amounts(1_000_000)),
        ('a call by someone who is not the owner', 0, 'pause()'),
    ]
    compare_tokens(rig, 'Ethereum USDT', t, owner, mock, A['deployer'], script,
                   lambda accounts, amount: [rig.send(rig.eth, 'deployer', mock, 'mint(address,uint256)', w, str(amount)) for w in accounts])

    # f. `deprecate`: the issuer replaces the token. Deposits stop for good; exits go through the forwarder.
    n = next_burn(rig)
    rig.burn(40 * U, A['bob'])
    upgraded = rig.create(rig.eth, 'solidity-tests/harness/TronUSDTLike.sol:TronUSDTUpgraded', t)
    held = rig.bal(t, rig.vault)
    owner_send(rig, owner, t, 'deprecate(address)', upgraded)
    check('11 issuer: after `deprecate` the vault reports the replacement and refuses every deposit (TokenUnsafe)',
          out(CAST, 'call', rig.vault, 'tokenState()(bool,bool,bool)', '--rpc-url', rig.eth).split() == ['true', 'false', 'true']
          and rf.selector('TokenUnsafe()')[2:] in rig.deposit_reverts(100 * U))
    rig.finalize_source()
    ok, a = half_deposit(rig, did)
    check('11 guard: the token replaced (`deprecate`): the source half attests no deposit and names it (minting stops)',
          not ok and 'the token was replaced (deprecate)' in differences(a), a)
    ev = pay_round(rig, n, tries=2)
    check('11 issuer: while the upgraded token holds nothing for the vault, a release is not paid and consumes nothing '
          '(the legacy contract answers the upgraded token\'s balance: InsufficientBacking)',
          not rig.released(rig.burn_id(n)) and rig.bal(t, rig.vault) == 0, [e for e in ev if 'release' in str(e.get('kind'))][-2:])
    rig.send(rig.eth, 'deployer', upgraded, 'mint(address,uint256)', rig.vault, str(held))  # the issuer migrates the balance
    pay_round(rig, n)
    check('11 issuer: once the upgraded token holds the vault\'s balance the same burn is paid through the forwarder; deposits stay closed',
          rig.released(rig.burn_id(n)) and rig.bal(upgraded, A['bob']) == rf.paid(40 * U)
          and rf.selector('TokenUnsafe()')[2:] in rig.deposit_reverts(100 * U) and books_exact(rig),
          (rig.bal(upgraded, A['bob']), rf.paid(40 * U)))


# ── usdt0: USD₮0 on Arbitrum One ────────────────────────────────────────────────
def usdt0(rig):
    A, U, t = rig.addr, rf.U, rig.asset
    owner = rig.view(rig.eth, t, 'owner()(address)')
    impl = '0x' + out(CAST, 'storage', t, rf.EIP1967_IMPLEMENTATION, '--rpc-url', rig.eth)[-40:]
    admin = '0x' + out(CAST, 'storage', t, '0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103', '--rpc-url', rig.eth)[-40:]
    guard_now(rig, 'the real contract is what this route pins: the proxy\'s code, the implementation and its code, the proxy admin, '
                   'the owner, the OFT contract, the proxy admin\'s owner, the vault not blocked')
    safe = rig.view(rig.eth, admin, 'owner()(address)')
    check('11 asset: one Safe (3 of 5) owns both the token and its proxy admin; symbol() is USD₮0',
          safe.lower() == owner.lower() and rig.view(rig.eth, safe, 'getThreshold()(uint256)') == '3'
          and len(out(CAST, 'call', safe, 'getOwners()(address[])', '--rpc-url', rig.eth).split(',')) == 5
          and 'USD' in out(CAST, 'call', t, 'symbol()(string)', '--rpc-url', rig.eth), (safe, owner))
    did = finalized_deposit(rig, 80 * U)
    ok, a = half_deposit(rig, did)
    check('11 guard: with the token as reviewed, the source half attests a finalized deposit (control)', ok, a)

    # a. a blocked release recipient is paid; b. a release the token refuses for good does not stop the next one
    owner_send(rig, owner, t, 'addToBlockedList(address)', A['carol'])
    n_carol, n_stuck, n_bob = next_burn(rig), next_burn(rig), next_burn(rig)
    rig.burn(40 * U, A['carol'])
    rig.burn(40 * U, t)  # the token contract itself: a transfer to it always reverts
    rig.burn(60 * U, A['bob'])
    bob_before, locked = rig.bal(t, A['bob']), int(rig.vview('totalLocked()(uint64)'))
    ev = []
    for n in (n_carol, n_stuck, n_bob):
        ev += pay_round(rig, n, tries=2)
    check('11 issuer: a burn to a recipient the owner BLOCKED is paid by this token (it checks the caller and `from` only)',
          rig.released(rig.burn_id(n_carol)) and rig.bal(t, A['carol']) == rf.paid(40 * U), rig.bal(t, A['carol']))
    check('11 token: a burn whose recipient the token refuses for good (the token contract itself) is never paid and consumes nothing',
          not rig.released(rig.burn_id(n_stuck)), [e for e in ev if 'release' in str(e.get('kind'))][-3:])
    check('11 token: that burn does not stop the next burn from being paid (the vault keeps no queue: nonces are a set)',
          rig.released(rig.burn_id(n_bob)) and rig.bal(t, A['bob']) == bob_before + rf.paid(60 * U))
    check('11 token: books after the refused burn: totalLocked fell only by the two paid burns',
          int(rig.vview('totalLocked()(uint64)')) == locked - 100 * U and books_exact(rig))
    owner_send(rig, owner, t, 'destroyBlockedFunds(address)', A['carol'])
    owner_send(rig, owner, t, 'removeFromBlockedList(address)', A['carol'])

    # c. the VAULT blocked
    n = next_burn(rig)
    rig.burn(40 * U, A['bob'])
    bob_before, locked = rig.bal(t, A['bob']), int(rig.vview('totalLocked()(uint64)'))

    def block_vault():
        owner_send(rig, owner, t, 'addToBlockedList(address)', rig.vault)
        ev = pay_round(rig, n, tries=2)
        check('11 issuer: with the VAULT blocked the token refuses the vault\'s transferFrom, so no deposit is taken; a release is '
              'not paid and consumes nothing', rf.selector('InvalidTransfer()')[2:] in rig.deposit_reverts(100 * U)
              and not rig.released(rig.burn_id(n)) and rig.bal(t, A['bob']) == bob_before
              and int(rig.vview('totalLocked()(uint64)')) == locked and books_exact(rig), [e for e in ev if 'release' in str(e.get('kind'))][-2:])
    guard_case(rig, 'the vault blocked', did, block_vault,
               lambda: owner_send(rig, owner, t, 'removeFromBlockedList(address)', rig.vault), ['the vault is blocked'])
    pay_round(rig, n)
    check('11 issuer: once the vault is unblocked the same burn is paid, exactly once',
          rig.released(rig.burn_id(n)) and rig.bal(t, A['bob']) == bob_before + rf.paid(40 * U) and books_exact(rig))

    # d. a blocked depositor
    owner_send(rig, owner, t, 'addToBlockedList(address)', A['alice'])
    check('11 issuer: a blocked depositor cannot deposit; nothing is booked', rig.deposit_reverts(100 * U) != '' and books_exact(rig))
    owner_send(rig, owner, t, 'removeFromBlockedList(address)', A['alice'])

    # e. the stand-in against the real contract (before the implementation is replaced below)
    mock = rig.create(rig.eth, 'solidity-tests/harness/UsdtRouteTokens.sol:Usdt0Like', A['deployer'])
    script = [
        ('approve 0 -> 5', 0, 'approve(address,uint256)', 1, *amounts(5)),
        ('approve 5 -> 700', 0, 'approve(address,uint256)', 1, *amounts(700)),
        ('transfer', 0, 'transfer(address,uint256)', 2, *amounts(100)),
        ('transfer above the balance', 0, 'transfer(address,uint256)', 2, *amounts(10**12)),
        ('transferFrom', 1, 'transferFrom(address,address,uint256)', 0, 2, *amounts(300)),
        ('transferFrom above the allowance', 1, 'transferFrom(address,address,uint256)', 0, 2, *amounts(401)),
        ('transfer to the token contract', 0, 'transfer(address,uint256)', 'token', *amounts(1)),
        ('transferFrom to the token contract', 1, 'transferFrom(address,address,uint256)', 0, 'token', *amounts(1)),
        ('block the third account', 'admin', 'addToBlockedList(address)', 2),
        ('transfer BY a blocked account', 2, 'transfer(address,uint256)', 0, *amounts(1)),
        ('transfer TO a blocked account', 0, 'transfer(address,uint256)', 2, *amounts(50)),
        ('transferFrom TO a blocked account', 1, 'transferFrom(address,address,uint256)', 0, 2, *amounts(50)),
        ('block the first account', 'admin', 'addToBlockedList(address)', 0),
        ('transferFrom FROM a blocked account', 1, 'transferFrom(address,address,uint256)', 0, 2, *amounts(10)),
        ('first account unblocked', 'admin', 'removeFromBlockedList(address)', 0),
        ('block the spender', 'admin', 'addToBlockedList(address)', 1),
        ('transferFrom BY a blocked spender', 1, 'transferFrom(address,address,uint256)', 0, 2, *amounts(10)),
        ('spender unblocked', 'admin', 'removeFromBlockedList(address)', 1),
        ('destroy the blocked balance', 'admin', 'destroyBlockedFunds(address)', 2),
        ('destroy a balance that is not blocked', 'admin', 'destroyBlockedFunds(address)', 0),
        ('third account unblocked', 'admin', 'removeFromBlockedList(address)', 2),
        ('a call by someone who is not the owner', 0, 'addToBlockedList(address)', 2),
        ('a mint by someone who is not the OFT contract', 0, 'mint(address,uint256)', 0, *amounts(1)),
    ]
    compare_tokens(rig, 'USD₮0', t, owner, mock, A['deployer'], script,
                   lambda accounts, amount: [rig.send(rig.eth, 'deployer', mock, 'mint(address,uint256)', w, str(amount)) for w in accounts])

    # f. the implementation replaced (what the proxy admin's owner can do)
    n = next_burn(rig)
    rig.burn(40 * U, A['bob'])
    bob_before = rig.bal(t, A['bob'])
    slot_value = out(CAST, 'storage', t, rf.EIP1967_IMPLEMENTATION, '--rpc-url', rig.eth)

    def upgrade():
        # another implementation: code that is a token but reads other storage (the stand-in's), so no balance is found
        sh(CAST, 'rpc', 'anvil_setStorageAt', t, rf.EIP1967_IMPLEMENTATION, '0x' + mock[2:].rjust(64, '0'), '--rpc-url', rig.eth)
        ev = pay_round(rig, n, tries=2)
        check('11 admin: with ANOTHER implementation behind the proxy no deposit is booked and no release is paid; nothing is consumed',
              rig.deposit_reverts(100 * U) != '' and not rig.released(rig.burn_id(n)), [e for e in ev if 'release' in str(e.get('kind'))][-2:])
    guard_case(rig, 'the implementation replaced', did, upgrade,
               lambda: sh(CAST, 'rpc', 'anvil_setStorageAt', t, rf.EIP1967_IMPLEMENTATION, slot_value, '--rpc-url', rig.eth),
               ['EIP-1967 implementation (an upgrade changes it)'])
    pay_round(rig, n)
    check('11 admin: with the reviewed implementation back the waiting burn is paid and the books are exact',
          rig.released(rig.burn_id(n)) and rig.bal(t, A['bob']) == bob_before + rf.paid(40 * U) and books_exact(rig))
    print(f'INFO asset {t}: proxy, implementation {impl}, proxy admin {admin}, owner and admin owner {safe}', flush=True)


# ── op-bridged: bridged USDT on OP Mainnet ──────────────────────────────────────────
def op_bridged(rig):
    A, U, t = rig.addr, rf.U, rig.asset
    bridge = rig.view(rig.eth, t, 'l2Bridge()(address)')
    guard_now(rig, 'the real contract is what this route pins: its code, l1Token = Tether\'s Ethereum contract, l2Bridge = the standard '
                   'bridge predeploy, and the bridge\'s implementation and proxy admin')
    check('11 asset: a plain token: no owner, no blocklist, no pause, no fee getters',
          all(rig.reverts(rig.eth, A['mallory'], t, sig, *args) != '' for sig, args in (
              ('owner()', ()), ('paused()', ()), ('basisPointsRate()', ()), ('isBlocked(address)', (A['bob'],)), ('isBlackListed(address)', (A['bob'],)))))
    did = finalized_deposit(rig, 80 * U)
    ok, a = half_deposit(rig, did)
    check('11 guard: with the token as reviewed, the source half attests a finalized deposit (control)', ok, a)

    # a. the bridge burns part of the vault's balance (its power over any holder), then mints it back
    n = next_burn(rig)
    rig.burn(40 * U, A['bob'])
    bob_before, locked = rig.bal(t, A['bob']), int(rig.vview('totalLocked()(uint64)'))
    owner_send(rig, bridge, t, 'burn(address,uint256)', rig.vault, str(10 * U))
    ev = pay_round(rig, n, tries=2)
    check('11 bridge: after the bridge burned part of the vault\'s balance, a deposit and a release stop on the backing check '
          '(InsufficientBacking); nothing is paid from other users\' funds and nothing is consumed',
          rf.selector('InsufficientBacking()')[2:] in rig.deposit_reverts(100 * U) and not rig.released(rig.burn_id(n))
          and rig.bal(t, A['bob']) == bob_before and int(rig.vview('totalLocked()(uint64)')) == locked,
          [e for e in ev if 'release' in str(e.get('kind'))][-2:])
    rc, lines = rig.reserves()
    check('11 bridge: the reserves monitor reports that the vault holds less than its books', rc != 0 or any(
        l.get('kind') == 'alert' for l in lines), (rc, lines[-2:]))
    owner_send(rig, bridge, t, 'mint(address,uint256)', rig.vault, str(10 * U))
    pay_round(rig, n)
    check('11 bridge: with the balance back the same burn is paid and the books are exact',
          rig.released(rig.burn_id(n)) and rig.bal(t, A['bob']) == bob_before + rf.paid(40 * U) and books_exact(rig))

    # b. the bridge upgraded (the contract that may mint and burn the token)
    slot = '0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc'
    value = out(CAST, 'storage', bridge, slot, '--rpc-url', rig.eth)
    guard_case(rig, 'the standard bridge upgraded', did,
               lambda: sh(CAST, 'rpc', 'anvil_setStorageAt', bridge, slot, '0x' + '00' * 12 + 'ab' * 20, '--rpc-url', rig.eth),
               lambda: sh(CAST, 'rpc', 'anvil_setStorageAt', bridge, slot, value, '--rpc-url', rig.eth),
               ['the standard bridge\'s implementation (an upgrade of the contract that may mint and burn the token)'])

    # c. the stand-in against the real contract
    mock = rig.create(rig.eth, 'solidity-tests/harness/UsdtRouteTokens.sol:OpBridgedUsdtLike',
                      '0xdAC17F958D2ee523a2206206994597C13D831ec7', bridge)
    script = [
        ('approve 0 -> 5', 0, 'approve(address,uint256)', 1, *amounts(5)),
        ('approve 5 -> 700', 0, 'approve(address,uint256)', 1, *amounts(700)),
        ('transfer', 0, 'transfer(address,uint256)', 2, *amounts(100)),
        ('transfer above the balance', 0, 'transfer(address,uint256)', 2, *amounts(10**12)),
        ('transferFrom', 1, 'transferFrom(address,address,uint256)', 0, 2, *amounts(300)),
        ('transferFrom above the allowance', 1, 'transferFrom(address,address,uint256)', 0, 2, *amounts(401)),
        ('transfer to the token contract', 0, 'transfer(address,uint256)', 'token', *amounts(1)),
        ('the bridge mints', 'admin', 'mint(address,uint256)', 2, *amounts(7)),
        ('the bridge burns a holder without an allowance', 'admin', 'burn(address,uint256)', 0, *amounts(9)),
        ('the bridge burns above a balance', 'admin', 'burn(address,uint256)', 1, *amounts(10**12)),
        ('a mint by someone who is not the bridge', 0, 'mint(address,uint256)', 0, *amounts(1)),
        ('a burn by someone who is not the bridge', 0, 'burn(address,uint256)', 2, *amounts(1)),
    ]
    compare_tokens(rig, 'OP Mainnet bridged USDT', t, bridge, mock, bridge, script,
                   lambda accounts, amount: [owner_send(rig, bridge, mock, 'mint(address,uint256)', w, str(amount)) for w in accounts])


rf.ISSUER_STEPS.update({'tether-legacy': tether_legacy, 'usdt0': usdt0, 'op-bridged': op_bridged})


def main():
    args = sys.argv[1:]
    routes = asset_routes.registry()['routes']
    if not args or args[0] not in routes:
        raise SystemExit(__doc__ + f'\nroutes: {", ".join(routes)}')
    spec = asset_routes.merged_spec(args[0])
    spec.setdefault('timing', {})
    print(f'INFO route {args[0]}: {spec["asset"]["symbol"]} at {spec["asset"]["address"]} on {spec["name"]}, vault '
          f'{spec["vault"]["contract"]} (transferMode {spec["vault"]["transferMode"]}), launch state {spec["launch"]["state"]}', flush=True)
    rf.main(route_spec=spec)


if __name__ == '__main__':
    main()
