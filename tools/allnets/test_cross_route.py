"""The cross-route certificate matrix (agent 375, round 18): a certificate made for one route is refused by every other.

  python3 -m unittest test_cross_route        (from tools/allnets; offline, throwaway keys, no chain, no `cast`)

Every route's committee is the SAME seven secp256k1 keys (BRIEF-ROUND16.md architecture point 5). So nothing but the
signed digest keeps a release or mint certificate of one route from being valid on another. This file computes, with
each route's OWN digest code (the functions its signers and guardians call), the digest of one and the same item for
every route, signs route A's digest with a throwaway 5-of-7 committee, and verifies the certificate the way route B's
tools do (in-process recovery, the contracts' signature form: 65 bytes, low s, v 27/28): accepted only when A == B.

Worst case, stated: every EVM-shaped vault is given the SAME 20-byte address (a deployer with the same nonce on two
EVM chains gets the same CREATE address) and every L2 token the same address in the mint matrix, so the only things
left to separate two routes are what the digest itself binds: the source chain id (unique by registry check C3) and,
for Stellar, its own tags. Families and their digest code:
  evm-v2    ethereum, arbitrum-one, op-mainnet, linea, base, bnb, tron:
            tools/signatario-stable/bridge_feed.py release_digest (ContextBoundSourceVault / ProvenanceSourceVault v2)
  solana    tools/signatario-solana/solana_lib.py release_authorization + eip191 (the same layout as evm-v2, bound to
            the 256-bit Solana chain id keccak("BLOCH-SVM-CHAIN-ID-v1" || genesis))
  stellar   tools/signatario-stellar/stellar_net.py release_digest + personal (tags BLOCH-XLM-*, network id)
  bitcoin   NOT an EIP-191 certificate: a release is a Bitcoin transaction whose BIP-143 signatures (DER + sighash
            flag) commit to the outpoints of that route's own P2WSH thread; a 65-byte certificate of any other route is
            not a script signature at all (Argument; the regtest rehearsal shows the script path), and a Bitcoin
            signature is not a 65-byte EIP-191 certificate (Test: test_bitcoin_signature_is_not_a_certificate).
Several routes on ONE network (round 20: ethereum and ethereum-usdt, arbitrum-one and arbitrum-one-usdt, op-mainnet
and op-mainnet-usdt) share the chain id word by definition. What separates their certificates is the vault word (two
contracts on one chain never have one address; the registry's check C9 refuses a shared custody address in the files)
and the route word (routeId() hashes the vault's own address and its token). So in this matrix the first route of
every network keeps the one shared address, the worst case across chains, and each further route of a network has an
address of its own; the control test at the end shows what the vault word carries.
Mint side: every L2 token is the frozen BridgedStablecoinV3; its EIP-712 mint digest binds the token address, chain
700770 and, in the struct, sourceChainId, sourceVault, sourceRoute (bridge_feed.mint_digest).
"""
import json
from pathlib import Path
import sys
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
for d in ('signatario-stable', 'signatario-solana', 'signatario-stellar', 'signatario-btc'):
    sys.path.insert(0, str(ROOT / 'tools' / d))
import bridge_feed as BF  # noqa: E402
import btc_core as BC  # noqa: E402
import sigverify as SV  # noqa: E402
import solana_lib as SL  # noqa: E402
import stellar_net as XN  # noqa: E402

REG = json.loads((ROOT / 'deployments/bridges.json').read_text())
ROUTES = {r['id']: r for r in REG['routes']}
EVM_V2 = [n for n, r in ROUTES.items() if r['network']['kind'] in ('evm', 'tvm')]
DIGEST_ROUTES = EVM_V2 + ['solana', 'stellar']
KEYS = [0x1000 + i for i in range(7)]  # throwaway committee
COMMITTEE = [BC.eth_address(BC.pubkey(k)) for k in KEYS]
THRESHOLD = 5
VAULT20 = bytes.fromhex('5a' * 20)
ROUTE32 = bytes.fromhex('7e' * 32)
RECIPIENT20 = bytes.fromhex('c1' * 20)
BURN32 = bytes.fromhex('b0' * 32)
MINT_HEAD = bytes.fromhex('4d' * 32)
ANCHOR_H, NATIVE_H = bytes.fromhex('a1' * 32), bytes.fromhex('f1' * 32)
ITEM = dict(nonce=7, amount=1_000_000_000, mint_count=3, minted_total=5_000_000_000, valid=1_900_000_000,
            anchor_n=21_000_000, native_n=4_000)
STELLAR_RECIPIENT = XN.strkey_encode('account', bytes.fromhex('c1' * 32))
STELLAR_VAULT = XN.strkey_encode('contract', bytes(12) + VAULT20)


def w(v):
    return v.to_bytes(32, 'big') if isinstance(v, int) else bytes(v).rjust(32, b'\0')


def chain_word(net):
    return int(ROUTES[net]['sourceChainId']).to_bytes(32, 'big')


FURTHER = [n for n, r in ROUTES.items() if 'route' in r]


def vault_of(net, shared=False):
    """The 20-byte vault of a route in the matrix: the one shared address for the first route of every network (a
    deployer with one nonce on two chains), and an own address for each further route of a network (one chain, two
    contracts, two addresses). `shared=True` is the impossible case used by the control test."""
    if shared or net not in FURTHER:
        return VAULT20
    import hashlib
    return hashlib.sha256(b'further-route-vault:' + net.encode()).digest()[:20]


def release_digest(net, shared_vault=False, route=ROUTE32):
    """The 32-byte digest route `net`'s committee signs for ITEM, by that route's own code."""
    i = ITEM
    if net in EVM_V2:
        return BF.release_digest(chain_word(net), w(vault_of(net, shared_vault)), route, w(i['nonce']), w(RECIPIENT20),
                                 w(i['amount']), BURN32, w(i['valid']), w(i['anchor_n']), ANCHOR_H, w(i['native_n']), NATIVE_H,
                                 chain=[w(i['mint_count']), w(i['minted_total']), MINT_HEAD])
    if net == 'solana':
        rel = {'route': ROUTE32, 'nonce': i['nonce'], 'recipient': RECIPIENT20, 'amount': i['amount'], 'nativeBurn': BURN32,
               'mintCount': i['mint_count'], 'mintedTotal': i['minted_total'], 'mintHead': MINT_HEAD}
        ctx = {'validUntil': i['valid'], 'sourceAnchorNumber': i['anchor_n'], 'sourceAnchorHash': ANCHOR_H,
               'nativeFinalizedNumber': i['native_n'], 'nativeFinalizedHash': NATIVE_H}
        return SL.eip191(SL.release_authorization(chain_word('solana'), VAULT20, rel, ctx))
    if net == 'stellar':
        passphrase = ROUTES['stellar']['network']['chainId']
        rel = {'route': ROUTE32, 'nonce': i['nonce'], 'recipient': STELLAR_RECIPIENT, 'amount': i['amount'],
               'native_burn': BURN32, 'mint_count': i['mint_count'], 'minted_total': i['minted_total'], 'mint_head': MINT_HEAD}
        ctx = {'valid_until': i['valid'], 'pause_count': 0, 'native_finalized_number': i['native_n'],
               'native_finalized_hash': NATIVE_H}
        return XN.personal(XN.release_digest(passphrase, STELLAR_VAULT, rel, ctx))
    raise KeyError(net)


def certificate(digest):
    out = []
    for k in KEYS[:THRESHOLD]:
        r, s, rec = BC.sign(digest, k)
        out.append('0x' + r.to_bytes(32, 'big').hex() + s.to_bytes(32, 'big').hex() + format(27 + rec, '02x'))
    return out


def accepted(digest, sigs):
    """Route-side check: THRESHOLD distinct committee members recovered in process from contract-form signatures."""
    signers = {SV.recover('0x' + digest.hex(), s) for s in sigs}
    return len(signers & {a.lower() for a in COMMITTEE}) >= THRESHOLD


class Matrix(unittest.TestCase):
    def test_every_route_has_a_digest_row(self):
        self.assertEqual(sorted(DIGEST_ROUTES + ['bitcoin']), sorted(ROUTES))

    def test_the_same_item_has_a_different_release_digest_on_every_route(self):
        digests = {n: release_digest(n) for n in DIGEST_ROUTES}
        self.assertEqual(len(set(digests.values())), len(digests), digests)

    def test_release_certificate_of_one_route_is_refused_by_every_other(self):
        digests = {n: release_digest(n) for n in DIGEST_ROUTES}
        certs = {n: certificate(d) for n, d in digests.items()}
        cells = 0
        for a in DIGEST_ROUTES:
            for b in DIGEST_ROUTES:
                with self.subTest(made_for=a, presented_to=b):
                    self.assertEqual(accepted(digests[b], certs[a]), a == b)
                cells += 1
        self.assertEqual(cells, len(DIGEST_ROUTES) ** 2)

    def test_mint_certificate_of_one_route_is_refused_by_every_other_even_at_one_token_address(self):
        token = w(bytes.fromhex('70' * 20))
        def mint(n):
            return BF.mint_digest('3', w(700770), token, chain_word(n), w(vault_of(n)), ROUTE32, BURN32, w(1), w(10**9), w(RECIPIENT20))
        nets = list(ROUTES)
        digests = {n: mint(n) for n in nets}
        self.assertEqual(len(set(digests.values())), len(nets))
        certs = {n: certificate(d) for n, d in digests.items()}
        for a in nets:
            for b in nets:
                with self.subTest(made_for=a, presented_to=b):
                    self.assertEqual(accepted(digests[b], certs[a]), a == b)

    def test_mint_certificate_is_bound_to_the_token_address(self):
        a, b = (w(bytes.fromhex(x * 20)) for x in ('70', '71'))
        args = ('3', w(700770))
        tail = (chain_word('tron'), w(VAULT20), ROUTE32, BURN32, w(1), w(10**9), w(RECIPIENT20))
        self.assertNotEqual(BF.mint_digest(*args, a, *tail), BF.mint_digest(*args, b, *tail))

    def test_a_route_with_another_routes_chain_id_would_accept_its_certificates(self):
        """Control: the separation rests on the chain id word, so the matrix is only as good as registry check C3."""
        real = ROUTES['linea']['sourceChainId']
        try:
            ROUTES['linea']['sourceChainId'] = ROUTES['arbitrum-one']['sourceChainId']
            d_arb, d_linea = release_digest('arbitrum-one'), release_digest('linea')
            self.assertEqual(d_arb, d_linea)
            self.assertTrue(accepted(d_linea, certificate(d_arb)))
        finally:
            ROUTES['linea']['sourceChainId'] = real

    def test_there_are_further_routes_and_each_shares_its_network_s_chain_word(self):
        self.assertEqual(sorted(FURTHER), ['arbitrum-one-usdt', 'ethereum-usdt', 'op-mainnet-usdt'])
        for n in FURTHER:
            self.assertEqual(chain_word(n), chain_word(ROUTES[n]['network']['id']))
            self.assertNotEqual(vault_of(n), vault_of(ROUTES[n]['network']['id']))
        self.assertEqual(len({vault_of(n) for n in FURTHER}), len(FURTHER))

    def test_two_routes_of_one_network_at_one_vault_address_would_accept_each_other_s_certificates(self):
        """Control: for routes of ONE network the separation rests on the vault word (and the route word below). One
        address cannot hold two contracts on a chain, and registry check C9 refuses the files that would say so."""
        for n in FURTHER:
            first = ROUTES[n]['network']['id']
            with self.subTest(route=n):
                same = release_digest(n, shared_vault=True)
                self.assertEqual(same, release_digest(first))
                self.assertTrue(accepted(release_digest(first), certificate(same)))
                self.assertNotEqual(release_digest(n), release_digest(first))
                self.assertFalse(accepted(release_digest(first), certificate(release_digest(n))))

    def test_the_route_word_alone_also_separates_two_routes_of_one_network(self):
        """routeId() hashes the vault's token and its own address, so two vaults never share it; a certificate for one
        route id is refused under another even at one (impossible) vault address."""
        other = bytes.fromhex('7f' * 32)
        for n in FURTHER:
            a, b = release_digest(n, shared_vault=True), release_digest(n, shared_vault=True, route=other)
            self.assertNotEqual(a, b)
            self.assertFalse(accepted(b, certificate(a)))

    def test_a_mint_certificate_of_one_route_is_refused_by_the_other_route_of_its_network(self):
        token = w(bytes.fromhex('70' * 20))
        for n in FURTHER:
            first = ROUTES[n]['network']['id']
            d = {x: BF.mint_digest('3', w(700770), token, chain_word(x), w(vault_of(x)), ROUTE32, BURN32, w(1), w(10**9), w(RECIPIENT20))
                 for x in (n, first)}
            self.assertNotEqual(d[n], d[first])
            self.assertFalse(accepted(d[first], certificate(d[n])))
            self.assertFalse(accepted(d[n], certificate(d[first])))

    def test_one_signature_too_few_is_refused_on_its_own_route(self):
        d = release_digest('solana')
        self.assertFalse(accepted(d, certificate(d)[:THRESHOLD - 1]))

    def test_bitcoin_signature_is_not_a_certificate(self):
        """A Bitcoin release signature is DER + a sighash flag over BIP-143 data; no other route takes that form."""
        r, s, _ = BC.sign(release_digest('ethereum'), KEYS[0])
        der = BC.der_sig(r, s)
        self.assertNotEqual(len(der), 65)
        with self.assertRaises(SV.Malformed):
            SV.recover('0x' + release_digest('ethereum').hex(), '0x' + der.hex())

    def test_route_digest_families_use_distinct_domain_tags_or_chain_words(self):
        tags = {b'BLOCH-USDT-RELEASE-AUTH-v2', b'BLOCH-XLM-RELEASE-AUTH-v1'}
        self.assertEqual(len(tags), 2)
        # one chain word per NETWORK (registry check C3); the further routes of a network share its word
        words = {ROUTES[n]['network']['id']: chain_word(n) for n in EVM_V2 + ['solana']}
        self.assertEqual(len(set(words.values())), len(words))
        self.assertEqual(len(words), len(EVM_V2 + ['solana']) - len(FURTHER))


if __name__ == '__main__':
    unittest.main()
