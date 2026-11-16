#!/usr/bin/env python3
"""Bridge signer for the Stellar route (USDC on Stellar <-> bUSDC.xlm on the Bloch L2).

  signatario_stellar.py --config CFG.json mint    --deposit-id 0xID --out SIG.json
  signatario_stellar.py --config CFG.json remint  --deposit-id 0xID [--locked] --out SIG.json
  signatario_stellar.py --config CFG.json combine --sig A.json --sig B.json [...] --out CALL.json
  signatario_stellar.py --config CFG.json release --burn-tx 0xHASH [--burn-id 0xID] [--context CERT.json] --out CERT.json

This is tools/signatario-stable/signatario.py itself, imported and run unchanged, with the three things that depend on
the source network replaced. Everything about the L2 (the token's code pin and source fields, the EIP-712 mint digest
compared with the contract's, the finalized burn read from an L2 this signer rebuilt, the `l2_pins`, the signer's
database, the proposal of a shared context) is that module's code and keeps its checks.

Replaced:
  1. the deposit id and the deposit's sender: a Stellar address (strkey) instead of an Ethereum address; the id is
     sha256 over the vault's Stellar fields with the nonce in its top 8 bytes (stellar_net.deposit_id);
  2. the release digest: the Soroban vault's (stellar_net.release_digest), signed as an Ethereum personal message,
     over the vault's pause count and the Stellar recipient whose commitment is the burn's 20-byte recipient. The
     half reports that address; it is accepted only if it hashes to the commitment read from the L2 burn, or, for
     a burn made directly on the token, if the account that burned (as this signer read it from the L2) signed
     the claim text naming it (stellar_net.claim_text);
  3. `combine` for a release: the arguments of the vault's `release` for the `stellar` CLI instead of an EVM call.

The config is signatario.py's, with `provenance: true`, `source_chain_id` = the Stellar network id as a decimal
integer, `source_vault` = the low 20 bytes of the vault's contract id, `eth_half_deposit` / `eth_half_release` =
argv templates running stellar_half.py, `eth_signer` = this operator's vault release key, plus `network_passphrase`
and `vault` (the C... address).
"""
import json
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / 'signatario-stable'))
import signatario as S  # noqa: E402
import stellar_net as sn  # noqa: E402


class StellarCtx(S.Ctx):
    def __init__(self, cfg_path):
        super().__init__(cfg_path)
        if not self.provenance:
            S.refuse('the Stellar route needs "provenance": true (BridgedStablecoinV3 over the mint chain)')
        c = self.cfg
        self.passphrase = c['network_passphrase']
        self.vault_contract = c['vault']
        try:
            if int.from_bytes(sn.network_id(self.passphrase), 'big') != self.source_chain_id:
                S.refuse('source_chain_id is not the id of network_passphrase')
            if '0x' + sn.vault20(self.vault_contract).hex() != self.source_vault:
                S.refuse('source_vault is not the low 20 bytes of the vault contract id')
        except sn.StellarError as e:
            S.refuse(str(e))
        self.stellar_recipient = None
        self.pause_count = None

    def deposit_id(self, route, nonce, sender, amount, pq):
        return '0x' + sn.deposit_id(route, nonce, sender, amount, pq[26:]).hex()

    def claim_holds(self, claim, burner, burn_id, recipient):
        """The burner's signed claim for a direct burn: checked here again, with the burner this signer read."""
        try:
            text = sn.claim_text(self.l2_chain_id, self.token, burn_id, recipient)
            if not isinstance(claim, dict) or claim.get('stellar_address') != recipient:
                return False
            if len(str(burner)) != 42 or str(burner).lower() == str(self.cfg.get('router', '')).lower():
                return False
            return subprocess.run([self.cast, 'wallet', 'verify', '--address', burner, text, str(claim.get('signature'))],
                                  capture_output=True).returncode == 0
        except (sn.StellarError, KeyError, ValueError, TypeError):
            return False

    def recipient_bound(self, recipient, commitment, claim, burner, burn_id):
        try:
            if '0x' + sn.recipient_commitment(recipient).hex() == commitment:
                return True
        except sn.StellarError:
            return False
        return self.claim_holds(claim, burner, burn_id, recipient)

    def eth_half(self, kind, **subs):
        out = super().eth_half(kind, **subs)
        if kind == 'release':
            recipient = out.get('stellar_recipient')
            rel = out.get('release') or {}
            commitment = S.address(rel.get('recipient', ''), 'recipient')
            intent = json.loads(Path(subs['intent']).read_text())
            burner = (intent.get('l2') or {}).get('from')
            if not self.recipient_bound(recipient, commitment, out.get('claim'), burner, rel.get('nativeBurn', '')):
                S.refuse('the Stellar recipient neither hashes to the burn\'s recipient commitment nor is claimed by '
                         'the account that burned', stellar_recipient=recipient, commitment=commitment)
            if out.get('vault_contract') != self.vault_contract:
                S.refuse('the Stellar half answered for another vault', half=out)
            self.stellar_recipient = recipient
            self.pause_count = S.uint(out.get('pause_count'), 64, 'pause_count')
        return out

    def release_digest(self, rel, context):
        """What the release key signs: the personal-message hash of the vault's digest."""
        if self.stellar_recipient is None or self.pause_count is None:
            S.refuse('no Stellar recipient was verified for this release')
        item = {'route': rel['route'], 'nonce': rel['nonce'], 'recipient': self.stellar_recipient,
                'amount': rel['amount'], 'native_burn': rel['nativeBurn'], 'mint_count': rel['mintCount'],
                'minted_total': rel['mintedTotal'], 'mint_head': rel['mintHead']}
        ctx = {'valid_until': context['validUntil'], 'pause_count': self.pause_count,
               'native_finalized_number': context['nativeFinalizedNumber'],
               'native_finalized_hash': context['nativeFinalizedHash']}
        return '0x' + sn.personal(sn.release_digest(self.passphrase, self.vault_contract, item, ctx)).hex()


def verified_deposit(ctx, deposit_id):
    """signatario.verified_deposit with a Stellar sender. Returns (dep, nonce, amount, recipient)."""
    dep = ctx.eth_half('deposit', deposit_id=deposit_id)
    if S.hex32(dep.get('deposit_id', ''), 'deposit_id') != deposit_id:
        S.refuse('the Stellar half answered for another deposit', half=dep)
    if S.as_int(dep.get('source_chain_id', -1)) != ctx.source_chain_id:
        S.refuse('the deposit is on another source network', half=dep.get('source_chain_id'), config=ctx.source_chain_id)
    if S.address(dep.get('vault', ''), 'vault') != ctx.source_vault or dep.get('vault_contract') != ctx.vault_contract:
        S.refuse('the deposit is in another vault', half=dep.get('vault_contract'), config=ctx.vault_contract)
    route = S.hex32(dep.get('route', ''), 'route')
    if route != ctx.source_route:
        S.refuse('the deposit is for another vault route', half=route, config=ctx.source_route)
    block_number = S.uint(dep.get('block_number'), 64, 'block_number')
    if dep.get('finalized') is not True or block_number > S.uint(dep.get('finalized_number'), 64, 'finalized_number'):
        S.refuse('the deposit ledger is not past the finality margin on Stellar', half=dep)
    nonce = S.uint(dep.get('nonce'), 64, 'deposit nonce')
    sender = dep.get('sender', '')
    try:
        sn.strkey_decode(sender)
    except sn.StellarError as e:
        S.refuse(f'the deposit sender is not a Stellar address: {e}')
    amount = S.uint(dep.get('amount'), 64, 'amount')
    pq = S.hex32(dep.get('pq_recipient_hash', ''), 'pq_recipient_hash')
    if amount == 0:
        S.refuse('zero deposit amount')
    if pq[2:26] != '0' * 24:
        S.refuse('the recipient field has non-zero high 12 bytes: not an L2 address', pq_recipient_hash=pq)
    if ctx.deposit_id(route, nonce, sender, amount, pq) != deposit_id:
        S.refuse('the deposit id recomputed from the returned fields differs', half=dep,
                 recomputed=ctx.deposit_id(route, nonce, sender, amount, pq))
    recipient = '0x' + pq[26:]
    if int(recipient, 16) == 0:
        S.refuse('the deposit names a zero L2 address')
    return dep, nonce, amount, recipient


_combine = S.cmd_combine


def cmd_combine(ctx, args):
    sigs = [json.loads(Path(p).read_text()) for p in S.option(args, '--sig', many=True)]
    if not sigs or sigs[0].get('kind') != 'stable-release':
        return _combine(ctx, args)  # mints and remints are L2 calls: unchanged
    out = Path(S.option(args, '--out'))
    fields = ('source_chain_id', 'source_vault', 'release', 'context', 'digest')
    first = {f: sigs[0][f] for f in fields}
    half = sigs[0].get('eth') or {}
    recipient, pause_count, claim = half.get('stellar_recipient'), half.get('pause_count'), half.get('claim')
    for s in sigs[1:]:
        h = s.get('eth') or {}
        if s.get('kind') != 'stable-release' or {f: s.get(f) for f in fields} != first \
                or h.get('stellar_recipient') != recipient or h.get('pause_count') != pause_count:
            S.refuse('the partial signatures are for different messages',
                     differ=[f for f in fields if s.get(f) != first[f]])
    rel, c = first['release'], first['context']
    burner = (sigs[0].get('l2') or {}).get('from')
    if not ctx.recipient_bound(recipient, rel['recipient'], claim, burner, rel['nativeBurn']):
        S.refuse('the Stellar recipient neither hashes to the release\'s recipient commitment nor is claimed by the '
                 'account that burned')
    ctx.stellar_recipient = recipient
    ctx.pause_count = S.uint(pause_count, 64, 'pause_count')
    if ctx.release_digest(rel, c) != first['digest']:
        S.refuse('the partials\' digest is not the vault digest of their release')
    k = int(ctx.cfg.get('vault_threshold', ctx.cfg['threshold']))
    by_signer = {s['signer']: s['signature'] for s in sigs}
    if len(by_signer) < k:
        S.refuse(f'need {k} distinct signers, have {len(by_signer)}')
    chosen = sorted(by_signer, key=lambda a: int(a, 16))[:k]
    unhex = lambda v: v[2:] if isinstance(v, str) and v.startswith('0x') else v  # noqa: E731
    call = {'fn': 'release',
            'args': {'item': {'route': unhex(rel['route']), 'nonce': rel['nonce'], 'recipient': recipient,
                              'amount': rel['amount'], 'native_burn': unhex(rel['nativeBurn']),
                              'mint_count': rel['mintCount'], 'minted_total': rel['mintedTotal'],
                              'mint_head': unhex(rel['mintHead'])},
                     'context': {'valid_until': c['validUntil'], 'pause_count': ctx.pause_count,
                                 'native_finalized_number': c['nativeFinalizedNumber'],
                                 'native_finalized_hash': unhex(c['nativeFinalizedHash'])},
                     'signatures': [unhex(by_signer[a]) for a in chosen]}}
    result = {'kind': 'stellar-release', **first, 'stellar_recipient': recipient, 'pause_count': ctx.pause_count,
              'signers': chosen,
              'signatures': [by_signer[a] for a in chosen], 'to': ctx.vault_contract, 'call': call}
    out.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


S.Ctx = StellarCtx
S.verified_deposit = verified_deposit
S.cmd_combine = cmd_combine

if __name__ == '__main__':
    S.main()
