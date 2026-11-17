#!/usr/bin/env python3
"""Offline proof that somebody holds the private key of a Solana address: a signed message, verified here.

  sol_proof.py fee-owner-message --config VAULT.json [--date YYYY-MM-DD]
  sol_proof.py exit-message --wallet BASE58 --l2-account 0x.. --router 0x.. --issued UNIX [--chain-id 700770]
  sol_proof.py verify --address BASE58 --message TEXT --signature SIG [--out PROOF.json]
  sol_proof.py check-fee-owner --config VAULT.json --proof PROOF.json

Why (review 330, R330-SOL-1 and its owner input): an address on the Ed25519 curve proves nothing about a key.
Nobody reading the chain can tell a wallet that was never used from a point no key exists for. A signature can.

  The fee owner. The vault's fee address is part of the vault's address for good, and 5 + 5 bps of every deposit
  and release can only ever be swept to its USDC account. Before the ceremony the owner signs the text of
  `fee-owner-message` with that key; `verify` checks it offline and writes PROOF.json; `sol_vault.py init`
  refuses to create a vault outside a rehearsal without a proof that `check-fee-owner` accepts.

  An exit destination. The bridge page takes the destination from the user's connected wallet and has it sign
  the text of `exit-message` (the wallet's `signMessage`) before it calls SolanaBurnRouter.burnTo. The page
  verifies the signature itself; this file is the reference for the text and the verification.

No network, no key: this tool never signs. The message is one line of printable ASCII, so that it can be signed
  by a wallet's `signMessage` (the signature is over the bytes of the text), or
  by `solana sign-offchain-message` (also with a hardware wallet); the signature is then over the off-chain
  message envelope around the text, which this tool rebuilds.
Both are accepted. A signature is 64 bytes, given as base58 (87 or 88 characters), as 128 hex characters with
or without 0x, or as base64 (88 characters ending in "=="). Everything is parsed strictly and verified in
process (solana_lib.ed25519_verify); no value is ever passed to another program, and no decision is read from an
exit code. Standard library only.
"""
import base64
import json
from pathlib import Path
import re
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import solana_lib as S  # noqa: E402

OFFCHAIN_DOMAIN = b'\xffsolana offchain'
DATE = re.compile(r'20\d\d-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])')
HEX_SIGNATURE = re.compile(r'(0x)?[0-9a-fA-F]{128}')
BASE64_SIGNATURE = re.compile(r'[A-Za-z0-9+/]{86}==')
BASE58_SIGNATURE = re.compile(r'[1-9A-HJ-NP-Za-km-z]{64,88}')
PRINTABLE = re.compile(r'[\x20-\x7e]{1,1000}')


def fee_owner_message(doc, date):
    """The one line the fee owner signs. It names the address, its token account, the mint and the cluster."""
    if not DATE.fullmatch(str(date)):
        raise S.Refused('the date is YYYY-MM-DD', got=date)
    config = S.Config.from_json(doc, allow_undecided=True)
    account = S.associated_token_address(config.fee_owner, config.mint)
    return ('Bloch bridge bUSDC.sol fee-owner proof: I hold the private key of ' + S.b58encode(config.fee_owner)
            + ' and accept the bridge fees of this route at its token account ' + S.b58encode(account)
            + ' (mint ' + S.b58encode(config.mint) + ', cluster ' + str(doc['solana']['genesisHash']) + '). Date ' + date + '.')


def exit_message(wallet, l2_account, router, issued, chain_id=700770):
    """The one line a user's wallet signs on the bridge page before the router is called."""
    key = S.pubkey(wallet)
    if S.b58encode(key) != wallet or not S.on_curve(key) or S.small_order(key):
        raise S.Refused('not a wallet address', got=wallet)
    account, route = S.hx(S.unhex(l2_account, 20, 'L2 account')), S.hx(S.unhex(router, 20, 'router'))
    return (f'Bloch bridge exit: pay bUSDC.sol exits to my Solana wallet {wallet}. L2 account {account}. '
            f'Router {route}. Chain {int(chain_id)}. Issued {int(issued)}.')


def parse_signature(text):
    """Exactly 64 bytes from base58, hex or base64 text; anything else is refused (never guessed)."""
    if not isinstance(text, str):
        raise S.Refused('the signature is not text')
    text = text.strip()
    if HEX_SIGNATURE.fullmatch(text):
        return bytes.fromhex(text[2:] if text[:2] in ('0x', '0X') else text)
    if BASE64_SIGNATURE.fullmatch(text):
        raw = base64.b64decode(text, validate=True)
        if base64.b64encode(raw).decode() == text:
            return raw
    if BASE58_SIGNATURE.fullmatch(text):
        try:
            raw = S.b58decode(text, 64)
        except S.Refused:
            raw = None
        if raw is not None and S.b58encode(raw) == text:
            return raw
    raise S.Refused('the signature is not 64 bytes in canonical base58, hex or base64')


def envelopes(message, public):
    """The byte strings a signature over `message` may cover: the text itself (a wallet's signMessage) and the
    off-chain message envelope of the Solana CLI, in its two published layouts (header version 0)."""
    body = len(message).to_bytes(2, 'little') + message
    return (('text', message),
            ('offchain-v0', OFFCHAIN_DOMAIN + b'\0' + b'\0' + body),
            ('offchain-v0-with-signers', OFFCHAIN_DOMAIN + b'\0' + bytes(32) + b'\0' + b'\x01' + public + body))


def verify(address, message, signature):
    """The name of the envelope under which `signature` is a signature of `message` by `address`, or a refusal."""
    if not isinstance(address, str) or not isinstance(message, str) or not PRINTABLE.fullmatch(message):
        raise S.Refused('the message is one line of printable ASCII, at most 1000 characters')
    public = S.pubkey(address)
    if S.b58encode(public) != address.strip() or not S.on_curve(public) or S.small_order(public):
        raise S.Refused('not an address a key can exist for', address=address)
    raw = parse_signature(signature)
    for name, covered in envelopes(message.encode('ascii'), public):
        if S.ed25519_verify(public, covered, raw):
            return name
    raise S.Refused('the signature is not a signature of this message by this address', address=address)


def proof_of(address, message, signature):
    return {'kind': 'bloch.solana.key-proof.v1', 'address': address, 'message': message, 'signature': signature,
            'envelope': verify(address, message, signature)}


def check_fee_owner_proof(proof, doc, now=None):
    """`init` calls this: the proof is for THIS configuration's fee owner, token account, mint and cluster, its
    text is exactly the canonical one for the date it names, the date is not in the future, and the signature
    verifies. Raises S.Refused otherwise; returns the envelope name."""
    if not isinstance(proof, dict) or proof.get('kind') != 'bloch.solana.key-proof.v1':
        raise S.Refused('not a key proof written by sol_proof.py verify')
    message = proof.get('message')
    if not isinstance(message, str) or not PRINTABLE.fullmatch(message):
        raise S.Refused('the proof carries no message')
    date = message[-11:-1]
    if not DATE.fullmatch(date) or message != fee_owner_message(doc, date):
        raise S.Refused('the proof is not for the fee owner, token account, mint and cluster of this configuration')
    if date > time.strftime('%Y-%m-%d', time.gmtime((now if now is not None else time.time()) + 86400)):
        raise S.Refused('the proof is dated in the future', date=date)
    config = S.Config.from_json(doc, allow_undecided=True)
    if proof.get('address') != S.b58encode(config.fee_owner):
        raise S.Refused('the proof is for another address than the fee owner')
    return verify(proof['address'], message, proof.get('signature'))


def opt(args, name, default=None):
    found = [args[i + 1] for i, a in enumerate(args[:-1]) if a == name]
    return found[-1] if found else default


def need(args, name):
    value = opt(args, name)
    if value is None:
        raise S.Refused(f'missing {name}')
    return value


def main(argv):
    if not argv or argv[0] in ('-h', '--help'):
        print(__doc__)
        return 2
    command, args = argv[0], argv[1:]
    try:
        if command == 'fee-owner-message':
            doc = json.loads(Path(need(args, '--config')).read_text())
            out = {'message': fee_owner_message(doc, opt(args, '--date', time.strftime('%Y-%m-%d', time.gmtime()))),
                   'address': doc['vault']['fees']['owner']}
        elif command == 'exit-message':
            out = {'message': exit_message(need(args, '--wallet'), need(args, '--l2-account'), need(args, '--router'),
                                           need(args, '--issued'), opt(args, '--chain-id', '700770'))}
        elif command == 'verify':
            out = proof_of(need(args, '--address'), need(args, '--message'), need(args, '--signature'))
            if opt(args, '--out'):
                Path(opt(args, '--out')).write_text(json.dumps(out, indent=2) + '\n')
        elif command == 'check-fee-owner':
            doc = json.loads(Path(need(args, '--config')).read_text())
            proof = json.loads(Path(need(args, '--proof')).read_text())
            out = {'envelope': check_fee_owner_proof(proof, doc), 'address': proof['address'], 'message': proof['message']}
        else:
            raise S.Refused('unknown command', command=command)
    except S.Refused as e:
        print(json.dumps({'ok': False, 'reason': e.reason, **{k: str(v) for k, v in e.detail.items()}}, indent=2))
        return 1
    except (ValueError, KeyError, OSError, TypeError) as e:
        print(json.dumps({'ok': False, 'reason': 'malformed input', 'error': repr(e)}, indent=2))
        return 1
    print(json.dumps({'ok': True, **out}, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
