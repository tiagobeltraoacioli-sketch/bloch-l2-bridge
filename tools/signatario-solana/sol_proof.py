#!/usr/bin/env python3
"""Proof that somebody holds the private key of a Solana address: a signed message, verified here in process.

  sol_proof.py fee-owner-message --config VAULT.json --program-id ID [--date YYYY-MM-DD]
  sol_proof.py verify --address BASE58 --message TEXT --signature SIG [--out PROOF.json]
  sol_proof.py check-fee-owner --config VAULT.json --program-id ID --proof PROOF.json
  sol_proof.py exit-message --wallet BASE58 --burner 0x.. --amount N --nonce N --router 0x.. --route 0x.. [--chain-id 700770]
  sol_proof.py redirect-message --wallet BASE58 --burner 0x.. --burn 0x.. --nonce N --router 0x.. --route 0x.. [--chain-id 700770]
  sol_proof.py exit-proof --wallet BASE58 --message TEXT --signature SIG [--envelope text|offchain|offchain-domain --domain 0x..]

Why: an address on the Ed25519 curve proves nothing about a key. Nobody reading the chain can tell a wallet that
was never used from a point no key exists for. A signature can.

  The fee owner. The vault's fee address is part of the vault's address for good, and 5 + 5 bps of every deposit
  and release can only ever be swept to its USDC account. The owner signs ONE line (`fee-owner-message`: the
  address, the route, the cluster's genesis hash, the purpose, a date) with that key; `verify` checks it and
  writes the proof file, which is committed; `sol_vault.py init` refuses to create a vault without it.

  An exit. The destination of every exit signs one line (`exit-message`) that names the amount, the burner, the
  wallet, the burner's nonce on the router, the router, the L2 chain id and the route. The signature travels
  INSIDE the exit: `SolanaBurnRouter.burnTo(amount, recipient, nonce, proof)` publishes it in the burn's log, and
  every signer, the relayer and the guardian verify it here before anything is certified, delivered or accepted.
  A burn whose proof does not verify is held. `redirect-message` is the line the NEW destination signs when the
  burner of a held burn sends it elsewhere (`redirectHeldBurn`).

  `proof` as the router takes it is `tag | 64-byte signature [| 32-byte application domain]`:
    tag 0  the signature covers the bytes of the line (the `signMessage` of a browser wallet);
    tag 1  it covers the Solana off-chain message envelope, version 0, as `solana sign-offchain-message` of
           Agave 4.4.1 builds it: 0xff "solana offchain" | 0x00 | 0x00 (format: restricted ASCII) | length u16 LE | line;
    tag 2  it covers the envelope with an application domain and the signer:
           0xff "solana offchain" | 0x00 | domain (32) | 0x00 | 0x01 | signer (32) | length u16 LE | line.
  `exit-proof` builds those bytes from a signature and says under which envelope it verifies.

No network, no key: this tool never signs. Every line is printable ASCII (format 0 of the off-chain message
standard, which a hardware wallet can display). A signature given as text is 64 bytes in canonical base58, 128
hex characters with or without 0x, or base64. Everything is parsed strictly and verified in process
(solana_lib.ed25519_verify); no value is ever passed to another program, and no decision is read from an exit
code. Standard library only.
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


def fee_owner_message(doc, program_id, date):
    """The one line the fee owner signs: the address, the route (so: this program, this vault configuration, this
    mint and cap), the cluster's genesis hash, the purpose, a date."""
    if not DATE.fullmatch(str(date)):
        raise S.Refused('the date is YYYY-MM-DD', got=date)
    if not program_id:
        raise S.Refused('the program id is undecided: the route the fee owner signs for follows from it')
    config = S.Config.from_json(doc)
    a = S.Addresses(S.pubkey(program_id), config)
    return ('Bloch bridge fee-owner proof v1: I hold the private key of ' + S.b58encode(config.fee_owner)
            + ' and accept at this address the bridge fees of route ' + S.hx(a.route) + ' on the Solana cluster with '
            'genesis hash ' + str(doc['solana']['genesisHash']) + '. Date ' + date + '.')


def _tail(nonce, router, chain_id, route):
    return (f'Nonce {int(nonce)}. Router {S.hx(S.unhex(router, 20, "router"))}. Chain {int(chain_id)}. '
            f'Route {S.hx(S.unhex(route, 32, "route"))}.')


def _wallet_text(wallet):
    key = S.pubkey(wallet)
    if S.b58encode(key) != wallet or not S.on_curve(key) or S.small_order(key):
        raise S.Refused('not a wallet address', got=wallet)
    return wallet


def exit_message(wallet, burner, amount, nonce, router, route, chain_id=700770):
    """The one line the DESTINATION key signs for an exit: byte for byte `SolanaBurnRouter.exitMessage`."""
    return (f'Bloch bridge exit v1: pay {int(amount)} units burned by {S.hx(S.unhex(burner, 20, "burner"))} to my Solana '
            f'wallet {_wallet_text(wallet)}. ' + _tail(nonce, router, chain_id, route))


def redirect_message(wallet, burner, burn_id, nonce, router, route, chain_id=700770):
    """The one line the NEW destination key signs for a redirected burn: `SolanaBurnRouter.redirectMessage`."""
    return (f'Bloch bridge redirect v1: pay burn {S.hx(S.unhex(burn_id, 32, "burn id"))} made by '
            f'{S.hx(S.unhex(burner, 20, "burner"))} to my Solana wallet {_wallet_text(wallet)}. '
            + _tail(nonce, router, chain_id, route))


ENVELOPE_TAGS = {'text': 0, 'offchain': 1, 'offchain-domain': 2}


def covered_bytes(tag, message, public, domain=None):
    """The bytes a proof of this tag signs for `message` (ASCII bytes) by `public`."""
    body = len(message).to_bytes(2, 'little') + message
    if tag == 0:
        return message
    if tag == 1:
        return OFFCHAIN_DOMAIN + b'\0' + b'\0' + body
    if tag == 2 and domain is not None and len(domain) == 32:
        return OFFCHAIN_DOMAIN + b'\0' + domain + b'\0' + b'\x01' + public + body
    return None


def exit_proof_valid(public, message, proof):
    """True only if `proof` (the router's bytes: tag | signature [| domain]) is a signature by `public` over
    `message` under the envelope its tag names. Strict: exact lengths, known tags, canonical signature, a key
    that is on the curve and not of small order. Never raises on malformed input."""
    if not (isinstance(public, (bytes, bytearray)) and len(public) == 32 and isinstance(proof, (bytes, bytearray))
            and isinstance(message, str) and PRINTABLE.fullmatch(message)):
        return False
    proof = bytes(proof)
    if not proof or not ((proof[0] in (0, 1) and len(proof) == 65) or (proof[0] == 2 and len(proof) == 97)):
        return False
    covered = covered_bytes(proof[0], message.encode('ascii'), bytes(public), proof[65:] if proof[0] == 2 else None)
    return covered is not None and S.ed25519_verify(bytes(public), covered, proof[1:65])


def make_exit_proof(wallet, message, signature, envelope=None, domain=None):
    """The router's `proof` bytes for a signature given as text, under the envelope named or the first that verifies."""
    public = S.pubkey(_wallet_text(wallet))
    raw = parse_signature(signature)
    domain = S.unhex(domain, 32, 'application domain') if domain is not None else None
    for name, tag in ENVELOPE_TAGS.items():
        if envelope not in (None, name) or (tag == 2 and domain is None):
            continue
        proof = bytes([tag]) + raw + (domain if tag == 2 else b'')
        if exit_proof_valid(public, message, proof):
            return name, proof
    raise S.Refused('the signature is not a signature of this message by this wallet under any accepted envelope')


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


FEE_PROOF_MAX_AGE_DAYS = 30


def check_fee_owner_proof(proof, doc, program_id, now=None, max_age_days=None):
    """The proof is for THIS route's fee owner on THIS cluster: its text is exactly the canonical one for the date
    it names, the date is not in the future, and the signature verifies. With `max_age_days` (what `init` passes:
    30) a proof dated longer ago is refused: the owner showed the key recently, not at some time in the past.
    Raises S.Refused otherwise; returns the envelope name."""
    if not isinstance(proof, dict) or proof.get('kind') != 'bloch.solana.key-proof.v1':
        raise S.Refused('not a key proof written by sol_proof.py verify')
    message = proof.get('message')
    if not isinstance(message, str) or not PRINTABLE.fullmatch(message):
        raise S.Refused('the proof carries no message')
    date = message[-11:-1]
    if not DATE.fullmatch(date) or message != fee_owner_message(doc, program_id, date):
        raise S.Refused('the proof is not for the fee owner, the route and the cluster of this configuration')
    now = now if now is not None else time.time()
    if date > time.strftime('%Y-%m-%d', time.gmtime(now + 86400)):
        raise S.Refused('the proof is dated in the future', date=date)
    if max_age_days is not None and date < time.strftime('%Y-%m-%d', time.gmtime(now - max_age_days * 86400)):
        raise S.Refused(f'the proof is dated more than {max_age_days} days ago: the fee owner signs a fresh one', date=date)
    config = S.Config.from_json(doc)
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
            program_id = opt(args, '--program-id') or (doc.get('program') or {}).get('id')
            out = {'message': fee_owner_message(doc, program_id, opt(args, '--date', time.strftime('%Y-%m-%d', time.gmtime()))),
                   'address': doc['vault']['fees']['owner']}
        elif command == 'exit-message':
            out = {'message': exit_message(need(args, '--wallet'), need(args, '--burner'), need(args, '--amount'),
                                           need(args, '--nonce'), need(args, '--router'), need(args, '--route'),
                                           opt(args, '--chain-id', '700770'))}
        elif command == 'redirect-message':
            out = {'message': redirect_message(need(args, '--wallet'), need(args, '--burner'), need(args, '--burn'),
                                               need(args, '--nonce'), need(args, '--router'), need(args, '--route'),
                                               opt(args, '--chain-id', '700770'))}
        elif command == 'exit-proof':
            name, proof = make_exit_proof(need(args, '--wallet'), need(args, '--message'), need(args, '--signature'),
                                          opt(args, '--envelope'), opt(args, '--domain'))
            out = {'envelope': name, 'proof': S.hx(proof)}
        elif command == 'verify':
            out = proof_of(need(args, '--address'), need(args, '--message'), need(args, '--signature'))
            if opt(args, '--out'):
                Path(opt(args, '--out')).write_text(json.dumps(out, indent=2) + '\n')
        elif command == 'check-fee-owner':
            doc = json.loads(Path(need(args, '--config')).read_text())
            program_id = opt(args, '--program-id') or (doc.get('program') or {}).get('id')
            proof = json.loads(Path(need(args, '--proof')).read_text())
            out = {'envelope': check_fee_owner_proof(proof, doc, program_id), 'address': proof['address'], 'message': proof['message']}
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
