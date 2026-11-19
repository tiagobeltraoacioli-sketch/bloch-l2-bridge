#!/usr/bin/env python3
"""Are the bridge signers' L2 pins still the L2 that is live? (round 20, agent 421; finding F410-2)

  l2_pins_check.py show
  l2_pins_check.py release DIR [--files]
  l2_pins_check.py live L1_RPC_URL [L1_RPC_URL ...]

Read-only: it signs nothing, sends nothing, opens no key. The pin set is the current one of l2_finality.py
(`CURRENT_MAINNET_PINS`), loaded exactly as the signer loads it (`named_pins`: refused when any value of it was not
verified at its source).

show      prints the current pin set, value by value, with where each value was verified.
release   DIR is an L2 release folder as the owner signs it (SHA256SUMS, SHA256SUMS.minisig, release.json). The
          signature must verify against the Bloch release key pinned in verify_l2_release_signature.py (the verifier
          of bloch-l2-evm, byte-identical) and its trusted comment must be the canonical line of release.json. Then the
          release is compared with the pins: release name, both commits, chain id, the SHA-256 of SHA256SUMS and the
          three binaries it lists. --files also hashes every file SHA256SUMS lists (the folder a signer installs from).
live      each URL is a Bloch L1 RPC. Its `getl2settlement` must be for the pinned network and chain and must report an
          accepted L2 settlement of exactly the pinned L2 program (statement tag and seven identities), with a
          finalized checkpoint of its own chain (l2_finality.l1_cross_check, as the signer runs it for every release).

Exit 0: CURRENT, the pins are the release / the live L2 program. Exit 1: STALE or DIFFERENT, with every difference
named: sign nothing and re-pin by a reviewed commit (docs/BRIDGE-V3-OPERATOR-RUNBOOK.md, "When the L2 release or
program changes"). Exit 2: the input proves nothing (unsigned or badly signed folder, unreachable RPC, usage).
"""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import sys
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import l2_finality  # noqa: E402
import verify_l2_release_signature as release_signature  # noqa: E402

RELEASE_FILES = {'follower': 'bloch-l2-native-follower', 'produce': 'bloch-l2-produce-dev', 'settled_rpc': 'bloch-l2-settled-rpc'}
CURRENT, STALE, NO_EVIDENCE = 0, 1, 2


class NoEvidence(Exception):
    """The input cannot say anything about the pins (exit 2)."""


def current_pins():
    return l2_finality.named_pins(l2_finality.CURRENT_MAINNET_PINS)


def show(pins, out):
    out(f'pin set {l2_finality.CURRENT_MAINNET_PINS}: {pins["name"]}')
    for key in l2_finality.NAMED_PIN_KEYS:
        out(f'  {key}: {json.dumps(pins[key], sort_keys=True)}')
        out(f'      verified: {pins["verified"][key]}')
    for name, (by, why) in sorted(l2_finality.SUPERSEDED.items()):
        out(f'superseded and refused: {name} (by {by}): {why}')
    return CURRENT


def signed_release(directory):
    """The facts of a signed L2 release folder: (release.json, sha256 of SHA256SUMS, {file name: sha256}, trusted comment).
    NoEvidence unless the signature by the pinned release key and the canonical trusted comment both hold."""
    d = Path(directory)
    try:
        sums = (d / 'SHA256SUMS').read_bytes()
        sig = (d / 'SHA256SUMS.minisig').read_bytes()[:release_signature.MAX_SIG_FILE + 1]
        release = json.loads((d / 'release.json').read_text())
    except (OSError, ValueError) as e:
        raise NoEvidence(f'{d} is not a signed release folder (SHA256SUMS, SHA256SUMS.minisig, release.json): {e}') from None
    sha = hashlib.sha256(sums).hexdigest()
    if sha in release_signature.REVOKED_SHA256SUMS:
        raise NoEvidence(f'the release SHA256SUMS {sha} was withdrawn by the owner')
    try:
        trusted = release_signature.verify_bytes(sums, sig, release_signature.RELEASE_PUBKEY)
        want = release_signature.canonical_trusted_comment(release, sha)
    except release_signature.VerifyError as e:
        raise NoEvidence(f'the signature over SHA256SUMS does not verify against the Bloch release key '
                         f'{release_signature.RELEASE_KEY_ID}: {e}') from None
    except (KeyError, TypeError, ValueError) as e:
        raise NoEvidence(f'release.json is unusable: {e}') from None
    if trusted != want:
        raise NoEvidence(f'the trusted comment is not the canonical line of this release.json: {trusted!r}')
    listed = {}
    for line in sums.decode('utf-8', 'replace').splitlines():
        m = release_signature._SUM_LINE.match(line)
        if not m or m[2] in listed:
            raise NoEvidence(f'SHA256SUMS holds a line that is not `sha256  name`, or a name twice: {line!r}')
        listed[m[2]] = m[1]
    if hashlib.sha256((d / 'release.json').read_bytes()).hexdigest() != listed.get('release.json'):
        raise NoEvidence('SHA256SUMS does not cover this release.json')
    return release, sha, listed, trusted


def release(pins, directory, files, out):
    info, sha, listed, trusted = signed_release(directory)
    out(f'signed by the Bloch release key {release_signature.RELEASE_KEY_ID}: {trusted}')
    if files:
        with contextlib.redirect_stdout(io.StringIO()):
            try:
                release_signature.check_sums(str(directory), (Path(directory) / 'SHA256SUMS').read_bytes())
            except release_signature.VerifyError as e:
                raise NoEvidence(f'a file of the folder is not the signed one: {e}') from None
        out(f'every file SHA256SUMS lists is in the folder and matches ({len(listed)} files)')
    want = pins['release']
    rows = [('release name', info.get('release'), want['name']),
            ('L2 commit', info.get('l2_commit'), want['l2_commit']),
            ('native commit', info.get('native_commit'), want['native_commit']),
            ('L2 chain id', info.get('chain_id'), pins['l2_chain_id']),
            ('sha256 of SHA256SUMS', sha, want['sha256sums'])]
    rows += [(f'{name} ({role})', listed.get(name), l2_finality.strip0x(pins['binaries'][role])) for role, name in RELEASE_FILES.items()]
    differ = [r for r in rows if r[1] != r[2]]
    for label, got, pinned in rows:
        out(f'  {"same  " if got == pinned else "DIFFER"} {label}: release {got}' + ('' if got == pinned else f', pins {pinned}'))
    if differ:
        out(f'STALE PINS: the owner signed the L2 release {info.get("release")}; the bridge pin set '
            f'{l2_finality.CURRENT_MAINNET_PINS} names {want["name"]}. {l2_finality.STALE_HINT}')
        return STALE
    out(f'CURRENT: the pin set {l2_finality.CURRENT_MAINNET_PINS} is this signed release')
    return CURRENT


def live(pins, urls, out, fetch=l2_finality.l1_rpc, now=None):
    if not urls:
        raise NoEvidence('live needs at least one L1 RPC URL')
    code = CURRENT
    for url in urls:
        try:
            seen = l2_finality.l1_cross_check([url], pins, time.time() if now is None else now, fetch=fetch)[0]
        except l2_finality.NotFinal as e:
            if 'unreachable' in e.reason:
                raise NoEvidence(f'{url}: {e.reason}: {e.detail.get("error")}') from None
            out(f'  DIFFER {url}: {e.reason}  {json.dumps(e.detail, sort_keys=True, default=str)}')
            code = STALE
            continue
        out(f'  same   {url}: accepted settlement {seen.get("accepted")}, finalized checkpoint epoch '
            f'{(seen.get("finalized_checkpoint") or {}).get("epoch")} of its own chain; program = the pinned one')
    if code == STALE:
        out(f'STALE OR DIFFERENT: the live L1 does not report the L2 the pin set {l2_finality.CURRENT_MAINNET_PINS} names. '
            + l2_finality.STALE_HINT)
    else:
        out(f'CURRENT: {len(urls)} L1 RPC(s) report an accepted settlement of the L2 program the pin set '
            f'{l2_finality.CURRENT_MAINNET_PINS} names')
    return code


def run(argv, out=print, fetch=l2_finality.l1_rpc):
    if not argv or argv[0] not in ('show', 'release', 'live'):
        raise NoEvidence(__doc__)
    try:
        pins = current_pins()
    except l2_finality.NotFinal as e:
        out(f'REFUSED: {e.reason}  {json.dumps(e.detail, sort_keys=True, default=str)}')
        return STALE
    if argv[0] == 'show':
        return show(pins, out)
    if argv[0] == 'release':
        rest = [a for a in argv[1:] if a != '--files']
        if len(rest) != 1:
            raise NoEvidence(__doc__)
        return release(pins, rest[0], '--files' in argv, out)
    return live(pins, argv[1:], out, fetch=fetch)


def main():
    try:
        code = run(sys.argv[1:])
    except NoEvidence as e:
        print(f'l2_pins_check: NO EVIDENCE: {e}', file=sys.stderr)
        code = NO_EVIDENCE
    raise SystemExit(code)


if __name__ == '__main__':
    main()
