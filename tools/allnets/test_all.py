#!/usr/bin/env python3
"""The single test entry point of the all-networks bridge tree (agent 375, round 18).

  python3 tools/allnets/test_all.py OUTDIR [STAGE ...] [--tools TOOLS.json] [--port-base N] [--umask OCTAL]
  python3 tools/allnets/test_all.py --identity                   the route-file identity check alone
  python3 tools/allnets/test_all.py --identity-record DECISION   record the owned files the integration changed (round 20)

Stages (default: every stage; a stage whose toolchain is not named in TOOLS.json is recorded NOT RUN with the reason,
never silently skipped and never counted as a pass):
  integration   registry check, test_registry, the cross-route matrix, mergecheck over every merge, regress.py
                (per-file test and assertion counts never below the freeze or any merged line tip), the never-merge and forbidden-path rules,
                route-file identity (every path a line owns is byte-identical to that line's merged tip, except
                the files recorded blob by blob in deployments/allnets/integration-changes.json), test_routes
  forge         `forge test --offline` (whole tree), A239Metamorphic isolated on shanghai and cancun
  artifacts     creation and runtime keccak of every contract: the frozen tree cc2511a and every line tip are built
                from `git archive` of that commit and compared with this tree's build (tools/allnets/artifacts.py)
  offline       every `tools/*/test_*.py` unittest module from its own directory, and the offline script tests
  ethereum      the Ethereum bridge's anvil suites and daemon drills (agent 306's stages anvil1, anvil2, anvil3, extra)
  evmnets       tools/evm-nets tests, the reviewer's deploy-gate cases, the registry checks, network files
  forks         one fork rehearsal per launchable EVM network (public endpoints as fork sources only, read-only)
  bitcoin       the regtest rehearsal (needs `bitcoinBin`)
  solana        the validator rehearsal (needs `solanaBin`, `solanaVaultSo`, `solanaHelperSo`)
  tron          the private-TVM rehearsal (needs `tronUrl` and `tronUsdtGetcontract`: a private java-tron the caller runs)
  stellar       the local-network rehearsal (needs `stellarRpc`, `stellarCli`, `stellarWasm`)
  scripts       scripts/tests (Rust verifiers of the custody line; needs `cargoTargetDir`)
TOOLS.json keys: foundryBin (default ~/.foundry/bin), and the ones named above; optional `cargoHome` (a CARGO_HOME
whose registry holds every crate of Cargo.lock: the custody verifiers of scripts/tests build with `--offline`, so on a
host whose registry lacks them three test classes stop in setUpClass; fill one, on an online host, with
`CARGO_HOME=<dir> cargo +1.94.1 fetch --locked` at the repository root; nothing is vendored).
`--umask OCTAL` runs every suite under that file-mode mask (round 19: no suite may depend on the caller's umask; the
table is run under 002, 022 and 077); the mask in force is written into the first line of summary.txt. Output: OUTDIR/summary.txt (one line per
suite), OUTDIR/table.json (machine-readable: stage, suite, status PASS / FAIL / NOT RUN, counts, log), one log per
suite. Exit 0 only when no suite FAILED; NOT RUN suites are listed in the table and in the report, not hidden.
Loopback only, throwaway keys only (each suite's own); nothing is sent to a public network.
"""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
STAGES = ('integration', 'forge', 'artifacts', 'offline', 'ethereum', 'evmnets', 'forks', 'bitcoin', 'solana', 'tron', 'stellar', 'scripts')
# Paths a route line owns: in the merged tree they must be byte-identical to the line's merged tip (the merge brought
# them whole). Shared files (signatario-stable, deploy-pontes, the schema) are checked by mergecheck instead.
OWNED = {
    'bitcoin': ['tools/signatario-btc', 'contracts/btc', 'deployments/bitcoin'],
    'tron': ['tools/signatario-tron', 'contracts/tron', 'deployments/tron', 'solidity-tests/tron-ported'],
    'solana': ['tools/signatario-solana', 'contracts/solana', 'deployments/solana', 'solana'],
    'stellar': ['tools/signatario-stellar', 'contracts/stellar', 'deployments/stellar', 'stellar'],
    'operator-pkg': ['ops', 'docs/OPERATOR-PACKAGES.md'],
    'ceremony': ['deploy/ceremony', 'docs/BRIDGE-OWNER-CEREMONY.md', 'tools/deploy-pontes/ceremony_kit.py',
                 'tools/deploy-pontes/test_ceremony_kit.py'],
    'evm-nets': ['tools/evm-nets', 'deployments/arbitrum-one', 'deployments/op-mainnet', 'deployments/linea',
                 'deployments/base', 'deployments/bnb'],
}
COUNT = [  # (regex over a suite's output, how to read it): the first that matches gives the counts
    (re.compile(r'(\d+) tests passed, (\d+) failed, (\d+) skipped'), lambda m: dict(passed=int(m[1]), failed=int(m[2]), skipped=int(m[3]))),
    (re.compile(r'Ran (\d+) tests? in [\d.]+s\s+(OK|FAILED)(?: \(([^)]*)\))?'), None),
    (re.compile(r'(\d+) passed, (\d+) failed'), lambda m: dict(passed=int(m[1]), failed=int(m[2]))),
    (re.compile(r'(\d+)/(\d+) (?:checks? )?passed'), lambda m: dict(passed=int(m[1]), total=int(m[2]))),
    (re.compile(r'(\d+) of (\d+)'), lambda m: dict(passed=int(m[1]), total=int(m[2]))),
]


def counts(text):
    for rx, fn in COUNT:
        ms = list(rx.finditer(text))
        if not ms:
            continue
        m = ms[-1]
        if fn:
            return fn(m)
        out = {'ran': int(m[1]), 'result': m[2]}
        for part in (m[3] or '').split(','):
            if '=' in part:
                k, v = part.strip().split('=')
                out[k] = int(v)
        return out
    return {}


class Run:
    def __init__(self, out, tools, port_base):
        self.out, self.tools, self.base = Path(out), tools, port_base
        self.out.mkdir(parents=True, exist_ok=True)
        self.rows = []
        fb = os.path.expanduser(tools.get('foundryBin', '~/.foundry/bin'))
        self.env = {**os.environ, 'FOUNDRY_BIN': fb, 'PATH': f'{fb}:{os.environ.get("PATH", "")}',
                    'AUDIT_PORT_BASE': str(port_base + 10), 'D6_PORT_BASE': str(port_base + 20),
                    'A239_ANVIL_PORT': str(port_base + 30)}
        self.forge = str(Path(fb) / 'forge')

    def suite(self, stage, name, argv, cwd=ROOT, env=None, ok_rc=(0,), expect=None, retry_busy=True):
        log = self.out / f'{stage}-{re.sub(r"[^A-Za-z0-9_.+-]", "_", name)}.log'
        for attempt in range(3 if retry_busy else 1):
            t0 = time.time()
            with open(log, 'w') as fh:
                rc = subprocess.run(['nice', '-n', '10', *argv], cwd=cwd, env={**self.env, **(env or {})},
                                    stdout=fh, stderr=subprocess.STDOUT).returncode
            text = log.read_text(errors='replace')
            if not ('Address already in use' in text or 'did not start' in text) or not retry_busy:
                break
            time.sleep(20)  # a fixed port of the suite is busy on the shared host: once more after a pause, then again
        c = counts(text)
        status = 'PASS' if rc in ok_rc else 'FAIL'
        if expect and status == 'PASS' and not expect(text, c):
            status = 'FAIL'
        if c.get('failed') or c.get('result') == 'FAILED':
            status = 'FAIL'
        row = {'stage': stage, 'suite': name, 'status': status, 'rc': rc, 'counts': c, 'seconds': round(time.time() - t0, 1),
               'log': log.name, 'tail': ' '.join(text.strip().splitlines()[-2:])[:240]}
        self.rows.append(row)
        self.line(row)
        return row

    def not_run(self, stage, name, why):
        row = {'stage': stage, 'suite': name, 'status': 'NOT RUN', 'reason': why}
        self.rows.append(row)
        self.line(row)

    def line(self, row):
        text = (f'{row["stage"]:11} {row["suite"]:38} {row["status"]:7} '
                + (json.dumps(row.get('counts', {})) if row['status'] != 'NOT RUN' else row['reason']))
        print(text, flush=True)
        with open(self.out / 'summary.txt', 'a') as fh:
            fh.write(text + '\n')

    def need(self, stage, *keys):
        missing = [k for k in keys if not self.tools.get(k)]
        if missing:
            self.not_run(stage, stage, f'toolchain not named in TOOLS.json: {", ".join(missing)}')
            return False
        return True


def py(*args):
    return [sys.executable, *args]


def stage_integration(r):
    r.suite('integration', 'registry-check', py('tools/allnets/registry.py', 'check'))
    r.suite('integration', 'test_registry', py('-m', 'unittest', 'test_registry'), cwd=HERE)
    r.suite('integration', 'test_cross_route', py('-m', 'unittest', 'test_cross_route'), cwd=HERE)
    r.suite('integration', 'mergecheck', py('tools/allnets/mergecheck.py'))
    r.suite('integration', 'regress-counts', py('tools/allnets/regress.py'))
    r.suite('integration', 'test_routes', py('test_routes.py'), cwd=ROOT / 'tools/deploy-pontes')
    r.suite('integration', 'remerge-status', py('tools/allnets/remerge.py', '--status'),
            expect=lambda t, c: 'MOVED' not in t)
    for lst in ('phase2-bridge', 'phase2b-bridge'):
        r.suite('integration', f'manifest-{lst}', ['sh', '-c', f'{sys.executable} -I scripts/audit-rfp/manifest.py . HEAD '
                f'docs/audit-rfp-r12/{lst}.list | cmp - docs/audit-rfp-r12/{lst}.manifest.tsv'])
    r.suite('integration', 'route-file-identity', py(str(HERE / 'test_all.py'), '--identity'))
    r.suite('integration', 'test_identity_r20', py('-m', 'unittest', 'test_identity_r20'), cwd=HERE)


CHANGES = 'deployments/allnets/integration-changes.json'
CHANGE_KEYS = {'line', 'path', 'lineTip', 'blob', 'mode', 'decision'}
# Review R420-1 (round 20): the record above is written by `--identity-record` from the tree it is meant to hold, so
# by itself it held nothing: change a line's file, run the tool, and the check passed. The record is therefore held a
# second time, BY HAND, in a file the tool never writes: one text line per recorded file, "MODE BLOB LINE PATH". The
# check fails unless the two agree exactly, entry for entry, and unless each file's mode at HEAD is the recorded one.
# A change to a line-owned file now needs three things in reviewed commits: the change, the tool's record, and the
# hand-written pin.
PINS = 'tools/allnets/identity-pins.txt'


def _git(root, *argv):
    return subprocess.run(['git', *argv], cwd=root, capture_output=True, text=True)


def owned_differences(root, line, tip, paths):
    """{file: blob at HEAD, or None when HEAD has no such file} of every file under a line's owned paths that differs
    from the line's merged tip."""
    out = {}
    for p in paths:
        done = _git(root, 'diff', '--name-only', '--no-renames', tip, 'HEAD', '--', p)
        if done.returncode != 0:
            raise SystemExit(f'git diff {tip[:7]} HEAD -- {p} failed: {done.stderr.strip()[-300:]}')
        for f in done.stdout.split('\n'):
            if f:
                blob = _git(root, 'rev-parse', '--verify', '--quiet', f'HEAD:{f}')
                out[f] = blob.stdout.strip() if blob.returncode == 0 else None
    return out


def file_mode(root, path):
    """The git mode of `path` at HEAD ('100644', '100755', '120000'), or None."""
    done = _git(root, 'ls-tree', 'HEAD', '--', path)
    row = done.stdout.split('\n')[0].split()
    return row[0] if done.returncode == 0 and len(row) >= 3 else None


def load_pins(root):
    """The hand-written second record: a set of "MODE BLOB LINE PATH" lines. A missing file is no pin at all (then no
    recorded change can pass); a malformed or repeated line stops the check."""
    path = Path(root) / PINS
    if not path.exists():
        return set()
    pins = set()
    for n, line in enumerate(path.read_text().split('\n'), 1):
        if not line.strip() or line.startswith('#'):
            continue
        parts = line.split(' ')
        if len(parts) != 4 or not re.fullmatch(r'1[02][0-7]{4}', parts[0]) or not re.fullmatch(r'[0-9a-f]{40}', parts[1]) or line in pins:
            raise SystemExit(f'{PINS}:{n}: not one "MODE BLOB LINE PATH" entry, or a repeated one')
        pins.add(line)
    return pins


def load_changes(root):
    """The integration's recorded changes to line-owned files, read fail-closed: a missing file means no change is
    recorded; an unreadable one, an unknown key or a malformed entry stops the check."""
    path = Path(root) / CHANGES
    if not path.exists():
        return {'decisions': {}, 'changes': []}
    try:
        doc = json.loads(path.read_text())
    except ValueError as e:
        raise SystemExit(f'{CHANGES} cannot be read as JSON ({e})')
    if not isinstance(doc, dict) or set(doc) != {'domain', 'note', 'decisions', 'changes'} \
            or not isinstance(doc['decisions'], dict) or not isinstance(doc['changes'], list):
        raise SystemExit(f'{CHANGES} must hold exactly domain, note, decisions (object), changes (list)')
    for d, text in doc['decisions'].items():
        if not isinstance(text, str) or len(text) < 40:
            raise SystemExit(f'{CHANGES}: decision {d!r} must state what was decided, by whom and when')
    for n, c in enumerate(doc['changes']):
        if not isinstance(c, dict) or set(c) != CHANGE_KEYS or not all(isinstance(c[k], str) and c[k] for k in CHANGE_KEYS):
            raise SystemExit(f'{CHANGES}: changes[{n}] must hold exactly {sorted(CHANGE_KEYS)}, each a non-empty text')
    return doc


def identity(root=ROOT, owned=None):
    """Every path a line owns equals that line's merged tip, byte for byte, EXCEPT the files the integration changed
    after the merge and recorded in deployments/allnets/integration-changes.json (round 20): each such file is held to
    the git blob recorded there, under a decision the file states, against the line tip it was changed from. A
    difference that is not recorded, a recorded file whose content is not the recorded blob, a record for a file that
    does not differ (stale), for a path no line owns, against another tip than the merged one, under an unknown decision,
    twice, or for a file that HEAD no longer has: each is a failure. So the check is as strict as before for every
    other byte, and a recorded file cannot drift after its record."""
    root = Path(root)
    owned = OWNED if owned is None else owned
    lock = json.loads((root / 'deployments/allnets/merge-lock.json').read_text())['lines']
    doc = load_changes(root)
    records, bad = {}, 0
    for c in doc['changes']:
        key = (c['line'], c['path'])
        if key in records:
            print(f'{c["line"]:9} {c["path"]}: recorded twice')
            bad += 1
        records[key] = c
        if c['decision'] not in doc['decisions']:
            print(f'{c["line"]:9} {c["path"]}: decision {c["decision"]!r} is not stated in `decisions`')
            bad += 1
        if c['line'] not in owned or not any(c['path'] == p or c['path'].startswith(p + '/') for p in owned.get(c['line'], [])):
            print(f'{c["line"]:9} {c["path"]}: recorded, but not a path that line owns')
            bad += 1
    # the second record (review R420-1): exactly the recorded entries, written by hand
    pins = load_pins(root)
    recorded = {f'{c["mode"]} {c["blob"]} {c["line"]} {c["path"]}' for c in doc['changes']}
    for entry in sorted(recorded - pins):
        print(f'{entry.split(" ", 3)[2]:9} {entry.split(" ", 3)[3]}: recorded, but {PINS} does not hold "{entry}" (the record is '
              'held a second time by hand; a re-run of --identity-record alone changes nothing)')
        bad += 1
    for entry in sorted(pins - recorded):
        print(f'{PINS}: "{entry}" is pinned, but no such record is in {CHANGES}')
        bad += 1
    seen = set()
    for line, paths in owned.items():
        tip = lock[line]['commit']
        differing = owned_differences(root, line, tip, paths)
        for p in paths:
            mine = sorted(f for f in differing if f == p or f.startswith(p + '/'))
            print(f'{line:9} {p:45} {"identical to " + tip[:7] if not mine else str(len(mine)) + " file(s) differ from " + tip[:7]}')
        for f, blob in sorted(differing.items()):
            rec = records.get((line, f))
            seen.add((line, f))
            if rec is None:
                print(f'{line:9}   {f}: DIFFERS from {tip[:7]} and no integration change is recorded')
                bad += 1
            elif blob is None:
                print(f'{line:9}   {f}: removed from the tree (a removal cannot be recorded)')
                bad += 1
            elif rec['lineTip'] != tip:
                print(f'{line:9}   {f}: recorded against {rec["lineTip"][:7]}, the merged tip is {tip[:7]} (record again after a re-merge)')
                bad += 1
            elif rec['blob'] != blob:
                print(f'{line:9}   {f}: DIFFERS from the recorded blob {rec["blob"][:12]} (it is {blob[:12]})')
                bad += 1
            elif rec['mode'] != file_mode(root, f):
                print(f'{line:9}   {f}: its mode is {file_mode(root, f)}, the recorded mode is {rec["mode"]}')
                bad += 1
            else:
                print(f'{line:9}   {f}: integration change, blob {blob[:12]} as recorded ({rec["decision"]})')
    for key in sorted(set(records) - seen):
        print(f'{key[0]:9} {key[1]}: recorded as changed, but it does not differ from the line tip (stale record)')
        bad += 1
    never = json.loads((HERE / 'lines.json').read_text())
    for path in never.get('forbiddenPaths', []):
        hit = subprocess.run(['git', 'rev-list', '-n', '1', 'HEAD', '--', path], cwd=root, capture_output=True, text=True).stdout.strip()
        print(f'forbidden path {path}: {"in history at " + hit[:7] if hit else "never in the history"}')
        bad += bool(hit)
    print(f'{bad} identity failure(s)')
    return 1 if bad else 0


def identity_record(decision):
    """Rewrite the `changes` list of integration-changes.json from the tree: one record per owned file that differs
    from its line's merged tip at HEAD, with its blob at HEAD. The decision must already be stated in the file (its
    text is written by hand, in a reviewed commit); files recorded before keep their decision."""
    doc = load_changes(ROOT)
    if decision not in doc['decisions']:
        raise SystemExit(f'state decision {decision!r} in {CHANGES} `decisions` first')
    lock = json.loads((ROOT / 'deployments/allnets/merge-lock.json').read_text())['lines']
    old = {(c['line'], c['path']): c['decision'] for c in doc['changes']}
    changes = []
    for line, paths in OWNED.items():
        tip = lock[line]['commit']
        for f, blob in sorted(owned_differences(ROOT, line, tip, paths).items()):
            if blob is None:
                raise SystemExit(f'{f} was removed from the tree: a removal cannot be recorded')
            changes.append({'line': line, 'path': f, 'lineTip': tip, 'blob': blob, 'mode': file_mode(ROOT, f),
                            'decision': old.get((line, f), decision)})
    doc['changes'] = changes
    (ROOT / CHANGES).write_text(json.dumps(doc, indent=2, ensure_ascii=False) + '\n')
    print(f'recorded {len(changes)} integration change(s) in {CHANGES}')
    print(f'NOT pinned: {PINS} is written by hand, one "MODE BLOB LINE PATH" line per record, in a reviewed commit; until then '
          '--identity fails for every entry that changed (review R420-1)')
    return 0


def stage_forge(r):
    r.suite('forge', 'forge-test-offline', [r.forge, 'test', '--offline'])
    for evm in ('shanghai', 'cancun'):
        r.suite('forge', f'metamorphic-{evm}', [r.forge, 'test', '--offline', '--isolate', '--evm-version', evm,
                                                '--match-contract', 'A239Metamorphic'], env={'A239_ISOLATE': 'true'})
    r.suite('forge', 'forge-build', [r.forge, 'build', '--offline'])


ART_SOURCES = {'evm-nets': ['contracts/evmnets', 'contracts/usdt'], 'bitcoin': ['contracts/btc'], 'tron': ['contracts/tron'],
               'solana': ['contracts/solana'], 'stellar': ['contracts/stellar'], 'shared-tools': ['contracts/']}


def stage_artifacts(r):
    art = HERE / 'artifacts.py'
    if not (ROOT / 'out').is_dir():
        r.not_run('artifacts', 'artifacts', 'no out/ of this tree (run the forge stage first)')
        return
    merged = r.out / 'manifest-merged.json'
    r.suite('artifacts', 'manifest-merged', ['sh', '-c', f'{sys.executable} {art} manifest {ROOT / "out"} > {merged}'], retry_busy=False)
    lock = json.loads((ROOT / 'deployments/allnets/merge-lock.json').read_text())['lines']
    bases = [('freeze-cc2511a', 'cc2511a', ['contracts/'])] + [(n, e['commit'], ART_SOURCES.get(n, [])) for n, e in lock.items()]
    for name, commit, sources in bases:
        d = r.out / f'art-{name}'
        build = (f'rm -rf {d} && mkdir -p {d} && git -C {ROOT} archive {commit} | tar -x -C {d} && '
                 f'{r.forge} build --offline --root {d} > {d}.build.log 2>&1 && '
                 f'{sys.executable} {art} manifest {d / "out"} > {d}.json')
        row = r.suite('artifacts', f'build-{name}', ['sh', '-c', build], retry_busy=False)
        if row['status'] == 'PASS':
            r.suite('artifacts', f'compare-{name}', py(str(art), 'compare', f'{d}.json', str(merged),
                    *(['--sources', *sources] if sources else [])), retry_busy=False)


def stage_offline(r):
    # every unittest module of every tools directory, from its own directory (as each line's own runs did)
    for path in sorted(ROOT.glob('tools/*/test_*.py')):
        text = path.read_text()
        if path.parent.name == 'allnets' or 'unittest' not in text or path.name in ('test_verifier_review.py', 'test_routes.py'):
            continue
        if 'unittest.main' not in text and 'class ' not in text:
            continue
        r.suite('offline', f'{path.parent.name}/{path.stem}', py('-m', 'unittest', path.stem), cwd=path.parent)
    r.suite('offline', 'signatario-stable/test_ops_templates', py('tools/signatario-stable/test_ops_templates.py', '.'))
    r.suite('offline', 'signatario-tron/test_tron_tools', py('tools/signatario-tron/test_tron_tools.py'))
    r.suite('offline', 'deploy-pontes/test_ceremony_kit', py('tools/deploy-pontes/test_ceremony_kit.py'))
    r.suite('offline', 'ops/test_bundle+test_bridgectl', py('-m', 'unittest', 'test_bundle', 'test_bridgectl'), cwd=ROOT / 'ops')


def stage_ethereum(r):
    w, ss, g = str(ROOT), ROOT / 'tools/signatario-stable', ROOT / 'tools/guardiao'
    for t in ('test_relay_nonce', 'test_vigia', 'test_signatario', 'test_bridge_review', 'test_hf1_finality', 'rehearse_feed',
              'test_signer_verify_r17'):
        r.suite('ethereum', t, py(f'{t}.py', w), cwd=ss)
    r.suite('ethereum', 'verifier_review', py('tools/deploy-pontes/test_verifier_review.py'))
    r.suite('ethereum', 'a239_switch_review', py('-m', 'unittest', '-v', 'test_a239_switch_review'), cwd=g)
    for t in ('v3relay', 'v3', 'v3fee', 'v3remint', 'hold', 'reorg', 'v3mintreorg', 'v3uncertain', 'v3retiredcli'):
        r.suite('ethereum', f'rp-{t}', py('test_release_paths.py', w, t), cwd=ss)
    r.suite('ethereum', 'rehearse_anvil', py('tools/deploy-pontes/rehearse_anvil.py'))
    for t in ('settle_quorum', 'guardiao', 'guardiao_hf1', 'mint_switch', 'mint_cancel', 'mint_hold', 'l2_tx_rpc', 'guard_chain', 'sombra'):
        r.suite('ethereum', f'g-{t}', py(f'test_{t}.py', w), cwd=g)
    r.suite('ethereum', 'g-a129_starve', py('a129_flood_daemon.py', w, 'starve'), cwd=g)
    r.suite('ethereum', 'g-daemons_r10', py('-m', 'unittest', 'test_daemons_r10'), cwd=g)
    r.suite('ethereum', 'reservas', py('tools/reservas/test_reservas.py', '.'))
    r.suite('ethereum', 'gnb_signatario', py('tools/signatario-gnb/test_signatario.py', '.'))
    r.suite('ethereum', 'gnb_vigia', py('tools/signatario-gnb/test_vigia.py', '.'))
    r.suite('ethereum', 'signatario_real', py('tools/signatario-stable/test_signatario.py', '.'), env={'ETH_HALF': 'real'})
    r.suite('ethereum', 'vigia_real', py('tools/signatario-stable/test_vigia.py', '.'), env={'ETH_HALF': 'real'})
    r.suite('ethereum', 'rp_reorg_v3', py('tools/signatario-stable/test_release_paths.py', '.', 'reorg'), env={'V3': '1'})
    # Controls that fail BY DESIGN (docs/AUDIT-SCOPE-BRIDGE-V3.md): recorded with their expected partial counts.
    r.suite('ethereum', 'd6_provenance(control 18/19)', py('tools/guardiao/d6_provenance_daemons.py', '.'), ok_rc=(0, 1))
    r.suite('ethereum', 'a111', py('tools/guardiao/a111_v3_daemons.py', '.'))
    for m in ('drop', 'cancel', 'remint', 'reorg', 'zero'):
        r.suite('ethereum', f'a123_{m}', py('tools/guardiao/a123_drop_daemon.py', '.', m))
    r.suite('ethereum', 'a129_starve1', py('tools/guardiao/a129_flood_daemon.py', '.', 'starve', '1'))
    for m in ('default', 'hold', 'off'):
        r.suite('ethereum', f'audit_v3_{m}(control)', py('tools/guardiao/audit_v3_daemons.py', '.'), env={'AUDIT_D6': m}, ok_rc=(0, 1))
    r.suite('ethereum', 'gas_v3', py('tools/deploy-pontes/gas_v3.py', '.', str(r.base + 40)))
    r.suite('ethereum', 'creation_gas_v3', py('tools/deploy-pontes/creation_gas_v3.py', '.', str(r.base + 41)))


def stage_evmnets(r):
    r.suite('evmnets', 'test_launch_r17+test_evm_nets', py('-m', 'unittest', 'test_launch_r17', 'test_evm_nets'), cwd=ROOT / 'tools/evm-nets')
    r.suite('evmnets', 'r329_demo_deploy_gate', py('tools/evm-nets/r329_demo_deploy_gate.py'))
    r.suite('evmnets', 'evm_nets-check', py('tools/evm-nets/evm_nets.py', 'check'))
    r.suite('evmnets', 'launch-check', py('tools/evm-nets/launch.py', 'check'))
    files = sorted(str(p.relative_to(ROOT)) for p in ROOT.glob('deployments/*/bridge.network.json'))
    r.suite('evmnets', f'network_json-check-x{len(files)}', py('tools/evm-nets/network_json.py', 'check', *files),
            expect=lambda t, c: t.count('"valid"') == len(files))


def stage_forks(r):
    reg = json.loads((ROOT / 'deployments/bridges.json').read_text())
    evm = [x['id'] for x in reg['routes'] if x['network']['kind'] == 'evm' and x['id'] != 'ethereum'
           and x['launch']['sourceState'] == 'launchable']
    for i, n in enumerate(evm):
        r.suite('forks', f'fork-{n}', py('tools/evm-nets/rehearse_fork.py', n, '--port', str(r.base + 50 + 4 * i)))


def stage_bitcoin(r):
    if not r.need('bitcoin', 'bitcoinBin'):
        return
    work = r.out / 'btc-work'
    r.suite('bitcoin', 'rehearse_regtest', py('tools/signatario-btc/rehearse_regtest.py', '--bitcoin-bin', r.tools['bitcoinBin'],
            '--artifact', 'out/BridgedStablecoinV3.sol/BridgedStablecoinV3.json',
            '--router-artifact', 'out/BitcoinBurnRouter.sol/BitcoinBurnRouter.json',
            '--account-artifact', 'out/BitcoinRehearsalAccount.sol/BitcoinRehearsalAccount.json',
            '--work', str(work), '--btc-port', str(r.base + 70), '--l2-port', str(r.base + 71)), retry_busy=False)


def stage_solana(r):
    if not r.need('solana', 'solanaBin', 'solanaVaultSo', 'solanaHelperSo'):
        return
    r.suite('solana', 'rehearse_local', py('tools/signatario-solana/rehearse_local.py', '--project', str(ROOT),
            '--work', str(r.out / 'sol-work'), '--vault-so', r.tools['solanaVaultSo'], '--helper-so', r.tools['solanaHelperSo'],
            '--solana-bin', r.tools['solanaBin'], '--foundry-bin', r.env['FOUNDRY_BIN'], '--port-base', str(r.base + 80)),
            env={'PATH': f'{r.tools["solanaBin"]}:{r.env["PATH"]}'}, retry_busy=False)


def stage_tron(r):
    if not r.need('tron', 'tronUrl', 'tronUsdtGetcontract'):
        return
    r.suite('tron', 'rehearse_tron', py('tools/signatario-tron/rehearse_tron.py', str(ROOT), str(r.out / 'tron-work'),
            r.tools['tronUsdtGetcontract']), env={'TRON_URL': r.tools['tronUrl'], 'PORT_BASE': str(r.base + 90)}, retry_busy=False)


def stage_stellar(r):
    if not r.need('stellar', 'stellarRpc', 'stellarCli', 'stellarWasm'):
        return
    r.suite('stellar', 'rehearse_stellar', py('tools/signatario-stellar/rehearse_stellar.py', '--run-dir', str(r.out / 'xlm-work'),
            '--stellar-rpc', r.tools['stellarRpc'], '--anvil-port', str(r.base + 95), '--wasm', r.tools['stellarWasm'],
            '--artifacts', str(ROOT / 'out')), env={'PATH': f'{Path(r.tools["stellarCli"]).parent}:{r.env["PATH"]}'}, retry_busy=False)


def stage_scripts(r):
    if not r.need('scripts', 'cargoTargetDir'):
        return
    r.suite('scripts', 'scripts-tests', py('-m', 'unittest', 'discover', '-s', 'tests', '-p', 'test_*.py'), cwd=ROOT / 'scripts',
            env={'CARGO_TARGET_DIR': r.tools['cargoTargetDir'], 'CARGO_BUILD_JOBS': '4',
                 **({'CARGO_HOME': r.tools['cargoHome']} if r.tools.get('cargoHome') else {})}, retry_busy=False)


def main(argv):
    if argv[:1] == ['--identity']:
        return identity()
    if argv[:1] == ['--identity-record'] and len(argv) == 2:
        return identity_record(argv[1])
    tools, base, args = {}, 47500, []
    it = iter(argv)
    for a in it:
        if a == '--tools':
            tools = json.loads(Path(next(it)).read_text())
        elif a == '--port-base':
            base = int(next(it))
        elif a == '--umask':
            os.umask(int(next(it), 8))
        else:
            args.append(a)
    if not args:
        raise SystemExit(__doc__)
    out, stages = args[0], args[1:] or list(STAGES)
    for s in stages:
        if s not in STAGES:
            raise SystemExit(f'unknown stage {s}; stages: {STAGES}')
    r = Run(out, tools, base)
    head = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=ROOT, capture_output=True, text=True).stdout.strip()
    clean = subprocess.run(['git', 'status', '--porcelain', '--untracked-files=no'], cwd=ROOT, capture_output=True, text=True).stdout
    mask = os.umask(0)
    os.umask(mask)
    with open(r.out / 'summary.txt', 'a') as fh:
        fh.write(f'tip {head} clean={not clean.strip()} stages={" ".join(stages)} umask={mask:04o} '
                 f'{time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}\n')
    for s in stages:
        globals()[f'stage_{s}'](r)
    table = {'tip': head, 'clean': not clean.strip(), 'umask': f'{mask:04o}', 'rows': r.rows,
             'pass': sum(x['status'] == 'PASS' for x in r.rows), 'fail': sum(x['status'] == 'FAIL' for x in r.rows),
             'notRun': sum(x['status'] == 'NOT RUN' for x in r.rows)}
    (r.out / 'table.json').write_text(json.dumps(table, indent=1) + '\n')
    with open(r.out / 'summary.txt', 'a') as fh:
        fh.write(f'DONE pass={table["pass"]} fail={table["fail"]} notRun={table["notRun"]}\n')
    print(f'DONE pass={table["pass"]} fail={table["fail"]} notRun={table["notRun"]}')
    return 1 if table['fail'] else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
