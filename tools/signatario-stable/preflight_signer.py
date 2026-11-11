#!/usr/bin/env python3
"""Pre-go-live check of one signer host of the bUSDC bridge (docs/BRIDGE-V3-OPERATOR-RUNBOOK.md, section 3).

  preflight_signer.py --config SIGNER.json [--eth-half-config ETH-HALF.json] [--relayer-config RELAYER.json]
                      [--allow-remote-eth-rpc] [--skip-dry-release] [--skip-binaries] [--json]

Read-only. It signs nothing, sends nothing and prints no key material. Run it as the service user on the signer host,
after the configs are filled and before the daemons are started. Exit 0: every check passed. Exit 1: at least one
check failed (each is listed). Exit 2: usage or an unreadable config.

Checks:
  config     no TBD-owner value is left; the decided values (chain ids 700770 and 1, thresholds 5 and 5, l2_pins
             mainnet-v2, l2_source rebuild, provenance true; eth-half: provenance true, release_hold false);
             at least two L1 RPC URLs; 6 feed peers and 7 + 7 feed signers.
  files      the configs, keystores and password files exist, belong to this user and are closed to group and others;
             the work, signature, scan and database directories exist and are writable.
  ethereum   eth_rpc is this operator's own node: a loopback or private address (BR-7). --allow-remote-eth-rpc turns
             this into a warning.
  binaries   follower, produce-dev and settled-rpc are the pinned launch build (sha256, l2_finality.MAINNET_V2).
  relayer    (with --relayer-config) the decided values (chain ids 700770 and 1, thresholds 5 and 5, l2_pins
             mainnet-v2, provenance true); relay_role primary or backup, a backup index 1 to 6, six other relayers'
             gas addresses, gas ceilings at most 50 gwei (L2) and 300 gwei (Ethereum), encrypted keystores; the
             release journal directory (relayer_submission_dir, default .relayer-submissions beside shared_dir) is
             outside shared_dir, on a disk that survives a reboot (not tmpfs), and private if it exists already.
  dry        the signer's dry release, `signatario.py --config SIGNER.json release --burn-tx 0x00..01 --out TMP`, must
             refuse for one reason only: "the burn transaction is not in this L2". Any other refusal means a pin, the
             rebuild or the private settled RPC failed, and is printed.
"""
import ipaddress
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
from urllib.parse import urlparse

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import l2_finality  # noqa: E402

DRY_BURN = '0x' + '00' * 31 + '01'
DRY_REASON = 'the burn transaction is not in this L2'
DECIDED_SIGNER = {'l2_chain_id': 700770, 'source_chain_id': 1, 'eth_chain_id': 1, 'threshold': 5, 'vault_threshold': 5,
                  'l2_pins': 'mainnet-v2', 'l2_source': 'rebuild', 'provenance': True}
DECIDED_RELAYER = {'l2_chain_id': 700770, 'source_chain_id': 1, 'eth_chain_id': 1, 'threshold': 5, 'vault_threshold': 5,
                   'l2_pins': 'mainnet-v2', 'provenance': True}
VOLATILE_FS = {'tmpfs', 'ramfs', 'devtmpfs'}
DECIDED_ETH_HALF = {'eth_chain_id': 1, 'provenance': True, 'release_hold': False}
MAX_L2_GWEI, MAX_ETH_GWEI = 50, 300


class Report:
    def __init__(self):
        self.rows = []

    def add(self, group, name, ok, detail='', warning=False):
        self.rows.append({'group': group, 'check': name, 'result': 'warn' if warning else ('pass' if ok else 'FAIL'),
                          'detail': detail})

    @property
    def failed(self):
        return [r for r in self.rows if r['result'] == 'FAIL']


def undecided(value, path=''):
    """Paths of every value that still holds a TBD-owner marker."""
    found = []
    if isinstance(value, dict):
        for k, v in value.items():
            if not str(k).startswith('_about'):
                found += undecided(v, f'{path}.{k}' if path else str(k))
    elif isinstance(value, list):
        for i, v in enumerate(value):
            found += undecided(v, f'{path}[{i}]')
    elif isinstance(value, str) and 'TBD' in value:
        found.append(path)
    return found


def private_file(report, group, label, path):
    p = Path(str(path))
    if not p.is_file():
        report.add(group, f'{label} exists', False, str(p))
        return
    st = p.stat()
    report.add(group, f'{label} belongs to this user', st.st_uid == os.getuid(), str(p))
    report.add(group, f'{label} is closed to group and others', stat.S_IMODE(st.st_mode) & 0o077 == 0,
               f'{p} mode {stat.S_IMODE(st.st_mode):04o}')


def writable_dir(report, group, label, path):
    p = Path(str(path))
    report.add(group, f'{label} is a writable directory', p.is_dir() and os.access(p, os.W_OK | os.X_OK), str(p))


def own_node(url):
    host = urlparse(str(url)).hostname or ''
    if host == 'localhost':
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_loopback or ip.is_private


def is_address(value):
    return isinstance(value, str) and len(value) == 42 and value.startswith('0x') and all(
        c in '0123456789abcdefABCDEF' for c in value[2:])


def check_signer(report, cfg, cfg_path, allow_remote, skip_binaries):
    left = undecided(cfg)
    report.add('config', 'signer config has no TBD-owner value', not left, ', '.join(left))
    for key, want in DECIDED_SIGNER.items():
        report.add('config', f'signer {key} is {want!r}', cfg.get(key) == want and type(cfg.get(key)) is type(want),
                   repr(cfg.get(key)))
    urls = cfg.get('l1_rpc_urls') or []
    report.add('config', 'at least two distinct L1 RPC URLs', isinstance(urls, list) and len(set(urls)) >= 2, str(len(urls)))
    feed = cfg.get('feed') or {}
    report.add('config', 'feed names the other six operators', len(set(feed.get('peers') or [])) == 6,
               str(len(feed.get('peers') or [])))
    for key in ('mint_signers', 'release_signers'):
        vals = feed.get(key) or []
        report.add('config', f'feed.{key} holds 7 distinct addresses',
                   len({str(v).lower() for v in vals}) == 7 and all(is_address(v) for v in vals), str(len(vals)))
    private_file(report, 'files', 'signer config', cfg_path)
    private_file(report, 'files', 'L2 mint keystore', cfg.get('keystore', ''))
    private_file(report, 'files', 'L2 mint password file', cfg.get('password_file', ''))
    writable_dir(report, 'files', 'work_dir', cfg.get('work_dir', ''))
    writable_dir(report, 'files', 'shared_dir', cfg.get('shared_dir', ''))
    writable_dir(report, 'files', 'scan_state_dir', cfg.get('scan_state_dir') or Path(str(cfg.get('shared_dir', ''))) / '.scan')
    writable_dir(report, 'files', 'database directory', Path(str(cfg.get('db', ''))).parent)
    if feed.get('publish_dir'):
        writable_dir(report, 'files', 'feed.publish_dir', feed['publish_dir'])
    ok = own_node(cfg.get('eth_rpc', ''))
    report.add('ethereum', "eth_rpc is this operator's own node (loopback or private address)", ok,
               urlparse(str(cfg.get('eth_rpc', ''))).hostname or '', warning=not ok and allow_remote)
    if skip_binaries:
        report.add('binaries', 'pinned L2 build', True, 'skipped (--skip-binaries)', warning=True)
        return
    try:
        pins = l2_finality.pins_from_config(cfg)
        l2_finality.check_binaries({'follower': cfg.get('follower_bin'), 'produce': cfg.get('produce'),
                                    'settled_rpc': cfg.get('settled_rpc')}, pins)
        report.add('binaries', 'follower, produce-dev and settled-rpc are the pinned launch build', True, pins.get('name', ''))
    except (l2_finality.NotFinal, OSError, KeyError, TypeError, ValueError) as e:  # each is a failed check, with its reason
        report.add('binaries', 'follower, produce-dev and settled-rpc are the pinned launch build', False, str(e)[:300])


def check_eth_half(report, cfg, cfg_path, signer_cfg, allow_remote):
    left = undecided(cfg)
    report.add('config', 'eth-half config has no TBD-owner value', not left, ', '.join(left))
    for key, want in DECIDED_ETH_HALF.items():
        report.add('config', f'eth-half {key} is {want!r}', cfg.get(key) == want and type(cfg.get(key)) is type(want),
                   repr(cfg.get(key)))
    report.add('config', 'eth-half reads the same Ethereum node as the signer', cfg.get('eth_rpc') == signer_cfg.get('eth_rpc'),
               '')
    ok = own_node(cfg.get('eth_rpc', ''))
    report.add('ethereum', "eth-half eth_rpc is this operator's own node", ok, '', warning=not ok and allow_remote)
    private_file(report, 'files', 'eth-half config', cfg_path)
    private_file(report, 'files', 'Ethereum release keystore', cfg.get('keystore', ''))
    private_file(report, 'files', 'Ethereum release password file', cfg.get('password_file', ''))
    report.add('files', 'the mint key and the release key are different files',
               cfg.get('keystore') != signer_cfg.get('keystore'), '')


def filesystem_type(path, mounts='/proc/mounts'):
    """Filesystem type of the mount that holds `path` (Linux), or None when it cannot be read."""
    try:
        rows = [line.split() for line in Path(mounts).read_text().splitlines()]
    except OSError:
        return None
    target, best = os.path.realpath(path), ('', None)
    for row in rows:
        if len(row) < 3:
            continue
        mount = row[1].replace('\\040', ' ')
        if (target == mount or target.startswith(mount.rstrip('/') + '/')) and len(mount) >= len(best[0]):
            best = (mount, row[2])
    return best[1]


def check_journal(report, cfg, mounts='/proc/mounts'):
    """The private release journal (review R310-7): lost at a reboot, a lost reply can send a second release."""
    shared = Path(str(cfg.get('shared_dir', '')))
    journal = Path(str(cfg.get('relayer_submission_dir') or shared.parent / '.relayer-submissions'))
    inside = shared.resolve() == journal.resolve() or shared.resolve() in journal.resolve().parents
    report.add('relayer', 'relayer_submission_dir is outside shared_dir', not inside, str(journal))
    existing = journal
    while not existing.exists() and existing != existing.parent:
        existing = existing.parent
    fs = filesystem_type(existing, mounts)
    report.add('relayer', 'relayer_submission_dir is on a disk that survives a reboot (not tmpfs)',
               fs not in VOLATILE_FS, f'{existing}: {fs or "filesystem type not readable on this system"}',
               warning=fs is None)
    if journal.exists():
        info = journal.lstat()
        report.add('relayer', 'relayer_submission_dir is a private directory of this user',
                   stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and not info.st_mode & 0o077, str(journal))
    else:
        report.add('relayer', 'relayer_submission_dir can be created (its parent is writable)',
                   existing.is_dir() and os.access(existing, os.W_OK | os.X_OK), str(existing))


def check_relayer(report, cfg, cfg_path):
    left = undecided(cfg)
    report.add('relayer', 'relayer config has no TBD-owner value', not left, ', '.join(left))
    for key, want in DECIDED_RELAYER.items():
        report.add('relayer', f'relayer {key} is {want!r}', cfg.get(key) == want and type(cfg.get(key)) is type(want),
                   repr(cfg.get(key)))
    check_journal(report, cfg)
    role = cfg.get('relay_role')
    report.add('relayer', 'relay_role is primary or backup', role in ('primary', 'backup'), repr(role))
    if role == 'backup':
        idx = cfg.get('relay_backup_index')
        report.add('relayer', 'relay_backup_index is 1 to 6', type(idx) is int and 1 <= idx <= 6, repr(idx))
    others = cfg.get('relay_other_gas_addresses') or []
    report.add('relayer', "relay_other_gas_addresses lists the other six relayers' L2 and Ethereum gas addresses",
               all(is_address(a) for a in others) and 6 <= len({a.lower() for a in others}) <= 12, str(len(others)))
    for key, most in (('l2_max_gas_price_gwei', MAX_L2_GWEI), ('eth_max_gas_price_gwei', MAX_ETH_GWEI)):
        v = cfg.get(key)
        report.add('relayer', f'{key} is set and at most {most}', isinstance(v, (int, float)) and not isinstance(v, bool)
                   and 0 < v <= most, repr(v))
    for key in ('l2_relayer_keystore', 'eth_relayer_keystore'):
        private_file(report, 'relayer', key, cfg.get(key, ''))
    report.add('relayer', 'the two gas keystores are different files',
               cfg.get('l2_relayer_keystore') != cfg.get('eth_relayer_keystore'), '')
    for key in ('l2_relayer_password_file', 'eth_relayer_password_file'):
        v = str(cfg.get(key, ''))
        report.add('relayer', f'{key} is a systemd credential or a private file',
                   v.startswith('credential:') or (Path(v).is_file() and stat.S_IMODE(Path(v).stat().st_mode) & 0o077 == 0), '')
    private_file(report, 'relayer', 'relayer config', cfg_path)
    writable_dir(report, 'relayer', 'relayer shared_dir', cfg.get('shared_dir', ''))


def dry_release(report, cfg_path, signatario):
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / 'dry.json'
        try:
            done = subprocess.run([sys.executable, str(signatario), '--config', str(cfg_path), 'release', '--burn-tx',
                                   DRY_BURN, '--out', str(out)], capture_output=True, text=True, timeout=1800)
        except subprocess.TimeoutExpired:
            report.add('dry', 'dry release refuses only because the burn does not exist', False, 'timed out after 1800 s')
            return
        reason, signed = None, None
        try:
            answer = json.loads(done.stdout)
            reason, signed = answer.get('reason'), answer.get('signed')
        except ValueError:
            pass
        ok = done.returncode == 1 and signed is False and reason == DRY_REASON and not out.exists()
        detail = reason if reason is not None else (done.stderr.strip() or done.stdout.strip())[-300:]
        report.add('dry', 'dry release refuses only because the burn does not exist', ok,
                   f'exit {done.returncode}: {detail}')


def load(path):
    try:
        cfg = json.loads(Path(path).read_text())
    except (OSError, ValueError) as e:
        raise SystemExit(f'preflight_signer: cannot read {path}: {e}') from None
    if not isinstance(cfg, dict):
        raise SystemExit(f'preflight_signer: {path} is not a JSON object')
    return cfg


def run(argv, signatario=HERE / 'signatario.py'):
    def opt(name):
        return argv[argv.index(name) + 1] if name in argv and argv.index(name) + 1 < len(argv) else None
    cfg_path = opt('--config')
    if not cfg_path:
        raise SystemExit(__doc__)
    allow_remote = '--allow-remote-eth-rpc' in argv
    report = Report()
    cfg = load(cfg_path)
    check_signer(report, cfg, cfg_path, allow_remote, '--skip-binaries' in argv)
    if opt('--eth-half-config'):
        check_eth_half(report, load(opt('--eth-half-config')), opt('--eth-half-config'), cfg, allow_remote)
    if opt('--relayer-config'):
        check_relayer(report, load(opt('--relayer-config')), opt('--relayer-config'))
    if '--skip-dry-release' in argv:
        report.add('dry', 'dry release', True, 'skipped (--skip-dry-release)', warning=True)
    elif any(r['group'] in ('config', 'files', 'binaries') for r in report.failed):
        report.add('dry', 'dry release', False, 'not run: fix the failed config, file and binary checks first')
    else:
        dry_release(report, cfg_path, signatario)
    return report


def main():
    argv = sys.argv[1:]
    if not argv or '-h' in argv or '--help' in argv:
        raise SystemExit(__doc__)
    try:
        report = run(argv)
    except SystemExit as e:
        print(e, file=sys.stderr)
        raise SystemExit(2) from None
    if '--json' in argv:
        print(json.dumps({'decision': 'fail' if report.failed else 'ok', 'checks': report.rows}, indent=2))
    else:
        for r in report.rows:
            print(f"{r['result']:4}  [{r['group']}] {r['check']}" + (f"  ({r['detail']})" if r['detail'] else ''))
        print(f"{'FAILED' if report.failed else 'OK'}: {len(report.rows) - len(report.failed)} of {len(report.rows)} checks passed")
    raise SystemExit(1 if report.failed else 0)


if __name__ == '__main__':
    main()
