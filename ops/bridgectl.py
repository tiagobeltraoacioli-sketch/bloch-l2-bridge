#!/usr/bin/env python3
"""bridgectl: install, check, start, health-check, upgrade and roll back one Bloch bridge operator bundle (agent 381).

  bridgectl.py install     BUNDLE.tar.gz --sha256 HEX [--allow-unreleased]
  bridgectl.py credentials INST
  bridgectl.py seal        INST CREDENTIAL [--from FILE] [--replace]      (reads stdin without --from; prints no secret)
  bridgectl.py check       INST [--with UNIT ...]
  bridgectl.py preflight   INST
  bridgectl.py start       INST [--with UNIT ...]
  bridgectl.py stop        INST
  bridgectl.py status      INST
  bridgectl.py health      INST [--alert] [--wait SECONDS] [--since UNIX]
  bridgectl.py upgrade     INST BUNDLE.tar.gz --sha256 HEX [--config-reviewed] [--allow-unreleased]
  bridgectl.py rollback    INST
  bridgectl.py verify      INST

INST is `<route>-<role>` (for example `ethereum-signer`). Run as root, except `health` (the health timer runs it as the
instance's own user) and `status`/`verify` (read-only). Every command but `health` prints one JSON document.

Layout (docs/OPERATOR-PACKAGES.md): code in /opt/bloch-bridge/INST/releases/<id>/ (root-owned, read-only to the
service; `current` and `previous` are symlinks swapped with rename(2)); configs in /etc/bloch-bridge/INST/ (root:bb-INST
0640: the service reads, never writes); secrets only as encrypted systemd credentials in
/etc/credstore.encrypted/bloch-bridge-INST/ (root 0700/0600), decrypted by systemd into the unit's private credentials
directory and staged 0400 into its RuntimeDirectory (/run/bloch-bridge-INST[-UNIT], tmpfs, removed when the unit stops),
because the tools refuse a key file readable by group (systemd hands credentials over as 0440 + ACL); state in
/var/lib/bloch-bridge/INST/ (bb-INST 0700, or 0750 when a monitor must read a health file); health and alert history in
/var/log/bloch-bridge/INST/health.log (rotated by logrotate); daemon output in journald.

Refusals (each tested in ops/test_bridgectl.py): a bundle whose SHA-256 is not the one given; a tar member that is not a
plain file or directory inside the bundle, or whose bytes or mode differ from MANIFEST.json, or that MANIFEST.json does
not list; an unreleased (worktree) bundle without --allow-unreleased; installing over an installed instance; starting
while `check` fails (a TBD-owner value left, a config file the service could write, a secret key that is not a staged
credential path, a missing credential, a cast binary whose SHA-256 differs from /etc/bloch-bridge/cast.sha256, no
executable alert hook); an upgrade to another instance, to the same release, to a lower state epoch, or with changed
config templates without --config-reviewed; a rollback with no previous release or across a state epoch. An upgrade
whose health check does not pass within 180 s is rolled back by itself.
"""
import difflib
import grp
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import pwd
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import time

ROOT = Path(os.environ.get('BRIDGECTL_ROOT', '/'))   # tests install into a scratch root (with BRIDGECTL_NO_SYSTEMD=1)
NO_SYSTEMD = os.environ.get('BRIDGECTL_NO_SYSTEMD') == '1'
TBD = re.compile(r'TBD-(owner|deploy)')
SECRET_KEY = re.compile(r'(keystore|password|passphrase|private|secret|mnemonic|seed)|(^|_)key$', re.I)
PEM = re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----')
LEVELS = {'OK': 0, 'WARN': 1, 'CRIT': 2, 'UNKNOWN': 3}
HOOK = '/etc/bloch-bridge/alert-hook'
CAST_PIN = '/etc/bloch-bridge/cast.sha256'
HEALTH_WAIT_S = 180
REMIND_S = 3600


class Refused(Exception):
    pass


def P(path):
    """A host path under ROOT (tests) or the real one."""
    return ROOT / str(path).lstrip('/')


def out(doc, code=0):
    print(json.dumps(doc, indent=1, sort_keys=True), flush=True)
    return code


def sh(*argv, check=True, input=None):
    done = subprocess.run([str(a) for a in argv], capture_output=True, text=True, input=input)
    if check and done.returncode:
        raise Refused(f'{" ".join(map(str, argv))}: exit {done.returncode}: {(done.stderr or done.stdout).strip()[-600:]}')
    return done


def systemctl(*args, check=True):
    if NO_SYSTEMD:
        return subprocess.CompletedProcess(args, 0, '', '')
    return sh('systemctl', *args, check=check)


def is_root():
    return os.geteuid() == 0


def chown(path, user, group):
    if is_root() and not NO_SYSTEMD:
        os.chown(path, pwd.getpwnam(user).pw_uid if user != 'root' else 0, grp.getgrnam(group).gr_gid if group != 'root' else 0)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------------------------------------------- bundle

def read_bundle(path, expect, allow_unreleased):
    data = Path(path).read_bytes()
    got = sha256(data)
    if not re.fullmatch(r'[0-9a-f]{64}', expect or ''):
        raise Refused('--sha256 must be the 64-hex SHA-256 of the bundle, taken from the release record (never from the bundle)')
    if got != expect:
        raise Refused(f'bundle SHA-256 {got} is not the expected {expect}')
    files = {}
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as tar:
        for m in tar.getmembers():
            name = PurePosixPath(m.name)
            if name.is_absolute() or '..' in name.parts or m.name != str(name):
                raise Refused(f'tar member {m.name!r}: not a plain relative path')
            if m.isdir():
                continue
            if not m.isreg():
                raise Refused(f'tar member {m.name!r}: not a regular file (links and devices are refused)')
            files[m.name] = (tar.extractfile(m).read(), m.mode & 0o7777)
    if 'MANIFEST.json' not in files:
        raise Refused('no MANIFEST.json')
    man = json.loads(files.pop('MANIFEST.json')[0])
    listed = man.get('files', {})
    if set(listed) != set(files):
        raise Refused(f'files not as listed in MANIFEST.json: extra {sorted(set(files) - set(listed))[:5]}, '
                      f'missing {sorted(set(listed) - set(files))[:5]}')
    for p, (b, mode) in files.items():
        if sha256(b) != listed[p]['sha256'] or f'{mode:04o}' != listed[p]['mode']:
            raise Refused(f'{p}: bytes or mode differ from MANIFEST.json')
        if mode & 0o7022:
            raise Refused(f'{p}: mode {mode:04o} (setuid, setgid, sticky or group/other writable)')
    if man.get('format') != 1 or not re.fullmatch(r'[a-z0-9]+(-[a-z0-9]+)*', man.get('inst', '')):
        raise Refused('MANIFEST.json: unknown format or instance name')
    if man['ops_rev'] == 'worktree' and not allow_unreleased:
        raise Refused('an unreleased bundle (ops from a working tree): only with --allow-unreleased, never on a production host')
    man['_bundle_sha256'] = got
    man['_release_id'] = got[:16]
    return man, files


def inst_dir(inst):
    return P(f'/opt/bloch-bridge/{inst}')


def load_record(inst):
    f = inst_dir(inst) / 'install.json'
    if not f.exists():
        raise Refused(f'{inst} is not installed ({f} missing)')
    return json.loads(f.read_text())


def save_record(inst, rec):
    f = inst_dir(inst) / 'install.json'
    tmp = f.with_name('install.json.tmp')
    tmp.write_text(json.dumps(rec, indent=1, sort_keys=True) + '\n')
    os.chmod(tmp, 0o644)
    os.replace(tmp, f)


def current_manifest(inst):
    return json.loads((inst_dir(inst) / 'current' / 'MANIFEST.json').read_text())


def write_release(man, files):
    inst = man['inst']
    rel = inst_dir(inst) / 'releases' / man['_release_id']
    if rel.exists():
        shutil.rmtree(rel)  # an earlier interrupted attempt of the same bytes; it was never `current`
    for p, (b, mode) in sorted(files.items()):
        q = rel / p
        q.parent.mkdir(parents=True, exist_ok=True)
        q.write_bytes(b)
        os.chmod(q, mode)
    clean = {k: v for k, v in man.items() if not k.startswith('_')}
    (rel / 'MANIFEST.json').write_text(json.dumps(clean, indent=1, sort_keys=True) + '\n')
    os.chmod(rel / 'MANIFEST.json', 0o644)
    for d in [rel, *[x for x in rel.rglob('*') if x.is_dir()]]:
        os.chmod(d, 0o755)
    return rel


def swap(inst, name, target):
    link = inst_dir(inst) / name
    tmp = inst_dir(inst) / f'.{name}.tmp'
    if tmp.is_symlink() or tmp.exists():
        tmp.unlink()
    os.symlink(f'releases/{target}', tmp)
    os.replace(tmp, link)


def release_of(inst, name):
    link = inst_dir(inst) / name
    return os.readlink(link).split('/')[-1] if link.is_symlink() else None


def verify_release(inst, release):
    rel = inst_dir(inst) / 'releases' / release
    man = json.loads((rel / 'MANIFEST.json').read_text())
    bad = []
    for p, meta in man['files'].items():
        q = rel / p
        if not q.is_file() or q.is_symlink():
            bad.append(f'{p}: missing')
            continue
        st = q.stat()
        if sha256(q.read_bytes()) != meta['sha256'] or f'{stat.S_IMODE(st.st_mode):04o}' != meta['mode']:
            bad.append(f'{p}: changed since install')
        if is_root() and not NO_SYSTEMD and st.st_uid != 0:
            bad.append(f'{p}: not owned by root')
    present = {str(x.relative_to(rel)) for x in rel.rglob('*') if x.is_file()} - {'MANIFEST.json'}
    bad += [f'{p}: not in MANIFEST.json' for p in sorted(present - set(man['files']))]
    return man, bad


# ------------------------------------------------------------------------------------------------------------- host side

def ensure_user(user):
    if NO_SYSTEMD:
        return
    try:
        pw = pwd.getpwnam(user)
        if pw.pw_shell not in ('/usr/sbin/nologin', '/sbin/nologin', '/bin/false') or pw.pw_uid == 0:
            raise Refused(f'user {user} exists with a login shell or uid 0: refusing to reuse it')
        return
    except KeyError:
        pass
    sh('useradd', '--system', '--user-group', '--no-create-home', '--home-dir', '/nonexistent', '--shell', '/usr/sbin/nologin',
       '--comment', 'Bloch bridge operator bundle', user)


def mkdir(path, mode, user='root', group='root'):
    q = P(path)
    q.mkdir(parents=True, exist_ok=True)
    os.chmod(q, mode)
    chown(q, user, group)
    return q


def install_units(man, rel):
    dest = mkdir('/etc/systemd/system', 0o755)
    names = []
    for p in sorted(man['files']):
        if p.startswith('units/'):
            name = p.split('/', 1)[1]
            tmp = dest / f'.{name}.tmp'
            shutil.copyfile(rel / p, tmp)
            os.chmod(tmp, 0o644)
            os.replace(tmp, dest / name)
            names.append(name)
    lr = [p for p in man['files'] if p.startswith('etc/logrotate.d/')]
    if lr:
        d = mkdir('/etc/logrotate.d', 0o755)
        for p in lr:
            shutil.copyfile(rel / p, d / PurePosixPath(p).name)
            os.chmod(d / PurePosixPath(p).name, 0o644)
    notes = []
    jd = 'etc/journald.conf.d/50-bloch-bridge.conf'
    if jd in man['files']:
        d = mkdir('/etc/systemd/journald.conf.d', 0o755)
        target = d / '50-bloch-bridge.conf'
        new = (rel / jd).read_bytes()
        if not target.exists():
            target.write_bytes(new)
            os.chmod(target, 0o644)
            notes.append('journald drop-in installed: run `systemctl restart systemd-journald` once to apply it')
        elif target.read_bytes() != new:
            notes.append(f'{target} differs from this bundle\'s: left as it is')
    systemctl('daemon-reload')
    return names, notes


def analyze(units):
    if NO_SYSTEMD:
        return []
    done = sh('systemd-analyze', 'verify', '--man=no', *[f'/etc/systemd/system/{u}' for u in units], check=False)
    lines = [l for l in (done.stdout + done.stderr).splitlines() if l.strip()]
    if done.returncode:
        raise Refused('systemd-analyze verify: ' + ' | '.join(lines[-8:]))
    return lines


def cmd_install(args):
    bundle = args[0]
    man, files = read_bundle(bundle, opt(args, '--sha256'), '--allow-unreleased' in args)
    if not is_root() and not NO_SYSTEMD:
        raise Refused('run as root')
    inst, lay = man['inst'], man['layout']
    if (inst_dir(inst) / 'install.json').exists():
        raise Refused(f'{inst} is already installed: use `upgrade`')
    user = lay['user']
    ensure_user(user)
    mkdir('/opt/bloch-bridge', 0o755)
    mkdir(f'/opt/bloch-bridge/{inst}', 0o755)
    mkdir(f'/opt/bloch-bridge/{inst}/releases', 0o755)
    rel = write_release(man, files)
    swap(inst, 'current', man['_release_id'])
    mkdir('/etc/bloch-bridge', 0o755)
    etc = mkdir(lay['etc'], 0o750, 'root', user)
    tdir = mkdir(f'{lay["etc"]}/templates', 0o755)
    written = []
    for name in man['configs']:
        shutil.copyfile(rel / 'etc/templates' / name, tdir / name)
        os.chmod(tdir / name, 0o644)
        target = etc / name
        if not target.exists():
            shutil.copyfile(rel / 'etc/templates' / name, target)
            os.chmod(target, 0o640)
            chown(target, 'root', user)
            written.append(str(target))
    mkdir('/etc/credstore.encrypted', 0o700)
    mkdir(lay['credstore'], 0o700)
    for d in man.get('extra_dirs', []):
        owner = user if d.get('owner') == 'service' else 'root'
        mkdir(d['path'], int(d['mode'], 8), owner, owner)
    hook_example = P('/etc/bloch-bridge/alert-hook.example')
    shutil.copyfile(rel / 'ops/alert-hook.example', hook_example)
    os.chmod(hook_example, 0o755)
    units, notes = install_units(man, rel)
    analyzed = analyze(units)
    rec = {'inst': inst, 'route': man['route'], 'role': man['role'], 'current': man['_release_id'], 'previous': None,
           'history': [{'release': man['_release_id'], 'sha256': man['_bundle_sha256'], 'source_rev': man['source_rev'],
                        'ops_rev': man['ops_rev'], 'state_epoch': man['state_epoch'], 'at': int(time.time()), 'action': 'install'}]}
    save_record(inst, rec)
    return out({'installed': inst, 'release': man['_release_id'], 'units': units, 'configs_written': written, 'notes': notes,
                'systemd_analyze': analyzed[-5:],
                'next': [f'bridgectl.py seal {inst} <credential> --from <file> (for each of: '
                         f'{", ".join(c["id"] for c in man["credentials"]) or "none"})',
                         f'edit every TBD-owner value in {lay["etc"]}/*.json',
                         f'install the alert hook at {HOOK} (example: {HOOK}.example) and the cast pin at {CAST_PIN}',
                         f'bridgectl.py check {inst}', f'bridgectl.py start {inst}']})


# -------------------------------------------------------------------------------------------------------------- checks

def config_problems(man):
    lay = man['layout']
    run_dirs = {u['run_dir'] for u in man['units']}
    probs = []
    etc = P(lay['etc'])
    st = etc.stat() if etc.exists() else None
    if st is None:
        return [f'{etc}: missing']
    if stat.S_IMODE(st.st_mode) & 0o027:
        probs.append(f'{etc}: mode {stat.S_IMODE(st.st_mode):04o}; want 0750')
    for name in man['configs']:
        f = etc / name
        if not f.exists():
            probs.append(f'{f}: missing')
            continue
        fst = f.stat()
        if stat.S_IMODE(fst.st_mode) & 0o137 or (is_root() and not NO_SYSTEMD and fst.st_uid != 0):
            probs.append(f'{f}: mode {stat.S_IMODE(fst.st_mode):04o} owner {fst.st_uid}; want 0640 root:{lay["user"]} '
                         '(the service must not be able to change its own config)')
        try:
            doc = json.loads(f.read_text())
        except ValueError as e:
            probs.append(f'{f}: not JSON ({e})')
            continue
        text = f.read_text()
        if PEM.search(text):
            probs.append(f'{f}: holds a PEM private key')
        for path, value in leaves(doc):
            if any(p.startswith('_') for p in path.split('.')):
                continue
            if isinstance(value, str) and TBD.search(value):
                probs.append(f'{f.name}:{path}: still {value[:60]!r}')
            key = [p for p in path.split('.') if not p.isdigit()][-1]
            if SECRET_KEY.search(key) and not key.startswith('relay_other'):
                if not (isinstance(value, str) and any(value.startswith(d + '/') for d in run_dirs)):
                    probs.append(f'{f.name}:{path}: a secret must be a staged credential path under {sorted(run_dirs)}, not {value!r}')
    return probs


def leaves(doc, prefix=''):
    if isinstance(doc, dict):
        for k, v in doc.items():
            yield from leaves(v, f'{prefix}.{k}' if prefix else k)
    elif isinstance(doc, list):
        for i, v in enumerate(doc):
            yield from leaves(v, f'{prefix}.{i}')
    else:
        yield prefix, doc


def selected_units(man, extra):
    names = {u['name'] for u in man['units']}
    for e in extra:
        if e not in names:
            raise Refused(f'--with {e}: no such unit (units: {sorted(names)})')
    return [u for u in man['units'] if not u['optional'] or u['name'] in extra]


def credential_problems(man, units):
    probs = []
    store = P(man['layout']['credstore'])
    if not store.is_dir():
        return [f'{store}: missing']
    if stat.S_IMODE(store.stat().st_mode) & 0o077:
        probs.append(f'{store}: mode {stat.S_IMODE(store.stat().st_mode):04o}; want 0700 root')
    for u in units:
        for c in u['credentials']:
            f = store / c
            if not f.is_file():
                probs.append(f'credential {c} (unit {u["name"]}): missing; `bridgectl.py seal {man["inst"]} {c} --from FILE`')
            elif stat.S_IMODE(f.stat().st_mode) & 0o077:
                probs.append(f'{f}: mode {stat.S_IMODE(f.stat().st_mode):04o}; want 0600 root')
    return probs


def needs_cast(man):
    rel = inst_dir(man['inst']) / 'current'
    for name in man['configs']:
        if '"cast"' in (rel / 'etc/templates' / name).read_text():
            return True
    return False


def host_problems(man):
    probs = []
    if needs_cast(man):
        pin, cast = P(CAST_PIN), P('/opt/foundry/bin/cast')
        if not pin.is_file():
            probs.append(f'{CAST_PIN}: missing (the SHA-256 of cast from the key ceremony record, line 1)')
        elif not cast.is_file():
            probs.append('/opt/foundry/bin/cast: missing')
        else:
            want = pin.read_text().split()[0].lower() if pin.read_text().split() else ''
            if sha256(cast.read_bytes()) != want:
                probs.append(f'/opt/foundry/bin/cast: SHA-256 is not the pinned {want[:16]}...')
            if stat.S_IMODE(cast.stat().st_mode) & 0o022:
                probs.append('/opt/foundry/bin/cast: writable by group or others')
    hook = P(HOOK)
    if not hook.is_file() or not os.access(hook, os.X_OK):
        probs.append(f'{HOOK}: missing or not executable (owner input: the pager command; example in {HOOK}.example)')
    elif stat.S_IMODE(hook.stat().st_mode) & 0o022 or (is_root() and not NO_SYSTEMD and hook.stat().st_uid != 0):
        probs.append(f'{HOOK}: must be root-owned and not writable by group or others')
    return probs


def cmd_check(args, quiet=False):
    inst = args[0]
    load_record(inst)
    man, bad = verify_release(inst, release_of(inst, 'current'))
    units = selected_units(man, [args[i + 1] for i, a in enumerate(args) if a == '--with'])
    probs = bad + config_problems(man) + credential_problems(man, units) + host_problems(man)
    if quiet:
        return probs
    return out({'inst': inst, 'release': release_of(inst, 'current'), 'ok': not probs, 'problems': probs}, 0 if not probs else 1)


def cmd_preflight(args):
    inst = args[0]
    man = current_manifest(inst)
    if not man.get('preflight'):
        return out({'inst': inst, 'preflight': 'none for this role'})
    primary = next(u for u in man['units'] if u['name'] == man['role'])
    active = systemctl('is-active', primary['unit'], check=False).stdout.strip()
    if active in ('active', 'activating', 'reloading'):
        raise Refused(f'{primary["unit"]} is running: the preflight shares its staged credentials; stop it first')
    unit = f'bloch-bridge-{inst}-preflight.service'
    t0 = time.time()
    systemctl('start', unit, check=False)
    res = systemctl('show', unit, '-p', 'ExecMainStatus', '-p', 'Result', check=False).stdout
    code = int(re.search(r'ExecMainStatus=(\d+)', res).group(1)) if 'ExecMainStatus=' in res else -1
    log = sh('journalctl', '-u', unit, '--since', f'@{int(t0) - 1}', '-o', 'cat', '--no-pager', check=False).stdout if not NO_SYSTEMD else ''
    ok = code in man.get('preflight_ok_codes', [0])
    return out({'inst': inst, 'preflight_exit': code, 'ok': ok, 'output_tail': log.splitlines()[-25:]}, 0 if ok else 1)


def cmd_start(args):
    inst = args[0]
    extra = [args[i + 1] for i, a in enumerate(args) if a == '--with']
    probs = cmd_check([inst, *sum([['--with', e] for e in extra], [])], quiet=True)
    if probs:
        raise Refused('check failed:\n  ' + '\n  '.join(probs))
    man = current_manifest(inst)
    units = [u['unit'] for u in selected_units(man, extra)]
    systemctl('enable', '--now', *units)
    systemctl('enable', '--now', f'bloch-bridge-{inst}-health.timer')
    return out({'started': units, 'health_timer': f'bloch-bridge-{inst}-health.timer'})


def all_units(man):
    return [u['unit'] for u in man['units']] + man['health_units']


def cmd_stop(args):
    inst = args[0]
    man = current_manifest(inst)
    systemctl('disable', '--now', *all_units(man), check=False)
    return out({'stopped': all_units(man)})


def unit_state(unit):
    if NO_SYSTEMD:
        return {'ActiveState': 'unknown'}
    res = sh('systemctl', 'show', unit, '-p', 'ActiveState', '-p', 'SubState', '-p', 'NRestarts', '-p', 'Result',
             '-p', 'UnitFileState', '-p', 'ActiveEnterTimestampMonotonic', '-p', 'MainPID', check=False).stdout
    return dict(l.split('=', 1) for l in res.splitlines() if '=' in l)


def cmd_status(args):
    inst = args[0]
    rec = load_record(inst)
    man = current_manifest(inst)
    return out({'inst': inst, 'current': rec['current'], 'previous': rec.get('previous'),
                'source_rev': man['source_rev'], 'ops_rev': man['ops_rev'],
                'units': {u: unit_state(u) for u in all_units(man)}})


# -------------------------------------------------------------------------------------------------------------- health

def journal_events(units, cursor, since):
    if NO_SYSTEMD:
        return [], cursor
    argv = ['journalctl', '--no-pager', '-o', 'json', *sum([['-u', u] for u in units], [])]
    argv += ['--after-cursor', cursor] if cursor else ['--since', f'@{int(since)}']
    done = sh(*argv, check=False)
    events, last = [], cursor
    for line in done.stdout.splitlines():
        try:
            e = json.loads(line)
        except ValueError:
            continue
        last = e.get('__CURSOR', last)
        msg = e.get('MESSAGE')
        if not isinstance(msg, str) or not msg.startswith('{'):
            continue
        try:
            doc = json.loads(msg)
        except ValueError:
            continue
        kind = str(doc.get('kind', ''))
        unit = e.get('_SYSTEMD_UNIT', '')
        if kind in ('alert', 'pause') or kind.endswith('-failed') or kind.startswith('alert'):
            sev = str(doc.get('severity', '')).lower()
            level = 'CRIT' if kind == 'pause' or sev in ('critical', 'hard', 'crit') else 'WARN'
            events.append({'level': level, 'unit': unit, 'kind': kind, 'id': doc.get('id'), 'detail': str(doc.get('detail', doc.get('reason', '')))[:200]})
        elif 'error' in doc:
            events.append({'level': 'WARN', 'unit': unit, 'kind': kind or 'error', 'detail': str(doc['error'])[:200]})
    return events, last


def health_once(man, since=None, mem=None):
    """(level, findings). `since`: heartbeats must be newer than it (after a restart). `mem`: the timer's state."""
    findings = []
    now = time.time()
    enabled = []
    for u in man['units']:
        st = unit_state(u['unit'])
        if st.get('UnitFileState') not in ('enabled', 'enabled-runtime') and st.get('ActiveState') != 'active':
            continue
        enabled.append(u['unit'])
        if st.get('ActiveState') != 'active':
            findings.append({'level': 'CRIT', 'what': f'{u["unit"]} is {st.get("ActiveState")}/{st.get("SubState")} ({st.get("Result")})'})
        if mem is not None:
            n = int(st.get('NRestarts', '0') or 0)
            prev = mem.setdefault('restarts', {}).get(u['unit'])
            if prev is not None and n > prev:
                findings.append({'level': 'WARN', 'what': f'{u["unit"]} restarted {n - prev} time(s) since the last check'})
            mem['restarts'][u['unit']] = n
    if not enabled:
        return 'UNKNOWN', [{'level': 'UNKNOWN', 'what': 'no unit of this instance is enabled or running'}]
    primary_on = any(u['unit'] in enabled and u['name'] == man['role'] for u in man['units'])
    for hb in man.get('heartbeats', []) if primary_on else []:
        f = P(hb['file'])
        try:
            doc = json.loads(f.read_text())
        except (OSError, ValueError) as e:
            findings.append({'level': 'CRIT', 'what': f'heartbeat {hb["file"]} unreadable ({type(e).__name__})'})
            continue
        t = doc.get('t')
        if not isinstance(t, (int, float)) or now - t > hb['max_age_s'] or (since and t < since):
            findings.append({'level': 'CRIT', 'what': f'heartbeat {f.name} is stale (t={t}, max age {hb["max_age_s"]} s)'})
        field = hb.get('healthy_field')
        if field and doc.get(field) is not True:
            findings.append({'level': 'CRIT', 'what': f'{f.name}: {field} is {doc.get(field)!r}',
                             'detail': json.dumps({k: doc.get(k) for k in ('problems', 'findings') if k in doc})[:400]})
        vf = hb.get('verified_field')
        if vf:
            v = doc.get(vf)
            if not isinstance(v, (int, float)) or now - v > hb['verified_max_age_s']:
                findings.append({'level': 'CRIT', 'what': f'{f.name}: last fully verified round {v} is older than {hb["verified_max_age_s"]} s (alive but blind)'})
    if mem is not None:
        events, mem['cursor'] = journal_events(enabled, mem.get('cursor'), mem.get('t', now - 300))
        for e in events[-20:]:
            findings.append({'level': e['level'], 'what': f'{e["unit"]}: {e["kind"]} {e.get("id") or ""}'.strip(), 'detail': e['detail']})
    level = max((f['level'] for f in findings), key=lambda x: LEVELS[x], default='OK')
    return level, findings


def cmd_health(args):
    inst = args[0]
    man = current_manifest(inst)
    lay = man['layout']
    alert = '--alert' in args
    wait = int(opt(args, '--wait', '0'))
    since = float(opt(args, '--since', '0')) or None
    mem_file = P(f'/var/lib/bloch-bridge/{inst}-health/state.json')
    mem = None
    if alert:
        try:
            mem = json.loads(mem_file.read_text())
        except (OSError, ValueError):
            mem = {}
    deadline = time.time() + wait
    while True:
        level, findings = health_once(man, since, mem)
        if level == 'OK' or time.time() >= deadline:
            break
        time.sleep(5)
    doc = {'t': int(time.time()), 'inst': inst, 'release': release_of(inst, 'current'), 'level': level, 'findings': findings}
    line = json.dumps(doc, sort_keys=True)
    print(line, flush=True)
    if alert:
        logf = P(f'{lay["logs"]}/health.log')
        try:
            with open(logf, 'a') as fh:
                fh.write(line + '\n')
        except OSError as e:
            print(json.dumps({'kind': 'health-log-failed', 'error': str(e)}), flush=True)
        key = json.dumps(sorted({f['level'] + ' ' + f['what'] for f in findings if f['level'] != 'OK'}))
        changed = key != mem.get('last_key')
        remind = level == 'CRIT' and time.time() - mem.get('last_hook', 0) >= REMIND_S
        if changed or remind:
            hook_level = 'RESOLVED' if level == 'OK' and mem.get('last_level') not in (None, 'OK') else level
            if hook_level != 'OK' or mem.get('last_level') is None:
                run_hook(hook_level, inst, line)
                mem['last_hook'] = time.time()
        mem.update(last_key=key, last_level=level, t=time.time())
        tmp = mem_file.with_name('state.json.tmp')
        tmp.write_text(json.dumps(mem))
        os.replace(tmp, mem_file)
    return LEVELS[level]


def run_hook(level, inst, summary):
    hook = P(HOOK)
    if not hook.is_file():
        print(json.dumps({'kind': 'alert-hook-missing', 'level': level}), flush=True)
        return
    try:
        done = subprocess.run([str(hook), level, inst, summary[:4000]], capture_output=True, text=True, timeout=30)
        if done.returncode:
            print(json.dumps({'kind': 'alert-hook-failed', 'rc': done.returncode, 'error': done.stderr.strip()[-200:]}), flush=True)
    except (OSError, subprocess.SubprocessError) as e:
        print(json.dumps({'kind': 'alert-hook-failed', 'error': str(e)}), flush=True)


# ------------------------------------------------------------------------------------------------------ upgrade/rollback

def active_units(man):
    return [u for u in all_units(man) if systemctl('is-active', u, check=False).stdout.strip() == 'active']


def switch_to(inst, release, restart):
    swap(inst, 'current', release)
    man = current_manifest(inst)
    install_units(man, inst_dir(inst) / 'releases' / release)
    if restart:
        systemctl('restart', *restart)
    return man


def cmd_upgrade(args):
    inst, bundle = args[0], args[1]
    rec = load_record(inst)
    man, files = read_bundle(bundle, opt(args, '--sha256'), '--allow-unreleased' in args)
    if man['inst'] != inst:
        raise Refused(f'the bundle is for {man["inst"]}, not {inst}')
    old_id = rec['current']
    old = current_manifest(inst)
    if man['_release_id'] == old_id:
        raise Refused('this release is already current')
    if man['state_epoch'] < old['state_epoch']:
        raise Refused(f'state epoch {man["state_epoch"]} < current {old["state_epoch"]}: the new code may not read this state')
    old_rel = inst_dir(inst) / 'releases' / old_id
    diffs = []
    for name in sorted(set(old['configs']) | set(man['configs'])):
        a = (old_rel / 'etc/templates' / name).read_text().splitlines() if name in old['configs'] else []
        b = files[f'etc/templates/{name}'][0].decode().splitlines() if name in man['configs'] else []
        if a != b:
            diffs += list(difflib.unified_diff(a, b, f'current/{name}', f'new/{name}', lineterm='', n=1))
    if diffs and '--config-reviewed' not in args:
        return out({'refused': 'the config templates changed: compare, update the configs, then rerun with --config-reviewed',
                    'diff': diffs[:200]}, 1)
    if set(man['configs']) - set(old['configs']):
        raise Refused(f'new config files {sorted(set(man["configs"]) - set(old["configs"]))}: install them before upgrading')
    restart = active_units(old)
    write_release(man, files)
    tdir = P(man['layout']['etc']) / 'templates'
    t0 = time.time()
    switch_to(inst, man['_release_id'], restart)
    for name in man['configs']:
        shutil.copyfile(inst_dir(inst) / 'current/etc/templates' / name, tdir / name)
    level = 'OK'
    if restart and not NO_SYSTEMD:
        level = LEVELS_INV[health_wait(inst, t0)]
    rec['history'].append({'release': man['_release_id'], 'sha256': man['_bundle_sha256'], 'source_rev': man['source_rev'],
                           'ops_rev': man['ops_rev'], 'state_epoch': man['state_epoch'], 'at': int(t0), 'action': 'upgrade',
                           'health': level})
    if level != 'OK':
        switch_to(inst, old_id, restart)
        for name in old['configs']:
            shutil.copyfile(old_rel / 'etc/templates' / name, tdir / name)
        rec['history'].append({'release': old_id, 'at': int(time.time()), 'action': 'auto-rollback'})
        save_record(inst, rec)
        return out({'upgrade': 'rolled back', 'health': level, 'current': old_id, 'failed_release': man['_release_id']}, 2)
    rec['previous'], rec['current'] = old_id, man['_release_id']
    swap(inst, 'previous', old_id)
    save_record(inst, rec)
    return out({'upgraded': inst, 'from': old_id, 'to': man['_release_id'], 'restarted': restart, 'health': level})


LEVELS_INV = {v: k for k, v in LEVELS.items()}


def health_wait(inst, since):
    exe = [sys.executable, '-E', '-s', str(inst_dir(inst) / 'current/ops/bridgectl.py'), 'health', inst,
           '--wait', str(HEALTH_WAIT_S), '--since', str(int(since))]
    done = subprocess.run(exe, capture_output=True, text=True)
    sys.stderr.write(done.stdout[-2000:])
    return done.returncode if done.returncode in LEVELS_INV else 3


def cmd_rollback(args):
    inst = args[0]
    rec = load_record(inst)
    prev = rec.get('previous')
    if not prev or not (inst_dir(inst) / 'releases' / prev).is_dir():
        raise Refused('no previous release to roll back to')
    cur = current_manifest(inst)
    pman, bad = verify_release(inst, prev)
    if bad:
        raise Refused(f'previous release {prev} changed since install: {bad[:3]}')
    if pman['state_epoch'] != cur['state_epoch']:
        raise Refused(f'state epoch {pman["state_epoch"]} != current {cur["state_epoch"]}: the older code may not read this state')
    restart = active_units(cur)
    t0 = time.time()
    switch_to(inst, prev, restart)
    tdir = P(cur['layout']['etc']) / 'templates'
    for name in pman['configs']:
        shutil.copyfile(inst_dir(inst) / 'current/etc/templates' / name, tdir / name)
    level = 'OK'
    if restart and not NO_SYSTEMD:
        level = LEVELS_INV[health_wait(inst, t0)]
    rec['previous'], rec['current'] = rec['current'], prev
    swap(inst, 'previous', rec['previous'])
    rec['history'].append({'release': prev, 'at': int(t0), 'action': 'rollback', 'health': level})
    save_record(inst, rec)
    return out({'rolled_back': inst, 'current': prev, 'previous': rec['previous'], 'restarted': restart, 'health': level},
               0 if level == 'OK' else 2)


def cmd_verify(args):
    inst = args[0]
    rec = load_record(inst)
    man, bad = verify_release(inst, rec['current'])
    rel = inst_dir(inst) / 'releases' / rec['current']
    for p in man['files']:
        if p.startswith('units/'):
            live = P('/etc/systemd/system') / p.split('/', 1)[1]
            if not live.is_file() or live.read_bytes() != (rel / p).read_bytes():
                bad.append(f'{live}: differs from the current release')
    return out({'inst': inst, 'release': rec['current'], 'ok': not bad, 'problems': bad}, 0 if not bad else 1)


# --------------------------------------------------------------------------------------------------------- credentials

def cmd_credentials(args):
    inst = args[0]
    man = current_manifest(inst)
    store = P(man['layout']['credstore'])
    rows = []
    for c in man['credentials']:
        f = store / c['id']
        rows.append({'id': c['id'], 'what': c['what'], 'optional': bool(c.get('optional')), 'present': f.is_file(),
                     'mode': f'{stat.S_IMODE(f.stat().st_mode):04o}' if f.is_file() else None})
    return out({'inst': inst, 'store': str(store), 'credentials': rows})


def cmd_seal(args):
    inst, cred = args[0], args[1]
    man = current_manifest(inst)
    if cred not in {c['id'] for c in man['credentials']}:
        raise Refused(f'{cred} is not a credential of {inst}: {[c["id"] for c in man["credentials"]]}')
    if not is_root() and not NO_SYSTEMD:
        raise Refused('run as root')
    src = opt(args, '--from')
    data = Path(src).read_bytes() if src else sys.stdin.buffer.read()
    if not data.strip():
        raise Refused('empty input')
    target = P(man['layout']['credstore']) / cred
    if target.exists() and '--replace' not in args:
        raise Refused(f'{target} exists (use --replace to rotate it)')
    tmp = target.with_name(f'.{cred}.tmp')
    old = os.umask(0o077)
    try:
        if NO_SYSTEMD:
            tmp.write_bytes(b'TEST-ONLY-NOT-ENCRYPTED:' + hashlib.sha256(data).hexdigest().encode())
        else:
            done = subprocess.run(['systemd-creds', 'encrypt', f'--name={cred}', '-', str(tmp)], input=data, capture_output=True)
            if done.returncode:
                raise Refused(f'systemd-creds encrypt: {done.stderr.decode().strip()[-300:]}')
        os.chmod(tmp, 0o600)
        os.replace(tmp, target)
    finally:
        os.umask(old)
        if tmp.exists():
            tmp.unlink()
    return out({'sealed': cred, 'inst': inst, 'file': str(target), 'bytes_in': len(data),
                'note': 'the plaintext source is not removed by this tool: shred it (it should have been on tmpfs)'})


# ------------------------------------------------------------------------------------------------------------------ cli

def opt(args, name, default=None):
    return args[args.index(name) + 1] if name in args and args.index(name) + 1 < len(args) else default


COMMANDS = {'install': (cmd_install, 1), 'check': (cmd_check, 1), 'preflight': (cmd_preflight, 1), 'start': (cmd_start, 1),
            'stop': (cmd_stop, 1), 'status': (cmd_status, 1), 'health': (cmd_health, 1), 'upgrade': (cmd_upgrade, 2),
            'rollback': (cmd_rollback, 1), 'verify': (cmd_verify, 1), 'credentials': (cmd_credentials, 1), 'seal': (cmd_seal, 2)}


def main(argv):
    if not argv or argv[0] not in COMMANDS or len(argv) - 1 < COMMANDS[argv[0]][1]:
        raise SystemExit(__doc__)
    fn = COMMANDS[argv[0]][0]
    try:
        return fn(argv[1:])
    except Refused as e:
        return out({'refused': str(e), 'command': argv[0]}, 1)


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
