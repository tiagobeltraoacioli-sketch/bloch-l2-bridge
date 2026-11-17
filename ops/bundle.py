#!/usr/bin/env python3
"""Operator bundles: build one installable bundle per (route, role) from committed sources (agent 381, round 18).

  python3 ops/bundle.py list
  python3 ops/bundle.py build  --route R --role X [--rev REV] [--ops-rev REV] [--worktree-ops] --out DIR
  python3 ops/bundle.py render --route R --role X [--rev REV] [--ops-rev REV] [--worktree-ops] --out DIR
  python3 ops/bundle.py lint   [--rev-of ROUTE=REV ...] [--worktree-ops]

A bundle is a gzip tar holding the route's tools at `--rev` (default: the route's `source_rev` in ops/routes.json), the
on-host tool `ops/bridgectl.py`, generated systemd units, config templates rendered from the route's committed
templates, a logrotate file, a journald drop-in and MANIFEST.json (every file's SHA-256 and mode, both revisions, the
units, the credentials, the heartbeats, the ports, the host size). The bytes depend only on the two revisions: two
builds of the same revisions are byte-identical (tested), so an operator can rebuild and compare before installing.

Sources are read from git objects, never from the working tree, unless `--worktree-ops` (development and tests): the
manifest then says `"ops_rev": "worktree"` and `bridgectl.py install` refuses it without `--allow-unreleased`.

Every rendered config is checked (also by `lint` and by test_bundle.py): each string is `TBD-owner ...`, a path of the
bundle's layout or a declared external path, or a fixed public fact listed in routes.json; every key that names a
key, keystore, password, secret, seed or mnemonic points into the runtime directory of a unit that loads it as an
encrypted systemd credential; no 32-byte hex value appears that is not a listed fact. Python standard library only.
"""
import fnmatch
import gzip
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]
OPS_FILES = ['ops/bridgectl.py', 'ops/routes.json', 'ops/bundle.py', 'ops/alert-hook.example']
FORMAT = 1
SECRET_KEY = re.compile(r'(keystore|password|passphrase|private|secret|mnemonic|seed)|(^|_)key$', re.I)
HEX32 = re.compile(r'0x[0-9a-fA-F]{64}')
PEM = re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----')
TBD = 'TBD-owner'
PY = '/usr/bin/python3 -E -s'
CAST = '/opt/foundry/bin/cast'
HARDENING_KEYS = None  # filled from routes.json


class BuildError(Exception):
    pass


def git(*args, cwd=ROOT, binary=False):
    done = subprocess.run(['git', *args], cwd=cwd, capture_output=True)
    if done.returncode:
        raise BuildError(f'git {" ".join(args)}: {done.stderr.decode().strip()}')
    return done.stdout if binary else done.stdout.decode()


def rev_parse(rev):
    return git('rev-parse', '--verify', f'{rev}^{{commit}}').strip()


def tree_files(rev, path):
    """[(path, mode, blob)] of every file under `path` at `rev` (regular files only; a symlink is refused)."""
    out = git('ls-tree', '-r', '-z', '--full-tree', rev, '--', path)
    files = []
    for entry in filter(None, out.split('\0')):
        meta, name = entry.split('\t', 1)
        mode, kind, blob = meta.split()
        if kind != 'blob':
            continue
        if mode == '120000':
            raise BuildError(f'{name} at {rev[:12]} is a symlink: refused')
        files.append((name, mode, blob))
    return files


def blob(sha):
    return git('cat-file', 'blob', sha, binary=True)


def read_at(rev, path):
    if rev == 'worktree':
        return (ROOT / path).read_bytes()
    try:
        return git('show', f'{rev}:{path}', binary=True)
    except BuildError as e:
        raise BuildError(f'{path} is not in {rev[:12]}: {e}') from None


def load_manifest(ops_rev):
    m = json.loads(read_at(ops_rev, 'ops/routes.json'))
    if m.get('format') != FORMAT:
        raise BuildError(f'ops/routes.json format {m.get("format")} != {FORMAT}')
    for name, r in list(m['routes'].items()):
        if 'inherit' in r:
            m['routes'][name] = inherit(m['routes'], name, r)
    return m


def inherit(routes, name, r):
    """A route whose roles are another route's with literal substitutions (applied in order to the roles' JSON text),
    units / configs / credentials dropped, extra config keys set and JSON-path patches. The result is what gets checked."""
    base = routes[r['inherit']]
    if 'inherit' in base:
        raise BuildError(f'{name}: inherits from {r["inherit"]}, which inherits itself (one level only)')
    text = json.dumps(base['roles'])
    for old, new in r.get('substitute', []):
        if old not in text:
            raise BuildError(f'{name}: substitution {old!r} matches nothing in {r["inherit"]}')
        text = text.replace(old, new)
    roles = json.loads(text)
    drop = r.get('drop', {})
    for role, spec in roles.items():
        spec['units'] = [u for u in spec['units'] if u['name'] not in drop.get('units', [])]
        spec['configs'] = {k: v for k, v in spec.get('configs', {}).items() if k not in drop.get('configs', [])}
        spec['credentials'] = [c for c in spec.get('credentials', []) if c['id'] not in drop.get('credentials', [])]
    for role, by_cfg in r.get('set_extra', {}).items():
        for cfg, kv in by_cfg.items():
            roles[role]['configs'][cfg].setdefault('set', {}).update(kv)
    for patch in r.get('patch', []):
        cur = roles
        parts = patch['path'].split('.')
        for part in parts[:-1]:
            cur = cur[int(part)] if isinstance(cur, list) else cur[part]
        last = parts[-1]
        if isinstance(cur, list):
            cur[int(last)] = patch['value']
        else:
            cur[last] = patch['value']
    return {**{k: v for k, v in r.items() if k not in ('substitute', 'drop', 'set_extra', 'patch')}, 'roles': roles}


def layout(route, role):
    inst = f'{route}-{role}'
    return {
        'inst': inst,
        'user': f'bb-{inst}',
        'release': f'/opt/bloch-bridge/{inst}/current',
        'etc': f'/etc/bloch-bridge/{inst}',
        'state': f'/var/lib/bloch-bridge/{inst}',
        'run': f'/run/bloch-bridge-{inst}',
        'credstore': f'/etc/credstore.encrypted/bloch-bridge-{inst}',
        'logs': f'/var/log/bloch-bridge/{inst}',
        'cast': CAST,
        'py': PY,
    }


def run_dir(lay, role, unit_name):
    return lay['run'] if unit_name == role else f'{lay["run"]}-{unit_name}'


def subst(value, lay, role, units):
    """Replace {inst} {release} {etc} {state} {run} {run:UNIT} {cast} {py} in a string (other braces stay: {deposit_id})."""
    if not isinstance(value, str):
        return value
    def one(mt):
        key = mt.group(1)
        if key.startswith('run:'):
            name = key[4:]
            if name not in units:
                raise BuildError(f'{{{key}}}: no unit named {name}')
            return run_dir(lay, role, name)
        return lay[key] if key in lay and key not in ('user', 'credstore', 'logs') else mt.group(0)
    return re.sub(r'\{([a-z]+(?::[a-z0-9-]+)?)\}', one, value)


def deep_subst(value, lay, role, units):
    if isinstance(value, list):
        return [deep_subst(v, lay, role, units) for v in value]
    if isinstance(value, dict):
        return {k: deep_subst(v, lay, role, units) for k, v in value.items()}
    return subst(value, lay, role, units)


def set_path(doc, dotted, value, may_add):
    parts = dotted.split('.')
    cur = doc
    for p in parts[:-1]:
        cur = cur[int(p)] if isinstance(cur, list) else cur.setdefault(p, {}) if may_add else cur[p]
    last = parts[-1]
    if isinstance(cur, list):
        cur[int(last)] = value
        return
    if last not in cur and not may_add:
        raise BuildError(f'{dotted}: not in the route template (add it to "add" if the tool reads it)')
    cur[last] = value


def leaves(doc, prefix=''):
    if isinstance(doc, dict):
        for k, v in doc.items():
            yield from leaves(v, f'{prefix}.{k}' if prefix else k)
    elif isinstance(doc, list):
        for i, v in enumerate(doc):
            yield from leaves(v, f'{prefix}.{i}')
    else:
        yield prefix, doc


def last_key(path):
    parts = [p for p in path.split('.') if not p.isdigit()]
    return parts[-1] if parts else ''


def allowed_roots(lay, role, spec):
    roots = [lay['release'] + '/', lay['etc'] + '/', lay['state'] + '/', lay['state'],
             lay['run'] + '/', CAST]
    roots += [run_dir(lay, role, u['name']) + '/' for u in spec['units']]
    roots += [d['path'] for d in spec.get('extra_dirs', [])]
    roots += [d['path'] + '/' for d in spec.get('extra_dirs', [])]
    roots += spec.get('external_paths', [])
    return roots


def check_config(name, doc, lay, role, spec, facts):
    """The rules of the module docstring. Returns a list of problems (empty = fine)."""
    problems = []
    roots = allowed_roots(lay, role, spec)
    cred_paths = {}
    for u in spec['units']:
        for c in u.get('credentials', []):
            cred_paths[f'{run_dir(lay, role, u["name"])}/{c}'] = c
    for path, value in leaves(doc):
        about = any(p.startswith('_') for p in path.split('.'))
        text = json.dumps(value) if not isinstance(value, str) else value
        if PEM.search(text):
            problems.append(f'{name}:{path}: a PEM private key')
        for h in HEX32.findall(text):
            if h.lower() not in {f.lower() for f in facts}:
                problems.append(f'{name}:{path}: a 32-byte hex value that is not a listed public fact')
        if about:
            continue
        key = last_key(path)
        if SECRET_KEY.search(key) and not key.startswith('relay_other'):
            if not (isinstance(value, str) and value in cred_paths):
                problems.append(f'{name}:{path}: names a secret but is not a staged credential path ({value!r})')
            continue
        if not isinstance(value, str):
            continue
        if value.startswith(TBD):
            continue
        if value in facts:
            continue
        if value.startswith('/') and any(value == r.rstrip('/') or value.startswith(r) for r in roots):
            continue
        problems.append(f'{name}:{path}: {value!r} is neither TBD-owner, a layout path nor a listed public fact')
    return problems


def render_configs(route, role, spec, src_rev, lay, facts):
    units = {u['name'] for u in spec['units']}
    out = {}
    for name, c in spec.get('configs', {}).items():
        doc = json.loads(read_at(src_rev, c['from']))
        add = set(c.get('add', []))
        for dotted, value in c.get('set', {}).items():
            set_path(doc, dotted, deep_subst(value, lay, role, units), dotted in add)
        doc['_bundle'] = (f'Rendered by ops/bundle.py for {lay["inst"]} from {c["from"]} at {src_rev[:12]}. Fill every TBD-owner '
                          f'value; secrets are never written here (encrypted systemd credentials, staged by the unit).')
        problems = check_config(name, doc, lay, role, spec, facts)
        if problems:
            raise BuildError('\n'.join(problems))
        out[name] = doc
    return out


def unit_text(kind, lay, role, spec, u, src_rev, hardening, preflight=None):
    """A daemon or feed unit; with `preflight` (argv) the primary unit's sandbox, credentials and user as a oneshot that
    conflicts with the daemon (both use one RuntimeDirectory), so the role's preflight sees exactly what the daemon sees."""
    name = u['name']
    rdir = run_dir(lay, role, name)
    user = lay['user']
    exec_line = ' '.join(subst(a, lay, role, {x['name'] for x in spec['units']}) for a in (preflight or u['exec']))
    for key in u.get('extra', []):
        if key.split('=')[0] in HARDENING_KEYS:
            raise BuildError(f'{lay["inst"]}/{name}: extra line {key!r} overrides the common hardening')
    head = [f'# Generated by ops/bundle.py for {lay["inst"]} ({name}) from ops/routes.json; tools at {src_rev[:12]}.',
            '# Do not edit on the host: build a new bundle and upgrade (bridgectl.py upgrade).']
    if kind == 'feed':
        serve = u['serve_dir']
        res = u.get('resources', {})
        lines = head + [
            '[Unit]', f'Description={u["description"]}', 'After=network-online.target', 'Wants=network-online.target',
            f'OnFailure=bloch-bridge-{lay["inst"]}-health.service', '',
            '[Service]', 'Type=simple', 'DynamicUser=yes', f'ExecStart={exec_line}', 'Restart=always', 'RestartSec=10',
            'TemporaryFileSystem=/var/lib:ro', f'BindReadOnlyPaths={serve}',
            f'InaccessiblePaths=-{lay["etc"]} -{lay["credstore"]} -{lay["run"]}',
            *[l for l in hardening if not l.startswith('RestrictAddressFamilies')],
            'RestrictAddressFamilies=AF_INET AF_INET6',
            *[f'{k}={v}' for k, v in res.items()], 'Nice=10', '',
            '[Install]', 'WantedBy=multi-user.target', '']
        return '\n'.join(lines)
    creds = u.get('credentials', [])
    res = u.get('resources', {})
    state_mode = '0750' if u.get('group_readable_state') else '0700'
    other_runs = [run_dir(lay, role, x['name']) for x in spec['units'] if x['name'] != name and x.get('kind') != 'feed']
    primary = f'bloch-bridge-{lay["inst"]}.service'
    if preflight:
        unit_head = ['[Unit]', f'Description=Bloch bridge {lay["inst"]}: preflight in the daemon\'s own sandbox (bridgectl.py preflight)',
                     *[f'After={a}' for a in u.get('after', [])], f'Conflicts={primary}', '',
                     '[Service]', 'Type=oneshot', f'User={user}', f'Group={user}']
        tail_run, install = ['TimeoutStartSec=1800'], []
    else:
        unit_head = ['[Unit]', f'Description={u["description"]}',
                     *[f'After={a}' for a in u.get('after', [])], 'Wants=network-online.target',
                     'StartLimitIntervalSec=900', 'StartLimitBurst=10',
                     f'OnFailure=bloch-bridge-{lay["inst"]}-health.service', '',
                     '[Service]', 'Type=simple', f'User={user}', f'Group={user}']
        tail_run, install = ['Restart=always', 'RestartSec=30', f'TimeoutStopSec={u.get("timeout_stop_s", 60)}'], \
            ['[Install]', 'WantedBy=multi-user.target', '']
    lines = head + [
        *unit_head,
        f'WorkingDirectory={lay["state"]}',
        f'StateDirectory=bloch-bridge/{lay["inst"]}', f'StateDirectoryMode={state_mode}',
        f'RuntimeDirectory={rdir[len("/run/"):]}', 'RuntimeDirectoryMode=0700', 'RuntimeDirectoryPreserve=no',
        *[f'LoadCredentialEncrypted={c}:{lay["credstore"]}/{c}' for c in creds],
        *[f'ExecStartPre=+/usr/bin/install -m 0400 -o {user} -g {user} ${{CREDENTIALS_DIRECTORY}}/{c} {rdir}/{c}' for c in creds],
        f'ExecStart={exec_line}',
        *tail_run,
        'Environment=PYTHONDONTWRITEBYTECODE=1',
        *[f'ReadWritePaths={p}' for p in u.get('read_write', [])],
        *[f'ReadOnlyPaths=-{p}' for p in u.get('read_only', [])],
        f'InaccessiblePaths=-/etc/credstore -/etc/credstore.encrypted {" ".join("-" + p for p in other_runs)}'.rstrip(),
        *hardening,
        *u.get('extra', []),
        *[f'{k}={v}' for k, v in res.items()], '',
        *install]
    return '\n'.join(lines)


def health_units(lay, role, spec, hardening):
    runs = ' '.join(f'-{run_dir(lay, role, u["name"])}' for u in spec['units'] if u.get('kind') != 'feed')
    svc = '\n'.join([
        f'# Generated by ops/bundle.py for {lay["inst"]}: health check and alert forwarding (bridgectl.py health).',
        '[Unit]', f'Description=Bloch bridge {lay["inst"]}: health check and alert forwarding',
        '', '[Service]', 'Type=oneshot', f'User={lay["user"]}', f'Group={lay["user"]}', 'SupplementaryGroups=systemd-journal',
        f'StateDirectory=bloch-bridge/{lay["inst"]}-health', 'StateDirectoryMode=0700',
        f'LogsDirectory=bloch-bridge/{lay["inst"]}', 'LogsDirectoryMode=0750',
        f'ExecStart={PY} {lay["release"]}/ops/bridgectl.py health {lay["inst"]} --alert',
        'SuccessExitStatus=1 2 3', 'TimeoutStartSec=120',
        f'ReadOnlyPaths=-{lay["state"]}',
        f'InaccessiblePaths=-/etc/credstore -/etc/credstore.encrypted {runs}',
        *[l for l in hardening if not l.startswith('PrivateIPC')],
        'MemoryMax=256M', 'Nice=10', ''])
    timer = '\n'.join([
        f'# Generated by ops/bundle.py for {lay["inst"]}.',
        '[Unit]', f'Description=Run the Bloch bridge {lay["inst"]} health check every minute', '',
        '[Timer]', 'OnBootSec=2min', 'OnUnitActiveSec=60s', 'AccuracySec=10s', '',
        '[Install]', 'WantedBy=timers.target', ''])
    return svc, timer


def logrotate_text(lay):
    return '\n'.join([
        f'# Generated by ops/bundle.py for {lay["inst"]}: health and alert history (the daemons log to journald).',
        f'{lay["logs"]}/*.log {{', f'    su {lay["user"]} {lay["user"]}', '    daily', '    rotate 90', '    maxsize 50M',
        '    compress', '    delaycompress', '    missingok', '    notifempty', f'    create 0640 {lay["user"]} {lay["user"]}', '}', ''])


JOURNALD = '\n'.join([
    '# Generated by ops/bundle.py: the bridge daemons log one JSON object per line to journald. Keep it on disk, bounded.',
    '[Journal]', 'Storage=persistent', 'SystemMaxUse=4G', 'SystemKeepFree=10G', 'MaxFileSec=1week', 'Compress=yes', ''])


def payload(spec, src_rev):
    files = {}
    for root in spec['payload']:
        for name, mode, sha in tree_files(src_rev, root):
            base = PurePosixPath(name).name
            if any(fnmatch.fnmatch(base, pat) for pat in spec.get('exclude', [])):
                continue
            files[name] = (blob(sha), 0o755 if mode == '100755' else 0o644)
    if not files:
        raise BuildError(f'no payload file at {src_rev[:12]} under {spec["payload"]}')
    return files


def assemble(route, role, src_rev=None, ops_rev='HEAD', worktree_ops=False):
    """Returns (files {path: (bytes, mode)}, manifest dict)."""
    global HARDENING_KEYS
    ops_ref = 'worktree' if worktree_ops else rev_parse(ops_rev)
    m = load_manifest(ops_ref)
    if route not in m['routes']:
        raise BuildError(f'unknown route {route}; routes: {", ".join(m["routes"])}')
    r = m['routes'][route]
    if role not in r['roles']:
        raise BuildError(f'route {route} has no role {role}; roles: {", ".join(r["roles"])}')
    spec = r['roles'][role]
    if r.get('refused'):
        raise BuildError(f'route {route} is refused: {r["refused"]}')
    src = rev_parse(src_rev or r['source_rev'])
    hardening = m['hardening']['lines']
    HARDENING_KEYS = {l.split('=')[0] for l in hardening}
    facts = set(m['facts']['values'])
    lay = layout(route, role)
    names = [u['name'] for u in spec['units']]
    if role not in names or len(set(names)) != len(names):
        raise BuildError(f'{lay["inst"]}: unit names must be unique and include one named {role}')
    declared = {c['id'] for c in spec.get('credentials', [])}
    used = [c for u in spec['units'] for c in u.get('credentials', [])]
    if set(used) != declared or len(used) != len(set(used)):
        raise BuildError(f'{lay["inst"]}: each declared credential must be loaded by exactly one unit ({sorted(declared)} vs {used})')
    files = {}
    for name, data_mode in payload(spec, src).items():
        files[name] = data_mode
    for name in OPS_FILES:
        data = read_at(ops_ref, name)
        files[name] = (data, 0o755 if name.endswith('bridgectl.py') else 0o644)
    configs = render_configs(route, role, spec, src, lay, facts)
    for name, doc in configs.items():
        files[f'etc/templates/{name}'] = ((json.dumps(doc, indent=2) + '\n').encode(), 0o644)
    unit_names = []
    for u in spec['units']:
        uname = f'bloch-bridge-{lay["inst"]}.service' if u['name'] == role else f'bloch-bridge-{lay["inst"]}-{u["name"]}.service'
        text = unit_text(u.get('kind', 'daemon'), lay, role, spec, u, src, hardening)
        if PEM.search(text) or any(h.lower() not in {f.lower() for f in facts} for h in HEX32.findall(text)):
            raise BuildError(f'{uname}: key-like material in a unit')
        files[f'units/{uname}'] = (text.encode(), 0o644)
        unit_names.append({'unit': uname, 'name': u['name'], 'kind': u.get('kind', 'daemon'), 'optional': bool(u.get('optional')),
                           'credentials': u.get('credentials', []), 'run_dir': run_dir(lay, role, u['name'])})
    preflight_unit = None
    if spec.get('preflight'):
        primary = next(u for u in spec['units'] if u['name'] == role)
        preflight_unit = f'bloch-bridge-{lay["inst"]}-preflight.service'
        text = unit_text('daemon', lay, role, spec, primary, src, hardening, preflight=spec['preflight'])
        files[f'units/{preflight_unit}'] = (text.encode(), 0o644)
    svc, timer = health_units(lay, role, spec, hardening)
    files[f'units/bloch-bridge-{lay["inst"]}-health.service'] = (svc.encode(), 0o644)
    files[f'units/bloch-bridge-{lay["inst"]}-health.timer'] = (timer.encode(), 0o644)
    files[f'etc/logrotate.d/bloch-bridge-{lay["inst"]}'] = (logrotate_text(lay).encode(), 0o644)
    files['etc/journald.conf.d/50-bloch-bridge.conf'] = (JOURNALD.encode(), 0o644)
    lay_out = {k: v for k, v in lay.items() if k != 'py'}
    manifest = {
        'format': FORMAT, 'route': route, 'role': role, 'inst': lay['inst'], 'summary': spec['summary'],
        'asset': r['asset'], 'launch_status': r['launch_status'],
        'source_rev': src, 'ops_rev': ops_ref, 'state_epoch': int(spec.get('state_epoch', 1)), 'layout': lay_out,
        'units': unit_names,
        'health_units': [f'bloch-bridge-{lay["inst"]}-health.service', f'bloch-bridge-{lay["inst"]}-health.timer'],
        'credentials': spec.get('credentials', []),
        'configs': sorted(configs),
        'extra_dirs': [{**d, 'path': subst(d['path'], lay, role, set(names))} for d in spec.get('extra_dirs', [])],
        'heartbeats': [{**h, 'file': subst(h['file'], lay, role, set(names))} for h in spec.get('heartbeats', [])],
        'preflight': [subst(a, lay, role, set(names)) for a in spec.get('preflight', [])], 'preflight_unit': preflight_unit,
        'preflight_ok_codes': spec.get('preflight_ok_codes', [0]),
        'requires': spec.get('requires', []), 'ports': spec.get('ports', {}), 'host': spec.get('host', {}),
        'files': {p: {'sha256': hashlib.sha256(d).hexdigest(), 'mode': f'{mo:04o}'} for p, (d, mo) in sorted(files.items())},
    }
    return files, manifest


def tar_bytes(files, manifest):
    """Deterministic: sorted entries, fixed owner and time, gzip without name or time."""
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode='w', format=tarfile.PAX_FORMAT) as tar:
        entries = dict(files)
        entries['MANIFEST.json'] = ((json.dumps(manifest, indent=1, sort_keys=True) + '\n').encode(), 0o644)
        dirs = set()
        for p in entries:
            parts = PurePosixPath(p).parts[:-1]
            for i in range(1, len(parts) + 1):
                dirs.add('/'.join(parts[:i]))
        for p in sorted(dirs | set(entries)):
            info = tarfile.TarInfo(p)
            info.mtime, info.uid, info.gid, info.uname, info.gname = 0, 0, 0, 'root', 'root'
            if p in entries:
                data, mode = entries[p]
                info.size, info.mode, info.type = len(data), mode, tarfile.REGTYPE
                tar.addfile(info, io.BytesIO(data))
            else:
                info.mode, info.type = 0o755, tarfile.DIRTYPE
                tar.addfile(info)
    out = io.BytesIO()
    with gzip.GzipFile(filename='', mode='wb', fileobj=out, mtime=0, compresslevel=9) as gz:
        gz.write(raw.getvalue())
    return out.getvalue()


def bundle_name(manifest):
    ops = manifest['ops_rev'][:12] if manifest['ops_rev'] != 'worktree' else 'worktree'
    return f'bloch-bridge-{manifest["inst"]}-{manifest["source_rev"][:12]}-{ops}.tar.gz'


def build(route, role, out_dir, src_rev=None, ops_rev='HEAD', worktree_ops=False):
    files, manifest = assemble(route, role, src_rev, ops_rev, worktree_ops)
    data = tar_bytes(files, manifest)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    path = out / bundle_name(manifest)
    path.write_bytes(data)
    digest = hashlib.sha256(data).hexdigest()
    (out / (path.name + '.sha256')).write_text(f'{digest}  {path.name}\n')
    return path, digest, manifest


def render(route, role, out_dir, src_rev=None, ops_rev='HEAD', worktree_ops=False):
    files, manifest = assemble(route, role, src_rev, ops_rev, worktree_ops)
    out = Path(out_dir)
    for p, (data, mode) in files.items():
        if p.startswith(('units/', 'etc/')):
            q = out / p
            q.parent.mkdir(parents=True, exist_ok=True)
            q.write_bytes(data)
    (out / 'MANIFEST.json').write_text(json.dumps(manifest, indent=1, sort_keys=True) + '\n')
    return out


def opt(args, name, default=None):
    if name in args:
        return args[args.index(name) + 1]
    return default


def main(argv):
    if not argv or argv[0] not in ('list', 'build', 'render', 'lint'):
        raise SystemExit(__doc__)
    worktree = '--worktree-ops' in argv
    ops_rev = opt(argv, '--ops-rev', 'HEAD')
    m = load_manifest('worktree' if worktree else rev_parse(ops_rev))
    if argv[0] == 'list':
        for route, r in m['routes'].items():
            print(f'{route:14} {r["launch_status"][:60]:60} roles: {", ".join(r["roles"])}')
        return 0
    if argv[0] == 'lint':
        revs = dict(x.split('=', 1) for x in [argv[i + 1] for i, a in enumerate(argv) if a == '--rev-of'])
        bad = 0
        for route, r in m['routes'].items():
            for role in r['roles']:
                try:
                    assemble(route, role, revs.get(route), ops_rev, worktree)
                    print(f'OK   {route}-{role}')
                except BuildError as e:
                    bad += 1
                    print(f'FAIL {route}-{role}: {e}')
        return 1 if bad else 0
    route, role, out = opt(argv, '--route'), opt(argv, '--role'), opt(argv, '--out')
    if not (route and role and out):
        raise SystemExit(__doc__)
    try:
        if argv[0] == 'build':
            path, digest, manifest = build(route, role, out, opt(argv, '--rev'), ops_rev, worktree)
            print(json.dumps({'bundle': str(path), 'sha256': digest, 'source_rev': manifest['source_rev'],
                              'ops_rev': manifest['ops_rev'], 'files': len(manifest['files'])}, indent=1))
        else:
            print(render(route, role, out, opt(argv, '--rev'), ops_rev, worktree))
    except BuildError as e:
        print(f'refused: {e}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
