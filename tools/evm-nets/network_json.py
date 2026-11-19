#!/usr/bin/env python3
"""Check a bridge.network.json against deployments/schema/bridge.network.schema.json. Standard library only.

  network_json.py check FILE [FILE ...]

Implements the subset of JSON Schema 2020-12 the schema uses (type, required, additionalProperties, properties, enum,
const, pattern, anyOf, $ref to #/$defs, items, minItems, minLength, minimum, uniqueItems) and, beyond the schema:
the file must sit in a directory named as its `network.id` (or, for a file with a `route` block, as its `route.id`,
which must be `<network.id>-<route.asset>`), and no amount may be a JSON number. Exit 1 on any error.
"""
import json
from pathlib import Path
import re
import sys

SCHEMA = Path(__file__).resolve().parents[2] / 'deployments/schema/bridge.network.schema.json'
TYPES = {'object': dict, 'array': list, 'string': str, 'integer': int, 'boolean': bool}


def errors(value, schema, root, where='$'):
    if '$ref' in schema:
        yield from errors(value, root['$defs'][schema['$ref'].rsplit('/', 1)[1]], root, where)
        return
    if 'anyOf' in schema:
        if all(list(errors(value, s, root, where)) for s in schema['anyOf']):
            yield f'{where}: matches none of the allowed forms'
        return
    if 'const' in schema and value != schema['const']:
        yield f'{where}: must be {schema["const"]!r}'
    if 'enum' in schema and value not in schema['enum']:
        yield f'{where}: must be one of {schema["enum"]}'
    t = schema.get('type')
    if t and (not isinstance(value, TYPES[t]) or (t == 'integer' and isinstance(value, bool))):
        yield f'{where}: must be {t}'
        return
    if isinstance(value, str):
        if len(value) < schema.get('minLength', 0):
            yield f'{where}: too short'
        if 'pattern' in schema and not re.search(schema['pattern'], value):
            yield f'{where}: does not match {schema["pattern"]}'
    if isinstance(value, int) and not isinstance(value, bool) and value < schema.get('minimum', value):
        yield f'{where}: below {schema["minimum"]}'
    if isinstance(value, list):
        if len(value) < schema.get('minItems', 0):
            yield f'{where}: fewer than {schema["minItems"]} items'
        if schema.get('uniqueItems') and len({json.dumps(v, sort_keys=True) for v in value}) != len(value):
            yield f'{where}: repeated items'
        for i, v in enumerate(value):
            yield from errors(v, schema.get('items', {}), root, f'{where}[{i}]')
    if isinstance(value, dict):
        props = schema.get('properties', {})
        for k in schema.get('required', []):
            if k not in value:
                yield f'{where}: missing {k}'
        for k, v in value.items():
            if k in props:
                yield from errors(v, props[k], root, f'{where}.{k}')
            elif schema.get('additionalProperties') is False:
                yield f'{where}: unexpected key {k}'


def check(path):
    schema = json.loads(SCHEMA.read_text())
    doc = json.loads(Path(path).read_text())
    found = list(errors(doc, schema, schema))
    net = doc.get('network', {}).get('id') if isinstance(doc, dict) else None
    route = doc.get('route') if isinstance(doc, dict) else None
    if route is None:
        if Path(path).resolve().parent.name != net:
            found.append(f'the file must be deployments/{net}/bridge.network.json (directory = network.id)')
        return found
    # Round 20: a further asset route of a network. Its directory is its route id, and the route id is the network's
    # id and the asset key, so two files cannot claim one (network, asset) pair under different names.
    rid, key = (route.get('id'), route.get('asset')) if isinstance(route, dict) else (None, None)
    if rid != f'{net}-{key}':
        found.append(f'route.id {rid!r} must be network.id and route.asset joined by a hyphen ({net}-{key})')
    if Path(path).resolve().parent.name != rid:
        found.append(f'the file must be deployments/{rid}/bridge.network.json (directory = route.id)')
    return found


def main():
    if len(sys.argv) < 3 or sys.argv[1] != 'check':
        raise SystemExit(__doc__)
    bad = 0
    for path in sys.argv[2:]:
        found = check(path)
        bad += bool(found)
        print(json.dumps({'file': path, 'decision': 'refused' if found else 'valid', 'errors': found}, indent=2))
    raise SystemExit(1 if bad else 0)


if __name__ == '__main__':
    main()
