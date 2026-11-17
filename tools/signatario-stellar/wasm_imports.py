#!/usr/bin/env python3
"""Lists the host functions a Soroban contract Wasm imports, and fails if it can replace its own code or deploy code.

  wasm_imports.py VAULT.wasm ENV.json

A Soroban contract's code is replaced only when the contract itself calls the host function
`update_current_contract_wasm`; nothing outside the contract can do it. So a Wasm that does not import that function
has no upgrade path. `ENV.json` is the host interface table shipped with the SDK the Wasm was built with
(`soroban-env-common-<version>/env.json` in the cargo registry); it maps the short import names to function names.
Prints the imports and the Wasm's SHA-256 (the hash the network stores it under). Exit 1 if the Wasm imports
`update_current_contract_wasm`, `create_contract`, `create_contract_with_constructor`, `upload_wasm` or any function
the table does not know.
"""
import hashlib
import json
import sys

FORBIDDEN = ('update_current_contract_wasm', 'create_contract', 'create_contract_with_constructor', 'upload_wasm',
             'create_asset_contract')


def leb(b, i):
    r = s = 0
    while True:
        c = b[i]
        i += 1
        r |= (c & 0x7f) << s
        s += 7
        if c < 0x80:
            return r, i


def imports(wasm):
    if wasm[:8] != b'\0asm\x01\0\0\0':
        raise SystemExit('not a Wasm module')
    i, out = 8, []
    while i < len(wasm):
        sid = wasm[i]
        size, i = leb(wasm, i + 1)
        end = i + size
        if sid == 2:
            n, j = leb(wasm, i)
            for _ in range(n):
                l, j = leb(wasm, j)
                mod = wasm[j:j + l].decode()
                j += l
                l, j = leb(wasm, j)
                field = wasm[j:j + l].decode()
                j += l
                kind = wasm[j]
                j += 1
                if kind != 0:
                    raise SystemExit(f'the module imports something that is not a function: {mod}.{field}')
                _, j = leb(wasm, j)
                out.append((mod, field))
        i = end
    return out


def main():
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    wasm = open(sys.argv[1], 'rb').read()
    table = {}
    for m in json.load(open(sys.argv[2]))['modules']:
        for f in m['functions']:
            table[(m['export'], f['export'])] = (m['name'], f['name'])
    used = imports(wasm)
    unknown = [x for x in used if x not in table]
    names = sorted(table[x] for x in used if x in table)
    bad = [f for _, f in names if f in FORBIDDEN]
    print(json.dumps({'sha256': hashlib.sha256(wasm).hexdigest(), 'bytes': len(wasm), 'imports': [f'{m}.{f}' for m, f in names],
                      'unknown': unknown, 'forbidden': bad, 'ok': not bad and not unknown}, indent=2))
    raise SystemExit(1 if bad or unknown else 0)


if __name__ == '__main__':
    main()
