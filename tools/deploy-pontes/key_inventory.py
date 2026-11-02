#!/usr/bin/env python3
"""Key inventory for the bUSDC bridge V3 key ceremony (docs/BRIDGE-V3-KEY-CEREMONY.md).

Offline. It holds only public data: role, operator, address, custody class and a proof-of-possession signature.
It never reads a key, a keystore or a password.

  message   prints the exact text an operator signs for one key (`cast wallet sign`, EIP-191 personal message).
  check     refuses unless the inventory is complete and consistent:
              - role counts: 7 L2 mint signers, 7 Ethereum release signers, 3 L2 token guardians,
                3 Ethereum vault guardians, 1 vault deployer, 1 L2 token deployer, at least 1 relayer gas key per chain;
              - every address appears once, across all roles (no key holds two roles, mint != release);
              - no committed legacy address (the 2026-10-14 deployers, signers and guardians), unless named with
                --allow-legacy-address after the operators confirm they generated and still hold that key;
              - guardian operators run no signer; one key per operator per role;
              - the custody class allowed for each role;
              - each attestation verifies against its address (`cast wallet verify`), except contract accounts;
              - with --token-config / --vault-config: the deploy configs list exactly the inventory's addresses and
                operators for each role, the deployers and the Safe.

Usage:
  key_inventory.py message --role ROLE --index N --operator NAME --address 0x.. --date YYYY-MM-DD
  key_inventory.py check --inventory FILE [--token-config FILE] [--vault-config FILE] [--allow-legacy-address 0x..]...
                         [--skip-signatures]

FOUNDRY_BIN selects the directory of `cast` (default ~/.foundry/bin).
"""
import json
import os
from pathlib import Path
import re
import subprocess
import sys

DOMAIN = 'bloch.bridge.key-inventory.v1'
FOUNDRY = Path(os.environ.get('FOUNDRY_BIN', str(Path.home() / '.foundry/bin')))
CAST = str(FOUNDRY / 'cast')

# role: (min count, max count, allowed custody classes, contract account (no attestation))
ROLES = {
    'l2-mint-signer': (7, 7, {'hot-keystore'}, False),
    'eth-release-signer': (7, 7, {'hot-keystore'}, False),
    'l2-token-guardian': (3, 3, {'hot-keystore'}, False),
    'eth-vault-guardian': (3, 3, {'hot-keystore'}, False),
    'eth-vault-deployer': (1, 1, {'hardware-wallet', 'air-gapped-keystore'}, False),
    'l2-token-deployer': (1, 1, {'hardware-wallet', 'air-gapped-keystore'}, False),
    'l2-relayer-gas': (1, 7, {'hot-keystore'}, False),
    'eth-relayer-gas': (1, 7, {'hot-keystore'}, False),
    'bloch-inc-safe': (1, 1, {'safe'}, True),
    'bloch-inc-safe-owner': (0, 16, {'hardware-wallet'}, False),
    'recovery-authority': (0, 1, {'safe'}, True),
    'recovery-authority-owner': (0, 16, {'hardware-wallet'}, False),
}
SIGNER_ROLES = ('l2-mint-signer', 'eth-release-signer')
GUARDIAN_ROLES = ('l2-token-guardian', 'eth-vault-guardian')
HOT_ROLES = SIGNER_ROLES + GUARDIAN_ROLES + ('l2-relayer-gas', 'eth-relayer-gas')
COLD_ROLES = ('bloch-inc-safe-owner', 'recovery-authority-owner', 'recovery-authority')

# Committed to deployments/mainnet/*.config.json on 2026-10-14 (commits d3f8a1f, 0315afd). Who holds these keys is not
# recorded, and they were generated in one place, so a threshold over them means nothing. Never reuse them by default.
LEGACY = {a.lower() for a in (
    '0x703a12b45fa13892ED8D03995218b2ea9D7f0F3b', '0xa64b47b03d5F1a7a961fE98597c01E471D4b504A',
    '0xa981e9A6fbb32626c6dd56b167860BCc7496E441', '0x181d1331163F9486C8153B38d7C4A43F18CEfDe9',
    '0x5bDB78421B38494040fcb504F79c99CD411Ea3a0', '0x91EC58A2aCf42Ac2FF1B592D8fD37033C2Bdc82D',
    '0x494856914ACC0f370A17227A51B830ADbF3A7E60', '0x811f46cc76c71f045c0291bA4aCf46080322AaE9',
    '0x3D800a0023b8CA3284b0D13513661F36A96B0A63', '0xDb5Ef90964ED561bF592D88a065e5f61248cc375',
    '0xC8578A95df5c948a5F09844Bf3A75F7Aa4fCd6e7', '0xB473Fa954CAB70a2132263f8b78FAbF236103c90',
    '0xb908e883581Ca4beE5061DaFc479B59A1Aa42741', '0x38b887B1f00fA03A7924F222110c1b096e236783',
    '0x372e8A729B67842E135E517dA9E9A1AE05B48522', '0x35b1d46862D43b454DeB145FFa7B44B8fa46CEA8',
    '0x39fbD26d0864E710E107d96CF1c97f7697DA9838', '0xc4552D49cA8E94960b43A95e3Df64a22C8d86cCA',
    '0x80403e894B6D06f18a32040B3D4b80812584D726', '0x399849A60901965C3787172598bD2eEBCb72faad',
    '0x3F6043Ae9BB695463A67751c8083E329B60BF6e8', '0xdCC271d790FC2a6140B30A962E6d6FEbd0d72F1F',
)}


class Refused(Exception):
    pass


def refuse(cond, message):
    if not cond:
        raise Refused(message)


def is_addr(v):
    return isinstance(v, str) and re.fullmatch(r'0x[0-9a-fA-F]{40}', v) is not None


def message(role, index, operator, address, date):
    refuse(role in ROLES, f'unknown role {role}')
    refuse(isinstance(index, int) and index >= 1, 'index must be 1 or more')
    refuse(isinstance(operator, str) and re.fullmatch(r'[A-Za-z0-9._-]{1,64}', operator or ''),
           'operator must be 1..64 of [A-Za-z0-9._-]')
    refuse(is_addr(address), 'address must be 0x + 40 hex')
    refuse(isinstance(date, str) and re.fullmatch(r'\d{4}-\d{2}-\d{2}', date), 'date must be YYYY-MM-DD')
    return (f'{DOMAIN} attestation: I generated and hold this key. role={role} index={index} '
            f'operator={operator} address={address.lower()} date={date}')


def verify_sig(address, text, sig):
    refuse(isinstance(sig, str) and re.fullmatch(r'0x[0-9a-fA-F]{130}', sig or ''), f'{address}: attestation missing')
    done = subprocess.run([CAST, 'wallet', 'verify', '--address', address, text, sig], capture_output=True, text=True)
    refuse(done.returncode == 0, f'{address}: attestation does not verify ({done.stderr.strip()[-200:]})')


def check(inv, token_cfg=None, vault_cfg=None, allow_legacy=(), skip_signatures=False):
    refuse(isinstance(inv, dict) and inv.get('domain') == DOMAIN, f'inventory domain must be {DOMAIN}')
    keys = inv.get('keys')
    refuse(isinstance(keys, list) and keys, 'inventory.keys is empty')
    allow = {a.lower() for a in allow_legacy}
    by_role, seen, ops_by_role = {r: [] for r in ROLES}, {}, {r: set() for r in ROLES}
    for i, k in enumerate(keys):
        refuse(isinstance(k, dict) and set(k) == {'role', 'index', 'operator', 'address', 'custody', 'date', 'attestation'},
               f'keys[{i}] must have exactly role, index, operator, address, custody, date, attestation')
        role, addr = k['role'], str(k['address'])
        refuse(role in ROLES, f'keys[{i}]: unknown role {role}')
        text = message(role, k['index'], k['operator'], addr, k['date'])
        a = addr.lower()
        refuse(a not in seen, f'{a} holds two roles ({seen.get(a)} and {role}): one key, one role')
        seen[a] = role
        refuse(a not in LEGACY or a in allow,
               f'{a} ({role}) is a committed 2026-10-14 address; replace it, or name it with --allow-legacy-address '
               'only after its operator confirms generating and holding it')
        refuse(k['custody'] in ROLES[role][2], f'{a}: custody {k["custody"]} not allowed for {role} {sorted(ROLES[role][2])}')
        op = k['operator'].lower()
        refuse(op not in ops_by_role[role], f'operator {op} holds two {role} keys: one key per operator')
        ops_by_role[role].add(op)
        by_role[role].append(k)
        if not ROLES[role][3] and not skip_signatures:
            verify_sig(addr, text, k['attestation'])
    for role, (lo, hi, _, _) in ROLES.items():
        n = len(by_role[role])
        refuse(lo <= n <= hi, f'{role}: {n} keys, policy {lo}..{hi}')
        idx = sorted(k['index'] for k in by_role[role])
        refuse(idx == list(range(1, n + 1)), f'{role}: indexes must be 1..{n}')
    signer_ops = ops_by_role['l2-mint-signer'] | ops_by_role['eth-release-signer']
    refuse(ops_by_role['l2-mint-signer'] == ops_by_role['eth-release-signer'],
           'the 7 release-signer operators must be the 7 mint-signer operators (one mint and one release key each)')
    guard_ops = ops_by_role['l2-token-guardian'] | ops_by_role['eth-vault-guardian']
    refuse(not guard_ops & signer_ops, f'guardian operators also run a signer: {sorted(guard_ops & signer_ops)}')
    cold_ops = set().union(*(ops_by_role[r] for r in COLD_ROLES))
    hot_ops = set().union(*(ops_by_role[r] for r in SIGNER_ROLES + GUARDIAN_ROLES))
    refuse(not (ops_by_role['recovery-authority-owner'] & signer_ops),
           'a recovery-authority owner also runs a signer: the authority must be separate from mint and release keys')
    addrs = lambda r: sorted(k['address'].lower() for k in by_role[r])
    ops = lambda r: {k['address'].lower(): k['operator'].lower() for k in by_role[r]}

    def same(cfg_set, role, where):
        got = {str(s.get('address')).lower(): str(s.get('operator') or '').lower() for s in cfg_set}
        refuse(sorted(got) == addrs(role), f'{where} addresses differ from the inventory {role} keys')
        refuse(got == ops(role), f'{where} operators differ from the inventory {role} operators')

    if token_cfg is not None:
        same(token_cfg['signers']['set'], 'l2-mint-signer', 'token signers.set')
        same(token_cfg['guardians']['set'], 'l2-token-guardian', 'token guardians.set')
        refuse(str(token_cfg['deployer']['address']).lower() == addrs('l2-token-deployer')[0],
               'token deployer.address differs from the inventory l2-token-deployer')
        refuse(str(token_cfg['deployer']['fundedBy']['safe']).lower() == addrs('bloch-inc-safe')[0],
               'token deployer.fundedBy.safe differs from the inventory bloch-inc-safe')
        vg = [str(a).lower() for a in ((token_cfg.get('ethereum') or {}).get('vaultGuard') or {}).get('guardians') or []]
        refuse(vg == addrs('eth-vault-guardian'), 'token ethereum.vaultGuard.guardians differ from the inventory '
               '(ascending eth-vault-guardian addresses)')
    if vault_cfg is not None:
        v = vault_cfg['vault']
        same(v['signers']['set'], 'eth-release-signer', 'vault signers.set')
        same(v['guard']['guardians'], 'eth-vault-guardian', 'vault guard.guardians')
        refuse(str(vault_cfg['deployer']['address']).lower() == addrs('eth-vault-deployer')[0],
               'vault deployer.address differs from the inventory eth-vault-deployer')
        refuse(str(vault_cfg['deployer']['fundedBy']['safe']).lower() == addrs('bloch-inc-safe')[0],
               'vault deployer.fundedBy.safe differs from the inventory bloch-inc-safe')
    return {
        'decision': 'ok',
        'keys': len(keys),
        'roles': {r: len(v) for r, v in by_role.items()},
        'signerOperators': sorted(signer_ops),
        'guardianOperators': sorted(guard_ops),
        'coldOperators': sorted(cold_ops),
        'hotOperatorsAlsoCold': sorted(hot_ops & cold_ops),
        'legacyAllowed': sorted(allow & set(seen)),
        'signaturesChecked': not skip_signatures,
    }


def main(argv):
    def opt(name, many=False):
        vals = [argv[i + 1] for i, a in enumerate(argv[:-1]) if a == name]
        return vals if many else (vals[-1] if vals else None)
    try:
        refuse(argv and argv[0] in ('message', 'check'), 'usage: key_inventory.py message|check ...')
        if argv[0] == 'message':
            idx = opt('--index')
            refuse(idx is not None and idx.isdigit(), '--index is required')
            print(message(opt('--role'), int(idx), opt('--operator'), opt('--address'), opt('--date')))
            return 0
        load = lambda p: json.loads(Path(p).read_text()) if p else None
        refuse(opt('--inventory'), '--inventory is required')
        out = check(load(opt('--inventory')), load(opt('--token-config')), load(opt('--vault-config')),
                    opt('--allow-legacy-address', many=True), '--skip-signatures' in argv)
        print(json.dumps(out, indent=2))
        return 0
    except Refused as e:
        print(json.dumps({'decision': 'refused', 'reason': str(e)}, indent=2))
        return 2


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
