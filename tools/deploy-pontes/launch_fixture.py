"""Agent 194 (round 10): fixtures for the offline tests of the owner's bridge V3 launch decisions of 2026-11-02.

`filled()` is deployments/mainnet/busdc-mainnet.config.json with every undecided or committed value replaced by a
throwaway one, so a refusal in a test names the rule under test and nothing else. `filled_vault()` does the same for
busdc-vault-mainnet.config.json, with vault guardians that match the token config's ethereum.vaultGuard.
"""
import copy
import json
import os
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
TOKEN_CFG = ROOT / 'deployments/mainnet/busdc-mainnet.config.json'
VAULT_CFG = ROOT / 'deployments/mainnet/busdc-vault-mainnet.config.json'
WGNB_CFG = ROOT / 'deployments/mainnet/wgnb-mainnet.config.json'


def fresh(i):
    """A throwaway address that no config ever committed."""
    return '0x' + format(0xF194_0000 + i, '040x')


def filled():
    cfg = json.loads(TOKEN_CFG.read_text())
    cfg['source']['revision'] = '1' * 40
    cfg['deployer']['address'] = fresh(1)
    cfg['deployer']['fundedBy']['safe'] = fresh(2)
    cfg['signers']['set'] = [{'operator': f'op{i}', 'address': fresh(10 + i)} for i in range(7)]
    cfg['guardians']['set'] = [{'operator': f'guard{i}', 'address': fresh(20 + i)} for i in range(3)]
    eth = cfg['ethereum']
    eth.update(vault=fresh(30), route='0x' + '7e' * 32, vaultCodeHash='0x' + 'c0' * 32, vaultCap=cfg['limits']['supplyCap'])
    eth['vaultGuard']['guardians'] = sorted((fresh(40 + i) for i in range(3)), key=lambda a: int(a, 16))
    cfg['tx']['maxGasPriceWei'] = 10**9
    return cfg


def filled_vault(token_cfg):
    cfg = json.loads(VAULT_CFG.read_text())
    cfg['source']['revision'] = '1' * 40
    cfg['deployer']['address'] = fresh(3)
    cfg['deployer']['fundedBy']['safe'] = fresh(2)
    v = cfg['vault']
    v['signers']['set'] = [{'operator': f'rel{i}', 'address': fresh(50 + i)} for i in range(7)]
    v['guard']['guardians'] = [{'operator': f'guard{i}', 'address': a}
                               for i, a in enumerate(token_cfg['ethereum']['vaultGuard']['guardians'])]
    v['provenance']['fees']['recipient'] = fresh(70)  # stand-in protocol treasury (agent 197)
    return cfg


def rehearsal(cfg):
    cfg = copy.deepcopy(cfg)
    cfg['network'].update(name='bloch-l2-local-rehearsal', chainId=31337, rehearsal=True)
    return cfg


def private_retired():
    """The 22 retired addresses from the private list, or [] where it is absent. The list is never committed: the tools
    hold sha256 digests only (legacy_digests.py). BLOCH_RETIRED_ADDRESSES_FILE names a file of addresses; the default
    is the `[retired-address]` section of the private publish denylist (BLOCH_PUBLISH_DENYLIST or its default path)."""
    named = os.environ.get('BLOCH_RETIRED_ADDRESSES_FILE')
    path = Path(named or os.environ.get('BLOCH_PUBLISH_DENYLIST') or Path.home() / '.config/bloch-publish-safety/denylist.conf')
    if not path.is_file():
        return []
    text = path.read_text()
    if not named:
        m = re.search(r'^\[retired-address\]\n(.*?)(?=^\[|\Z)', text, re.M | re.S)
        text = m.group(1) if m else ''
    return sorted({a.lower() for a in re.findall(r'0x[0-9a-fA-F]{40}', text)})


def stand_in_retired(n=3):
    """Throwaway addresses and the BLOCH_BRIDGE_REFUSE_SHA256 value that makes the tools refuse them like a retired one."""
    import legacy_digests
    addrs = [fresh(0x900 + i) for i in range(n)]
    return addrs, ','.join(legacy_digests.address_digest(a) for a in addrs)
