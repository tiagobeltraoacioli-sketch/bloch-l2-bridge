"""When an L2 block is final enough for a bridge signature: the v2 L2 build and the L1 HF1 claim-finality rule.

Used by signatario.py (release). Pure functions over the native follower's status.json, plus two
read-only helpers (binary pins, an optional L1 RPC cross-check). Guardians do not import this module on
purpose (independent code); they apply the same rule from their own RPC.

The v2 L2 build (bloch-l2-evm 1aad0a20, native 78d4921c) pins:
  follower     bloch-l2-native-follower  c18752fd...  writes status schema bloch.l2.native-follower-status.v2
  produce      bloch-l2-produce-dev      7c1cc62b...  `reconstruct` rebuilds the L2 from the follower's L1 blocks
  settled RPC  bloch-l2-settled-rpc      4fc9fa1e...  serves `finalized` only from a verified status
  chain 700770, native network f47d3e49..., L2 genesis 632e45ae...

HF1 claim finality (native params HF1_CLAIM_FINALITY_EPOCH = 7180; transition/l2_claim.rs
`l2_record_finalized_for_claim`): an L1 claim against an L2 settlement needs
  (a) the settlement's accepting native block inside the FFG-finalized prefix (`record_finalized`: its slot
      below finalized_epoch * SLOTS_PER_EPOCH), and
  (b) once the rule is active, the finalized checkpoint to be this chain's own (CHECKPOINT-ROOTS:
      `checkpoint_root(finalized.epoch) == finalized.root`). Own roots are recorded only from the gate
      epoch, so right after it nothing is claimable until a checkpoint of epoch >= gate finalizes
      (about 2 epochs, ~32 min).
A bridge signer applies the same predicate to the L2 block holding a burn:
  - the burn's L2 block is covered by a settlement in the follower's finalized list (settled + finalized);
  - that settlement's native slot is below native_finalized_epoch * SLOTS_PER_EPOCH;
  - the follower replays FFG on its own chain and only reports a finalized checkpoint that is its own
    chain's block at that epoch (condition (b) by construction);
  - from the gate on (by wall clock or by the follower's verified slot) the follower's finalized epoch
    must be >= the gate: the one-time claim-finality pause applies to bridge signatures too;
  - optionally, the signer's own L1 RPCs must not report a finalized checkpoint that is not their own
    (`getl2settlement.withdrawals.finalized_checkpoint`, own_root != root while own_chain_rule_active).
"""
import hashlib
import json
from pathlib import Path
import urllib.request

SLOTS_PER_EPOCH = 32  # bloch-pos-committee params (mainnet: 30 s slots, 960 s epochs)
EPOCH_SECONDS = 960
STATUS_SCHEMA_V2 = 'bloch.l2.native-follower-status.v2'

# PROVISIONAL: `binaries.settled_rpc` below is the v2 build. The owner decided on one v2.1 rebuild of settled-rpc (the
# spool-dos and receipt/latest fixes); replace this hash with the released v2.1 hash and set the flag to False.
# Nothing else in this table depends on that build. Do not deploy signers while this is True.
SETTLED_RPC_PIN_PROVISIONAL = True

MAINNET_V2 = {
    'name': 'bloch-l2-mainnet-v2 (L2 1aad0a20 / native 78d4921c)',
    'l2_chain_id': 700770,
    'network_pin': 'f47d3e498ff978e34471dafff5f94fe139fc3ff489b1a00f469c030258311966',
    'l2_genesis_hash': '632e45ae778da371a88dc1ae430193aa77eabb67a11de18e84fea7d20d11f468',
    'l1_genesis_time': 1786656679,
    'hf1_claim_finality_epoch': 7180,
    'timestamp_rule': '1:1786656679:30000',
    'l2_network_args': ['--rules', 'mainnet', '--domain',
                        '1c3f8772d0bdfc22f33efce250a4f471343587859f815f083cfee69d3b6f0733',
                        '--genesis-time', '1786656679'],
    'binaries': {
        'follower': 'c18752fd4c6942678bcb45d8d36436bcd644b1ee6e48416d67e4999e7c7cf29a',
        'produce': '7c1cc62bf5fb5aa142dced01156e3a51ddb6239096034400558ef46586025a3c',
        # PROVISIONAL, see SETTLED_RPC_PIN_PROVISIONAL.
        'settled_rpc': '4fc9fa1ecc2b75dec8c918e77cefb81fe7fc216c5baead133e17c15fc4c54534',
    },
}
PIN_KEYS = ('l2_chain_id', 'network_pin', 'l2_genesis_hash', 'l1_genesis_time', 'hf1_claim_finality_epoch',
            'timestamp_rule', 'l2_network_args', 'binaries')


class NotFinal(Exception):
    """The L2 block is not final under the rules (or the inputs cannot show it). args: (reason, detail)."""

    def __init__(self, reason, **detail):
        super().__init__(reason)
        self.reason, self.detail = reason, detail


def pins_from_config(cfg):
    """`l2_pins`: "mainnet-v2" (the constants above) or a full object (rehearsals). None: legacy devnet mode."""
    raw = cfg.get('l2_pins')
    if raw is None:
        return None
    if raw == 'mainnet-v2':
        pins = dict(MAINNET_V2)
    elif isinstance(raw, dict):
        missing = [k for k in PIN_KEYS if k not in raw]
        if missing:
            raise NotFinal('l2_pins is missing keys', missing=missing)
        pins = dict(raw)
    else:
        raise NotFinal('l2_pins must be "mainnet-v2" or an object', got=raw)
    if int(cfg['l2_chain_id']) != int(pins['l2_chain_id']):
        raise NotFinal('l2_chain_id differs from the L2 pins', config=cfg['l2_chain_id'], pins=pins['l2_chain_id'])
    return pins


def strip0x(h):
    return str(h or '').lower().removeprefix('0x')


def epoch_of_slot(slot):
    return int(slot) // SLOTS_PER_EPOCH


def wall_epoch(now, genesis_time):
    return max(0, (int(now) - int(genesis_time)) // EPOCH_SECONDS)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def check_binaries(paths, pins):
    """Every L2 binary the signer runs must be the pinned v2 build (by SHA-256)."""
    for role, want in pins['binaries'].items():
        path = paths.get(role)
        if not path:
            raise NotFinal(f'no path configured for the pinned {role} binary')
        got = sha256_file(path)
        if got != strip0x(want):
            raise NotFinal(f'the {role} binary is not the pinned v2 build', path=str(path), sha256=got,
                           pinned=strip0x(want))


def check_status(status, pins, now, max_age):
    """The follower status is the v2 schema, for the pinned network, chain and L2 genesis, fresh and coherent."""
    if status.get('schema') != STATUS_SCHEMA_V2:
        raise NotFinal('the follower status is not the v2 schema (old follower build?)', schema=status.get('schema'))
    if strip0x(status.get('network')) != strip0x(pins['network_pin']):
        raise NotFinal('the follower verifies another network', follower=status.get('network'),
                       pinned=pins['network_pin'])
    if status.get('chain_id') != int(pins['l2_chain_id']):
        raise NotFinal('the follower status is for another L2 chain', follower=status.get('chain_id'),
                       pinned=pins['l2_chain_id'])
    if status.get('production_finality') is not False:
        raise NotFinal('the follower status claims production finality (not a native replay status)')
    age = int(now) - int(status.get('written_at_unix', 0))
    if age > int(max_age):
        raise NotFinal(f'the follower status is {age} s old (stalled follower)')
    genesis = status.get('l2_genesis') or {}
    if strip0x(genesis.get('hash')) != strip0x(pins['l2_genesis_hash']) or genesis.get('finalized') is not True:
        raise NotFinal('the pinned L2 genesis is not final on the follower', l2_genesis=genesis or None)
    fin_epoch = status.get('native_finalized_epoch')
    fin_slot = status.get('native_finalized_slot')
    if not isinstance(fin_epoch, int) or not isinstance(fin_slot, int) or fin_slot >= fin_epoch * SLOTS_PER_EPOCH:
        raise NotFinal('the follower finalized checkpoint is incoherent (slot not below its epoch boundary)',
                       epoch=fin_epoch, slot=fin_slot)
    verified_slot = status.get('verified_slot')
    if not isinstance(verified_slot, int) or verified_slot < fin_slot:
        raise NotFinal('the follower verified slot is below its finalized slot', verified_slot=verified_slot,
                       finalized_slot=fin_slot)
    expected = 1
    for s in status.get('finalized_settlements') or []:
        if s.get('l2_number') != expected:
            raise NotFinal('the finalized settlements are not contiguous from L2 block 1', at=s.get('l2_number'),
                           expected=expected)
        expected += 1
        slot = s.get('native_slot')
        if not isinstance(slot, int) or slot >= fin_epoch * SLOTS_PER_EPOCH:
            raise NotFinal('a finalized settlement lies outside the finalized native prefix',
                           l2_number=s.get('l2_number'), native_slot=slot, finalized_epoch=fin_epoch)
    return status


def claim_finality(status, pins, now):
    """The HF1 claim-finality view of this status: active, paused (no signature) and why."""
    gate = int(pins['hf1_claim_finality_epoch'])
    by_clock = wall_epoch(now, pins['l1_genesis_time'])
    by_chain = epoch_of_slot(status['verified_slot'])
    fin_epoch = int(status['native_finalized_epoch'])
    active = max(by_clock, by_chain) >= gate
    return {'gate_epoch': gate, 'wall_epoch': by_clock, 'verified_epoch': by_chain,
            'finalized_epoch': fin_epoch, 'active': active, 'paused': active and fin_epoch < gate}


def require_claim_final(status, pins, now):
    cf = claim_finality(status, pins, now)
    if cf['paused']:
        raise NotFinal('HF1 claim-finality pause: no checkpoint of epoch >= the gate is finalized yet; '
                       'own checkpoint roots are recorded only from the gate (retry in about 2 epochs)', **cf)
    return cf


def covering_settlement(status, l2_number):
    """The first finalized settlement that settles L2 block `l2_number` (settlements are contiguous)."""
    for s in status.get('finalized_settlements') or []:
        if s['l2_number'] >= l2_number:
            return s
    return None


def require_settled_final(status, pins, now, l2_number, l2_hash):
    """The L2 block (number, hash) is settled and finalized under the HF1 rules. Returns the facts."""
    cf = require_claim_final(status, pins, now)
    s = covering_settlement(status, l2_number)
    if s is None:
        last = (status.get('finalized_settlements') or [{}])[-1].get('l2_number', 0)
        raise NotFinal('the burn block is not covered by a finalized settlement yet', burn_block=l2_number,
                       last_finalized_settlement=last)
    if s['l2_number'] == l2_number and strip0x(s.get('l2_hash')) != strip0x(l2_hash):
        raise NotFinal('the burn block hash differs from the finalized settlement', burn_block=l2_number,
                       block_hash=l2_hash, settled=s.get('l2_hash'))
    return {'claim_finality': cf,
            'settlement': {k: s.get(k) for k in ('l2_number', 'l2_hash', 'native_slot', 'native_block', 'commitment')},
            'native_finalized': {'epoch': status['native_finalized_epoch'], 'slot': status['native_finalized_slot'],
                                 'block': status.get('native_finalized_block')}}


def check_rebuild(report, status, pins):
    """`produce reconstruct` output: the pinned L2 genesis, and every finalized settlement rebuilt identically."""
    if strip0x(report.get('genesis')) != strip0x(pins['l2_genesis_hash']):
        raise NotFinal('the rebuilt L2 genesis differs from the pin', rebuilt=report.get('genesis'),
                       pinned=pins['l2_genesis_hash'])
    blocks = report.get('blocks')
    if not isinstance(blocks, list):
        raise NotFinal('the reconstruct report has no block list (not the v2 producer?)')
    rebuilt = {b.get('number'): b for b in blocks}
    for s in status.get('finalized_settlements') or []:
        b = rebuilt.get(s['l2_number'])
        if b is None or (strip0x(b.get('hash')), strip0x(b.get('state_root'))) != (strip0x(s.get('l2_hash')),
                                                                                    strip0x(s.get('l2_state_root'))):
            raise NotFinal('an L2 block rebuilt from L1 differs from its finalized settlement',
                           l2_number=s['l2_number'], rebuilt=b, settled={k: s.get(k) for k in ('l2_hash',
                                                                                               'l2_state_root')})


def l1_rpc(url, method, params=(), timeout=30):
    body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': list(params)}).encode()
    req = urllib.request.Request(url, body, {'content-type': 'application/json'})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        out = json.loads(r.read(16_000_000))
    if 'result' not in out:
        raise ValueError(f'{method}: {out.get("error")}')
    return out['result']


def l1_cross_check(urls, pins, now, fetch=l1_rpc):
    """Each configured L1 RPC of the signer: same network and chain; no foreign finalized checkpoint under the
    own-chain rule; from the gate on, an HF1 node (it reports finalized_checkpoint). Read-only."""
    seen = []
    for url in urls or []:
        try:
            view = fetch(url, 'getl2settlement')
        except (OSError, ValueError) as e:
            raise NotFinal('an L1 RPC of this signer is unreachable', url=url, error=str(e)) from None
        if strip0x(view.get('network')) != strip0x(pins['network_pin']) or view.get('chain_id') != int(pins['l2_chain_id']):
            raise NotFinal('an L1 RPC follows another network or L2 chain', url=url, network=view.get('network'),
                           chain_id=view.get('chain_id'))
        fc = (view.get('withdrawals') or {}).get('finalized_checkpoint')
        if fc is None:
            if wall_epoch(now, pins['l1_genesis_time']) >= int(pins['hf1_claim_finality_epoch']):
                raise NotFinal('an L1 RPC does not report finalized_checkpoint after the HF1 gate (not an HF1 node)',
                               url=url)
            seen.append({'url': url, 'finalized_checkpoint': None})
            continue
        if fc.get('own_chain_rule_active') and strip0x(fc.get('own_root')) != strip0x(fc.get('root')):
            raise NotFinal("an L1 RPC's finalized checkpoint is not its own chain's (own_root != root): "
                           'claims are unsafe there', url=url, finalized_checkpoint=fc)
        seen.append({'url': url, 'finalized_checkpoint': fc})
    return seen


def legacy_network(genesis_path):
    """Devnet followers (no pins): the network id is sha3-256 of the genesis file."""
    return hashlib.sha3_256(Path(genesis_path).read_bytes()).hexdigest()
