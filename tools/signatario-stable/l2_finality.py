"""When an L2 block is final enough for a bridge signature: the v2 L2 build and the L1 HF1 claim-finality rule.

Used by signatario.py (release). Pure functions over the native follower's status.json, plus two
read-only helpers (binary pins, an optional L1 RPC cross-check). Guardians do not import this module on
purpose (independent code); they apply the same rule from their own RPC.

The L2 deposit-only launch build (release bloch-l2-2026-11-03-next-native-78d4921c,
bloch-l2-evm 926d2cf, native 78d4921c, release SHA256SUMS 6d3bd628...) pins:
  follower     bloch-l2-native-follower  cdf5da5c...  writes status schema bloch.l2.native-follower-status.v2 or v3
  produce      bloch-l2-produce-dev      e3f1a290...  `reconstruct` rebuilds the L2 from the follower's L1 blocks
  settled RPC  bloch-l2-settled-rpc      53e88565...  serves `finalized` only from a verified status
  chain 700770, native network f47d3e49..., L2 genesis 632e45ae...

Round 20 (agent 421, finding F410-2). The L2 did NOT go live with that build: the owner signed the release
bloch-l2-2026-11-17-launch-native-906336fd on 2026-11-17 (bloch-l2-evm 3d35a0f, native 906336fd, release SHA256SUMS
4039f26a...) and the first L2 settlement was accepted on L1 on 2026-11-19. The pin set of the live L2 is MAINNET_V3
(`l2_pins: "mainnet-v3"`); MAINNET_V2 is kept unchanged as the record of the 2026-11-03 build and is REFUSED by name
(superseded). A named pin set is usable only when every one of its values states where it was verified at its source
(`verified`); see `named_pins`. MAINNET_V3 also pins what the L1 itself reports about the L2 program (the seven
identities of the accepted settlement statement) and the follower's settlement policy, so that a later L2 program
change makes every signer refuse with a stale-pin reason instead of signing on an old build
(docs/BRIDGE-V3-OPERATOR-RUNBOOK.md, "When the L2 release or program changes"; tools/signatario-stable/l2_pins_check.py).

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
STATUS_SCHEMA_V3 = 'bloch.l2.native-follower-status.v3'

# `binaries` below are the FINAL L2 deposit-only launch build (agents/201-kit-final.md, two-host rebuild at 01:47 UTC
# 2026-11-03): release bloch-l2-2026-11-03-next-native-78d4921c, build commit 926d2cf, byte-identical on 45.77 and 136.
# Its SHA256SUMS, sha256 6d3bd62885ca269e50e85b53c8c378a7d86467680563292e784c6f0459258c19, is the owner's signing target
# and lists exactly these three hashes. They replace the v2.1 pins (c18752fd / fb0d5313 / 18be911a) and the superseded
# launch candidate 17383fe (settled_rpc e5754d05, without the 15M simulation gas cap; its follower and produce are these).
# The flag says whether these hashes may still move: False, they are frozen. Signers install the binaries only from the
# release folder whose SHA256SUMS carries the owner's signature (docs/BUSDC-MAINNET-V2.md 4.6); any other build is
# refused by `check_binaries`.
SETTLED_RPC_PIN_PROVISIONAL = False

MAINNET_V2 = {
    'name': 'bloch-l2-2026-11-03-next-native-78d4921c (L2 926d2cf / native 78d4921c)',
    'l2_chain_id': 700770,
    'network_pin': 'f47d3e498ff978e34471dafff5f94fe139fc3ff489b1a00f469c030258311966',
    'l2_genesis_hash': '632e45ae778da371a88dc1ae430193aa77eabb67a11de18e84fea7d20d11f468',
    'l1_genesis_time': 1786656679,
    'hf1_claim_finality_epoch': 7180,
    'timestamp_rule': '1:1786656679:30000',
    'l2_network_args': ['--rules', 'mainnet', '--domain',
                        '1c3f8772d0bdfc22f33efce250a4f471343587859f815f083cfee69d3b6f0733',
                        '--genesis-time', '1786656679'],
    'binaries': {  # the final launch build, see SETTLED_RPC_PIN_PROVISIONAL
        'follower': 'cdf5da5cb38b12a483fc8822fa22c2b3e90e9e4c7918ec73814f682bc37550b2',
        'produce': 'e3f1a290bf60b65702034fb0bc973ab15d1b05b236145c48880cfd2d0f477f69',
        'settled_rpc': '53e88565c2a322f369c5f07d01fa00b11e1ef56fdb7b58c9e7af88c685eabb0d',
    },
}
PIN_KEYS = ('l2_chain_id', 'network_pin', 'l2_genesis_hash', 'l1_genesis_time', 'hf1_claim_finality_epoch',
            'timestamp_rule', 'l2_network_args', 'binaries')

# The pin set of the L2 that is LIVE (round 20, agent 421; finding F410-2 of agent 410). Release
# bloch-l2-2026-11-17-launch-native-906336fd, signed by the owner on 2026-11-17 with the Bloch release key
# 1A5D96A5C4955EF7; first L2 settlement accepted on L1 on 2026-11-19 (commitment e8a5ffa7...5705). Against MAINNET_V2
# only the follower and the producer moved (cdf5da5c -> d4d2b99a, e3f1a290 -> 598873ae); the settled RPC, the network,
# the L2 genesis, the L2 domain, the HF1 gate and the timestamp rule are the same values, verified again.
# `verified` says, value by value, where agent 421 verified it AT ITS SOURCE on 2026-11-19 (the report
# agents/421-bridge-repin-r20.md holds the readings). A value that was only quoted from a report must be written
# 'UNVERIFIED: ...' (or left out): `named_pins` then refuses the whole set, on every tool.
SIGNED = ('the SHA256SUMS of the release (sha256 4039f26a...f0cb), whose minisign signature by the Bloch release key '
          '1A5D96A5C4955EF7 verifies (testdata/l2-release-2026-11-17, test_l2_pins_r20); the three binaries of that folder '
          'hashed on the build host and on both copies of the owner\'s signing folder')
LIVE = ('read on 2026-11-19 from four public Bloch L1 RPCs (getl2settlement / getchaininfo, identical answers): ')
SEQUENCER = ('sequencer_mainnet.py of the signed release (sha256 15daa26f..., a line of the signed SHA256SUMS), read on '
             '2026-11-19: TIMESTAMP_RULE and NETWORK_ARGS are these values')
MAINNET_V3 = {
    'name': 'bloch-l2-2026-11-17-launch-native-906336fd (L2 3d35a0f / native 906336fd)',
    'release': {
        'name': 'bloch-l2-2026-11-17-launch-native-906336fd',
        'sha256sums': '4039f26a10cb7203ad1d54a3512217f501371bf0c692157c39424f3037edf0cb',
        'l2_commit': '3d35a0f42f9b5f1a8657ee892dc3239a789a50ae',
        'native_commit': '906336fd35f157dac380523b59dee8a5a325175a',
        'signing_key_id': '1A5D96A5C4955EF7',
        'signed': '2026-11-17',
    },
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
        'follower': 'd4d2b99a20f6093cbaf2b9cebead41b3c6b4bf5aad37f2a091752746a659fe96',
        'produce': '598873aef6770002297a710387969218dd7d684ea8e9d8bdcf067d43123b37db',
        'settled_rpc': '53e88565c2a322f369c5f07d01fa00b11e1ef56fdb7b58c9e7af88c685eabb0d',
    },
    # What the released follower writes as `settlement_policy` in its status on mainnet.
    'settlement_policy': '5ff3c6bde04220d28337e6ea4657e1d0ed69af0a47be73f74820c460944e5e59',
    # The L2 program the L1 accepts settlements of: the statement tag and the seven identities every accepted statement
    # starts with (native crates/bloch-pos-committee/src/l2_settlement.rs, `mainnet::PROGRAM` at 906336fd).
    'l2_program': {
        'statement_tag': 'BLOCH:EVM:SETTLEMENT:3',
        'identities': [
            'f47d3e498ff978e34471dafff5f94fe139fc3ff489b1a00f469c030258311966',  # L1 admission network domain
            '9953da73a2794e190b1c551a787f39d6486a288f40b69ecc361281d5a893e415',  # L1 native genesis block id
            '1c3f8772d0bdfc22f33efce250a4f471343587859f815f083cfee69d3b6f0733',  # L2 domain
            '8ec1c804e67190434fdf72b723103d26938797e90e1b652d366a1b053e3d8f2b',  # L2 execution configuration commitment
            '6e4c844007cbea4c5a3686f44cfb3b91362c146f3e87199a5229d619fae5c073',  # settlement guest ELF (keccak-256)
            '389cfbde2516711668008cf00222398c6b2a3852266ca79c4ec42c5a6b39ac0e',  # SP1 KoalaBear verifying-key hash
            '007139f7bc9459c45b40046780222398cd65470a499b29e72762162d6b39ac0e',  # SP1 BN254 (Groth16) verifying-key hash
        ],
    },
    'verified': {
        'release': SIGNED + '; release.json and the trusted comment of the signature name the release, both commits and chain 700770',
        'binaries': SIGNED,
        'l2_chain_id': LIVE + '`chain_id` 700770; also release.json and the chain id inside the accepted statement',
        'network_pin': LIVE + '`network`; also the first identity of the accepted statement and the status of the released follower',
        'l2_genesis_hash': (LIVE + 'the parent of L2 block 1 inside the accepted statement (offset 272); also BUILD-INFO of the signed '
                            'release and `l2_genesis.hash` (finalized) in the status of the released follower'),
        'l1_genesis_time': LIVE + 'wall slot x 30 s + 1786656679 was the time of the reading (within one slot); also the released unit files',
        'hf1_claim_finality_epoch': LIVE + '`hard_forks.hf1_claim_finality.activation_epoch` 7180, active',
        'timestamp_rule': SEQUENCER + ' (the rule is 1 : L1 genesis time : L1 slot milliseconds)',
        'l2_network_args': (SEQUENCER + '; ' + LIVE + 'the L2 domain is the third identity of the accepted statement; the unit '
                            'file bloch-l2-mainnet-rpc.service of bloch-l2-evm b17b3ae passes exactly these arguments'),
        'settlement_policy': ('status.json written by the released follower d4d2b99a on the mainnet L1 history (the replay of agent '
                              '383 on the build host, whose process identity agent 407 recorded), read on 2026-11-19; the released '
                              'follower takes the policy from the pinned L1 genesis manifest'),
        'l2_program': LIVE + 'the tag and the seven identities of `accepted.statement`, equal to `mainnet::PROGRAM` of native 906336fd',
    },
}
NAMED_PIN_KEYS = PIN_KEYS + ('release', 'settlement_policy', 'l2_program')

# Every pin set that ever had a name. Nothing is removed from here: a superseded set stays readable, and is refused.
PIN_SETS = {'mainnet-v2': MAINNET_V2, 'mainnet-v3': MAINNET_V3}
CURRENT_MAINNET_PINS = 'mainnet-v3'
SUPERSEDED = {
    'mainnet-v2': ('mainnet-v3', 'it pins the L2 release of 2026-11-03 (follower cdf5da5c, producer e3f1a290); the L2 went live with '
                                 'the release of 2026-11-17 (follower d4d2b99a, producer 598873ae)'),
}
STALE_HINT = ('If the L2 release or the L2 program changed, the bridge pins are STALE: sign nothing, do not install another '
              'build to satisfy them, and follow docs/BRIDGE-V3-OPERATOR-RUNBOOK.md, "When the L2 release or program changes" '
              '(tools/signatario-stable/l2_pins_check.py tells a stale pin from a wrong binary).')
STATEMENT_TAG_BYTES = 22  # len(b"BLOCH:EVM:SETTLEMENT:3")
HEX64 = frozenset('0123456789abcdef')


class NotFinal(Exception):
    """The L2 block is not final under the rules (or the inputs cannot show it). args: (reason, detail)."""

    def __init__(self, reason, **detail):
        super().__init__(reason)
        self.reason, self.detail = reason, detail


def is_hash(value):
    return isinstance(value, str) and len(value) == 64 and set(value) <= HEX64


def named_pins(name, sets=None, superseded=None, current=None):
    """The pin set called `name`, only if it is the current one and every value of it was verified at its source.
    Refused: an unknown name; a superseded set (it names the release it was replaced by); a set that is not the current
    one; a set with a required value missing, null, or without a `verified` statement (or with one that starts
    'UNVERIFIED'): a value somebody only quoted must never become the thing seven signers trust."""
    sets = PIN_SETS if sets is None else sets
    superseded = SUPERSEDED if superseded is None else superseded
    current = CURRENT_MAINNET_PINS if current is None else current
    if not isinstance(name, str) or name not in sets:
        raise NotFinal(f'l2_pins must be "{current}" or an object', got=name)
    if name in superseded:
        by, why = superseded[name]
        raise NotFinal(f'the L2 pin set "{name}" is superseded by "{by}": {why}. A signer on "{name}" certifies nothing '
                       f'on the live L2; set "l2_pins": "{by}" and install the binaries of that signed release',
                       got=name, current=current)
    if name != current:
        raise NotFinal(f'the L2 pin set "{name}" is not the current one ("{current}")', got=name)
    pins = dict(sets[name])
    verified = pins.get('verified')
    verified = verified if isinstance(verified, dict) else {}
    unverified = [k for k in NAMED_PIN_KEYS
                  if pins.get(k) is None or not isinstance(verified.get(k), str) or not verified[k].strip()
                  or verified[k].lstrip().upper().startswith('UNVERIFIED')]
    if unverified:
        raise NotFinal(f'the L2 pin set "{name}" holds values nobody verified at their source: refused', unverified=unverified)
    program = pins['l2_program']
    ids = program.get('identities') if isinstance(program, dict) else None
    if not isinstance(ids, list) or len(ids) != 7 or not all(is_hash(i) for i in ids) \
            or not isinstance(program.get('statement_tag'), str) or len(program['statement_tag'].encode()) != STATEMENT_TAG_BYTES:
        raise NotFinal(f'the L2 pin set "{name}" has a malformed l2_program')
    if not all(is_hash(strip0x(v)) for v in pins['binaries'].values()) or set(pins['binaries']) != {'follower', 'produce', 'settled_rpc'} \
            or not is_hash(pins['settlement_policy']) or not is_hash(pins['release'].get('sha256sums')):
        raise NotFinal(f'the L2 pin set "{name}" has a malformed hash')
    if ids[0] != strip0x(pins['network_pin']) or ids[2] != pins['l2_network_args'][3]:
        raise NotFinal(f'the L2 pin set "{name}" contradicts itself (network or L2 domain against l2_program)')
    return pins


def pins_from_config(cfg):
    """`l2_pins`: the name of the current pin set (CURRENT_MAINNET_PINS; `named_pins` refuses any other name, "mainnet-v2"
    included) or a full object (rehearsals). None: legacy devnet mode."""
    raw = cfg.get('l2_pins')
    if raw is None:
        if int(cfg.get('l2_chain_id', 0)) == int(MAINNET_V2['l2_chain_id']):
            raise NotFinal('chain 700770 needs l2_pins: without them nothing pins the binaries, and l2_source "rpc" trusts an RPC for finality')
        return None
    if isinstance(raw, dict):
        missing = [k for k in PIN_KEYS if k not in raw]
        if missing:
            raise NotFinal('l2_pins is missing keys', missing=missing)
        pins = dict(raw)
    else:
        pins = named_pins(raw)
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
    """Every L2 binary the signer runs must be the pinned build (by SHA-256)."""
    for role, want in pins['binaries'].items():
        path = paths.get(role)
        if not path:
            raise NotFinal(f'no path configured for the pinned {role} binary')
        got = sha256_file(path)
        if got != strip0x(want):
            raise NotFinal(f'the {role} binary is not the pinned build', path=str(path), sha256=got,
                           pinned=strip0x(want), pin_set=pins.get('name'), hint=STALE_HINT)


def load_status(path):
    """The follower status at `path`, always in the v2 shape the checks here read. A v3 status names a log beside it with
    every settlement; the log must hold exactly what the status names. It is not a trust anchor: check_rebuild still
    compares each entry with the L2 rebuilt from L1. Raises NotFinal if the log and the status differ, and OSError or
    ValueError if the file cannot be read."""
    path = Path(path)
    status = json.loads(path.read_text())
    if status.get('schema') != STATUS_SCHEMA_V3:
        return status
    log = status.get('settlement_log') or {}
    name, entries, size = log.get('file'), log.get('entries'), log.get('bytes')
    if not isinstance(name, str) or not name or '/' in name or name in ('.', '..') or not isinstance(entries, int) \
            or not isinstance(size, int):
        raise NotFinal('the follower status names a bad settlement log', settlement_log=log)
    data = b''
    if entries:
        with open(path.with_name(name), 'rb') as f:
            data = f.read(size)
    lines = data.splitlines()
    if len(data) != size or len(lines) != entries or (data and not data.endswith(b'\n')):
        raise NotFinal('the follower settlement log does not match its status', entries=entries, read=len(lines))
    settlements = [json.loads(line) for line in lines]
    recent = status.get('finalized_settlements_recent') or []
    if status.get('finalized_settlements_count') != entries or (entries and (not recent or settlements[-len(recent):] != recent)):
        raise NotFinal('the follower settlement log differs from its status', entries=entries)
    for name in ('finalized_settlements_count', 'finalized_settlements_recent', 'settlement_log'):
        status.pop(name)
    status['schema'] = STATUS_SCHEMA_V2
    status['finalized_settlements'] = settlements
    return status


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
    if pins.get('settlement_policy') is not None and strip0x(status.get('settlement_policy')) != strip0x(pins['settlement_policy']):
        raise NotFinal('the follower verifies another L2 settlement policy than the pinned one: the L2 program changed '
                       'and the L2 pins are stale, or this is not the pinned follower', follower=status.get('settlement_policy'),
                       pinned=pins['settlement_policy'], hint=STALE_HINT)
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


def statement_program(statement):
    """(tag, [seven identities], chain id) of an L2 settlement statement as the L1 reports it (hex). The statement starts
    with its 22-byte tag, then seven 32-byte identities, 32 further bytes, and the L2 chain id (8 bytes, big endian):
    native crates/bloch-pos-committee/src/l2_settlement.rs (`h(s, S + i * 32)`, `n(s, S + 256)`)."""
    try:
        raw = bytes.fromhex(strip0x(statement))
    except (ValueError, TypeError):
        raise NotFinal('an L1 RPC reports an accepted L2 statement that is not hex') from None
    s = STATEMENT_TAG_BYTES
    if len(raw) < s + 264:
        raise NotFinal('an L1 RPC reports an accepted L2 statement that is too short', bytes=len(raw))
    return (raw[:s].decode('ascii', 'replace'), [raw[s + 32 * i:s + 32 * i + 32].hex() for i in range(7)],
            int.from_bytes(raw[s + 256:s + 264], 'big'))


def check_l1_program(view, pins, url=None):
    """The L2 program the L1 has accepted a settlement of is the pinned one (pin sets with `l2_program`). The L1 is where
    an L2 program change becomes real: once it accepts a statement of another program (another guest, verifying key,
    execution configuration or statement version), the binaries these pins name no longer describe the live L2, whatever
    they still manage to rebuild. Returns the accepted commitment."""
    program = pins.get('l2_program')
    if program is None:
        return None
    accepted = view.get('accepted')
    if not isinstance(accepted, dict) or not accepted.get('statement'):
        raise NotFinal('an L1 RPC reports no accepted L2 settlement: with these pins the L2 has settled, so this RPC is '
                       'behind or follows another chain', url=url)
    tag, identities, chain_id = statement_program(accepted['statement'])
    want = [strip0x(i) for i in program['identities']]
    if tag != program['statement_tag'] or identities != want or chain_id != int(pins['l2_chain_id']):
        names = ('network', 'native genesis', 'L2 domain', 'L2 configuration', 'guest ELF', 'KoalaBear key', 'BN254 key')
        moved = [names[i] for i in range(7) if identities[i] != want[i]]
        raise NotFinal('the L1 has accepted a settlement of another L2 program than the pinned one: the L2 pins are STALE',
                       url=url, statement_tag=tag, pinned_tag=program['statement_tag'], changed=moved, chain_id=chain_id,
                       accepted=identities, pinned=want, hint=STALE_HINT)
    return accepted.get('commitment')


def l1_cross_check(urls, pins, now, fetch=l1_rpc):
    """Each configured L1 RPC of the signer: same network and chain; no foreign finalized checkpoint under the
    own-chain rule; from the gate on, an HF1 node (it reports finalized_checkpoint); with pins that name the L2
    program (`l2_program`), the L1 has accepted a settlement of exactly that program, and at least one L1 RPC must be
    configured to say so. Read-only."""
    seen = []
    if pins.get('l2_program') is not None and not urls:
        raise NotFinal('no L1 RPC is configured (l1_rpc_urls): with these pins the signer reads from its own L1 RPCs which '
                       'L2 program the L1 accepts, and signs nothing without that reading')
    for url in urls or []:
        try:
            view = fetch(url, 'getl2settlement')
        except (OSError, ValueError) as e:
            raise NotFinal('an L1 RPC of this signer is unreachable', url=url, error=str(e)) from None
        if strip0x(view.get('network')) != strip0x(pins['network_pin']) or view.get('chain_id') != int(pins['l2_chain_id']):
            raise NotFinal('an L1 RPC follows another network or L2 chain', url=url, network=view.get('network'),
                           chain_id=view.get('chain_id'))
        accepted = check_l1_program(view, pins, url)
        fc = (view.get('withdrawals') or {}).get('finalized_checkpoint')
        if fc is None:
            if wall_epoch(now, pins['l1_genesis_time']) >= int(pins['hf1_claim_finality_epoch']):
                raise NotFinal('an L1 RPC does not report finalized_checkpoint after the HF1 gate (not an HF1 node)',
                               url=url)
            seen.append({'url': url, 'finalized_checkpoint': None, **({'accepted': accepted} if accepted else {})})
            continue
        if fc.get('own_chain_rule_active') and strip0x(fc.get('own_root')) != strip0x(fc.get('root')):
            raise NotFinal("an L1 RPC's finalized checkpoint is not its own chain's (own_root != root): "
                           'claims are unsafe there', url=url, finalized_checkpoint=fc)
        seen.append({'url': url, 'finalized_checkpoint': fc, **({'accepted': accepted} if accepted else {})})
    return seen


def legacy_network(genesis_path):
    """Devnet followers (no pins): the network id is sha3-256 of the genesis file."""
    return hashlib.sha3_256(Path(genesis_path).read_bytes()).hexdigest()
