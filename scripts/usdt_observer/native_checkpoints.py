"""Compare supplied node reports; agreement is not authenticated native DEX state."""
from .common import integer, require, word


def compare_checkpoints(reports):
    """Read bounded getchaininfo results from distinct operator-labelled sources.

    Labels cannot prove independent operators, chain identity, or freshness.
    Head state roots must never be substituted for finalized block roots.
    """
    require(type(reports) is list and 2 <= len(reports) <= 16, 'two to sixteen node reports required')
    sources, checkpoints, heads = set(), [], []
    for report in reports:
        require(type(report) is dict and set(report) == {'source', 'chaininfo'}, 'invalid node report')
        source, info = report['source'], report['chaininfo']
        require(type(source) is str and 1 <= len(source) <= 64 and source.isascii()
                and all(c.isalnum() or c in '-_.' for c in source) and source not in sources,
                'distinct source labels required')
        sources.add(source)
        require(type(info) is dict, 'invalid chaininfo result')
        height, slot, epoch = integer(info['height']), integer(info['slot']), integer(info['epoch'])
        slots = integer(info['slots_per_epoch'])
        require(slots > 0 and slot // slots == epoch and height <= slot, 'inconsistent node head')
        finalized_height = integer(info['finalized_height'])
        finalized = info['finalized']
        require(type(finalized) is dict and set(finalized) == {'epoch', 'root'}, 'invalid finalized checkpoint')
        finalized_epoch = integer(finalized['epoch'])
        root = word(finalized['root'], 32)
        require(any(root) and finalized_epoch <= epoch and finalized_height <= height,
                'invalid finalized checkpoint position')
        # Validate both identities but deliberately do not compare head state
        # roots: honest nodes may have different heads above a common checkpoint.
        word(info['state_root'], 32)
        word(info['block_id'], 32)
        checkpoints.append((finalized_epoch, finalized_height, root, slots))
        heads.append({'source': source, 'height': str(height), 'epoch': str(epoch)})
    require(all(value == checkpoints[0] for value in checkpoints), 'native checkpoint disagreement')
    epoch, height, root, _ = checkpoints[0]
    return {'node_report_agreement': True, 'finalized_epoch': str(epoch),
            'finalized_height': str(height), 'finalized_block_root': '0x'+root.hex(),
            'sources': heads, 'reports_authenticated': False, 'reports_fresh': False,
            'operator_independence_verified': False, 'native_dex_state_bound': False,
            'finality_verified': False, 'mint_authorized': False, 'redemption_settled': False,
            'bridge_ready': False}
