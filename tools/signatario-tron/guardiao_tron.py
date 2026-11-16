#!/usr/bin/env python3
"""`guardiao.py` for the TRON route: the guardian of tools/guardiao, unchanged, with its one source-side
transaction (`guardianPause()` on the vault) sent as a TRON transaction.

  guardiao_tron.py --config CFG.json check|watch [--dry-run] [--interval S]

Config: `guardiao.py`'s, with `eth_rpc` = the guardian's own `tron_rpc_shim.py`, `eth_chain_id` = the TRON chain id,
`vault` = the 20-byte vault address, plus `tron_node` (own FullNode HTTP API), optional `tron_solidity`,
`tron_fee_limit_sun` (default 150 TRX), `tron_journal_dir`. `eth_keystore` / `eth_password_file` name the guardian's
TRON key (secp256k1, the same keystore format). Every read, rule and decision is `guardiao.py`'s.
"""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / 'guardiao'))
import guardiao  # noqa: E402
import tron_send  # noqa: E402
import tronlib  # noqa: E402


class GuardianTron(guardiao.Guardian):
    def run(self, argv):
        argv = [str(a) for a in argv]
        if len(argv) > 3 and argv[1] == 'send' and '--rpc-url' in argv \
                and argv[argv.index('--rpc-url') + 1] == self.cfg.get('eth_rpc'):
            if argv[2].lower() != self.cfg['vault'].lower() or argv[3] != 'guardianPause()':
                return 1, '', 'the TRON guardian sends only guardianPause() to the configured vault'
            return self.tron_pause()
        return super().run(argv)

    def tron_pause(self):
        c = self.cfg
        try:
            s = tron_send.Sender({
                'tron_node': c['tron_node'], 'tron_solidity': c.get('tron_solidity'), 'cast': self.cast,
                'tron_allow_remote_node': c.get('tron_allow_remote_node'),
                'tron_chain_id': c['eth_chain_id'], 'vault': c['vault'],
                'keystore': c.get('eth_keystore', c['keystore']),
                'password_file': c.get('eth_password_file', c['password_file']),
                'journal_dir': c.get('tron_journal_dir', str(Path(c['state']).parent / '.tron-guardian')
                                     if c.get('state') else '.tron-guardian'),
                'fee_limit_sun': c.get('tron_fee_limit_sun', tron_send.DEFAULT_FEE_LIMIT)})
            key = 'pause-' + s.sender()[2:]
            out = s.send(key, c['vault'], s.node.calldata('guardianPause()'))
            if out['state'] == 'backoff':
                return 1, '', f"guardianPause() landed and failed {out['failed']} time(s); next attempt at {out['retry_at']}"
            state, doc = s.wait(key, timeout=int(c.get('tron_wait_s', 180)))
        except (tron_send.Refused, tronlib.TronError) as e:
            return 1, '', str(e)
        receipt = (doc or {}).get('receipt') or {}
        ok = state == 'landed' and receipt.get('result') == 'SUCCESS'
        return 0, json.dumps({'status': '0x1' if ok else '0x0', 'transactionHash': '0x' + out['txid'],
                              'blockNumber': hex(receipt['block']) if receipt.get('block') else None,
                              'gasUsed': hex(receipt.get('energy_total', 0))}), ''


def main():
    guardiao.Guardian = GuardianTron
    guardiao.main()


if __name__ == '__main__':
    main()
