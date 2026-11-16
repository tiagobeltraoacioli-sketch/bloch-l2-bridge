#!/usr/bin/env python3
"""`vigia.py` for the TRON route (USDT TRC-20 -> bUSDT.trx): the relayer and signer driver of
tools/signatario-stable, unchanged, with the three places where TRON is not Ethereum overridden.

  vigia_tron.py --config CFG.json sign|relay [--once] [--interval S]

Config: exactly `vigia.py`'s, where the "Ethereum" side is the TRON side:
  `eth_rpc`        the operator's own `tron_rpc_shim.py` (reads; `finalized` there is TRON's solidified block);
  `eth_chain_id`   the TRON chain id (mainnet 728126428);
  `source_vault`   the vault's 20-byte address (0x form);
  `tron_node`      the operator's own java-tron FullNode HTTP API (for sending), optional `tron_solidity`;
  `eth_relayer_keystore` / `eth_relayer_password_file`   the TRON gas key (a secp256k1 keystore like any other);
  `tron_fee_limit_sun`   the most one release may burn (default 150 TRX), in place of `eth_max_gas_price_gwei`;
  `tron_valid_s`   lifetime of a relayed transaction (default 90).

What is overridden, and why:
  unpayable            the Ethereum relayer parks a burn when the token's simulated `transfer` returns false. USDT on
                       TRON returns false from EVERY successful transfer, so here only a revert parks a burn (the vault
                       itself, in transfer mode 1, ignores the return value and checks exact balance movement).
  send (source side)   a TRON transaction has no nonce and cannot be repriced: tron_send.Sender signs once per burn,
                       journals before broadcasting, and signs again only after the solidified chain shows the first
                       one expired. The Ethereum nonce record and release journal are not used on this side.
  replace_stuck_release  nothing to do: a TRON transaction lands or expires within `tron_valid_s`.
  relay_round          first closes the journal entries the solidified chain has settled.
The L2 side (mints, executes, drains) is `vigia.py`'s code, untouched.
"""
import hashlib
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / 'signatario-stable'))
import vigia  # noqa: E402
import tron_send  # noqa: E402

TRON_MAINNET = 728126428


class VigiaTron(vigia.Vigia):
    _tron = None

    def tron(self):
        if self._tron is None:
            c = self.cfg
            cfg = {'tron_node': c['tron_node'], 'tron_solidity': c.get('tron_solidity'), 'cast': self.cast,
                   'tron_chain_id': c['eth_chain_id'], 'vault': self.vault,
                   'journal_dir': c.get('relayer_submission_dir', str(self.shared.parent / '.tron-submissions')),
                   'fee_limit_sun': c.get('tron_fee_limit_sun', tron_send.DEFAULT_FEE_LIMIT),
                   'valid_s': c.get('tron_valid_s', 90)}
            sender = tron_send.Sender(cfg)
            sender.wallet = lambda: self.relayer_wallet('eth')
            self._tron = sender
        return self._tron

    def relayer_wallet(self, side):
        if side == 'eth' and int(self.cfg.get('eth_chain_id', 0) or 0) == TRON_MAINNET \
                and not self.cfg.get('eth_relayer_keystore'):
            raise SystemExit('eth_relayer_key (raw hex) is refused on TRON mainnet: use eth_relayer_keystore and '
                             'eth_relayer_password_file')
        return super().relayer_wallet(side)

    def unpayable(self, b):
        if 'recipient' not in b:
            return False
        url = self.cfg['eth_rpc']
        if 'mint_head' in b and not self.flag(url, self.vault, 'provenanceMatches(uint64,uint64,bytes32)', b['mint_count'],
                                              b['minted_total'], b['mint_head']):
            if b['burn_id'] not in self.parked_logged:
                vigia.log(kind='alert', severity='critical', id='release-held-provenance', burn=b['burn_id'],
                          mint_count=b['mint_count'], mint_head=b['mint_head'],
                          reason='the burn was made under a mint chain the vault deposits do not back')
            return True
        token = self.chain_read('token', lambda: '0x' + self.call(url, self.vault, 'token()')[-40:])
        data = '0xa9059cbb' + b['recipient'][2:].rjust(64, '0') + f"{b['amount']:064x}"
        try:
            self.rpc(url, 'eth_call', [{'from': self.vault, 'to': token, 'data': data}, 'latest'])
        except RuntimeError as e:
            if vigia.is_revert(e):  # blacklisted vault, paused token, missing balance: the token itself refuses
                return True
            raise
        return False  # the return value says nothing on TRON (USDT answers false on success)

    def replace_stuck_release(self, d, burn_id, rnd):
        return

    def relay_round(self):
        for key, state in self.tron().settle_all():
            vigia.log(kind='tron-settled', key=key, state=state)
        super().relay_round()

    def send_locked(self, side, to, call, gas, replace, release_id, locks):
        if side != 'eth':
            return super().send_locked(side, to, call, gas, replace, release_id, locks)
        if to.lower() != self.vault:
            raise RuntimeError('the TRON side sends only to the configured vault')
        data = self.cast_out('calldata', *call)
        key = release_id[2:] if release_id else 'call-' + hashlib.sha256(data.encode()).hexdigest()[:32]
        try:
            out = self.tron().send(key, to, data)
        except tron_send.Refused as e:
            raise RuntimeError(f'TRON send refused: {e}') from e
        vigia.log(kind='tron-send', key=key, **out)
        return '0x' + out['txid']


def main():
    vigia.Vigia = VigiaTron
    vigia.main()


if __name__ == '__main__':
    main()
