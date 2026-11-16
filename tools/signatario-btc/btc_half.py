#!/usr/bin/env python3
"""Bitcoin half of the bBTC signer: answers `signatario.py mint` about one deposit, from this operator's own node.

  python3 btc_half.py --config BTC.json deposit --deposit-id 0xID
  python3 btc_half.py --config BTC.json status

It is the `eth_half_deposit` argv of tools/signatario-stable/signatario.py, which is used UNCHANGED for bBTC with
`"provenance": true`: the deposit id is ProvenanceSourceVault's formula over (route, nonce, sender, amount, recipient),
where for Bitcoin nonce = the position of the deposit in the vault's sweep order, sender = a commitment to the outpoint
and amount = the token units credited (btc_policy.deposit_credit). signatario.py recomputes the id from the answer.

Answers ok only if, on this node:
  1. the vault thread replays from the anchor to the tip through the rules (btc_vault.VaultView);
  2. the deposit with that nonce exists in it and its id is the one asked;
  3. its sweep has the confirmations the policy requires for everything swept since (btc_policy.required_confirmations);
  4. the L2 token agrees with the ledger so far (btc_l2.ledger_prefix_problem): otherwise HOLD;
  5. this operator never attested the same outpoint under another id (journal): otherwise HOLD.
Exit 0 with {"ok": true, ...}, exit 1 with {"ok": false, "reason": ...}. No key is read here. UNAUDITED.

Config: {"vault": path of the vault config, "btc_rpc": "http://127.0.0.1:PORT", "btc_cookie": path,
         "l2_rpc": url, "token": address, "l2_chain_id": n, "token_code_keccak": hex, "journal": path}
"""
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import btc_l2  # noqa: E402
import btc_policy as pol  # noqa: E402
import btc_vault  # noqa: E402


def answer(ok, **fields):
    print(json.dumps({'ok': ok, **fields}, indent=2))
    raise SystemExit(0 if ok else 1)


def open_view(cfg):
    vault = btc_vault.load_vault(cfg['vault'])
    node = btc_vault.Node(cfg['btc_rpc'], cfg['btc_cookie'], vault.network)
    return vault, btc_vault.VaultView(vault, node).load()


def journal_load(path):
    return json.loads(Path(path).read_text()) if Path(path).exists() else {'outpoints': {}}


def journal_save(path, data):
    tmp = Path(str(path) + '.tmp')
    with open(tmp, 'w') as f:
        f.write(json.dumps(data, indent=1) + '\n')
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def main():
    args = sys.argv[1:]
    cfg = json.loads(Path(args[args.index('--config') + 1]).read_text())
    try:
        vault, view = open_view(cfg)
    except (btc_vault.Held, btc_vault.NodeError, pol.PolicyError) as e:
        answer(False, reason=f'hold: {e}')
    credits = view.credits()
    if 'status' in args:
        answer(True, tip=view.tip_state()['txid'], height=view.at['height'], marker=view.tip_state()['marker'].as_dict(),
               deposits=[{'nonce': x['nonce'], 'deposit_id': '0x' + x['deposit_id'].hex(), 'units': x['units'],
                          'recipient': '0x' + x['recipient'].hex(), 'outpoint': f"{x['txid']}:{x['vout']}",
                          'confirmations': x['confirmations'], 'required': x['required'], 'final': x['final']}
                         for x in credits])
    want = args[args.index('--deposit-id') + 1].lower().removeprefix('0x')
    if len(want) != 64:
        answer(False, reason='a deposit id is 32 bytes of hex')
    nonce = int(want[:16], 16)
    if nonce >= len(credits):
        answer(False, reason='no swept deposit has this nonce on this node', nonce=nonce, swept=len(credits))
    cr = credits[nonce]
    if cr['deposit_id'].hex() != want:
        answer(False, reason='the deposit swept under this nonce has another id (reorganised or forged)',
               ledger='0x' + cr['deposit_id'].hex())
    if not cr['final']:
        answer(False, reason='the sweep of this deposit is not deep enough yet', confirmations=cr['confirmations'],
               required=cr['required'])
    token = btc_l2.Token(cfg['l2_rpc'], cfg['token'], cfg.get('l2_chain_id'), cfg.get('token_code_keccak'))
    try:
        token.check()
        problem = btc_l2.ledger_prefix_problem(token, vault, credits)
    except btc_l2.L2Error as e:
        answer(False, reason=f'hold: {e}')
    if problem:
        answer(False, reason='hold: ' + problem)
    journal = journal_load(cfg['journal'])
    outpoint = f"{cr['txid']}:{cr['vout']}"
    prior = journal['outpoints'].get(outpoint)
    if prior is not None and prior != want:
        answer(False, reason='hold: this operator attested the same outpoint under another deposit id', prior='0x' + prior)
    journal['outpoints'][outpoint] = want
    journal_save(cfg['journal'], journal)
    answer(True, source_chain_id=vault.chain_id, vault='0x' + vault.source_vault.hex(), route='0x' + vault.route.hex(),
           deposit_id='0x' + want, nonce=nonce, sender='0x' + btc_vault.c.outpoint_sender(cr['txid'], cr['vout']).hex(),
           amount=cr['units'], pq_recipient_hash='0x' + cr['recipient'].rjust(32, b'\0').hex(),
           tx_hash='0x' + cr['sweep_txid'], log_index=cr['input_index'], block_number=cr['height'],
           block_hash='0x' + cr['blockhash'], finalized=True, finalized_number=view.at['height'] - cr['required'] + 1,
           outpoint=outpoint, value_sats=cr['value'], confirmations=cr['confirmations'], required=cr['required'])


if __name__ == '__main__':
    main()
