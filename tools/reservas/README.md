# reservas — reserves monitor for the Bloch bridges (read-only)

```
python3 reservas.py --config CFG.json check            # one round; exit 0 ok, 2 deficit, 3 surplus, 1 error
python3 reservas.py --config CFG.json watch [--interval 300]
```

For each configured bridge, one JSON line `kind: reserves` with the source backing and the L2 token's
liabilities, both read at finality:

| | Backing (source, final) | Liabilities (L2 `finalized`) |
| --- | --- | --- |
| `stable` | `min(vault.totalLocked(), USDC.balanceOf(vault))` at Ethereum `finalized` | `totalSupply() + pendingSupply()` |
| `wgnb` | sum of the GnB vault's UTXOs (`getutxos`; truncated answers and UTXOs paying another script are refused) | `totalSupply() + pendingSupply()` (0 pending for a v1 token) |

Signers release only after the burn is final on the L2 and mint only after the deposit/lock is final on the
source, so an honest bridge has backing ≥ liabilities. The difference is burns waiting for their release plus
deposits/locks waiting for their mint.

- **deficit** (backing < liabilities): hard alert, exit 2. Value left the source without a matching burn.
- **surplus** (backing > liabilities + `tolerance`): soft alert, exit 3. In-flight or stuck burns/deposits.
- Read errors: `unverifiable`, exit 1, never a deficit.

The monitor holds no key and sends nothing; pausing is the guardians' job (`tools/guardiao`). It is a
supply-level check only: a release without a burn on a vault whose deposits are not all minted shows as a
smaller surplus, not a deficit; `guardiao.py` catches that case burn by burn.

Config: `{"bridges": [...], "cast": optional}`, each bridge `kind`, `name`, `l2_rpc`, `token`, `tolerance`
(base units, 0) and `eth_rpc` + `vault` (stable) or `gnb_rpc` + `gnb_vault_address` + optional
`gnb_vault_script` (wgnb).

Tests: `python3 test_reservas.py <foundry project>` (anvil, vault fixture, `MockSupply` tokens, fake GnB
RPC): 14 checks.
