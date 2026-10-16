# signatario-gnb — Bloch half of the wGSMH bridge signer

Set-once automatic signer, same pattern as `atestador.py` (devnet4): it signs only what it verified on
its own nodes. Formats: `INTERFACE-PONTE-BLOCH-GNB.md`, section "Bloch" (B2–B7).

| Command | Checks before signing |
| --- | --- |
| `mint --txid HEX --vout 0 --out SIG.json` | GnB half: lock format + depth N / PoWit on the signer's own GnB node. L2: chain id, pinned wGSMH code hash, gnbChainId/threshold, not minted, within caps, local EIP-712 digest == contract `mintDigest`. Signs with a `cast` keystore. |
| `combine --sig A --sig B --out MINT.json` | Same mint in every partial; k distinct signers ordered by address; prints the `mint(...)` call. Anyone may run it. |
| `release --burn-tx HASH --spend RELEASE.json --out PARTIAL.json` | Rebuilds the L2 from L1 data (`produce reconstruct` over the native follower), serves it on a private `settled-rpc`, requires the burn in a block ≤ finalized whose hash matches the follower's FFG replay, checks the code pin and the `burnId`, then hands the intent to the GnB half (marker absent → co-sign). |

Config (one JSON per signer, written once at deploy): `l2_rpc`, `l2_chain_id`, `wgnb`, `wgnb_code_keccak`,
`gnb_chain_id`, `threshold`, `keystore`, `password_file`, `db`, `gnb_half_lock` / `gnb_half_release` (argv templates with `{txid}`, `{burn}`, `{spend}` for gnb-smh `tools/ponte/signatario_gnb.py`), and for release
`follower`, `genesis`, `produce`, `settled_rpc`, `work_dir`, `timestamp_rule_file` (default `timestamp-rule.txt` next to
the genesis, as `atestador.py`). `l2_source: "rpc"` trusts `l2_rpc` for
finality and exists only for tests.

Tests: `python3 test_signatario.py <foundry project>` (anvil, chain id 700771, GnB half test double).
