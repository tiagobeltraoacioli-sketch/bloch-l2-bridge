# wGSMH pilot: GnB-SMH mainnet ↔ Bloch L2 devnet4 (2026-10-16)

End-to-end run of the GnB-SMH bridge with real mainnet coins (user-approved pilot of 30 GSMH),
against devnet4 L2 (chain id 700771). Goal: a working wGSMH token with `bucketCapacity()` so the DEX
can later list a wGSMH/WBLCH pair.

Ticker: the GnB-SMH coin is **GSMH**; the L2 token is **wGSMH** ("Wrapped GnB-SMH", 8 decimals).
Contract names (`WrappedGnBV2`), the GnB chain ids (0x474E0001 mainnet) and `gnb1…` addresses are unchanged.

## What was built

| Side | Change |
| --- | --- |
| GnB (gnb-smh, branch `feat/vault-single-branch` from main 820c102) | Single-branch vault: `gnb-cli vaultcreate <out> --release K <keys…>` without `--recovery` writes a plain policy-v1 `k`-of-`n` vault (`gnb1m…`). `vaultlock`/`vaultchecklock`/`vaultrelease`/`vaultcheckrelease`/`vaultutxos` accept it; same lock shape (vault in output 0, 20-byte L2 marker of 546 in output 1) and release shape (payout, `GNB-RELEASE-v1` burn marker, change to the vault). Depth by `--min-conf N`. `GNB_WALLET_PASSWORD(_FILE)` restored for unattended signers (lost in the audit merge). The GnB-half signer accepts nodes that report only `network`. |
| Bloch (this repo, branch `feat/pontes-gsmh` from `feat/pontes-v11`) | `WrappedGnBV2` name/symbol "Wrapped GnB-SMH"/`wGSMH` (EIP-712 domain name stays "Bloch wGnB", so signers are unchanged); forge test of the pilot configuration; `tools/signatario-gnb/deploy_wgsmh_pilot.sh` (deploy + signer configs). |

Tests: gnb-smh bridge unit tests 5/5, `policy_spend` 4/4, node `vault_single_branch` 3/3, `vault_policy_tree` 4/4,
`policy_spend_transport` 3/3; forge 82 passed (1 skipped); `test_signatario.py` 15/15; `test_vigia.py` 16/16.

## Setup

| Item | Value |
| --- | --- |
| GnB node | separate validate-only mainnet node on 45.77.142.123 (RPC 127.0.0.1:17520, unit `gsmh-gnb-node`), binary sha256 `92996c05…` (= the mainnet release), started from a copy of the stuck `~/gnb-ponte-main/node` db; synced to the same tip as 136.244.93.186 (h14640 `608749a3…`). The old node (17510, pre-PoWit binary) is stuck at selected height 9999 and was not touched. |
| Vault (single-branch, 2-of-3) | `gnb1m3361d86892c688c70da594135c949f86d06adafe06bb0d5543fa311ad448bca977118605` (= the precomputed policy; `~/gnb-ponte-main/vault.json`) |
| Pilot wallet (funds, release recipient) | `gnb1q4c73e4703da1d8e12370895e8a6b66015c4ec63a9a780adf` (30.0 GSMH, utxo `2e17f0a6…0369:0`) |
| wGSMH token | `0xB2B4952b6E57e589109aF764859886e236798AD4`, deploy tx `0xc251d28a528c5c44d70aa3636371ff9c9fd1b730b6ecf4b85d0996f317ba4cb1`, L2 block 421, gas 2,063,044, deployer `0x4630a5EB8d04401e610Dd986b481A489410122D9` (nonce 0) |
| Runtime code keccak | `0xa7602699759ecff36f21ef98bcd31f8a2f3cd82b79ca742472978a6455c0a7d5` |
| Parameters | gnbChainId 0x474E0001; 2-of-3 signers `0x1a6f9bbd…b86c`, `0x8bbe6a87…258b`, `0xdf2d2e05…0a65` (pilot set, keystores `/var/lib/bloch-l2-devnet4-pontes-main/keys`); supplyCap 3,000,000,000 (30 GSMH); bucketCapacity 1,000,000,000 (10 GSMH); refillPerSecond 11,574 (full in 24 h); largeMintThreshold 500,000,000 (5 GSMH), largeMintDelay 3,600 s; minBurn 100,000; no guardians |
| Signer configs | `/var/lib/bloch-l2-devnet4-pontes-gsmh/signer{1,2,3}.json` (new dir; old configs untouched), GnB half: `--min-conf 30 --rpc-port 17520`, gnb-cli sha256 `75f00d6e…28cc` |

## Run

| Step | Result |
| --- | --- |
| 1. Lock 3 GSMH (`vaultlock … 3 0x4630…22D9 --fee 0.0001`) | txid `ae3b6e6e49e4d6cffeee08e06a74eade9acfa66913e0fd7d54fc925a5189926d`, GnB block 14641 (`9081e1fc22c2c1747564f8ceb0efdc900205cc198b3afc7b5cc0a18f60f7b71d`); outputs: 300,000,000 → vault, 546 → `4630a5eb…22d9` (L2 marker), 2,699,982,468 change; fee 16,986 |
| 2. Depth | `vaultchecklock --min-conf 30` ok at 30 confirmations |
| 3. Mint signatures | signers 1, 2, 3 each verified the lock on the GnB node (30 conf) and the L2 contract, and signed digest `0x3a71831d217d2364a3b313aaef25aacd8f58a44cbe80c765adcef4e6a6ef7fb7`; `combine` chose `0x1a6f…`, `0x8bbe…` |
| 4. Mint (relayed by `0x4630…22D9`) | tx `0x1ab44db21c5ec05917fa2f8e90d18a05e058e847d98287b6c9b483ef4562698a`, L2 block 425 (`0xad91666e9a64cca5a83629d7d4f405206bef45fc512b44af2003f590c3e78c18`), gas 128,515: 3 wGSMH minted at once (below the 5 GSMH delay threshold) |
| 5. Burn 1 wGSMH to the pilot wallet | tx `0xa03a4e6b9696e9beee88d580fe345d657f96ee9bc05fde564d08e4829f82ce50`, L2 block 425, gas 60,652; burnNonce 1, burnId `0x88d8250737c8c1a7aaca7fe5db430066e25c21f37fb1064fd77439c82bc9ee87` = keccak(abi.encode(700771, token, 1)); script `4c73e4703da1d8e12370895e8a6b66015c4ec63a` |
| 6. Release built (`vaultrelease … --next-height 14681`) | payout 99,957,480 + marker 546 + fee 41,974 = 100,000,000 (the burn, exactly); change 200,000,000 to the vault; plain policy spend (version 1 / sighash v2 below the hardening activation) |
| 7. Release signatures (after L2 finalized ≥ 425) | signers 1 and 2: each rebuilt the L2 from L1 (123,466 native blocks, 425 L2 blocks), found the burn ≤ finalized 425, then the GnB half (`vaultcheckrelease`: vault inputs, exact shape, fee cap, marker absent) co-signed: keys 0 and 1 |
| 8. Broadcast | release txid `8bb33a9a35364501b0cbe9885520ca3ebbe2aa6a4bc2a4142ca7776a5a0da78f`, GnB block 14714 (`1586131e2df971e3e216b80dcd7f6e576d292550cb9c4f3db6cf2270f6591808`); outputs 99,957,480 → pilot wallet, 546 → burn marker `gnb1q832ad1fe3f3f8a8f4f411ffa4587e3c67bc778f8d47af7f0`, 200,000,000 → vault |

## Replays (all refused)

| Attempt | Refusal |
| --- | --- |
| Second release of the same burn from the vault change (`8bb33a9a…:2`), signer 3 (never signed it) | GnB half: "a release for this burn already exists on chain" (marker output present) |
| Same, signer 1 (signed the first release) | GnB half journal: "this signer already signed a different release for this burn" |
| Mint the same lock again, signer 1 | "this lock is already minted" (contract `minted(lockId)` = true) |

## Final state

| | |
| --- | --- |
| Vault | 200,000,000 (2 GSMH) in `8bb33a9a…:2` |
| wGSMH | totalSupply 200,000,000 = vault balance; `0x4630a5EB8d04401e610Dd986b481A489410122D9` holds 200,000,000 (2 wGSMH, kept for the DEX test); pendingSupply 0; burnNonce 1 |
| Pilot wallet | 2,799,939,948 (27.99939948 GSMH): 30 − 2 in the vault − lock fee 16,986 − two 546 markers − release fee 41,974 |
| L2 key | 0.2991537 BLCH left (deploy + mint + burn) |

## For the DEX listing (wGSMH/WBLCH)

Token `0xB2B4952b6E57e589109aF764859886e236798AD4`, runtime code keccak
`0xa7602699759ecff36f21ef98bcd31f8a2f3cd82b79ca742472978a6455c0a7d5`, decimals 8,
`bucketCapacity()` = 1,000,000,000, so the DEX cap (bucket/10) is 100,000,000 = 1 wGSMH.
2 wGSMH are on `0x4630…22D9` for the test.

## Notes

- Depth N = 30 blocks validates the flow only; with few miners it is not security.
- A single-branch vault has no recovery path: the 2 GSMH left depend on the 2-of-3 pilot signers alone.
- On the mainnet line (main 820c102) policy trees are consensus from the PoWit height (10,000), which mainnet has
  passed, so a two-branch vault with timelocked recovery is now possible on mainnet for anything beyond the pilot.
- The signers run on one host here (rehearsal); a real signer set runs one machine per signer with its own GnB node.
