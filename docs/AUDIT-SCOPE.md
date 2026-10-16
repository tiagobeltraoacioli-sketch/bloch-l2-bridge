# Audit scope: Bloch bridges (bUSDC ↔ Ethereum, wGSMH ↔ GnB-SMH), audit candidate 2026-10-16

Branch `release/bridge-audit-candidate-20261016` of `bloch-l2-bridge`. It merges the mainnet line
(`feat/pontes-mainnet`: v1.1 tokens, guardian, deploy tooling, stablecoin vigia), the Ethereum half and
shadow-mode guardian line (`feat/pontes-eth-half`, `feat/pontes-shadow-guardian-20261016`), the reserves monitor
(`feat/pontes-reservas-20261016`), the wGSMH pilot (`feat/pontes-gsmh`) and the vault line
(`feat/vault-shadow-guardian-20261016`: context binding, one-way light-client switch, SP1 verifier, guardians).
The merge changed no behaviour. The integration commit removed the byte-identical test copies of the vault and
the SP1 verifier and added the vault's guardian policy to the bUSDC deploy config. Everything here is
UNAUDITED.

## 1. Contracts in scope

Naming: the coin and chain are **GnB-SMH**. Its native ticker is **GSMH**; the wrapped L2 token is **wGSMH**
("Wrapped GnB-SMH", fixed in `WrappedGnBV2`'s constructor). Kept on purpose as protocol or code identifiers:
the EIP-712 domain name `Bloch wGnB`, the release marker tag `GNB-RELEASE-v1`, chain ids `0x474E0001/2`, `gnb1`
addresses, `gnb_*` config keys, the `wgnb` bridge kind and paths, and the legacy v1 `WrappedGnB` (symbol `wGnB`,
devnet only).

Solidity 0.8.24, optimizer 200 runs, `evm_version = shanghai`, `bytecode_hash = none` (`foundry.toml`). LOC =
non-blank, non-comment lines.

| Contract | File | LOC (total) | Last commit | Chain | Role |
| --- | --- | --- | --- | --- | --- |
| `ContextBoundSourceVault` | `contracts/usdt/ContextBoundSourceVault.sol` | 443 (544) | `a5d039a` | Ethereum | USDC custody. Committee-certified releases bound to chain, vault, Ethereum anchor block and Bloch L2 finalized block. Fixed per-window release limit. One-way switch to a proof verifier. Guardian pause. |
| `SP1ReleaseVerifier` | `contracts/usdt/SP1ReleaseVerifier.sol` | 36 (60) | `dc1d8fc` | Ethereum | Adapter between the vault's `IReleaseVerifier` and a version-pinned SP1 verifier. Pins `programVKey`, `trustAnchor`, `l2ChainId` and `l2Token`. |
| `SignerMintedToken` | `contracts/bridged/SignerMintedToken.sol` | 274 (336) | `da4a26c` | Bloch L2 | Shared core of the v1.1 tokens: k-of-n EIP-712 mints, token bucket, queued large mints, supply cap, expiring pause-only guardians, burns. |
| `BridgedStablecoinV2` | `contracts/stable/BridgedStablecoinV2.sol` | 59 (76) | `da4a26c` | Bloch L2 | bUSDC: one vault route (`sourceVault`, `sourceRoute`). Burns map to vault `Release` items. |
| `WrappedGnBV2` | `contracts/wgnb/WrappedGnBV2.sol` | 42 (62) | `de067dc` | Bloch L2 | wGSMH (name and symbol set in the constructor). GnB-SMH chain id is pinned. |

Out of scope, but pinned and listed for completeness:

| Item | Notes |
| --- | --- |
| `contracts/sp1/v6.1.0/SP1VerifierGroth16.sol`, `Groth16Verifier.sol`, `contracts/sp1/ISP1Verifier.sol` (`e5aa162`) | Vendored from Succinct `sp1-contracts` v6.1.0, unmodified. The vault must point at this version-pinned verifier, never at the owner-controlled gateway. |
| Light-client programs (repo `bloch-sis-pow`, branch `codex/bloch-lc-20261014`, `crates/bloch-light-client`, commits `49691b43` and `9cdef9b7`) | SP1 guests `step` and `release` plus the host `lc` and `lc_prover.py`. They need their own review: the soundness of the switch depends on them. |
| `USDTSourceVault`, `L2BlochBridge`, Chameleon, WBLCH, v1 tokens, Rust custody/evidence tooling | Earlier lines; not deployed by this candidate. |

## 2. Off-chain components in scope

| Tool | File | Lines | Last commit | Authority |
| --- | --- | --- | --- | --- |
| Stablecoin signer, Bloch half | `tools/signatario-stable/signatario.py` | 601 | `3ee7c49` | L2 mint key (k-of-n). Rebuilds the L2 from L1 data before certifying a burn. |
| Stablecoin signer, Ethereum half | `tools/signatario-stable/eth_half.py` | 326 | `3ee7c49` | Ethereum release key (k-of-n). Pins the vault code, uses `finalized` only, recomputes `releaseDigest`. |
| Stablecoin automation | `tools/signatario-stable/vigia.py` | 307 | `3ee7c49` | Calls the signer. The relayer holds only gas keys. |
| GnB-SMH signer and automation | `tools/signatario-gnb/signatario.py`, `vigia.py` | 438, 243 | `da4a26c`, `f6de7ab` | Same pattern for wGSMH. |
| Guardian (fast path) | `tools/guardiao/guardiao.py` | 626 | `28cd313` | Pause only: token `pause()` and vault `guardianPause()`. Each uses its own key. |
| Guardian (proof path) | `tools/guardiao/sombra.py` | 276 | `5b98d79` | Pause only: vault `guardianPause()`. |
| Reserves monitor | `tools/reservas/reservas.py` | 164 | `29323e0` | None (read-only). |
| Mainnet deploy tool | `tools/deploy-pontes/deploy_pontes.py` | 713 | `07ccb69` | Deployer key, single use. |

## 3. Trust model

1. **Ethereum → L2 (deposit → mint).** A k-of-n committee of L2 keys mints bUSDC for a `Deposited` event that
   is final on Ethereum (`finalized`). Mints are bounded by the token bucket and the supply cap. Mints above
   `largeMintThreshold` are queued for `largeMintDelay`.
2. **L2 → Ethereum (burn → release), committee mode (now).** A `threshold`-of-n committee of Ethereum keys
   (2-of-3 in the rehearsals; the plan is 5-of-7) signs a release certificate. The certificate binds:
   - chain id and vault;
   - an Ethereum block the signer saw as finalized, checked on-chain with `blockhash`, so it is valid only
     on that fork and within 256 blocks;
   - the Bloch L2 block holding the burn, final under native FFG;
   - `validUntil`.
   Releases are capped at `windowLimit` per `windowSeconds`. A colluding quorum can drain at most that much
   per window.
3. **One-way switch to the light client.** `switchThreshold` signers (at least `threshold`; 3-of-3 in the
   rehearsals) propose an `IReleaseVerifier`, pinned to its code hash. Anyone activates it after
   `switchDelay ≥ 7 days`, unless the same quorum cancelled it.
   - After activation, `release()` reverts `CommitteeRetired` forever.
   - Releases then need `releaseWithProof`: an SP1 Groth16 proof that the burn is final under Bloch L1 FFG,
     starting from the one-time `trustAnchor`.
   - The committee can no longer disable releases. Per-window limits still apply.
   - There is no recurring signature.
4. **Guardians (committee mode only).** The guardians are fixed in the constructor: at most 7, sorted, never
   a signer.
   - `guardianPause()` stops `release()` and `deposit()` for `pauseDuration`. The pause expires by itself
     and may be renewed only after it ends.
   - Only `switchThreshold` signers may end it early (`unpause`, bound to `pauseCount`). Guardians then wait
     `pauseCooldown`. A guardian can never release or unpause.
   - `releaseWithProof`, `setControls` and the switch never stop.
   - After the switch, guardians have no power and `paused()` is false.
   - Two independent watchers hold guardian keys:
     - `guardiao.py` pauses on a release with no matching L2 burn, or on reserves below supply; detection
       takes about 30 min.
     - `sombra.py` pauses on a release not proven by the light-client prover within its grace. It checks
       the proof itself with `eth_call` on a deployed, never-activated `SP1ReleaseVerifier`.
5. **L2 token guardians.** These are `SignerMintedToken` guardians: they can pause mints only. Burns and
   transfers never stop. The pause expires, `pauseCooldown ≥ pauseDuration`, and k signers may unpause.
6. **Reserves monitor.** `reservas.py` compares, at finality, the vault backing
   (`min(totalLocked, balanceOf)`) or the GnB-SMH vault UTXO sum with `totalSupply + pendingSupply`. It only
   alerts.

## 4. Invariants to check

Vault (`ContextBoundSourceVault`):
- **V1. Backing.** `token.balanceOf(vault) ≥ totalLocked` after every call. A donation never creates
  deposit credit. A release pays exactly `amount` and lowers `totalLocked` by `amount` (exact-delta checks,
  including fee-on-transfer and false-success tokens in `transferMode`).
- **V2. Single release.** Each `nonce` and each `nativeBurn` is released at most once, across both
  `release` and `releaseWithProof`.
- **V3. Release domain.** A certificate's digest commits to `block.chainid`, the vault, `releaseId`, the
  Ethereum anchor, the L2 block and `validUntil`. Check that it cannot be replayed on another vault, chain
  or fork, or after `validUntil`. Control, switch and unpause digests are separated by their domain tags.
- **V4. Throughput.** `windowReleased ≤ windowLimit` for each window, on both release paths.
- **V5. Switch.**
  - At most one pending proposal.
  - Activation only after `verifierActivatesAt` and only with the proposed code hash unchanged.
  - Activation is irreversible.
  - Afterwards: committee `release` always reverts, and `setControls` cannot disable releases.
  - Only an exact `verifyRelease.selector` return accepts a proof.
- **V6. Guardians.**
  - Only a guardian pauses, and only before the switch.
  - No stacking: a pause cannot be started while one is active.
  - Deposits and committee releases revert `Paused` exactly while `block.timestamp < pausedUntil` and the
    verifier is unset.
  - `unpause` needs `switchThreshold` and the current `pauseCount`.
  - The cooldown applies only after an `unpause`.
  - No guardian path moves funds or changes any other state.
- **V7. Immutables.** No upgrade, owner, signer rotation, rescue or mint path. Everything listed as
  immutable stays fixed.

Light-client adapter (`SP1ReleaseVerifier`):
- **S1.** Public values must equal `abi.encode(trustAnchor, l2ChainId, l2Token, block.chainid, vault,
  releaseId)` byte for byte. A proof for another vault, chain, token, anchor or release fails.
- **S2.** The SP1 verifier is the version-pinned Groth16 verifier, not the gateway.

L2 tokens (`SignerMintedToken`, `BridgedStablecoinV2`, `WrappedGnBV2`):
- **T1.** `totalSupply + pendingSupply ≤ supplyCap`. The bucket never exceeds capacity and refills linearly.
- **T2.** Each deposit/lock id mints at most once, whether direct or queued then executed.
- **T3.** Queued mints execute only after `readyAt` and not while paused. Guardians cannot cancel or redirect
  them.
- **T4.** Burns are never paused. `burnId` is unique. Stablecoin burns produce exactly the vault `Release`
  fields: `route`, `nonce`, `recipient`, `amount`, `nativeBurn`.
- **T5.** The EIP-712 domain (version "2") and the k-of-n signature checks: signatures sorted and distinct,
  low-s, signers only.

Cross-system:
- **X1.** At finality on both sides, an honest bridge has backing ≥ supply + pending
  (`tools/reservas`). The gap is in-flight burns plus unminted deposits.
- **X2.** Signers release only after the L2 burn is final, and mint only after the source deposit is final.

## 5. Known limitations

- **Synthetic anchor, two-period limit.** Until the L1 roster leaf (0x23) activates at epoch 12288
  (~2026-10-22), the light client runs from a synthetic anchor. That anchor commits only the rosters of its
  own period and the next, and steps cannot advance, so only burns settled within about 4.5–9 h of the
  anchor can be proven (64 s epochs, 256-epoch periods). Vault v3 (anchor e3974) can no longer prove burns
  settled after epoch 4350. Because the switch is one-way and the committee is retired, new v3 burns would
  have no exit. The definitive run uses the real anchor.
- **Release window.** The per-window limit resets `windowSeconds` after the first release of a window. It is
  not a token bucket, so up to 2 × `windowLimit` can leave around a window boundary. The L2 tokens use a
  token bucket.
- **Ethereum side tested only on anvil.**
  - All Ethereum-side rehearsals ran on a local anvil (chain id 11155111, port 18950), not on a public
    testnet.
  - The shared anvil's clock was moved about 14 days ahead by switch drills. Signers then need
    `eth_clock: chain`, because `validUntil` is compared with `block.timestamp`.
- **Guardian grace windows.**
  - `guardiao.py` measures its grace in L2 block time, and L2 blocks are about 10 min apart, so a release
    without a burn is paused after about 30–40 min.
  - `sombra.py` waits for its grace (2 h in the rehearsal) because a proof takes about 30–35 min on one host.
  - Losses before a pause are bounded by `windowLimit`.
- **L2 RPC.** The settled devnet4 RPC has no `pending` level. L2 transactions from tools are offline-signed
  legacy transactions with fixed gas (`l2_raw_tx` in `guardiao.py`).
- **Devnet residues.** These come from the drills; they are not accounting bugs.
  - Vault v4 (`0xe6e340d1…`) holds 10 USDC against 14 bUSDC: a deliberate unbacked release of 4 USDC.
  - Vault v5 (`0x70e0ba84…`) is paused, with 3 USDC released without a burn and deposits never minted.

## 6. Live evidence index

Ethereum = anvil 11155111 on 45.77.142.123:18950. L2 = Bloch devnet4 (700771). GnB-SMH = GnB-SMH mainnet.

**v3: switched to the light client, release by a real Groth16 proof**

| Item | Value |
| --- | --- |
| Vault | `0xc6e7df5e7b4f2a278906862b61205850344d4e7d`, created in tx `0xa5b2fa5bcea5a1ed41197e06bd18bd7a8c25d7b1bda2eb248834e8988ce3cce3` (block 47792) |
| bUSDC | `0x1b7c0fb59f34683cd9214566636e63a0f7e092f6`, deploy tx `0x8e04b93e074d5e6cb6ce1c0958df861d74ae17fc111b186eb9017209f085b37a` (L2 384) |
| Controls on | `0x4031a7246209b3c3bc46d146bcd702627b40021337ff9468237f34b6b39830bb` (47794) |
| Deposit | `0x851ea619ce667184622567d248c85f99fa4a6cc8f3ecdb78af353da6a571b5a3` (48104) |
| Verifier proposed | `0x619a3563297a146b76493b3fc5e4ed680605b6bd73421dead08bcd4b1f3e631b` (48447), `SP1ReleaseVerifier` `0xa85233c63b9ee964add6f2cffe00fd84eb32338f`, trustAnchor `0x97f608a0a745e3a426d08fa2c3a63a1df27a9f3b537ea57f27f8d40637f70bd7` |
| Verifier activated | `0x3f80ab0def502809c18d5e7bd4831c24762710314109f1c1e51e807df233efb0` (48450) |
| Burn | `0xeb2bbe6592aa053bac3f9b0324017fd7dd98a0accf350104ecda678353173367` (L2 386) |
| `releaseWithProof` | `0x7152bee6808e96a7b5ac1f0c00191042f11209572726085ce8a9734de4e32c7d` (54981), 388,007 gas |

**v4: shadow mode, proof path**

| Item | Value |
| --- | --- |
| Vault | `0xe6e340d132b5f46d1e472debcd681b2abc16e57e` |
| bUSDC | `0xcf88b5c66c576b25499f40c37e7ea0dfdc9d6dc9` |
| Shadow verifier | `0x9e545e3c0baab3e08cdfd552c960a1050f373042`, trustAnchor `0x08a6a1f6b5b410a543a1b17a24ffecde9331539e3e8a86af1ca00a74b1010a5c` |
| Deposit | `0xeb629267d1c12fa76605f67e10ab2fb6cfa7e977b1747ebf082cf318868eba6f` (56102) |
| Mint | `0xfea1d0454a4cbbc8d09a46e5fb5ae77e0721de27758eab8f833fe3df96fb437a` (L2 410) |
| Burn | `0x734d02b086509621d99985af4068da7d8749cdb05570d2388b83b0124d268920` (L2 411) |
| Committee release | `0xcc770441815ee3b02a6101c6ca58341fcc20c7d3adda6723fe40f0f10dcc8397` (57453); proven later, releaseId `0x0ee13a5c6748ed866a328a7b45c06a52a2361085e187fa6c13118f66a5df4270`, 1982 s of proving |
| Unbacked release (drill) | `0xaa702bf3e9a48d44d4af60d0c64bcb1bc5c29ee3b1503bede6279162ee124e6b` (57496) |
| `sombra.py` pause | `0xd2cdaaeda1205c7fa95897bab28209749d774892aa309684f3339131f6624eaf` (61114), 53,255 gas |

**v5: both guardians, fast path**

| Item | Value |
| --- | --- |
| Vault | `0x70e0ba845a1a0f2da3359c97e0285013525ffc49` |
| bUSDC | `0xb62c62e27082f0a5b1a9ed7e47d4e4a0b1ae8bf2` |
| Deposit | `0x85b95eeb8f587b47da5ad2bca68164e5a6f56de0b69644327f4d7bc6072503d2` (72577) |
| Unbacked release (drill) | `0x954597b60121994422640bf235f193854e1c147f5810dd1f46fbed55fe6113e5` (72583) |
| `guardiao.py` vault pause | `0x7966ef7abb073f5e5bf4eaa7471266cb4f8340cbdade525f63d49dc6aed9bbe6` (73525), 1887 s after the release |
| Token pause | `0x1036283630591a49e1e68e386568ebf0b2d3e0337af4c0bea9678c24cb58e19e` (L2 462) |
| Deposit after expiry | `0x19098266930f20fe89ab024485147d7e3193bff96d9165ab2035083b93081dd5` (74128) |
| `sombra.py` renewal | `0xfb0170fe82856b9120a53c311fe5b46e2e41aec63ce24d2a9b6feb4afc5cebe4` (74129) |

**v6: automatic signers and relayer (vigia daemons), guardian silent**

| Item | Value |
| --- | --- |
| Vault | `0x5f3f1dbd7b74c6b46e8c44f98792a1daf8d69154` |
| bUSDC | `0x99f14f1e09c0abbce1848fb66e31f2c4c40909c4` |
| Deposit | `0xc78fe77a8b0101f9251d454f00c9906656c1d941fd8152aafd7c38f7c8081cd9` (75307) |
| Mint | `0x3643626004b18ab2c876ebad515468a38c896900a5b4452b4f3e2113d6408a3c` (L2 466) |
| Burn | `0xbd9fa4be5cd3644d15f0755d64e74258b93378197173ae4cbe4f9c431561bfce` (L2 467) |
| Release | `0xa0019c6aaef36be604b21bbde9858938a0fb049476bf4afee9a50f8b8a2d2d88` (76577), 171,017 gas |
| Guardian | 0 alerts, 0 pauses |

**wGSMH pilot (GnB-SMH mainnet ↔ devnet4), details in `docs/PILOT-WGSMH-MAINNET-20261016.md`**

| Item | Value |
| --- | --- |
| Token | `0xB2B4952b6E57e589109aF764859886e236798AD4`, deploy tx `0xc251d28a528c5c44d70aa3636371ff9c9fd1b730b6ecf4b85d0996f317ba4cb1` (L2 421) |
| GnB-SMH lock | `ae3b6e6e49e4d6cffeee08e06a74eade9acfa66913e0fd7d54fc925a5189926d` (GnB-SMH 14641) |
| Mint | `0x1ab44db21c5ec05917fa2f8e90d18a05e058e847d98287b6c9b483ef4562698a` (L2 425) |
| Burns | `0xa03a4e6b9696e9beee88d580fe345d657f96ee9bc05fde564d08e4829f82ce50` (L2 425) and `0x0b535068b902a05b6ea9d257b9289874242adb5a78a3cb87e6af8acab4a059fb` (L2 438) |
| GnB-SMH releases | `8bb33a9a35364501b0cbe9885520ca3ebbe2aa6a4bc2a4142ca7776a5a0da78f` (GnB-SMH 14714) and `4d9e17856583055d5b34e0e32f22e197d83a2b946c649b4c1301a28451182643` (GnB-SMH 15034) |

**Reserves, 2026-10-16 (`tools/reservas`)**

| Bridge | Backing | Liabilities | Result |
| --- | --- | --- | --- |
| wGSMH | GnB-SMH vault 68,295,768 sat | 68,295,768 | ok |
| bUSDC v3 | 21,000,000 | 21,000,000 | ok |
| bUSDC v6 | 3,000,000 | 3,000,000 | ok |
| bUSDC v4 | 10,000,000 | 14,000,000 | deficit of 4 USDC (drill) |
| bUSDC v5 | 8,000,000 | 0 | surplus (deposits never minted) |

## 7. How to run the suites

From a clean checkout with Foundry in `~/.foundry/bin`:
- `forge test`
- `python3 tools/<tool>/test_*.py .`, for `guardiao` (`test_guardiao`, `test_sombra`), `reservas`,
  `signatario-gnb` and `signatario-stable` (also with `ETH_HALF=real` for the production Ethereum half)
- `python3 tools/deploy-pontes/rehearse_anvil.py`

Results for `eba8e02`, from a clean clone on 45.77 (Foundry stable, anvil):

| Suite | Fake / default | `ETH_HALF=real` |
| --- | --- | --- |
| forge (11 suites) | 141 passed, 0 failed, 1 skipped | |
| `guardiao/test_guardiao` | 32/32 | 32/32 |
| `guardiao/test_sombra` | 18/18 | 18/18 |
| `reservas/test_reservas` | 14/14 | 14/14 |
| `signatario-gnb/test_signatario` | 15/15 | 15/15 |
| `signatario-gnb/test_vigia` | 16/16 | 16/16 |
| `signatario-stable/test_signatario` | 23/23 | 34/34 (production `eth_half.py`) |
| `signatario-stable/test_vigia` | 26/26 | 26/26 (production `eth_half.py`) |
| `deploy-pontes/rehearse_anvil` | 56/56, `REHEARSAL OK` | |

`ETH_HALF=real` changes only the two `signatario-stable` suites; the other suites run the same code in both
columns.
