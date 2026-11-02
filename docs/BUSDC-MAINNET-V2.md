# bUSDC on the Bloch L2 mainnet with the v2 L2 build: configuration, deployment sequence, hosts

Status 2026-10-30, branch `codex/bridge-busdc-mainnet-v2-20261030` (from
`release/bridge-audit-candidate-20261016` @ `6abbaf8`). Nothing here deploys, installs or sends anything.
Every contract and tool is **UNAUDITED**. Every Ethereum and L2 transaction below is run by the owner (or the
named operator), never by an agent.

## 1. What changed from the audit candidate

| Area | Change |
| --- | --- |
| Bridge review | Contracts changed (section 9): the vault refuses a deposit above `windowLimit` or without an address-shaped recipient, and bUSDC refuses a burn above `bucketCapacity`, because each could never complete and has no refund. The release limit is a token bucket, guardian renewals are bounded and verifier proposals expire. Runtime code hashes differ from 8678454. |
| L2 build | The signer and the watchers target the L2 v2 build: bloch-l2-evm `1aad0a20` against native `78d4921c` (HF1+HF2+HF3 armed; correct for the L1 fleet on `fa980367`). Binaries of that v2 build: follower `c18752fd…f29a`, produce-dev `7c1cc62b…3a3c`, settled-rpc `4fc9fa1e…4534`; the signer now pins the provisional v2.1 build, see section 9. Chain 700770, native network `f47d3e49…1966`, L2 genesis `632e45ae…f468`. |
| Signer (release) | `l2_pins: "mainnet-v2"` (`tools/signatario-stable/l2_finality.py`): binary SHA-256 pins, v2 follower status checks, mainnet network rules and timestamp rule for the rebuild and the private settled RPC, rebuild must equal every finalized settlement, HF1 claim-finality rule (section 2), optional L1 RPC cross-check. |
| `guardiao.py` | Keeps watching when the v2 RPC serves `finalized` = null; new `release-before-final` finding; `l2_genesis_hash` pin. |
| `sombra.py` | `lc_max_epoch`: releases the deployed light-client programs cannot prove (programs built before an L1 fork) are soft alerts, never pauses. |
| `reservas.py` | `l2_genesis_hash` pin. |
| Ethereum vault | New `tools/deploy-pontes/vault_pontes.py` (validate / args / verify) and `deployments/mainnet/busdc-vault-mainnet.config.json`; rehearsed in `rehearse_anvil.py` section 3. |
| Configs | `deployments/mainnet/busdc-mainnet.config.json` now carries the L2 genesis hash and the TBD-owner list; per-role templates in `deployments/mainnet/busdc-ops/`. |

## 2. When a burn is final enough to sign (HF1 claim-finality semantics)

The L1 hard fork HF1 (`HF1_CLAIM_FINALITY_EPOCH` = 7180, 2026-11-01 16:11 UTC) changes when an L1 claim
against an L2 settlement is valid (`transition/l2_claim.rs`, `l2_record_finalized_for_claim`):

1. the settlement's accepting native block is inside the FFG-finalized prefix (its slot is below
   `finalized_epoch × 32`); and
2. from the gate on, the finalized checkpoint is this chain's own: `checkpoint_root(finalized.epoch) ==
   finalized.root`, from the committed `CHECKPOINT-ROOTS` state section. Own roots are recorded only from
   the gate epoch, so right after it nothing is claimable until a checkpoint of epoch ≥ 7180 finalizes
   (about 2 epochs, ~32 min).

The bridge signer applies the same predicate to the L2 block that holds a burn. `signatario.py release`
refuses unless all of these hold:

| Check | Where |
| --- | --- |
| The follower, produce-dev and settled-rpc binaries hash to the pinned v2 build | `check_binaries` |
| Follower status: schema `bloch.l2.native-follower-status.v2`, network `f47d3e49…`, chain 700770, `production_finality` false, fresh (`max_status_age`, default 600 s), L2 genesis `632e45ae…` final, finalized slot below its epoch boundary, settlements contiguous from 1 and each inside the finalized native prefix | `check_status` |
| `produce reconstruct` ran with `--timestamp-rule 1:1786656679:30000 --rules mainnet --domain 1c3f8772… --genesis-time 1786656679`, rebuilt the pinned genesis and reproduced the hash and state root of every finalized settlement | `own_l2`, `check_rebuild` |
| The private settled RPC (same network arguments) serves the follower's finalized level; the burn receipt is in a block ≤ finalized whose hash matches | `own_l2`, `finalized_burn` |
| The burn block is covered by a finalized settlement (same hash when it is the settled block itself) | `require_settled_final` |
| From epoch 7180 (by wall clock or by the follower's verified slot) the follower's finalized epoch is ≥ 7180 | `require_claim_final` |
| Optional `l1_rpc_urls`: each node follows the same network/chain, reports `withdrawals.finalized_checkpoint` after the gate, and never `own_root != root` while `own_chain_rule_active` | `l1_cross_check` |

The follower replays FFG on its own chain and reports only a finalized checkpoint that is its own chain's
block at that epoch, so condition 2 holds by construction on the signer's side; the extra rule is the
one-time pause. The certificate is unchanged: the vault context still binds the burn's L2 block
(`nativeFinalizedNumber/Hash`). The certificate's `l2.finality` field records the covering settlement,
the native finalized checkpoint and the claim-finality view.

Live check (read-only, 2026-10-30, `getl2settlement` on 80.240.16.185): `finalized_checkpoint` is
present with `own_root: null` and `own_chain_rule_active: false` (pre-gate), `profile.user_transactions:
true`, `accepted: null` (the L2 has never been settled).

## 3. Prerequisites outside this repository

- **The L2 mainnet must settle.** Today `accepted` is null and the L2 head is its genesis. A burn can be
  certified only once its L2 block is in an accepted settlement inside the finalized prefix. Settler,
  prover and attestors are another workstream; until they run, the bridge can mint (deposits need only
  Ethereum finality and an L2 that includes the mint) but **cannot release**. Do not enable deposits
  before settlement works end to end.
- Every L2 host (signers, guardians) runs the v2 build before epoch 7178 (2026-11-01 15:39 UTC).
- Light client (proof path): not on mainnet. The deployed programs predate HF1 (roster must come from the
  frozen finality set) and HF2 (bound signature form at 7270). `sombra.py` runs with `lc_max_epoch: 7180`
  until the LC port and a re-anchor; the one-way switch must not be proposed before that.

## 4. Deployment sequence (owner-run)

Order: decisions → Ethereum vault (controls off) → L2 token → signers, relayer, guardians, monitor →
disposable-value rehearsal on mainnet → controls on. Run from a clean checkout of the reviewed revision
with Foundry installed (the suites ran with forge 1.7.1). `ETH_RPC` is the owner's own Ethereum node,
`L2_RPC` the owner's own settled RPC.

### 4.1 Decisions and review

Fill every `null` in `deployments/mainnet/busdc-vault-mainnet.config.json` and every `TBD-owner` in
`deployments/mainnet/busdc-mainnet.config.json` (section 7). Fill `ethereum.vaultGuard` of the L2 config
with the two Ethereum guardian addresses (sorted ascending) before the vault exists; the rest of
`ethereum` comes from step 4.4. Review both as a pull request.

### 4.2 Validate the vault config and derive the constructor arguments

```
python3 tools/deploy-pontes/vault_pontes.py validate --config deployments/mainnet/busdc-vault-mainnet.config.json --token-config deployments/mainnet/busdc-mainnet.config.json
```
```
python3 tools/deploy-pontes/vault_pontes.py args --config deployments/mainnet/busdc-vault-mainnet.config.json
```

The second command prints `constructorArgs` (ten values) and the `forge create` line. A second reviewer
runs both and compares `configSha256` and the arguments.

### 4.3 Deploy the vault (deposits and releases start disabled)

Bloch Inc's Safe sends the deployer only the gas (a mainnet-shaped vault creation, 7 signers and 2
guardians, used 3,351,987 gas on anvil; at 30 gwei that is ~0.101 ETH, so send 0.15 ETH). Then, with the ten arguments from 4.2 in order (`ARG1` … `ARG10`):

```
forge create --rpc-url "$ETH_RPC" --ledger contracts/usdt/ContextBoundSourceVault.sol:ContextBoundSourceVault --constructor-args "$ARG1" "$ARG2" "$ARG3" "$ARG4" "$ARG5" "$ARG6" "$ARG7" "$ARG8" "$ARG9" "$ARG10"
```
```
forge create --rpc-url "$ETH_RPC" --ledger --broadcast contracts/usdt/ContextBoundSourceVault.sol:ContextBoundSourceVault --constructor-args "$ARG1" "$ARG2" "$ARG3" "$ARG4" "$ARG5" "$ARG6" "$ARG7" "$ARG8" "$ARG9" "$ARG10"
```

`windowLimit` must equal the token's `bucketCapacity`, `l2MinBurn` its `minBurn`, and the cap its `supplyCap` (`validate --token-config`). The first is the dry run. Note the address (`VAULT`) and the block. A creation that does not land as
planned is not repaired: new deployer key, new review.

### 4.4 Verify at Ethereum finality (~13 min later)

```
python3 tools/deploy-pontes/vault_pontes.py verify --config deployments/mainnet/busdc-vault-mainnet.config.json --rpc "$ETH_RPC" --address "$VAULT" --unused
```

It must say `verified`. `--unused` refuses a vault that has taken a deposit: **a token never goes over a used vault.** Copy `busdcEthereum` into `ethereum` of `busdc-mainnet.config.json` and `ethHalf`
into every signer's `eth-half.json`. `state.depositsEnabled` and `state.releasesEnabled` are `false`.

### 4.5 Deploy the L2 token

**One token, one vault, for life.** Never point a new token at a vault that has taken a deposit, including for a migration or a change of
parameter. Its signers would mint the old deposits a second time with no contract or guardian finding, and its burn nonces restart at 1,
so a burn collides with `releasedNonce` and cannot exit (`docs/AUDIT-SCOPE.md`, section 5). A new token gets a new vault.

Follow `docs/BRIDGES-MAINNET.md` section 4 (steps 2–9) with `deploy_pontes.py`: `validate`, `plan`
(second reviewer regenerates), `rehearse_anvil.py` = `REHEARSAL OK`, dry `run` against `L2_RPC`,
`run --broadcast --confirm <configSha256>`, `record`, then after L2 finality:

```
python3 tools/deploy-pontes/deploy_pontes.py verify --config deployments/mainnet/busdc-mainnet.config.json --plan deployments/mainnet/busdc.plan.json --rpc "$L2_RPC" --record deployments/mainnet/busdc.deployment.json --source-rpc "$ETH_RPC"
```

L2 finality needs an accepted, finalized settlement of the deployment block (section 3).

### 4.6 Signers, relayer, guardians, monitor

Per operator, from `deployments/mainnet/busdc-ops/*.template.json`: fill the TBD-owner values from the
two deployment records; keystores and password files are created by each operator on its own host and
never leave it. Before going live, each signer runs a dry check that must refuse only because the burn
does not exist (every pin, the rebuild and the private settled RPC pass):

```
python3 tools/signatario-stable/signatario.py --config /etc/bloch-busdc-signer/signer.json release --burn-tx 0x0000000000000000000000000000000000000000000000000000000000000001 --out /tmp/busdc-dry.json
```

Expected: `"reason": "the burn transaction is not in this L2"`. Then the daemons (`vigia.py sign`,
`vigia.py relay`, `guardiao.py watch`, `sombra.py watch`, `reservas.py watch`) under the operators' own
service managers.

### 4.7 Enable deposits and releases (5 of 7 release signers)

Choose `VALID_UNTIL` (unix time, e.g. one hour ahead), then read the digest:

```
cast call "$VAULT" "controlDigest(bool,bool,uint64,uint256)(bytes32)" true true 0 "$VALID_UNTIL" --rpc-url "$ETH_RPC"
```

Each of five release signers signs it on their own machine (`--ledger` or their keystore):

```
cast wallet sign --no-hash --ledger "$DIGEST"
```

Anyone submits the five signatures ordered by signer address, ascending:

```
cast send "$VAULT" "setControls(bool,bool,uint64,uint256,bytes[])" true true 0 "$VALID_UNTIL" "[$SIG1,$SIG2,$SIG3,$SIG4,$SIG5]" --rpc-url "$ETH_RPC" --ledger
```

Do this only after a disposable-value round trip worked (10 USDC deposit → mint → burn → release), which
needs the controls on: so enable, rehearse with 10 USDC, and if anything is wrong disable with the same
three steps and `false false 1`.

### 4.8 HF1 window

Signers refuse new release certificates from epoch 7180 until the follower finalizes a checkpoint of epoch
≥ 7180 (~16:11–16:45 UTC on 2026-11-01). Do not schedule the go-live in that window.

## 5. Host specifications

**Signer host (7, one per operator)**, everything on one host per operator:

| Component | CPU | RAM | Disk | Notes |
| --- | --- | --- | --- | --- |
| Bloch L2 follower (v2) | 1 core sustained, 4 at start | 1 GB (peak RSS 0.6 GB measured) | 4 GB today (3.3 GB state for 181k L1 blocks), ~20 GB/year | Re-verifies all retained history from Genesis-4 on start: ~50–70 min today, growing with L1 |
| Rebuild + private settled RPC per release | 2 cores for seconds | 1 GB | temporary, a few GB once the L2 has history | Work dir under `work_dir`, removed after each release |
| Ethereum node (execution + consensus, full, not archive) | 4–8 cores | 32 GB | 2–4 TB NVMe (TLC, high IOPS) | `finalized` and `eth_getLogs` from the vault's block; the signer trusts only this node |
| signer, eth_half, vigia (Python 3.12, Foundry `cast`) | – | < 0.5 GB | < 1 GB | |
| **Total** | **8 vCPU** | **32 GB** (64 GB comfortable) | **4 TB NVMe** | 1 Gbps; no inbound port except the operators' choice for the shared partials |

Without a colocated Ethereum node (separate host of the same operator): 4 vCPU, 8 GB RAM, 100 GB SSD.
The follower reads L1 blocks from one Bloch L1 RPC and verifies them itself (an RPC affects liveness only);
use a different L1 RPC per operator and at least two in `l1_rpc_urls`. Keys: the L2 mint key and the
Ethereum release key are hot keystores (automatic signer), one per operator, on an encrypted disk, owned
by a dedicated user; the release key never signs anything but `eth_half.py` digests.

**Guardian hosts (2, independent operators)**: `guardiao.py` needs its own Ethereum node (as above) and
its own L2 RPC (follower + settled RPC; 4 vCPU, 8 GB, 100 GB on top). `sombra.py` additionally needs the
light-client prover (not before the LC mainnet port). `reservas.py` is read-only and can share the
guardian's nodes.

**Relayer**: any small host (2 vCPU, 2 GB) with gas keys only.

## 6. Tests and rehearsals (this branch)

| Suite | Result |
| --- | --- |
| forge (11 suites) | 141 passed, 0 failed, 1 skipped |
| `guardiao/test_guardiao` | 32/32 |
| `guardiao/test_sombra` | 19/19 (+1: `lc_max_epoch`) |
| `guardiao/test_guardiao_hf1` (new) | 7/7 |
| `reservas/test_reservas` | 16/16 (+2: genesis pin) |
| `signatario-gnb/test_signatario`, `test_vigia` | 15/15, 16/16 |
| `signatario-stable/test_signatario` | 23/23; `ETH_HALF=real` 34/34 |
| `signatario-stable/test_vigia` | 26/26; `ETH_HALF=real` 26/26 |
| `signatario-stable/test_hf1_finality` (new) | 56/56 (32 unit, 24 on private anvils) |
| `deploy-pontes/rehearse_anvil` | 75/75, `REHEARSAL OK` (56 as before + 19 for the vault tool, section 3) |

These counts are for `8347568`. Counts for the bridge review are in `docs/AUDIT-SCOPE.md` section 7.

Real-binary dry check (2026-10-30, the three pinned v2 binaries, a follower state at 186,671 L1 blocks and no L2
history, since the L2 has never settled): every pin and status check passed, with the status age limit relaxed to
one day, and `signatario.py release` refused only because the burn does not exist, after 41 s. No certificate has
been made on real L2 data.

## 7. TBD-owner

| Item | File / key |
| --- | --- |
| Reviewed source revision | both configs: `source.revision` |
| Fresh deployer keys (Ethereum vault, L2 token), nonce 0 | `deployer.address` (both) |
| Bloch Inc Safe address | `deployer.fundedBy.safe` (both) |
| 7 release signer operators and Ethereum addresses | vault config `vault.signers.set` |
| 7 L2 mint signer operators (addresses are set) | L2 config `signers.set[].operator` |
| 2 Ethereum guardian operators and addresses (guardiao, sombra), independent of every signer | vault config `vault.guard.guardians`; L2 config `ethereum.vaultGuard.guardians` |
| 3 L2 guardian operators (addresses are set) | L2 config `guardians.set[].operator` |
| Vault address, route, code hash, cap | L2 config `ethereum.*` (from 4.4) |
| L2 gas price cap | L2 config `tx.maxGasPriceWei` |
| cap, windowLimit, minDeposit (proposed 10 USDC), switchThreshold (proposed 6), switchDelay (proposed 14 d) | vault config (proposed values filled) |
| Feed base URL of each of the 7 operators (`docs/SIG-TRANSPORT.md`) | `feed.peers` (signer, relayer) |
| L2 RPC for mint pre-checks; L2 RPC for the guardian and monitor | `l2_rpc` |
| L2 send endpoint for the guardian and relayer: the public gateway, `https://l2rpc.blochl1.com` | `l2_tx_rpc` (decided; required on chain 700770) |
| Light-client prover and shadow verifier (after the LC port) | sombra `prover_dir`, `shadow_verifier` |

## 8. Open decisions

1. switchThreshold 6-of-7 and switchDelay 14 days (contract minimum 7 days), windowLimit 10,000 USDC/24 h.
2. Whether the Ethereum release keys must differ from the same operators' L2 mint keys (recommended).
3. Transport for partial signatures: per-operator read-only feeds, built. See `docs/SIG-TRANSPORT.md`, which also states the one setting to decide.
4. Where the guardians' independent L2 RPC comes from (the follower-rpc package installs on the settler
   host; a non-settler host needs a replica).
5. `release_before_final` soft (default) or hard on the fast-path guardian.
6. Items from the bridge review (2026-10-30), `docs/AUDIT-SCOPE.md` section 5: who pays relayer gas (`minBurn`) and
   the mint leg after the switch.

## 9. Bridge review, 2026-10-30 (`codex/bridge-review-20261030`)

Contracts:

- `ContextBoundSourceVault.deposit` refuses `amount > windowLimit` and a `pqRecipientHash` with non-zero high 12
  bytes. Before, a deposit above the token bucket or with no L2 address was accepted and could never be minted, and
  the vault has no refund.
- `ContextBoundSourceVault.deposit` refuses `amount < minDeposit` before funds move. `minDeposit` and `l2MinBurn` are immutable
  constructor values (`Policy`), proposed 10 USDC each. The constructor requires `l2MinBurn <= minDeposit <= windowLimit`.
  `validate --token-config` requires `l2MinBurn` to equal the token's `minBurn`, because the vault cannot read the L2. The token
  is unchanged. **UI limit:** a deposit must be between `minDeposit()` and `windowLimit()`, both read from the vault.
  Measured on the mainnet shape (7 signers, 2 guardians, private anvil): vault creation 3,351,987 gas, first deposit 85,647, next
  68,547; vault runtime 12,855 bytes, deployed keccak `0x92e361…0dc7` on that rehearsal (immutables differ per deployment); compiled
  keccak `0x86f74c…d142`. Token runtime unchanged: 7,928 bytes, deployed keccak `0xa1efec…1e48`.
- `BridgedStablecoinV2.burn` refuses `amount > bucketCapacity`. Before, a burn above the vault window was accepted
  and could never be released. A holder above the limit exits with several burns.

- The release limit is a token bucket (capacity `windowLimit`, full refill in `windowSeconds`) instead of a tumbling
  window, so no boundary lets 2x through.
- Each guardian starts one pause per chain of consecutive pauses (`pauseCooldown` apart starts a new chain). One key
  still pauses at once; another guardian can renew at once. Mainnet shape: at most 6 days frozen, then 3 days open.
  **Runbook consequence:** in a real incident the second guardian's operator must renew when the first pause ends.
  Until the LC port `sombra.py` will not do this by itself.
- A verifier proposal can be activated only within 30 days after its delay; then it expires and can be replaced.

Automation (`vigia.py`, `signatario.py`, `eth_half.py`):

- One item that reverts (a USDC-blacklisted recipient, for example) no longer stops every later mint and release.
- SHARED is really untrusted now: forged rounds, partials and `done`, `executed` or `sent` files are ignored.
- A relayed transaction with no receipt after `resend_after_s` is sent again.
- A transaction holding several burns (a smart wallet, Multicall3) is certified burn by burn (`--burn-id`).
- `eth_half.py` refuses while the vault is paused.
- A signer joins open rounds first and opens at most `max_new_rounds` per pass.
- `eth_getLogs` is chunked.

Guardian on a replica: `l2_rpc` may be read-only, and `l2_tx_rpc` takes the sends. A failed pause raises a critical alert, retries,
and marks the guardian unhealthy (`check` exits 4). Grace periods must exceed the settlement delay, because a replica does not show
unsettled mints: defaults on chain 700770 are now 2700 s (`tools/guardiao/README.md`, "Reads on a replica").

Watchers: a malformed answer is `unverifiable`, never a crash; `liveness-not-final` reports a burn that does not
become final within the SLA (L1 finality or L2 settlement stalled).

Tooling: `vault_pontes.py validate` requires the cap to equal `supplyCap`, `windowLimit` to equal
`bucketCapacity`, `l2MinBurn` to equal `minBurn` and `l2MinBurn <= minDeposit <= windowLimit`, and the whole cap to fit through the window within `switchDelay`.

Pins: `l2_finality.MAINNET_V2` holds the **provisional** v2.1 release (build commit `a39b04e`): settled-rpc
`18be911a…e83f`, produce-dev `fb0d5313…0be9`, follower unchanged. `SETTLED_RPC_PIN_PROVISIONAL` stays `True`, and signers
must not be deployed, until the owner signs that release. A signer on any other build refuses with
"the <role> binary is not the pinned build".
