# Bridge TRON → Bloch L2: USDT (TRC-20) ↔ `bUSDT.trx`

**UNAUDITED. Nothing is deployed, on any network. No real key was used.** Round 16, agent 323, branch
`codex/bridge-tron-r16-20261116` (from `cc2511a`). This bridge needs its own external audit before any real funds.

Companion files: `docs/TRON-VAULT-DIFF.md` (the vault as "the Ethereum vault plus five changes", platform
differences, USDT-on-TRON behaviour), `tools/signatario-tron/README.md` (the tools),
`deployments/tron/` (configs and `bridge.network.json`).

Contents: 1 what it is, 2 what differs from the Ethereum bridge, 3 the compiler, 4 finality, 5 fees, 6 keys and
ceremony, 7 deployment, 8 operator runbook, 9 tests and rehearsal, 10 audit note, 11 not done / not proven,
12 owner inputs.

## 1. What it is

A user deposits USDT on TRON into a vault (`contracts/tron/TronSourceVault.sol`). After the deposit's block is
solidified, 5 of the 7 committee keys attest it, and `bUSDT.trx` is minted on the Bloch L2 (chain 700770) after the
12 hour mint delay, 1:1 less 5 bps. Burning `bUSDT.trx` on the L2 is certified by 5 of 7 after L2 finality, and the
vault pays USDT on TRON less 5 bps. The fees accrue in the vault outside the backing and are swept to the owner's
address `TCQ2d5gxTczSeN2oeni16JwMW7HWLzXEKc`, which is a constructor argument.

| Piece | What | Reuse |
|---|---|---|
| L2 token | `BridgedStablecoinV3`, name "Bloch Bridged USDT (Tron)", symbol `bUSDT.trx`, 6 decimals | Byte-identical (creation keccak `0xe560441f…1de7`); constructor arguments only. `sourceChainId` 728126428, `sourceVault` = the vault's 20-byte address |
| Vault | `TronSourceVault` | `ProvenanceSourceVault` (the Ethereum vault, unchanged on this branch) plus five marked changes; `python3 scripts/tron/vault_diff.py` prints and pins the diff (43 lines added, 14 removed) |
| Committee | 7 secp256k1 signers (5 release, 6 unpause or switch), 3 guardians (pause only) | The same keys as the Ethereum bridge; `ecrecover` on the TVM. No new key type |
| Signer, relayer, guardian, reserves monitor | `tools/signatario-stable`, `tools/guardiao`, `tools/reservas` | Unchanged. New code: a read-only shim and a TRON sender (`tools/signatario-tron`, 1,287 lines without tests and rehearsal) |
| Limits | cap 100,000 USDT; window 10,000 per 24 h; minimum deposit 11; L2 minimum burn 10; mint delay 12 h for every mint (T = 0); guardian pause 72 h | The Ethereum bridge's launch values, proposed; the owner confirms |

Isolation: this vault backs only `bUSDT.trx`. Nothing here touches another bridge's backing.

Why USDT and not USDC on TRON: Circle stopped minting USDC on TRON on 2024-02-21 and lists no TRON contract
(sources in `deployments/tron/bridge.network.json`, `asset.verified`).

## 2. What differs from the Ethereum bridge, and matters for safety

1. **The issuer's token behaves differently.** USDT on TRON returns ABI `false` from every successful `transfer`,
   accepts transfers INTO a blacklisted address, and its owner can pause it, charge a transfer fee, destroy a
   blacklisted balance and redirect it to another contract (`deprecate`). The vault therefore runs only in
   transfer mode 1 (exact balance movement decides, the return value does not), refuses deposits while it is
   blacklisted or the token is deprecated, and keeps its books provable if its balance is destroyed
   (`docs/TRON-VAULT-DIFF.md` sections 1 and 3). **Accepted limit: Tether can stop exits for as long as it likes and
   can destroy the backing. No contract can prevent that.**
2. **Finality is "solidified"**, about a minute behind the head, served only by `/walletsolidity/*`. java-tron's own
   JSON-RPC has no `finalized`. A new component, the shim, maps `finalized` to the solidified API; every signer
   safety property now also depends on that mapping being right (section 4).
3. **The release anchor window is 13 minutes, not 51.** `blockhash` reaches 256 blocks back and TRON blocks are 3 s.
   A certificate not relayed within about 12 minutes of its anchor is dead and must be signed again. Dead
   certificates pay nothing.
4. **Transactions have no nonce and cannot be repriced.** The relayer's nonce reservation is replaced by a
   one-live-transaction journal (`tron_send.py`). A reverted TRON transaction still burns its energy, so the
   sender simulates first.
5. **The chain id is 728126428**, the last 4 bytes of the genesis block id, and only while chain parameter 71 is
   active. Every digest binds it. The same committee key signing for Ethereum (chain id 1) and for TRON cannot be
   replayed across: chain id, vault address and route all differ in the digest.
6. **The deployer account keeps three powers** that Ethereum has no equivalent of: it can change
   `consume_user_resource_percent` and `origin_energy_limit` and clear the stored ABI. None touches funds or
   logic. Deploy with 100 and 1 and never use the account again.
7. **The compiler** (section 3): the vault was built and rehearsed with stock solc only.

## 3. The compiler

**What was built and tested.** Every test and every rehearsal run in this document used the repository build:
stock **solc 0.8.24+commit.e11b9ed9** through Foundry 1.7.1, `evm_version = shanghai`, optimizer on with 1 run,
`bytecode_hash = none` (`foundry.toml`). Vault creation code: 23,549 bytes, sha256
`d9f6620ae8f298f590d8686bec5327ca03bd4b17e356155b00635c0860b843c2` (printed by the rehearsal). That bytecode
deployed and ran correctly on java-tron 4.8.2.

**What a real TRON deployment must use.** TRON's own distribution of the compiler, from
`https://github.com/tronprotocol/solidity`: release tag **`tv_0.8.24`**, release name `0.8.24_Kant_v4.8.0`,
published 2025-05-14, asset **`solc-static-linux`** (15,086,296 bytes; the release also carries `shasum.txt`,
`keccak256.txt` and `solc-static-linux.sig`). Its release note says it is fully compatible with Solidity 0.8.24
and that its default target VM is Shanghai. TRON's developer documentation names the TRON distribution as the
compiler to use, and Tronscan verifies source only against it. Read on 2026-11-16 from the release metadata; the
metadata lists no digest for this release, so the hash must be taken from `shasum.txt` when it is downloaded.

**Why it was not used here.** Downloading TRON's compiler to the host was denied to the agent. The denial was not
worked around: no binary was fetched by any route. Only the release's public metadata page was read.

**What could differ in the bytecode.** Not measured. In order of likelihood:

| Possible difference | Consequence |
|---|---|
| The metadata trailer at the end of the code (compiler name and version) | A different creation code hash and a different runtime code hash even if every instruction is the same. Every pin must come from the TRON build: `vaultCodeHash` in the L2 token config, `vault_code_keccak` in every signer's source config, the hashes `tron_deploy.py plan` prints |
| Code generated for the things TRON's fork changes: address values (21 bytes at the API, 20 in the VM), calls to precompiles, low-level calls, `CREATE2` | A different instruction sequence in the paths the vault uses (`ecrecover`, `staticcall` and `call` to the token, `blockhash`, `chainid`, `extcodehash`, ABI decoding of addresses). Different energy; in principle different behaviour. The 305 forge tests and the rehearsal say nothing about that bytecode until they are run on it |
| Words the fork reserves for TRON features (units, staking, TRC-10) | The source might not compile unchanged if an identifier collides. Not checked |
| The optimizer | The same upstream base; expected equal, not verified |

**The command for the owner** (Linux x86-64; any directory outside the repository for the binary). One block at a
time.

```
mkdir -p ~/tron-solc-0.8.24
```

```
curl -fL -o ~/tron-solc-0.8.24/solc-static-linux https://github.com/tronprotocol/solidity/releases/download/tv_0.8.24/solc-static-linux
```

```
curl -fL -o ~/tron-solc-0.8.24/shasum.txt https://github.com/tronprotocol/solidity/releases/download/tv_0.8.24/shasum.txt
```

```
sha256sum ~/tron-solc-0.8.24/solc-static-linux
```

```
cat ~/tron-solc-0.8.24/shasum.txt
```

The two hashes must be equal. Record the value in `agents/323-bridge-tron-r16.md`. Then, from the repository root:

```
chmod +x ~/tron-solc-0.8.24/solc-static-linux
```

```
~/tron-solc-0.8.24/solc-static-linux --version
```

```
~/tron-solc-0.8.24/solc-static-linux --optimize --optimize-runs 1 --evm-version shanghai --metadata-hash none --bin --bin-runtime --overwrite -o out-tron-solc contracts/tron/TronSourceVault.sol
```

```
sha256sum out-tron-solc/TronSourceVault.bin out/TronSourceVault.sol/TronSourceVault.json
```

Then the rehearsal on that bytecode (private TVM as in section 9):

```
VAULT_CREATION_BIN=out-tron-solc/TronSourceVault.bin TRON_URL=http://127.0.0.1:42390 PORT_BASE=42300 python3 tools/signatario-tron/rehearse_tron.py $PWD $HOME/tron-rehearsal-work $HOME/usdt-getcontract.json
```

It must print `58/58 checks passed`. These commands were written from the compiler's documented options and were
**not run**: the option names follow upstream solc 0.8.24, and if the TRON build spells one differently the
compile step fails loudly rather than silently. `tron_deploy.py` accepts the resulting file directly
(`--artifact out-tron-solc/TronSourceVault.bin`).

## 4. Finality and reorgs

**Rule a signer applies before attesting a deposit:** the `Deposited` log must be served by the signer's OWN
java-tron node from the solidified state. A block is solidified when 19 of the 27 block producers have built on
it; that is about one minute behind the head in normal operation. The signer's unchanged source half asks its
Ethereum RPC for `finalized`; the shim answers that word, and only that word, from `/walletsolidity/*`.

**Release anchor:** a release certificate names a solidified TRON block and its id. The vault refuses an anchor
that is not a past block of its own chain inside the 256-block window, so a certificate made against a fork is
dead.

**A reorg after attestation** (a solidified block is lost: needs more than a third of the block producers to be
faulty):

- The mint is still inside the 12 hour L2 delay. Each guardian re-reads the deposit from its own node; with the
  deposit gone, 2 of the 3 guardians cancel the queued mint. It is never credited. If they cannot cancel, they
  pause the L2 token.
- If a mint with no deposit did credit, the vault refuses every burn made under that mint chain
  (`ProvenanceMismatch`): later releases are held, not paid twice.
- A guardian pauses the vault itself on a reserves shortfall or on evidence of a forged mint; a missing deposit
  alone does not pause the vault (a lagging node would otherwise close it).
- The relayer's journal closes an entry only by the solidified chain, so a release transaction that was in the
  head and then dropped is sent again as the same bytes, not as a second payment.

Worst case for a deposit: if fewer than 19 block producers are live, nothing solidifies and nothing is attested
until they return. Fail-safe: hold.

## 5. Fees and revenue

5 bps of every deposit and 5 bps of every release, the same as the Ethereum bridge (ceiling 30 bps in the
contract). Fees accrue in `feesAccrued`, outside `totalLocked`. Anyone may call `sweepFees()`; the vault pays the
whole accrued amount to the recipient fixed at construction, `TCQ2d5gxTczSeN2oeni16JwMW7HWLzXEKc`
(`0x1aa1fc9a1b311556132b30af41026ca5c6b6fafc`; Base58Check checksum verified). The recipient cannot be changed.
`tron_deploy.py` refuses a mainnet config with a zero fee. The rehearsal checks that the sweep pays exactly the
accrued fees to that address and nothing else.

Network costs are separate and go to TRON, not to the bridge: section 9, "Energy".

## 6. Keys and ceremony

`docs/BRIDGE-V3-KEY-CEREMONY.md` applies unchanged. The differences:

| Key | Count | New? | Notes |
|---|---|---|---|
| Release signers (`eth-release-signer`) | 7 | No | The same keys as the Ethereum vault. A secp256k1 key has the same 20-byte address on TRON. Signers never send a TRON transaction and need no TRX |
| L2 mint signers | 7 | No | As bUSDC |
| Vault guardians | 3 | No, but funded | The same keys as the Ethereum vault guardians. Each guardian address must be an activated TRON account holding TRX, because `guardianPause()` is a transaction it pays for (about 79,000 energy measured). Suggested: 100 TRX each |
| L2 token guardians | 3 | No | As bUSDC |
| TRON relayer gas key | 1 per relayer | **Yes** | An ordinary secp256k1 keystore. Holds only TRX. Suggested float: 2,000 TRX, alert below 500 |
| TRON deployer | 1 | **Yes** | A fresh account with at least 600 TRX, used for one transaction. A keystore on an offline-prepared machine: `tron_deploy.py` signs with `cast`, and a hardware wallet cannot sign a TRON transaction through `cast` (see section 11) |

To print the TRON form of an existing committee address (no key involved):

```
python3 -c "import sys; sys.path.insert(0, 'tools/signatario-tron'); import tronlib; print(tronlib.base58(sys.argv[1]))" 0xADDRESS
```

Proof of possession, intake, backup and rotation: as sections 4 to 6 of the key ceremony document. A committee
key attested for the Ethereum bridge needs no second attestation; the intake for this bridge lists the same
addresses in `deployments/tron/busdt-trx-vault.config.json` (as `T…` or `0x…`).

What an attacker gains is as in section 7 of that document, read for this vault alone: 5 release keys can drain
this vault's USDT (not another network's); a guardian key can pause this vault for 72 h once per cooldown; the
relayer key can spend its own TRX; the deployer key can change the two resource settings and clear the stored ABI.

## 7. Deployment (owner; an agent never deploys)

Before anything: the external audit of this bridge, and section 11 item 1 (the build and rehearsal with TRON's
compiler). Each block below is one command.

**7.1 Read the network's parameters.** The vault needs the Shanghai opcodes and the 4-byte chain id.

```
curl -s -X POST http://127.0.0.1:8090/wallet/getchainparameters
```

`getAllowTvmShangHai` must be 1 and the parameter that makes `CHAINID` 4 bytes (proposal 71,
`getAllowOptimizedReturnValueOfChainId`) must be 1. Both were 1 on mainnet on 2026-11-16.

**7.2 Fill and validate the vault config** (`source.revision`, `deployer.address`, 7 signers, 3 guardians).

```
python3 tools/signatario-tron/tron_deploy.py validate --config deployments/tron/busdt-trx-vault.config.json --token-config deployments/tron/busdt-trx-token.config.json
```

**7.3 Plan.** Two people run it and compare the output byte for byte.

```
python3 tools/signatario-tron/tron_deploy.py plan --config deployments/tron/busdt-trx-vault.config.json --artifact out-tron-solc/TronSourceVault.bin
```

**7.4 Dry run of the creation** (builds the transaction, prints its id, sends nothing).

```
python3 tools/signatario-tron/tron_deploy.py create --config deployments/tron/busdt-trx-vault.config.json --artifact out-tron-solc/TronSourceVault.bin --node http://127.0.0.1:8090 --keystore DEPLOYER_KEYSTORE --password-file DEPLOYER_PASSWORD_FILE
```

**7.5 Create.** One-way. Costs about 431 TRX at 100 sun per energy (measured: 4,311,475 energy).

```
python3 tools/signatario-tron/tron_deploy.py create --config deployments/tron/busdt-trx-vault.config.json --artifact out-tron-solc/TronSourceVault.bin --node http://127.0.0.1:8090 --keystore DEPLOYER_KEYSTORE --password-file DEPLOYER_PASSWORD_FILE --broadcast
```

**7.6 Verify** from a second machine and node. It compares the creation code TRON stored with the artifact plus
the config's constructor arguments, byte for byte, and every public value at the solidified level.

```
python3 tools/signatario-tron/tron_deploy.py verify --config deployments/tron/busdt-trx-vault.config.json --artifact out-tron-solc/TronSourceVault.bin --node http://127.0.0.1:8090 --vault TVAULTADDRESS
```

It prints `vaultHex`, `routeId`, `runtimeCodeKeccak` and `mintChainGenesis`.

**7.7 The L2 token.** Put those values into `deployments/tron/busdt-trx-token.config.json` (`ethereum.vault`,
`ethereum.route`, `ethereum.vaultCodeHash`, `ethereum.vaultCap`) and deploy with the existing tool, with the
operator's shim as the source RPC. **Blocked today:** `deploy_pontes.py` refuses a source chain id other than 1 on
chain 700770 (`agents/R16-CROSS-AREA.md`, the line of agent 323). After that change:

```
python3 tools/deploy-pontes/deploy_pontes.py validate --config deployments/tron/busdt-trx-token.config.json
```

```
python3 tools/deploy-pontes/deploy_pontes.py plan --config deployments/tron/busdt-trx-token.config.json --write busdt-trx.plan.json
```

```
python3 tools/deploy-pontes/deploy_pontes.py run --config deployments/tron/busdt-trx-token.config.json --plan busdt-trx.plan.json --rpc L2_RPC_URL --source-rpc http://127.0.0.1:42320
```

Then `run` again with `--broadcast --confirm CONFIGSHA256 --write busdt-trx.broadcast.json` and the wallet options,
then `record` and `verify`, exactly as for bUSDC (`docs/BUSDC-MAINNET-V2.md`). `run` refuses a vault that was ever
used. This path through the shim was not rehearsed (section 11).

**7.8 Operators start** their node, shim, signer, relayer and guardian (section 8) and run the preflight of
`docs/BRIDGE-V3-OPERATOR-RUNBOOK.md` section 3 with the shim as the Ethereum RPC.

**7.9 Open deposits and releases.** The vault starts closed. Five signers sign the control digest. Each, against
its own shim (`VALIDUNTIL` = an agreed Unix time a few hours ahead):

```
cast call VAULTHEX 'controlDigest(bool,bool,uint64,uint256)(bytes32)' true true 0 VALIDUNTIL --rpc-url http://127.0.0.1:42320 --block finalized
```

```
cast wallet sign --no-hash --keystore SIGNER_KEYSTORE --password-file SIGNER_PASSWORD_FILE DIGEST
```

All five must see the same digest. Anyone with TRX submits the five signatures, ordered by ascending signer
address:

```
python3 tools/signatario-tron/tron_send.py --config send.json call 'setControls(bool,bool,uint64,uint256,bytes[])' true true 0 VALIDUNTIL '[SIG1,SIG2,SIG3,SIG4,SIG5]'
```

**7.10 First deposit**: the smallest allowed (11 USDT), by the owner, followed through credit, burn and release
before the address is published in `deployments/tron/bridge.network.json`.

## 8. Operator runbook: the delta

`docs/BRIDGE-V3-OPERATOR-RUNBOOK.md` applies. What changes for this route:

| Runbook rule | On TRON |
|---|---|
| 2.1 Own Ethereum node per operator | Own **java-tron FullNode** per operator (HTTP API on loopback, with the solidity API), and the operator's own `tron_rpc_shim.py` in front of it. A public API endpoint (TronGrid or another) is never a signer's or guardian's source. Start the shim with `--chain-id 728126428`: it refuses another chain |
| 2.3 Gas ceilings | `tron_fee_limit_sun` (default 150 TRX per transaction). The sender also refuses when the simulated energy × the energy price × 3/2 exceeds it. Budget from a mainnet simulation: USDT carries the maximum dynamic-energy penalty there |
| 2.3a A release reservation left behind | Does not exist on TRON. The equivalent is a journal file in `.tron-submissions/`: never delete it by hand before `tron_valid_s` plus two minutes have passed (`tools/signatario-tron/README.md`, "The journal") |
| 2.4 Two L2 views before a vault pause | Unchanged (it concerns the L2 side) |
| 2.6 Unpause needs 6 of 7 | Unchanged. Digest: `unpauseDigest(uint64 pauseCount, uint256 validUntil)` read through the shim; submit with `tron_send.py call 'unpause(uint64,uint256,bytes[])' …` |
| 3 Pre-go-live check | Add: the node is synced (`/wallet/getnowblock` within 10 s of the clock, `/walletsolidity/getnowblock` within 2 minutes of the head); `eth_chainId` on the shim is `0x2b6653dc`; the vault's runtime code keccak at `finalized` equals `runtimeCodeKeccak` from `tron_deploy.py verify`; `tokenState()` is (true, false, false); the relayer and every guardian account are activated and funded |

New alerts and what to do:

| Signal | Meaning | Action |
|---|---|---|
| `tokenState()` returns blacklisted = true | Tether blacklisted the vault | Deposits are already refused by the vault. Releases revert in the token and stay payable. Publish; contact the issuer. The books are unchanged |
| `tokenState()` returns replaced = true, or known = false | Tether deprecated the token, or a getter stopped answering | Deposits are already refused. Do not sign anything new until the replacement contract has been reviewed |
| `reservas` reports a shortfall | The vault's balance is below `totalLocked + feesAccrued` (destroyed funds, or a transfer fee) | A guardian pauses the vault (automatic). No release is paid until the whole shortfall is back. Owner decision |
| Relayer logs `TRON send refused: fee ceiling` | Energy needed is above `tron_fee_limit_sun` | Check the energy price and the dynamic-energy factor; raise the limit deliberately or wait |
| Relayer logs `TRON send refused: the call would revert now` | Token paused, vault blacklisted, vault paused, or a certificate whose anchor is older than 256 blocks | For a stale anchor the signers sign a new round on their own. Otherwise see the token state |
| The solidified height stops advancing | Fewer than 19 block producers are live, or the operator's node is stuck | Nothing is attested (safe). Check the node against a second view before anything else |
| Relayer TRX balance below 500 | The relayer will stop paying releases | Top up. Burns stay payable; nothing is lost |

A burn paid to a recipient that Tether has blacklisted succeeds (the token allows it); the funds are then frozen
at that address by the issuer, not by the bridge.

## 9. Tests and rehearsal

**Forge** (Mac, stock solc, 2026-11-16): `forge test --offline --match-path 'solidity-tests/Tron*'` 66 tests in 6
suites, all pass (the mock of USDT-on-TRON, the vault, issuer cases, a stateful fuzz, a differential fuzz against
the Ethereum vault). `forge test --offline --match-path 'solidity-tests/tron-ported/*'` 239 tests in 21 suites,
all pass (the Ethereum vault's suites ported by `scripts/tron/port_vault_suites.py`).

**Offline tool tests**: `python3 tools/signatario-tron/test_tron_tools.py`, 108 checks, all pass.

**Rehearsal on a private TVM** (`tools/signatario-tron/rehearse_tron.py`), host 45.77.142.123, loopback only,
throwaway keys:

- TRON side: the official quickstart image `tronbox/tre@sha256:f4332e11df12a9f360639a4546fd046593909630fda48af00b30410c144342f0`
  (TRE 2.0.0, java-tron 4.8.2). The **real TetherToken creation code** read from TRON mainnet (15,575 bytes,
  sha256 `28668160…93b5`) deployed locally. The vault in the launch shape.
- L2 side: anvil standing in for the L2, with `BridgedStablecoinV3` from the frozen source (creation keccak
  checked against the launch pin).
- Daemons: the unchanged signer and source half, `vigia_tron.py`, `guardiao_tron.py`, the unchanged `reservas.py`.

| Run | Script | Result |
|---|---|---|
| 1 | before `8dd2cb4` (not preserved) | 46 of 58 |
| 2 | `8dd2cb4` | 50 of 58 |
| 3 | `bfef0d6` | **58 of 58** |
| 4 | the final script of this branch | **58 of 58** (log sha256 `5487846980407df270de899f8aefacac136ecf724e409176d329dfa9d2ab56a7`) |

Logs: `agents/323-evidence/run1.log` to `run4.log`.

**What the 58 checks cover** (adversarial cases in bold): deposit; no signature while the deposit is in the head
but not solidified; credit after solidification and the 12 h delay; burn; release less 5 bps with USDT's `false`
return; **replay of a certificate** (`InvalidRelease`) and **of the identical transaction** (refused by the
chain); **forged attestations**: 5 outsider keys, 4 committee keys plus 1 outsider, 4 committee keys
(`InvalidCertificate`), also broadcast on chain (reverts, books unchanged); **a real certificate with another
anchor hash** (`InvalidContext`); **a real certificate for a burn under another mint chain**
(`ProvenanceMismatch`); limits: deposit above the window, below the minimum, a recipient that is not 20 bytes,
the L2 mint bucket, a burn above the bucket, the release window exhausted; **token paused by the issuer**;
**vault blacklisted** (with the control that the real token would accept the deposit); **vault funds destroyed**;
guardian pause by the guardian daemon as a TRON transaction, no deposit and no release while paused, a guardian
cannot pause twice, a stranger cannot pause, 5 of 7 cannot unpause and 6 of 7 can; fee sweep to the owner's
address; **a solidified block lost after attestation**: 2 of 3 guardians cancel the queued mint, never credited;
final books.

**Every failure of runs 1 and 2, by cause.** None was a failure of the vault, the token or the daemons: in each
case the system refused or held, and the script expected something else.

| Run | Failed checks | Cause |
|---|---|---|
| 1 | Forged attestation ×3, forged context, provenance (5) | Every simulation returned `InvalidRelease` (`0x1cbb0709`) where the check expected `InvalidCertificate`, `InvalidContext` or `ProvenanceMismatch`. `InvalidRelease` is the vault's first group of checks on the release item (route, amount, recipient, burn id, amount against `totalLocked`, used nonce or burn): the script's forged item was itself invalid, so the vault refused it one step before the property under test. Fixed by building the forged item from valid fields. The run 1 script was not committed, so the exact wrong field cannot be named |
| 1 | A burn above the bucket capacity is refused on the L2 (1) | Script-side handling of the reverted L2 transaction (the L2 token is the frozen bytecode and refused the burn in runs 2 to 4 with the same contract). The run 1 line was not preserved; this is the least certain entry of the table |
| 1 | Reorg after attestation: guardians cancel the queued mint (1) | The guardians did find the mint without a deposit and held their cancel votes: `cancel-hold … Ethereum head at 1794857277 is not 300 s past the mint at 1795030076`. The rig had moved the L2 stand-in's clock two days forward (bucket refill and delays) and TRON's clock cannot be moved; the guardian's freshness rule compares the two. They paused the L2 token instead, so the mint was not credited (safe), but not cancelled. Fixed for the rig only with `cancel_fresh_s` off. Consequence: that rule is not exercised here (section 11) |
| 2 | Forged attestation ×3 (3) | Returned `InvalidContext` (`0x271a26f1`) instead of `InvalidCertificate`. The script anchored its certificates at the solidified block itself; the quickstart node solidifies the head at once, and a TVM constant call runs with the head's own block number, so the anchor was not strictly below `block.number` in the simulation. The vault checks the anchor before the signatures. Fixed by anchoring one block lower. On mainnet anchors are about 19 blocks behind the head. The same forged call broadcast on chain did revert in both runs |
| 1 and 2 | Guardian pause: sends `guardianPause()` (1) | The script expected the lost-deposit stage to make a guardian pause the TRON vault. By design it does not: a missing deposit alone is evidence a lagging node could give, so the guardian cancels the mint or pauses the L2 token, and pauses the vault only on a reserves shortfall or an evidenced forgery. `pausedUntil` stayed 0. Fixed by moving the stage to the reserves shortfall, where the guardian daemon does send the transaction |
| 1 and 2 | Deposits refused while paused; a guardian cannot pause twice; unpause 5 of 7 / 6 of 7; the held burn is paid exactly once (4) | Consequences of the line above, with the vault not paused: the deposit simulation succeeded; a guardian could still pause; `unpause` reverted with `InvalidPause` (`0x00cfc693`, "not paused"); and the burn was paid normally during the stage (journal: written and landed 14 s apart) before the script took its balance baseline, so the expected difference was 0. Inferred from the logged values |

**Energy** (run 4, private TVM, 100 sun per energy, everything bought by burning TRX):

| Transaction | Energy | TRX |
|---|---|---|
| Vault creation (7 signers, 3 guardians) | 4,311,475 | 431.4 |
| `setControls` (5 of 7) | 58,532 | 5.9 |
| `deposit` (first / later) | 114,428 / 82,996 | 11.4 / 8.3 |
| `release` (5 of 7, relayed) | 142,520 | 14.3 |
| `release` replay, reverted | 9,958 | 1.0 |
| `release` forged, reverted | 30,228 | 3.0 |
| `guardianPause` | 78,941 | 7.9 |
| `unpause` (6 of 7) | 53,747 | 5.4 |
| `sweepFees` | 66,315 | 6.6 |

On mainnet, calls that touch USDT cost more: USDT is at the maximum dynamic-energy factor (a simulated mainnet
transfer used 64,285 energy, 49,635 of it penalty). Expect roughly 50,000 more energy for a deposit, a release and
a sweep. At these prices a deposit costs the user on the order of 15 TRX plus an approval, which is material
against the 11 USDT minimum; the frontend must show it.

**What the rig cannot show**: the quickstart node solidifies every block at once and cannot reorganise. "Not yet
solidified" and "a solidified block is lost" are produced by a proxy in front of `/walletsolidity` that the
rehearsal controls. Constant calls at the solidified level are answered from the head state by that node.

## 10. Audit note

**New code to audit**

| File | Lines | Notes |
|---|---|---|
| `contracts/tron/TronSourceVault.sol` | 890 (43 added, 14 removed against the Ethereum vault) | Review as a diff: `python3 scripts/tron/vault_diff.py` |
| `tools/signatario-tron/tronlib.py` | 350 | Transaction encoding and decoding; the address forms |
| `tools/signatario-tron/tron_rpc_shim.py` | 280 | The `finalized` mapping |
| `tools/signatario-tron/tron_send.py` | 237 | The journal |
| `tools/signatario-tron/vigia_tron.py`, `guardiao_tron.py` | 113, 63 | Overrides only |
| `tools/signatario-tron/tron_deploy.py` | 244 | Owner tool |
| `solidity-tests/harness/TronUSDTLike.sol` | 387 | Test mock of USDT-on-TRON, modelled on behaviour measured on the real bytecode. Not deployed |

**Reused byte-identical**: `BridgedStablecoinV3` (creation keccak `0xe560441f…1de7`);
`contracts/usdt/ProvenanceSourceVault.sol` (unchanged, imported for two interfaces); `tools/signatario-stable`,
`tools/guardiao`, `tools/reservas` (no line changed on this branch).

**What an auditor should look at first**

1. `_tokenFlags`, `_tokenAcceptsDeposits` and the two constructor checks (TRON-3 to TRON-5): can a hostile or
   upgraded token make them answer "safe" wrongly, consume unbounded energy, or re-enter? They use `staticcall`
   and accept exactly one ABI word.
2. Transfer mode 1 against USDT's real semantics: `false` on success, the fee switch, `deprecate` forwarding to
   an unknown contract. Releases are deliberately not gated by the token flags.
3. The shim's rule for state at a height: it serves the current solidified state for any height at or below the
   solidified one. Is every read the daemons make this way really monotone? (`tron_rpc_shim.py` docstring.)
4. `tronlib.describe` and `build_trigger`: can a transaction that differs from the call asked for pass the check
   before signing?
5. The journal's expiry rule (`Sender.settle`): can an entry close as expired while its transaction can still
   land? It compares the SOLIDIFIED block's timestamp with the expiration and looks twice.
6. `block.chainid` on TRON: it depends on a chain parameter. What happens to every digest if governance changed
   it (the vault would stop accepting certificates: safe, but a halt)?
7. The compiler question of section 3.

## 11. Not done / not proven

1. **Build and rehearse with TRON's own compiler.** The vault was built with stock solc 0.8.24 because the
   download of TRON's compiler was denied. Until the commands of section 3 have been run and the rehearsal passes
   58 of 58 on that bytecode, the bytecode that would be deployed has never been executed. First command:
   `curl -fL -o ~/tron-solc-0.8.24/solc-static-linux https://github.com/tronprotocol/solidity/releases/download/tv_0.8.24/solc-static-linux`
   (the full sequence is in section 3).
2. **No external audit.** Mandatory before real funds.
3. **No real java-tron network behaviour.** The private node is a single-producer quickstart: no real
   solidification lag, no reorg, no 27 producers. Lag and loss were simulated by a proxy. Not tested on Nile or
   Shasta (testnets were out of bounds for the agent).
4. **The solidified API's state.** On a real node `/walletsolidity/triggerconstantcontract` reads solidified
   state; the quickstart answers from the head. The shim's central claim was therefore tested for logs, blocks
   and receipts, but for contract state only offline.
5. **The guardian's freshness rule** (`cancel_fresh_s`, 300 s) was switched off in the rig because the two clocks
   cannot be aligned there. Its interaction with TRON block timestamps is unproven.
6. **Mainnet energy.** Costs were measured on a private node. USDT's dynamic-energy penalty on mainnet was read
   from one simulated transfer only. Staked or rented energy is not handled by the tools.
7. **`deprecate`** on the real USDT bytecode was not exercised (ABI only); the vault's reaction was tested against
   the mock.
8. **The L2 token deployment through the shim** (`deploy_pontes.py --source-rpc`) was not rehearsed, and the tool
   refuses chain id 728126428 today (cross-area). The manual commands of 7.9 were not run in that form: the
   rehearsal opened the controls with the same digest and signatures but through its own helpers, and the
   `tron_send.py` command line was run on the private TVM with `sweepFees()` only
   (`agents/323-evidence/cli-sweep.json`).
9. **Hardware wallet for the deployer**: not supported; the deployer is a keystore key used once.
10. **The differential fuzz and the ported suites run on the EVM**, not on the TVM. TVM-specific behaviour is
    covered only by the 58 rehearsal checks.
11. **Long outages**: a signer catching up more than 20,000 blocks pages through `eth_getLogs`; not load-tested.
12. **Tronscan source verification** needs the TRON compiler build; not attempted.
13. **The verifier switch** (light client) stays NO-GO, as on Ethereum; its code paths exist in the vault and
    were only run through the ported suites.
14. `docs/USDT-NETWORK-INTEGRATION.md` and the frontend are not updated for this route (agents 313 and 318 read
    `deployments/tron/bridge.network.json`).

## 12. Owner inputs

| Input | Where |
|---|---|
| Run section 3 (TRON's compiler) and report the hash and the rehearsal result | section 3 |
| The external audit of this bridge | - |
| Confirm the limits (cap 100,000; window 10,000 per day; minimum 11; 12 h delay) and the fee (5 + 5 bps) | `deployments/tron/busdt-trx-vault.config.json` |
| Confirm the fee address `TCQ2d5gxTczSeN2oeni16JwMW7HWLzXEKc` once more from the wallet itself (it is immutable) | same |
| The 7 release signer addresses and operators, the 3 guardian addresses and operators (the Ethereum bridge's) | same |
| A fresh TRON deployer account with at least 600 TRX; relayer float (about 2,000 TRX); 100 TRX on each guardian address | section 6 |
| Each operator: a java-tron FullNode of their own | section 8 |
| The decision to widen `deploy_pontes.py` to this source network | `agents/R16-CROSS-AREA.md` |
| The L2 explorer URL patterns | `deployments/tron/bridge.network.json` (`explorers.l2`) |
