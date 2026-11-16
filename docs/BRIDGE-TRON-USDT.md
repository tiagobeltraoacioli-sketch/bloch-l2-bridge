# Bridge TRON → Bloch L2: USDT (TRC-20) ↔ `bUSDT.trx`

**UNAUDITED. Nothing is deployed, on any network. No real key was used.** Round 16, agent 323, branch
`codex/bridge-tron-r16-20261116` (from `cc2511a`). This bridge needs its own external audit before any real funds.

Companion files: `docs/TRON-VAULT-DIFF.md` (the vault as "the Ethereum vault plus seven changes", platform
differences, USDT-on-TRON behaviour), `tools/signatario-tron/README.md` (the tools),
`deployments/tron/` (configs and `bridge.network.json`).

Contents: 1 what it is, 2 what differs from the Ethereum bridge, 3 the compiler, 4 finality, 5 fees, 6 keys and
ceremony, 7 deployment, 8 operator runbook, 9 tests and rehearsal, 10 audit note, 11 not done / not proven,
12 owner inputs, 13 review of round 16 (reviewer 325) and what was done.

## 1. What it is

A user deposits USDT on TRON into a vault (`contracts/tron/TronSourceVault.sol`). After the deposit's block is
solidified, 5 of the 7 committee keys attest it, and `bUSDT.trx` is minted on the Bloch L2 (chain 700770) after the
12 hour mint delay, 1:1 less 5 bps. Burning `bUSDT.trx` on the L2 is certified by 5 of 7 after L2 finality, and the
vault pays USDT on TRON less 5 bps and less a fixed 8 USDT. The fees accrue in the vault outside the backing and are swept to the owner's
address `TCQ2d5gxTczSeN2oeni16JwMW7HWLzXEKc`, which is a constructor argument.

| Piece | What | Reuse |
|---|---|---|
| L2 token | `BridgedStablecoinV3`, name "Bloch Bridged USDT (Tron)", symbol `bUSDT.trx`, 6 decimals | Byte-identical (creation keccak `0xe560441f…1de7`); constructor arguments only. `sourceChainId` 728126428, `sourceVault` = the vault's 20-byte address |
| Vault | `TronSourceVault` | `ProvenanceSourceVault` (the Ethereum vault, unchanged on this branch) plus seven marked changes; `python3 scripts/tron/vault_diff.py` prints and pins the diff (82 lines added, 22 removed) |
| Committee | 7 secp256k1 signers (5 release, 6 unpause or switch), 3 guardians (pause only) | The same keys as the Ethereum bridge; `ecrecover` on the TVM. No new key type |
| Signer, relayer, guardian, reserves monitor | `tools/signatario-stable`, `tools/guardiao`, `tools/reservas` | Unchanged. New code: a read-only shim with a verified log index, and a TRON sender (`tools/signatario-tron`, 1,848 lines without tests and rehearsals) |
| Limits | cap 100,000 USDT; window 10,000 per 24 h; minimum deposit 21; L2 minimum burn 20; mint delay 12 h for every mint (T = 0); guardian pause 72 h | The Ethereum bridge's launch values except the two minimums (raised with the fixed release fee, section 5); the owner confirms |

Isolation: this vault backs only `bUSDT.trx`. Nothing here touches another bridge's backing.

Why USDT and not USDC on TRON: Circle stopped minting USDC on TRON on 2024-02-21 and lists no TRON contract
(sources in `deployments/tron/bridge.network.json`, `asset.verified`).

## 2. What differs from the Ethereum bridge, and matters for safety

1. **The issuer's token behaves differently.** USDT on TRON returns ABI `false` from every successful `transfer`,
   accepts transfers INTO a blacklisted address, and its owner can pause it, charge a transfer fee, destroy a
   blacklisted balance and redirect it to another contract (`deprecate`). The vault therefore runs only in
   transfer mode 1 (exact balance movement decides, the return value does not), refuses deposits while it is
   blacklisted or the token is deprecated, and keeps its books provable if its balance is destroyed
   (`docs/TRON-VAULT-DIFF.md` sections 1 and 3). If the issuer switches its transfer fee on, exits still pay: the
   vault's balance falls by exactly what it sends and the recipient bears the issuer's fee, at most 20 bps and 50
   USDT (TRON-6); deposits stop, because a deposit must deliver its whole amount. **Accepted limit: Tether can stop
   exits by blacklisting the vault or pausing the token, for as long as it likes, and can destroy the backing. No
   contract can prevent that.**
2. **Finality is "solidified"**, about a minute behind the head, served only by `/walletsolidity/*`. java-tron's own
   JSON-RPC has no `finalized`. A new component, the shim, maps `finalized` to the solidified API; every signer
   safety property now also depends on that mapping being right (section 4). The shim also keeps the index of the
   vault's logs that an Ethereum node keeps by itself; the index is checked against the vault's own solidified
   deposit chain, so a node that omits, alters or invents a deposit log is not believed (section 4).
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
8. **A release costs the relayer real money** (about 20 TRX on mainnet whatever its size), so every release pays a
   fixed fee as well as the 5 bps (TRON-7, section 5).

## 3. The compiler

**What was built and tested.** Every test and every rehearsal run in this document used the repository build:
stock **solc 0.8.24+commit.e11b9ed9** through Foundry 1.7.1, `evm_version = shanghai`, optimizer on with 1 run,
`bytecode_hash = none` (`foundry.toml`). Vault creation code: 24,288 bytes, sha256
`22402ad300000150ac82bec9962ea1c30b7ab7e693e6d81bb29a76214226f4a8` (printed by the rehearsal; before the review
fixes TRON-6 and TRON-7 it was 23,549 bytes, `d9f6620a…43c2`). That bytecode
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

It must print `66/66 checks passed`. These commands were written from the compiler's documented options and were
**not run**: the option names follow upstream solc 0.8.24, and if the TRON build spells one differently the
compile step fails loudly rather than silently. `tron_deploy.py` accepts the resulting file directly
(`--artifact out-tron-solc/TronSourceVault.bin`).

**What must be checked again on THAT bytecode** (the reviewer's list, R325-TRX-9):

1. It compiles unchanged: no reserved word collides, and the import of the two interfaces from the Ethereum vault's
   file resolves.
2. The 66-check rehearsal passes, and the long-history rehearsal (`rehearse_tron_history.py`).
3. The paths the fork touches behave: `ecrecover` results and the `isSigner` lookup (20-byte addresses, no `0x41`);
   `address(this)` inside `routeId()` and every digest; `abi.decode` of the token's answers; gas forwarding of the
   low-level `call` and `staticcall`; `blockhash`; `block.chainid`; `extcodehash` for the verifier pin. The
   rehearsal exercises all of them except the verifier pin.
4. Every pinned hash is taken from that build: creation, runtime, `vaultCodeHash` in the L2 token config,
   `vault_code_keccak` in every signer config.
5. Energy of a deposit and a release under mainnet's dynamic-energy factor, by simulation, and the fixed release
   fee re-checked against it (section 5).
6. The opcode set against the target network's chain parameters (`PUSH0` needs `getAllowTvmShangHai`).

## 4. Finality and reorgs

**Rule a signer applies before attesting a deposit:** the `Deposited` log must be served by the signer's OWN
java-tron node from the solidified state. A block is solidified when 19 of the 27 block producers have built on
it; that is about one minute behind the head in normal operation. The signer's unchanged source half asks its
Ethereum RPC for `finalized`; the shim answers that word, and only that word, from `/walletsolidity/*`.

**Finding the deposit.** The source half looks for the `Deposited` log by asking for the vault's logs. The shim
answers from its index of the vault's logs (`tools/signatario-tron/tron_log_index.py`):

- a log enters the index only from the solidified receipts of the operator's own node;
- deposits are complete and genuine by the vault's own solidified state, not by the receipts: nonces contiguous
  from 0, each log confirmed by `depositMatches(nonce, id, amount, recipient)` (the vault's append-only deposit
  chain), and the count equal to `depositCount()`. A query is answered only up to the last block at which that
  held; beyond it the shim returns an error and the signer's round is retried. Never a shorter answer;
- every round the block id at the index's cursor is compared with the node's and the receipts of the vault's logs
  of the last day are read again. A replaced block or a vanished transaction drops the index back and that span
  is read again.

The source half then checks the log against the receipt and the vault's `depositId(...)` at `finalized`, as on
Ethereum. What the index trusts for the vault's other logs is written at the top of `tron_log_index.py`.

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

| Fee | Amount | When | To |
|---|---|---|---|
| Deposit | 5 bps of the amount | at deposit | accrued, swept to the owner's address |
| Release, proportional | 5 bps of the burned amount | at release | same |
| Release, fixed (TRON-7) | **8 USDT** (`releaseFlat` 8000000) | at release | same |

A burn of A pays out `A - floor(A * 5 / 10000) - 8` USDT. Minimum deposit 21 USDT, minimum burn 20 USDT (the fixed
fee is at most half of the minimum burn; the vault's constructor enforces it). Ceilings in the contract: 30 bps
each way; the fixed fee is immutable. Fees accrue in `feesAccrued`, outside `totalLocked`. Anyone may call
`sweepFees()`; the vault pays the whole accrued amount to the recipient fixed at construction,
`TCQ2d5gxTczSeN2oeni16JwMW7HWLzXEKc` (`0x1aa1fc9a1b311556132b30af41026ca5c6b6fafc`; Base58Check checksum verified).
`tron_deploy.py` refuses a mainnet config with a zero percentage or a zero fixed fee. The rehearsal checks every
payout and that the sweep pays exactly the accrued fees to that address.

**Why a fixed fee (review R325-TRX-3).** A release costs its relayer the same energy whatever its size. At 5 bps a
minimum burn earned 0.005 USDT and cost the relayer about 20 TRX; 1,000 minimum burns would have emptied the
relayers' floats for 5 USDT of income.

**How it is sized.** Cost of one release to the relayer, when the energy is bought by burning TRX:

    cost in USDT = energy x (sun per energy) x (USD per TRX) / 1,000,000

| Input | Value | Source |
|---|---|---|
| Energy of a release on the private TVM | 143,753 | rehearsal run 5 (no dynamic-energy penalty on a fresh token) |
| Extra on mainnet for USDT's dynamic-energy penalty | about 55,000 | one simulated mainnet transfer: 64,285 energy, 49,635 of it penalty (factor 3.4 on USDT's own part), plus the four balance reads |
| Energy used for sizing | 200,000 | the two above, rounded up |
| Energy price | 100 sun | TRON mainnet chain parameter `getEnergyFee`, read 2026-11-16 |
| TRX price | 0.305 USD | CoinGecko simple price, read 2026-11-16 |
| **Cost of one release** | **20 TRX = 6.11 USDT** | |
| **Fixed fee** | **8 USDT** | cost x 1.31 |

How the cost moves (USDT per release, at 200,000 energy):

| Energy price \ TRX price | 0.20 USD | 0.305 USD | 0.40 USD | 0.60 USD |
|---|---|---|---|---|
| 100 sun | 4.00 | 6.11 | 8.00 | 12.00 |
| 210 sun | 8.40 | 12.83 | 16.80 | 25.20 |
| 420 sun | 16.80 | 25.67 | 33.60 | 50.40 |

The fixed fee covers a burned-TRX release while `(sun per energy) x (USD per TRX) <= 40`, that is up to 0.40 USD
per TRX at today's energy price, or up to 131 sun at today's TRX price. The fee is immutable; above that line the
relayer loses the difference on each release unless it uses staked energy (below). The energy price is a chain
parameter set by TRON governance: read `getEnergyFee` again before deployment.

**A griefing burst now costs the attacker more than the operators.** Each minimum burn (20 USDT) costs the attacker
8.01 USDT in fees to the owner's address, plus its own deposit fee and deposit energy; it costs the relayer about
6.11 USDT of TRX. 1,000 minimum burns: the attacker pays 8,010 USDT, the relayers spend about 20,000 TRX (6,110
USDT), the owner's address receives 8,010 USDT. The relayers still need TRX at hand: the fee arrives in USDT at the
owner's address, not at the relayer. So: `tron_max_releases_per_hour` (default 120 per relayer; at most about 2,400
TRX an hour) bounds how fast a float can be spent, a burn above the cap stays payable, and the float alert of
section 8 stands.

**Staked or delegated energy (operator option, not rehearsed).** TRON lets an account obtain energy by staking TRX
(Stake 2.0) or by receiving a delegation of another account's energy. The vault is deployed with
`consume_user_resource_percent` 100, so the CALLER's energy is used: the account to stake for, or delegate to, is
the relayer's (and each guardian's, for the rare pause). A relayer with enough staked energy burns no TRX for a
release, and the fixed fee is then margin. The tools need no change (`tron_send.py` reports `energy_from_stake` in
every receipt and keeps the fee limit as the ceiling for the burned part). How much TRX must be staked for a given
number of releases a day depends on the network-wide stake and was not measured. Staking the vault's creator
account instead (a lower `consume_user_resource_percent`) was rejected: it would make the creator pay for every
caller, including an attacker's deposits.

**OWNER DECISION (revenue; proposed middle ground).** 8 USDT fixed plus 5 bps, minimum burn 20, minimum deposit 21.
Lower (for example 4 USDT) is right only if the operators commit to staked energy; higher protects against a TRX
price above 0.40 USD. All three numbers are immutable at deployment.

**The issuer's own fee is not the bridge's.** If Tether switches its transfer fee on, the recipient of a release
(and the owner's address on a sweep) receives less by that fee; the bridge's books do not change (section 2,
point 1).

Network costs of a deposit are the user's: section 9, "Energy".

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

**7.5 Create.** One-way. Costs about 442 TRX at 100 sun per energy (measured: 4,421,209 energy).

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

**7.8 Operators start** their node, shim, signer, relayer and guardian (section 8). The shim is started with the
vault and its creation block (`block` in the output of 7.5), and builds its log index before the daemons can use it:

```
python3 tools/signatario-tron/tron_rpc_shim.py --node http://127.0.0.1:8090 --port 42320 --chain-id 728126428 --vault VAULTHEX --from-block VAULTCREATIONBLOCK --index /var/lib/bridge-tron/shim-index
```

Then they run the preflight of
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

**7.10 First deposit**: the smallest allowed (21 USDT), by the owner, followed through credit, burn and release
before the address is published in `deployments/tron/bridge.network.json`.

## 8. Operator runbook: the delta

`docs/BRIDGE-V3-OPERATOR-RUNBOOK.md` applies. What changes for this route:

| Runbook rule | On TRON |
|---|---|
| 2.1 Own Ethereum node per operator | Own **java-tron FullNode** per operator (HTTP API on loopback, with the solidity API), and the operator's own `tron_rpc_shim.py` in front of it. A public API endpoint (TronGrid or another) is never a signer's or guardian's source: the tools refuse a node that is not on loopback (the override `tron_allow_remote_node` / `--allow-remote-node` raises a critical alert at every start and must not be used by a signer or a guardian). Start the shim with `--chain-id 728126428` (it refuses another chain), `--vault`, `--from-block` and `--index` |
| 2.3 Gas ceilings | `tron_fee_limit_sun` (default 150 TRX per transaction). The sender also refuses when the simulated energy × the energy price × 3/2 exceeds it, and gives each transaction that product as its own limit. `tron_max_releases_per_hour` (default 120) caps what one relayer signs in an hour. Budget from a mainnet simulation: USDT carries the maximum dynamic-energy penalty there |
| 2.3a A release reservation left behind | Does not exist on TRON. The equivalent is a journal file in `.tron-submissions/`: never delete it by hand before `tron_valid_s` plus two minutes have passed (`tools/signatario-tron/README.md`, "The journal") |
| 2.4 Two L2 views before a vault pause | Unchanged (it concerns the L2 side) |
| 2.6 Unpause needs 6 of 7 | Unchanged. Digest: `unpauseDigest(uint64 pauseCount, uint256 validUntil)` read through the shim; submit with `tron_send.py call 'unpause(uint64,uint256,bytes[])' …` |
| 3 Pre-go-live check | Add: the node is synced (`/wallet/getnowblock` within 10 s of the clock, `/walletsolidity/getnowblock` within 2 minutes of the head); `eth_chainId` on the shim is `0x2b6653dc`; the vault's runtime code keccak at `finalized` equals `runtimeCodeKeccak` from `tron_deploy.py verify`; `tokenState()` is (true, false, false); the relayer and every guardian account are activated and funded |

New alerts and what to do:

| Signal | Meaning | Action |
|---|---|---|
| `tokenState()` returns blacklisted = true | Tether blacklisted the vault | Deposits are already refused by the vault. Releases revert in the token and stay payable. Publish; contact the issuer. The books are unchanged. Owner decision (R325-TRX-10): what the DEX does with pools of `bUSDT.trx` meanwhile; the L2 token stays transferable and burns are still accepted |
| `tokenState()` returns replaced = true, or known = false | Tether deprecated the token, or a getter stopped answering | Deposits are already refused. Do not sign anything new until the replacement contract has been reviewed |
| `reservas` reports a shortfall | The vault's balance is below `totalLocked + feesAccrued` (destroyed funds) | A guardian pauses the vault (automatic). No release is paid until the whole shortfall is back. Owner decision |
| Relayer logs `TRON send refused: fee ceiling` | Energy needed is above `tron_fee_limit_sun` | Check the energy price and the dynamic-energy factor; raise the limit deliberately or wait |
| Relayer logs `TRON send refused: the call would revert now` | Token paused, vault blacklisted, vault paused, or a certificate whose anchor is older than 256 blocks | For a stale anchor the signers sign a new round on their own. Otherwise see the token state |
| The solidified height stops advancing | Fewer than 19 block producers are live, or the operator's node is stuck | Nothing is attested (safe). Check the node against a second view before anything else |
| Relayer TRX balance below 500 | The relayer will stop paying releases | Top up. Burns stay payable; nothing is lost |
| Shim logs `tron-log-index` (critical), daemons fail with `TRON log index refuses to answer` | The node's solidified receipts and the vault's solidified state disagree about the deposits (a deposit the state holds is missing from the receipts, or a `Deposited` log the state does not confirm) | Nothing is signed from this node (safe). Check the node (sync, database) against a second view. When the node is sound again the index heals by itself; deleting the index directory rebuilds it |
| Daemons fail with `TRON log index is catching up` | A new or restarted shim is still reading history, or the node is behind | Wait. Progress: `curl -s -X POST -d '{"jsonrpc":"2.0","id":1,"method":"tron_shimStats","params":[]}' http://127.0.0.1:42320` |
| `tron_shimStats` shows `rollbacks` rising | The solidified chain changed under the index (a replaced block, a vanished transaction) | The index has already dropped and re-read that span. A solidified block being replaced means more than a third of the block producers misbehaved: stop and compare with other operators before signing anything |
| Relayer logs `tron-release-failed-on-chain` | A release transaction landed and failed (another relayer's landed first, or it ran out of energy). The relayer waits 60 s, doubling, before another attempt | Once: nothing. Severity `hard` (two in a row for one burn): look at the receipt (`result`), the energy limit and whether two relayers race |
| Relayer logs `TRON send refused: rate cap` | `tron_max_releases_per_hour` reached | Burns stay payable. A burst of small burns: check the float; raise the cap only deliberately |
| Any tool logs `tron-remote-node` | A node that is not on loopback is configured | Not acceptable for a signer or guardian |
| Issuer transfer fee on (`IssuerFeeKept` events; `basisPointsRate()` not 0) | Tether charges its own fee | Exits continue; recipients receive less by the issuer's fee. Deposits revert. Publish it; the frontend must show it |

A burn paid to a recipient that Tether has blacklisted succeeds (the token allows it); the funds are then frozen
at that address by the issuer, not by the bridge.

## 9. Tests and rehearsal

**Forge** (Mac, stock solc, 2026-11-16, after the review fixes): `forge test --offline --match-path
'solidity-tests/Tron*'` 87 tests in 9 suites, all pass (the mock of USDT-on-TRON, the vault, issuer cases, the fee
bounds of TRON-6 and TRON-7 with hostile tokens, a stateful fuzz, a differential fuzz against the Ethereum vault).
`forge test --offline --match-path 'solidity-tests/tron-ported/*'` 238 tests in 21 suites, all pass (the Ethereum
vault's suites ported by `scripts/tron/port_vault_suites.py`; one test is not ported, section 13). The Ethereum
vault's own suites are untouched.

**Offline tool tests**: `python3 tools/signatario-tron/test_tron_tools.py`, 143 checks, all pass.

**Rehearsal on a private TVM** (`tools/signatario-tron/rehearse_tron.py`), host 45.77.142.123, loopback only,
throwaway keys:

- TRON side: the official quickstart image `tronbox/tre@sha256:f4332e11df12a9f360639a4546fd046593909630fda48af00b30410c144342f0`
  (TRE 2.0.0, java-tron 4.8.2). The **real TetherToken creation code** read from TRON mainnet (15,575 bytes,
  sha256 `28668160…93b5`) deployed locally. The vault in the launch shape (fixed release fee 8 USDT, minimum
  deposit 21, minimum burn 20).
- L2 side: anvil standing in for the L2, with `BridgedStablecoinV3` from the frozen source (creation keccak
  checked against the launch pin).
- Daemons: the unchanged signer and source half, `vigia_tron.py`, `guardiao_tron.py`, the unchanged `reservas.py`,
  all through the shim with its log index (scan mode).

| Run | Code | Result |
|---|---|---|
| 1 | before `8dd2cb4` (script not preserved) | 46 of 58 |
| 2 | `8dd2cb4` | 50 of 58 |
| 3 | `bfef0d6` | 58 of 58 |
| 4 | `6b4a7fe` (the tip the reviewer saw; reproduced twice by the reviewer) | 58 of 58 |
| 5 | review fixes, before the hourly cap | **65 of 65** |
| 6 | as 5 plus the hourly cap | 63 of 65: see below |
| 7 | as the final tip except the shim's start-up (below) | 66 of 66 |
| 8 | **the final tip of this branch** | **66 of 66** |
| history 1 | the tools of run 6, 30,000 blocks and 3,000 unrelated transactions | 25 of 25 |
| history 2 | the tools of run 7, the same history, the shim with its production settings | 21 of 21, then stopped: the shim of the cold-build step could not bind its port (below). The two cold builds were then measured by hand on the same chain with the final tools (`cold2.log`) |

Logs: `agents/323-evidence/run1.log` to `run8.log`, `hist1.log`, `hist2.log`, `cold2.log`, `history-measured.json`
(history 2).

**Run 6 (63 of 65) and what it showed.** The stage "a solidified block is lost" failed: the first guardian saw no
finding and only the second voted to cancel. Cause: a query for history was answered from the index without first
checking the index against the node, so for the two seconds until the background round the index still held the
lost deposit; run 5 passed the same stage by timing. That was a real gap in the first version of the index, not a
script error. Fixed: a query checks the index first whenever the last check is older than `--fresh-s` (1 s; 0 in
this rehearsal), and the document now states how long a log that left the solidified chain can still be served
(`--fresh-s` + `--recheck-s`). The second failed check (final books) was its consequence. A first attempt at run 7
then showed a second weakness: on this node a state read can run a moment ahead of the receipts, the index took
that for a contradiction and refused to answer for ten minutes. Fixed: such a mismatch is first waited for
(`--grace-s`), then looked for by re-reading, and only then refused (`tron_log_index.py`). History 2 showed a third:
the shim died at start with "address already in use" on a port nobody listened on. The host's ephemeral port range
(32768 to 60999) contains this agent's port range, and another process's outgoing connection held the port for a
moment. Fixed: the shim retries a busy port for ten seconds, and binds before it starts reading the chain. An
operator should still give the shim a port outside the system's ephemeral range.

**What the 66 checks cover** (adversarial cases in bold): deposit; no signature while the deposit is in the head
but not solidified; credit after solidification and the 12 h delay; burn; release less 5 bps and the fixed fee,
with USDT's `false` return; **replay of a certificate** (`InvalidRelease`) and **of the identical transaction**
(refused by the chain); **forged attestations**: 5 outsider keys, 4 committee keys plus 1 outsider, 4 committee
keys (`InvalidCertificate`), also broadcast on chain (reverts, books unchanged); **a real certificate with another
anchor hash** (`InvalidContext`); **a real certificate for a burn under another mint chain**
(`ProvenanceMismatch`); limits: deposit above the window, below the minimum, a recipient that is not 20 bytes,
the L2 mint bucket, a burn above the bucket, the release window exhausted; **token paused by the issuer**;
**the issuer's transfer fee switched on** (deposit refused; sweep and release still pay, the recipient short by
exactly the issuer's fee, the vault's balance down by exactly what it sent, the books those of a fee-free release;
deposits accepted again once it is off); **vault blacklisted** (with the control that the real token would accept
the deposit); **vault funds destroyed**; guardian pause by the guardian daemon as a TRON transaction, no deposit
and no release while paused, a guardian cannot pause twice, a stranger cannot pause, 5 of 7 cannot unpause and 6
of 7 can; fee sweep to the owner's address; **a solidified block lost after attestation**: the index drops the
deposit, 2 of 3 guardians cancel the queued mint, never credited; when the block returns the index finds the
deposit again; final books; the log index verified at the solidified block with exactly the vault's deposits.

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

**Long history (review R325-TRX-1)**: `tools/signatario-tron/rehearse_tron_history.py`. One deposit, then 30,000
blocks (about 25 hours of TRON mainnet at 3 s) of which 3,000 carry an unrelated USDT transfer (every 50th one TO
the vault, so its address sits in a topic of somebody else's log), then a second deposit, its attestation and
mint, a burn and its release, a guardian round, a reserves check, and two shims started on an empty index. Node
requests are the shim's own counter; time is the wall clock of the real daemon process.

| Measured in history 2 (one signer unless said; shim with production settings) | Node requests | Time |
|---|---|---|
| Attestation of a deposit, new vault (a few blocks old) | 33 | 1.18 s |
| Attestation of a deposit, vault 30,000 blocks old | **25** | **1.04 s** |
| Relay round that queues the mint | 14 | 0.67 s |
| Release certificate (source half), vault 30,000 blocks old | **37** | **1.16 s** |
| Relay rounds until the release is solidified | 37 | 3.08 s |
| Guardian round | 25 | 0.71 s |
| Reserves check | 11 | 0.25 s |
| Following the chain | 1 per new block, plus 4 small ones per 2 s round (2.0 a second when idle) | - |
| Cold build of the index, scan mode (every block) | 30,169 for 30,027 blocks | 36.5 s (823 blocks a second) straight to the node; 55.4 s through the rig's proxy in history 1 |
| Cold build of the index, hint mode (the node's log filter) | 30, plus 16 `eth_getLogs` to the node | 0.2 s |
| The same attestation before the fix (arithmetic from the old code) | 20,001 per query, 60,059 per attestation | could not finish |

History 1 (the shim re-reading recent receipts on every round) gave 35 and 25 requests for the two attestations and
41 for the release certificate.

An attestation and a release cost the same on the old vault as on the new one: no request depends on the vault's
age. The five signers' figures are the same (each has its own shim in production; in the rig they share one).

**Expected at TRON mainnet's block rate** (28,800 blocks a day). Measured parts are marked; the rest is arithmetic.

| Quantity | Expected | Basis |
|---|---|---|
| Node requests per attestation, per release certificate | 25 to 40, about 1 s | measured; independent of history |
| Of those, requests that return a whole block's receipts | at most 3 (the deposit's own block twice for the receipt check, and the newest block) | code path; a mainnet block's receipts are about 85 KB (reviewer's reading of block 88,063,136) |
| Following the chain, scan mode | 28,800 block-receipt requests a day (one every 3 s), about 2.4 GB of JSON a day on loopback | 1 request per block (measured) x 85 KB |
| Following the chain, hint mode | about 15 `eth_getLogs` a day plus 2 requests per block that holds a vault log | 1 query per 2,000 blocks (measured) |
| Cold build or catch-up after an outage, scan mode | one request per missed block: one day of chain = 28,800 requests. At 823 blocks a second (measured here on blocks with at most one transaction) that is under a minute; a mainnet node serving 85 KB per block will be slower. If it serves 50 blocks a second across the 8 parallel readers, a day of chain takes 10 minutes and a month 5 hours. **Not measured on mainnet-size blocks** | measured rate x block count; the mainnet rate is an assumption |
| Work of one `eth_getLogs` while catching up | at most 400 node requests, then an error "catching up"; the daemon's round is retried | `QUERY_BUDGET`, offline test |
| Before the fix | 2 x (vault age in blocks) per attestation: 57,600 after a day, 1.7 million after a month | reviewer's test, reproduced |

**Energy** (run 5, private TVM, 100 sun per energy, everything bought by burning TRX):

| Transaction | Energy | TRX |
|---|---|---|
| Vault creation (7 signers, 3 guardians) | 4,421,209 | 442.4 |
| `setControls` (5 of 7) | 58,596 | 5.9 |
| `deposit` (first / later) | 114,428 / 82,996 | 11.4 / 8.3 |
| `release` (5 of 7, relayed) | 143,753 | 14.4 |
| `release` under an issuer transfer fee (with this node's dynamic-energy penalty of 23,975) | 182,468 | 18.3 |
| `release` replay, reverted | 10,019 | 1.0 |
| `release` forged, reverted | 31,001 | 3.1 |
| `guardianPause` | 78,989 | 7.9 |
| `unpause` (6 of 7) | 53,807 | 5.4 |
| `sweepFees` | 48,628 to 84,209 | 4.9 to 8.4 |

On mainnet, calls that touch USDT cost more: USDT is at the maximum dynamic-energy factor (a simulated mainnet
transfer used 64,285 energy, 49,635 of it penalty). Expect roughly 55,000 more energy for a deposit, a release and
a sweep (section 5 sizes the fixed release fee on 200,000). At these prices a deposit costs the user on the order
of 15 TRX plus an approval, which is material against the 21 USDT minimum; the frontend must show it.

**What the rig cannot show**: the quickstart node solidifies every block at once and cannot reorganise. "Not yet
solidified" and "a solidified block is lost" are produced by a proxy in front of `/walletsolidity` that the
rehearsal controls. Constant calls at the solidified level are answered from the head state by that node; for the
two calls the log index's completeness check makes (`depositCount()`, `depositMatches`) the proxy answers as a real
node's solidified state would while a deposit is held back or lost. Blocks hold at most one transaction.

## 10. Audit note

**New code to audit**

| File | Lines | Notes |
|---|---|---|
| `contracts/tron/TronSourceVault.sol` | 922 (82 added, 22 removed against the Ethereum vault) | Review as a diff: `python3 scripts/tron/vault_diff.py`. TRON-6 and TRON-7 were added after the first review and have not been reviewed by anyone but their author and a test-writing sub-agent |
| `tools/signatario-tron/tronlib.py` | 377 | Transaction encoding and decoding; the address forms |
| `tools/signatario-tron/tron_rpc_shim.py` | 375 | The `finalized` mapping; log queries |
| `tools/signatario-tron/tron_log_index.py` | 366 | The vault's log index: what it trusts, the deposit completeness check, the re-checks. New after the first review |
| `tools/signatario-tron/tron_send.py` | 281 | The journal, the back-off, the hourly cap |
| `tools/signatario-tron/vigia_tron.py`, `guardiao_tron.py` | 123, 66 | Overrides only |
| `tools/signatario-tron/tron_deploy.py` | 260 | Owner tool |
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
8. TRON-6 (`_received`): the vault's side is exact; is there a token behaviour inside the tolerated bounds that
   harms the vault rather than the recipient? Can `IssuerFeeKept` or the extra balance read open a re-entry (the
   functions keep the reentrancy guard)? Is 20 bps / 50 USDT the right bound for a token the issuer may replace?
9. TRON-7: `fee + releaseFlatFee` arithmetic, the check in `_checkRelease` (a release not above its fee is refused
   before anything is consumed, on the direct, delayed and proof paths), the constructor bound.
10. The log index's completeness argument (`tron_log_index.py`, "What is trusted"): deposits are bound to the
    vault's state; the vault's OTHER logs are only as complete as the node's receipts (scan mode) or log filter
    (hint mode). Which daemon decision reads those?

Two facts for the audit note (R325-TRX-8): `block.chainid` on TRON is a chain parameter read live, so a TRON upgrade
that changed it would change every digest and `mintChainGenesis()` at once (fail-safe: nothing verifies; no recovery
in an ownerless vault). And every private `tronbox/tre` network shares one genesis and so one chain id: never sign
with real keys on one.

## 11. Not done / not proven

1. **Build and rehearse with TRON's own compiler.** The vault was built with stock solc 0.8.24 because the
   download of TRON's compiler was denied. Until the commands of section 3 have been run and the rehearsal passes
   66 of 66 on that bytecode, the bytecode that would be deployed has never been executed. First command:
   `curl -fL -o ~/tron-solc-0.8.24/solc-static-linux https://github.com/tronprotocol/solidity/releases/download/tv_0.8.24/solc-static-linux`
   (the full sequence is in section 3).
2. **No external audit.** Mandatory before real funds.
3. **No real java-tron network behaviour.** The private node is a single-producer quickstart: no real
   solidification lag, no reorg, no 27 producers. Lag and loss were simulated by a proxy. Not tested on Nile or
   Shasta (testnets were out of bounds for the agent).
4. **The solidified API's state.** On a real node `/walletsolidity/triggerconstantcontract` reads solidified
   state; the quickstart answers from the head. The shim's central claim was therefore tested for logs, blocks
   and receipts, but for contract state only offline. The log index leans on the same claim (its completeness check
   reads `depositCount()` and `depositMatches` at the solidified level); in the rehearsal the proxy stands in for
   the solidified state of those two calls while a deposit is held back or lost. Prove both on a multi-producer
   node (a testnet, or a private 3-producer network) before launch (R325-TRX-5).
4a. **State "at a height" (R325-TRX-5, known issue, not fixed).** The shim answers a state read at a height at or
   below the solidified one with the CURRENT solidified state. That is sound for what the signer reads (immutable
   code, pure views, set-once flags, append-only chains). `reservas.py` compares the vault's totals with the L2
   supply and so sees a moving snapshot: a deposit solidified between its two reads can show as a short false
   surplus or deficit. A false deficit that lasts past the guardian's grace would pause the vault. Mitigation in
   place: none in code; `reserves_grace_s` above zero in production configs. A list of allowed reads enforced by
   the shim is not written.
4b. **Hint mode** (`--logs-rpc`) was exercised on the private node's JSON-RPC only. Whether a mainnet node's log
   filter is complete for old blocks depends on how the node was synced; the deposit check catches an omitted
   deposit, nothing catches an omitted release log in that mode.
5. **The guardian's freshness rule** (`cancel_fresh_s`, 300 s) was switched off in the rig because the two clocks
   cannot be aligned there. Its interaction with TRON block timestamps is unproven.
6. **Mainnet energy.** Costs were measured on a private node. USDT's dynamic-energy penalty on mainnet was read
   from one simulated transfer only, and the fixed release fee is sized on an ESTIMATE of 200,000 energy: simulate
   a release against mainnet state before the fee is frozen. Staked or delegated energy was not rehearsed.
6a. **Mainnet block size.** The long-history rehearsal has at most one transaction per block. Reading a mainnet
   block's receipts (about 85 KB for 230 transactions) was not load-tested; section 9 gives the arithmetic.
7. **`deprecate`** on the real USDT bytecode was not exercised (ABI only); the vault's reaction was tested against
   the mock.
8. **The L2 token deployment through the shim** (`deploy_pontes.py --source-rpc`) was not rehearsed, and the tool
   refuses chain id 728126428 today (cross-area). The manual commands of 7.9 were not run in that form: the
   rehearsal opened the controls with the same digest and signatures but through its own helpers, and the
   `tron_send.py` command line was run on the private TVM with `sweepFees()` only
   (`agents/323-evidence/cli-sweep.json`).
9. **Hardware wallet for the deployer**: not supported; the deployer is a keystore key used once.
10. **The differential fuzz and the ported suites run on the EVM**, not on the TVM. TVM-specific behaviour is
    covered only by the 66 rehearsal checks and the long-history rehearsal.
11. **Long outages**: a shim that was down catches up from its checkpoint at one request per block (section 9);
    measured on the private chain only.
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
| **Revenue decision**: the fixed release fee (proposed 8 USDT), with minimum burn 20 and minimum deposit 21; or another value from the table of section 5. Immutable | section 5; `deployments/tron/busdt-trx-vault.config.json` |
| Whether operators stake TRX for energy (then a lower fixed fee is defensible) | section 5 |
| What the DEX does with `bUSDT.trx` pools while the reserves monitor reports a shortfall or the vault is blacklisted (R325-TRX-10) | - |
| Confirm the limits (cap 100,000; window 10,000 per day; 12 h delay) and the percentage fee (5 + 5 bps) | `deployments/tron/busdt-trx-vault.config.json` |
| Confirm the fee address `TCQ2d5gxTczSeN2oeni16JwMW7HWLzXEKc` once more from the wallet itself (it is immutable) | same |
| The 7 release signer addresses and operators, the 3 guardian addresses and operators (the Ethereum bridge's) | same |
| A fresh TRON deployer account with at least 600 TRX; relayer float (about 2,000 TRX); 100 TRX on each guardian address | section 6 |
| Each operator: a java-tron FullNode of their own | section 8 |
| The decision to widen `deploy_pontes.py` to this source network | `agents/R16-CROSS-AREA.md` |
| The L2 explorer URL patterns | `deployments/tron/bridge.network.json` (`explorers.l2`) |

## 13. Review of round 16 (reviewer 325) and what was done

Reviewer's section: `agents/325-bridges-review-r16.md` section 2, on tip `6b4a7fe`.

| Finding | Severity | What was done | Regression |
|---|---|---|---|
| R325-TRX-1: every attestation re-read the vault's whole history, two node requests per block | High | The shim keeps a persisted, verified index of the vault's logs (`tron_log_index.py`): each block is read once (one request, in parallel batches; or only the blocks the node's own log filter names), deposits are bound to the vault's solidified deposit chain, a query costs no node request once the index is current and at most the budget (400) plus about 250 while it catches up, and a query the index cannot answer completely is an error. The Ethereum daemons are unchanged. A query for an address without an index is served for at most 100 blocks | `test_tron_tools.py` "R325-TRX-1: …" (8 checks, including the reviewer's test restated: one attestation of a one-day-old vault, at most 200 node requests per query); `rehearse_tron_history.py` (section 9) |
| R325-TRX-2: an issuer transfer fee stopped every exit with no bound | Medium | Decided: exits continue at the recipient's cost. TRON-6: the vault's balance must fall by exactly what it sends; the recipient may be short by at most 20 bps and 50 USDT. Deposits still require the whole amount to arrive | `TronVaultFees.t.sol` (13), `TronVaultIssuer.t.sol::test_d_…`, the stateful fuzz; rehearsal stage "issuer fee" on the real token (5 checks) |
| R325-TRX-3: a release cost the relayer about 14 to 20 TRX against 0.005 USDT of fee | Medium | TRON-7: a fixed release fee (proposed 8 USDT = measured cost x 1.31), minimum burn 20, minimum deposit 21; an hourly cap on what a relayer signs; staked energy documented as an operator option. Owner decision on the numbers (section 5) | `TronVaultFees.t.sol` (9), every release check of the rehearsal, `test_tron_tools.py` "R325-TRX-3: …" |
| R325-TRX-4: a remote, plain-http node was accepted silently | Low | `tronlib.Node` refuses a URL that is not on loopback; explicit override with a critical alert | The reviewer's test passes unchanged; `test_tron_tools.py` "R325-TRX-4: …" (3) |
| R325-TRX-5: state at a height is the current solidified state; solidified constant calls unproven on a real node | Low | **Known issue, not fixed** (section 11, items 4 and 4a) | - |
| R325-TRX-6: a release that landed and failed was signed again at once; an out-of-energy failure burned the whole configured limit | Low | The transaction's own fee limit is the simulated energy x price x 3/2. After a failed landing the payment waits 60 s, doubling (at most an hour), with an alert from the second | `test_tron_tools.py` "R325-TRX-6: …" (5) |
| R325-TRX-7: the diff is the documented one | Info | The diff is now larger (82 added, 22 removed) and pinned again; TRON-6 and TRON-7 need the reviewer's eyes | `scripts/tron/vault_diff.py` |
| R325-TRX-8: chain id is a live chain parameter; all `tronbox/tre` networks share one chain id | Info | Stated in the audit note (section 10) | - |
| R325-TRX-9: re-check list for the TRON compiler build | Info | Copied into section 3 | - |
| R325-TRX-10: the L2 side does nothing by itself when the backing is frozen or destroyed | Info | Owner decision recorded (sections 8 and 12) | - |

One ported Ethereum test is no longer run on the TRON vault, with its reason in the generator
(`scripts/tron/port_vault_suites.py`, `NOT_PORTED`): `A172VaultReview::test_U4_feeUpgradeFailsClosed` asserts that a
token which starts keeping a fee from the recipient makes every release revert, which is exactly what TRON-6
changes. A defect in the first version of TRON-7 was found by the test-writing sub-agent and fixed before this tip:
on the delayed-release path a release not above its fee was queued and its nonce consumed; the check now runs when
the certificate is submitted (`test_tron7_delayedReleaseNotAboveItsFee_refusedAtSubmissionConsumesNothing`).
