# TRON vault: `TronSourceVault` as "the Ethereum vault plus these changes"

UNAUDITED. Nothing is deployed. Written in round 16 (agent 323) on `codex/bridge-tron-r16-20261116`, from `cc2511a`.

`contracts/tron/TronSourceVault.sol` is `contracts/usdt/ProvenanceSourceVault.sol` (the Ethereum vault of the audit
scope, creation keccak `0x901d52d0…3a74`, unchanged on this branch) with five marked changes. Check it yourself:

```
python3 scripts/tron/vault_diff.py
```

It prints the whole diff (7 hunks, 43 lines added, 14 removed, most of them the header comment) and fails if the diff
is not the pinned one.

## 1. Source changes

| # | Where | Change | Why | What fails without it |
|---|---|---|---|---|
| TRON-1 | file header, contract name | The contract is named `TronSourceVault`; the two verifier interfaces are imported from the Ethereum vault's file instead of being declared again; a header lists these changes | Naming only | - |
| TRON-2 | constructor | `transferMode_ > 1` becomes `transferMode_ != 1` | USDT on TRON returns ABI `false` from every successful `transfer` and `true` from `transferFrom` (section 3). In mode 0 the vault would accept deposits (`transferFrom`) and then refuse every release and fee sweep (`transfer`): funds in, never out. Mode 1 ignores the return value and requires exact balance movement on both sides | `test_ctor_transferMode0And2Refused`; on the TVM the creation with mode 0 reverts |
| TRON-3 | constructor | The token must answer `isBlackListed(address(this))` and `deprecated()` with one ABI word each, both false | A token without these getters is not USDT-on-TRON, and the deposit gate below would then refuse every deposit for good | `test_ctor_tokenWithoutGettersRefused`, `…malformedGettersRefused`, `…preBlacklistedVaultAddressRefused`, `…deprecatedTokenRefused` |
| TRON-4 | `deposit` | After the pause check: `if (!_tokenAcceptsDeposits(token)) revert TokenUnsafe();` | Measured on the real bytecode: `transferFrom` checks only the blacklist entry of `from`, so a deposit INTO a blacklisted vault succeeds. Without the gate users could keep depositing into a vault whose funds the issuer has frozen and can destroy. The same gate refuses deposits once the issuer has deprecated the token (calls are then forwarded to a contract nobody reviewed) or when a getter stops answering | `test_a_vaultBlacklisted_…`, `test_e_deprecated_…`, `test_h_gettersTurnMalformed_…`, the stateful fuzz; on the TVM the control check "the real token does accept a transfer into the blacklisted vault" |
| TRON-5 | new view, two private helpers, one error | `tokenState()` returns `(known, blacklisted, replaced)`; `_tokenFlags` and `_tokenAcceptsDeposits`; `error TokenUnsafe()` | For monitors and frontends, and to serve TRON-3 and TRON-4. `_tokenFlags` never reverts: a failed or malformed answer is `known = false` | - |

Nothing else differs: every digest, id, tag, event, limit, pause rule, switch rule, fee rule and the reentrancy guard
are the Ethereum vault's lines. Releases are deliberately not gated: a release into a frozen or paused token reverts
inside the token and the whole transaction rolls back, so no nonce or nullifier is consumed.

A differential fuzz (`solidity-tests/TronVaultDifferential.t.sol`) drives both vaults with the same sequences on a
healthy token and requires the same result, the same revert selector and the same accounting after every step.

## 2. Platform differences with no source change

Verified on 2026-11-16 against TRON's developer documentation, TRON mainnet chain parameters read from a public node
(`/wallet/getchainparameters`, node version 4.8.2.4) and a private TVM (java-tron 4.8.2).

| Topic | Ethereum | TRON | Consequence for the vault |
|---|---|---|---|
| Compiler | solc | TRON's fork of solc is the documented compiler ("you must use the TRON distribution"); releases follow upstream (`0.8.24_Kant_v4.8.0` exists; latest `0.8.33`). Bytecode from stock solc 0.8.24 runs on the TVM | The rehearsal deployed the repository's stock solc 0.8.24 build. **A build with TRON's 0.8.24 was not made** (the download was denied to the agent); explorer verification needs it. Open item: the required compiler, what could differ and the owner's commands are in `docs/BRIDGE-TRON-USDT.md` section 3 |
| EVM version | shanghai (`PUSH0`) | Opcode sets are switched on by chain parameters. Mainnet today: Constantinople, Istanbul, London, Shanghai, Cancun, Blob, Prague, Osaka all 1 | `PUSH0`, `EXTCODEHASH`, `CHAINID`, `STATICCALL` available. Before deploying on any other TRON network read its parameters first |
| `block.chainid` | 1 | With parameter 71 on (mainnet): the last 4 bytes of the genesis block id, `0x2b6653dc` = 728126428. Without it: the whole 32-byte id | Every digest and the mint-chain genesis bind 728126428. The L2 token's `sourceChainId` constructor argument is that number. The rehearsal checks the vault's own `mintChainGenesis()` against it |
| Addresses | 20 bytes | 21 bytes (`0x41` + 20) at the API, Base58Check `T…` for people; 20 bytes inside the TVM, in ABI words, topics and `ecrecover` results | No change in the contract. Tools convert at the boundary and verify checksums (`tronlib.py`). A committee key has the same 20-byte address on both chains |
| `ecrecover` | precompile 1 | The same | 5-of-7 and 6-of-7 certificates verified on the TVM in the rehearsal |
| Other precompiles | 3 = RIPEMD-160, 9 = Blake2F | 3 and 9 differ | Not used |
| `blockhash(n)` | block hash, 256 blocks = about 51 min | The block id (height in its first 8 bytes), 256 blocks = about 13 min | The release anchor works unchanged. A certificate must land within about 12 minutes of the solidified anchor it names; signer configs use `anchor_max_age` 100 and `valid_seconds` 420 |
| `block.number` in a simulation | the next block | A constant call runs with the head's own number | An anchor equal to the head is refused in simulation only; on mainnet anchors are about 19 blocks behind |
| Fees | gas, bid price | Energy (100 sun each on mainnet, or staked) and bandwidth; a per-transaction `fee_limit` in sun (maximum 15,000 TRX); a reverted call still pays its energy; 80 ms CPU limit per transaction | `tron_send.py` simulates first, never sends a call that would revert, and refuses above `fee_limit_sun`. Measured costs in section 4 |
| Dynamic energy | - | A heavily used contract costs its callers more; USDT is at the maximum factor (`energy_factor` 34000: a mainnet simulated transfer used 64,285 energy, 49,635 of it penalty) | Deposit and release cost more on mainnet than on a private net. Budget from a mainnet simulation, not from section 5 |
| Deployment settings | - | `consume_user_resource_percent`, `origin_energy_limit`, contract name; the creator account may later change the two settings and clear the stored ABI | Deploy with 100 and 1: the creator never pays for callers. None of the three later powers touches funds or logic. Use the creator account once |
| Transactions | nonce, replaceable | No nonce; a reference block and an expiration; id = sha256 of `raw_data`; cannot be repriced | New sender with a one-live-transaction journal (`tron_send.py`) instead of the nonce journal |
| Finality | `finalized` | Solidified: confirmed by 19 of 27 block producers, about a minute behind the head; `/walletsolidity/*` serves it. java-tron's JSON-RPC serves state only at `latest` | The read-only shim maps `finalized` to the solidified API (`tron_rpc_shim.py`) |
| Logs | `logIndex` | Receipts have no log index | The shim numbers a block's logs in order |
| `SELFDESTRUCT`, `CREATE2` | restricted since Cancun; prefix `0xff` | Restricted (parameter on); prefix `0x41` | The verifier code-hash re-check stays as on Ethereum |

## 3. USDT on TRON: verified behaviour

Contract `TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t` (`41a614f803b6fd780986a42c78ec9c7f77e6ded13c`), read-only, 2026-11-16:
name `TetherToken`, `decimals()` 6, owner `TBPxhVAsuzoFnKyXtc1o2UySEydPHgATto`, not paused, not deprecated,
`basisPointsRate` 0, creation code 15,575 bytes (sha256 `28668160…93b5`). The same creation code was deployed on a
private TVM and exercised (it cannot run on an EVM: it uses TVM-only opcodes).

| Behaviour | Result | Source |
|---|---|---|
| `transfer` success | no revert, returns ABI **false** | mainnet simulation and private TVM |
| `transferFrom` success | returns true | private TVM |
| `approve` | returns true; nonzero over nonzero allowed | private TVM |
| Blacklisted sender (`transfer`) or `from` (`transferFrom`) | reverts | private TVM |
| Transfer or `transferFrom` TO a blacklisted address | **succeeds** | private TVM |
| `destroyBlackFunds(a)` | balance of a blacklisted address becomes 0 | private TVM |
| `pause()` | `transfer`, `transferFrom`, `approve` revert | private TVM |
| `setParams` (fee below 20 bps, capped) | recipient gets less, the fee goes to the owner | private TVM |
| `deprecate(newContract)` | calls are forwarded to another contract | ABI only; not exercised on the real bytecode |

What the vault does in each case (forge suites `TronVaultIssuer`, `TronVaultStateful`, and the TVM rehearsal):

| Issuer action | Deposits | Releases, fee sweep | Books |
|---|---|---|---|
| Vault blacklisted | refused, `TokenUnsafe` | revert in the token; nothing consumed; paid once after the listing ends | unchanged |
| Vault funds destroyed | refused, `InsufficientBacking` | refused, `InsufficientBacking`, until the whole shortfall is returned; no first-come drain | `totalLocked`, `feesAccrued` and the deposit chain still state every liability; `reservas` reports the shortfall |
| Token paused | revert | revert; paid once after the unpause | unchanged |
| Transfer fee switched on | revert (`InvalidTransfer`) | revert (`InvalidTransfer`), except amounts whose fee rounds to zero | unchanged |
| Token deprecated | refused, `TokenUnsafe` | paid only if the new contract moves exact amounts | unchanged |
| Release recipient blacklisted | - | paid (the token allows it; the issuer then holds the funds at that address) | consistent |

Accepted limits: the issuer can stop exits for as long as it likes (blacklist, pause, fee) and can destroy the
backing; the vault cannot prevent that, it only refuses new deposits and keeps the books provable. While a transfer
fee is on, exits wait.

## 4. Energy measured on the private TVM (java-tron 4.8.2, runs 3 and 4)

See `docs/BRIDGE-TRON-USDT.md` section 9, "Energy". Figures include the quickstart node's own dynamic-energy penalty
on the local USDT and exclude mainnet's higher one.
