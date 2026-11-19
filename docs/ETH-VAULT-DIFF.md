# Native-ether vault: `NativeEtherSourceVault` as "the Ethereum vault plus these changes"

UNAUDITED. Nothing is deployed. The route `ethereum-eth` (ETH on Ethereum to `bETH` on the Bloch L2) is HELD.
Written in round 20 (agent 412) on `codex/bridge-eth-r20-20261119`, from `main` `135bdba`.

`contracts/eth/NativeEtherSourceVault.sol` is `contracts/usdt/ProvenanceSourceVault.sol` (the Ethereum vault of the
audit scope, creation keccak `0x901d52d0…3a74`, unchanged on this branch) with ten marked changes. Check it yourself:

```
python3 scripts/eth/vault_diff.py
```

It prints the whole diff (152 lines added, 60 removed, about half of them the header comment) and fails if the diff
is not the pinned one. The build is pinned by `deployments/ethereum-eth/vault-build.pin.json`
(`python3 scripts/eth/vault_build_pin.py check` after `forge build`): creation code 23,284 bytes, keccak
`0x43d28dd04d6d52d697f09c39a07fec8447079f1df65f56c30110357eeca2591d`; runtime 19,668 bytes (EIP-170 limit 24,576).

Why a second contract and not an edit: the frozen vault's bytes may not move (its creation hash is an audit and
deployment identity), its token calls are `private` and not virtual, and its constructor requires a token with code
and six decimals. A derived contract cannot replace them; a copy with a pinned diff can be read against the audited
text line by line. The TRON route set the precedent (`docs/TRON-VAULT-DIFF.md`).

## 1. Source changes

| # | Where | Change | Why | What fails without it |
|---|---|---|---|---|
| ETH-1 | file header, contract name | The contract is named `NativeEtherSourceVault`; the two verifier interfaces are imported from the Ethereum vault's file; a header lists these changes | Naming only | - |
| ETH-2 | state, constructor | `token` is the constant `NATIVE_ETHER` = `0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE` (no code, no known key; on Ethereum mainnet the address holds 204 ETH that people sent to it and has nonce 0, read 2026-11-19). The constructor keeps its eleven arguments and refuses any `token_` but the marker and any `transferMode_` but 0; the `decimals()` question to a token is gone; `transferMode` is the constant 0. The fee recipient may not be the marker | The asset is ether: there is no contract to call. Keeping `token` as a word of `routeId` keeps the route-id formula, and every tool that reads the vault's getters, unchanged | `test_ctor_onlyTheNativeEtherMarkerIsAToken`, `test_ctor_transferModeOtherThan0Refused`, `test_ctor_feeRecipientMayNotBeTheMarkerOrTheVault`, `test_ctor_creationWithValueFails` (the constructor is not payable); mutant M16 |
| ETH-3 | constants | `UNIT = 1e12` wei; `decimals` stays 6. Every amount of the contract is in units | The books, ids, digests and events keep the Ethereum vault's `uint64` words (2^64 wei would be 18.4 ETH), and one unit is one unit of the frozen six-decimal L2 token (`docs/BRIDGE-ETH.md` section 3) | `test_identity_viewsAndFormulas`; every test that states wei against units |
| ETH-4 | `deposit`, `receive` | `deposit` is payable and requires `msg.value == amount * UNIT` exactly (`ValueMismatch`), checked right after the pause check; the `transferFrom` and its two balance comparisons are gone. `receive()` reverts with `DirectTransferRefused`; there is no `fallback`. The L2 recipient rule is the Ethereum vault's, unchanged: stated, non-zero, 20 bytes, never the sender by default | "Stated amount versus value" has one answer: they are equal or the call fails. No wei below a unit can enter and nothing ever needs refunding. A plain transfer names no L2 recipient, so it could only be lost | `test_deposit_valueMustBeExactlyTheStatedAmount`, `test_deposit_plainTransfersAreRefused`, `test_deposit_fromAContractCreditsTheStatedRecipient`, `test_deposit_recipientMustBeStated`; mutants M7, M9, M10 |
| ETH-5 | `_fee`, `_checkRelease`, `_transferOut` | Fees round UP to the unit. A release whose amount does not exceed its fee is refused (`InvalidRelease`) at submission, on every path | Coordinator decision 2, "no rounding gain for the user": the protocol never receives less than the exact rate, and splitting an amount never lowers its fee. The Ethereum vault rounds down. Rounded up, a one-unit release would pay nothing, hence the refusal | `testFuzz_fee_depositRoundsUpNeverInTheUsersFavour`, `testFuzz_fee_splittingNeverLowersIt`, `testFuzz_fee_releaseRoundsUpAndPaysExactWei`, `test_fee_knownValues`, `test_fee_releaseNotAboveItsFeeRefused`; mutants M8, M17 |
| ETH-6 | `owedWei()`, `surplusWei()`, every backing check | Backing is counted, never measured. The books are `totalLocked + feesAccrued + totalClaimable`; the balance must only COVER them (`InsufficientBacking` if not). In `deposit` the comparison is made on the balance before the deposit's own value | Ether can be forced into any address (SELFDESTRUCT, a block reward, ether sent before the contract exists). The Ethereum vault's exact balance-delta rule would turn one forced wei into a stopped vault. Forced ether is a surplus: no function pays it out, it counts toward no limit | `test_forced_selfdestructBreaksNothing`, `test_forced_capIsNotFilledByForcedEther`, `test_forced_prefundedAddress`, `test_forced_blockRewardStandIn`, `test_forced_surplusIsNeverPaidOut`; mutants M6, M11, M13; stateful I4, I5 |
| ETH-7 | `_transferOut`, `_send`, `PUSH_GAS`, `claimable`, `totalClaimable`, `ReleaseDeferred`, `InsufficientGas` | A release pays by `call` with exactly `PUSH_GAS` = 30,000 gas (plus the EVM's 2,300 stipend), copying no return data. Before the call the vault requires `gasleft() >= PUSH_GAS * 64 / 63 + 40,000`. If the call fails, the release STILL completes (nonce, burn and window consumed; `Released` emitted) and the payment is booked in `claimable[recipient]` | Section 2 | `test_release_revertingRecipientDoesNotBlockTheQueue`, `test_release_gasBurningRecipientIsBounded`, `test_release_returnDataIsNeverCopied`, `test_release_relayerCannotStarveThePush`, `test_release_recipientGetsThePushGas`, `test_release_reentrancyFromThePushIsRefused`, `test_release_accountWithCodeThatChanges`, `test_release_delayedPathDefersToo`; mutants M1 to M5, M12, M18 |
| ETH-8 | `claim(to)`, `claimFor(recipient)`, `Claimed`, `NothingToClaim`, `PaymentFailed` | The recipient of deferred payments takes all of them to any address it names; anyone may pay them to the recipient itself. All gas is forwarded; a failed payment reverts the whole claim. A claim is not held by a pause, the window or the committee's controls | A claim is a release already made. `claimFor` lets a relayer (or anyone) deliver to a wallet that needs more than 30,000 gas; `claim(to)` lets a contract that cannot receive ether at all still take its payment | `test_claim_paths`, `test_claim_recipientRedirects`, `test_claim_notHeldByPauseControlsOrWindow`, `test_release_reentrancyFromAClaimIsRefused`; mutants M14, M15 |
| ETH-9 | `sweepFees` | Pays the accrued fees in ether to the immutable `feeRecipient` with all gas; a refusal reverts the sweep (`PaymentFailed`) and the fees stay accrued | The recipient is the owner's plain address. If it ever refuses ether only the fees wait; deposits and releases are untouched | `test_fee_sweepPaysExactlyTheFeesInWei`, `test_fee_sweepToARefusingRecipientRevertsAndKeepsTheFees`, `test_release_reentrancyFromTheSweepIsRefused` |
| ETH-10 | where `feesAccrued` and `totalClaimable` are declared | Storage placement only. `feesAccrued` is declared beside the release bucket (one slot with the reentrancy flag, which every deposit and release writes anyway). `totalClaimable` shares its slot with a private flag that is always true | What a release costs its relayer must not depend on a state anyone can arrange. A sum written into an EMPTY storage slot costs 17,100 gas more than into a used one: `feesAccrued` is zero after every sweep (anyone may sweep) and `totalClaimable` is zero whenever no claim is outstanding. Before the change the rehearsal measured 229,088 gas for a merely reverting recipient in that state (a gas-burning one would have cost about 261,000); after it the worst case is 222,402 in every state; a plain release fell from 166,966 to 162,275 and a deposit from 77,705 to 75,834. No value, rule or event changes | `test_release_costDoesNotDependOnSweptFeesOrOutstandingClaims`; mutants M19, M20 |

Nothing else differs: every digest, id, tag, limit, pause rule, switch rule and the reentrancy guard are the
Ethereum vault's lines; so are the events (two added) and the errors (five added). On fee-exact amounts and plain
recipients the two vaults behave identically, call for call (the differential fuzz, section 4).

## 2. The release payment: why a bounded push with a claim, and why these numbers

A release that cannot be paid must neither block the queue nor lose the burn's payment. Three designs were weighed.

| Design | A recipient that reverts | Cost a recipient can impose on the relayer | A user with an empty account | Verdict |
|---|---|---|---|---|
| Push, revert on failure (the token vault's shape) | the release never completes; the relayer retries for ever; with a delay queue it would hold the head | all the gas of the transaction if gas is not bounded | paid | refused (mutant M2) |
| Pull only: every release books a claim | nothing to refuse | none | **cannot exit**: an account that bridged everything has no ether on Ethereum to pay for its claim, unless someone else pushes it, which is the first design again | refused |
| **Push with `PUSH_GAS`, claim on failure** (chosen) | the release completes, the payment waits in `claimable` | at most 30,000 + 2,300 gas and two storage writes (measured below) | paid by the push | chosen |

- **`PUSH_GAS` = 30,000.** Measured on the fork of Ethereum (`docs/BRIDGE-ETH.md` section 8): the `receive` of a Safe
  1.4.1 proxy used about 6,300 gas and that of an ERC-4337 SimpleAccount proxy about 4,900, so both are paid by the push. A `receive` that writes one fresh storage
  slot and logs (about 24,000) still fits. More than that waits for `claimFor`. The number is also the most a
  hostile recipient can make a relayer burn per release, and that enters the minimum burn; 50,000 would raise the
  minimum burn by 0.6 ETH.
- **No return data is copied.** The call is made in assembly with a zero-length output area and `returndatacopy` is
  never executed. A Solidity low-level call copies the whole return data into memory at the caller's cost: a
  recipient answering with 96 KB made the caller pay about 39,000 gas more in mutant M4.
- **EIP-150.** A call forwards at most 63/64 of the gas left. Without a check, a transaction with just too little
  gas would give the recipient less than `PUSH_GAS`, the push would fail and a payable release would be booked as a
  claim. `eth_estimateGas` searches for the smallest gas at which the transaction does not revert, so an honest
  relayer could find exactly that point. The vault therefore requires, immediately before the call,
  `gasleft() >= PUSH_GAS * 64 / 63 + 40,000`: the 40,000 covers the call's own charges (9,000 for the value, 25,000
  for a new account, 2,600 for a cold address) with 3,400 to spare, so the recipient is guaranteed its 30,000. A
  transaction below that reverts as a whole (`InsufficientGas`) and consumes nothing.
- **Reentrancy.** Every state change of a release, a claim and a sweep is made before the ether moves, and every
  state-changing entry point is behind the Ethereum vault's own guard. The tests re-enter from the push (30,000
  gas), from a claim and from the sweep (all gas), with a valid second release prepared in advance; each attempt is
  refused with `Reentrancy()`.
- **The window and the cap.** A deferred release charges the release window exactly as a paid one (mutant M18). The
  cap bounds `totalLocked`, the backing of the L2 token; payments waiting in `claimable` are no longer backing and no
  longer within the committee's reach (only `claim` and `claimFor` move them), so they are not counted against the
  cap. Consequence, accepted and stated in the route file: the vault's ether balance can exceed the cap by unclaimed
  payments and by forced ether.
- **What a recipient cannot do.** Refusing the push gains nothing: the window was charged, the fee taken, and the
  claim can only be paid to the recipient or where the recipient says. A guardian pause does not take a claim back,
  exactly as it does not take back a token release already executed.
- **What stays possible, by the burner's own choice.** A burn naming a contract that can neither receive ether nor
  call `claim(to)` leaves its payment in the vault for good (owed, never lost to anyone else). The route file tells
  pages to say so.

## 3. Hazard table (coordinator decision 2) and the test that pins each row

"Fails first": `python3 scripts/eth/mutants.py WORKDIR` removes ONE defence from a copy of the vault and requires
the pinning tests to fail on it. 20 mutants, 20 killed (the run is in the agent report; the control run of the
unchanged vault passes the whole suite).

| Hazard | Defence | Pinned by | Mutant that shows the test failing |
|---|---|---|---|
| Reentrancy on release, claim and sweep | guard on every entry point; effects before the call | `test_release_reentrancyFromThePushIsRefused`, `…FromAClaimIsRefused`, `…FromTheSweepIsRefused` | M1 (guard removed) |
| A recipient that reverts | the release completes as a claim | `test_release_revertingRecipientDoesNotBlockTheQueue`, `test_release_delayedPathDefersToo` | M2 (revert on failed push), M12 (no claim booked) |
| A recipient that consumes all gas | `PUSH_GAS` | `test_release_gasBurningRecipientIsBounded`, `test_release_recipientGetsThePushGas` | M3 (all gas forwarded) |
| A recipient that returns a huge payload | no return data copied | `test_release_returnDataIsNeverCopied` | M4 (Solidity low-level call) |
| A relayer that starves the push | gas check before the call | `test_release_relayerCannotStarveThePush` (every gas limit from 60,000 to 400,000 in steps of 500: reverted or paid, never deferred) | M5 (check removed) |
| A claim taken by someone else, or lost | `claim` pays only where the recipient says; `claimFor` only the recipient; a failed payment reverts | `test_claim_paths`, `test_claim_recipientRedirects` | M14, M15 |
| Forced ether (SELFDESTRUCT, block reward, pre-funded address) breaking accounting | books counted, not measured | the five `test_forced_*` | M6 (exact-balance rule), M13 (sweep pays the excess) |
| Forced ether filling the cap | the cap counts deposits | `test_forced_capIsNotFilledByForcedEther` | M11 |
| Deposit by plain transfer | `receive` reverts; no `fallback` | `test_deposit_plainTransfersAreRefused` | M7 |
| `msg.value` versus the stated amount | exact equality | `test_deposit_valueMustBeExactlyTheStatedAmount` | M9 (lower bound only) |
| Fee rounding in the user's favour | fee rounded up; a release not above its fee refused | the three `testFuzz_fee_*`, `test_fee_knownValues`, `test_fee_releaseNotAboveItsFeeRefused` | M8, M17 |
| Deposits from contracts and account-abstraction wallets | the L2 recipient is stated, never the sender | `test_deposit_fromAContractCreditsTheStatedRecipient`, `test_deposit_recipientMustBeStated`; rehearsal step 1 (a deposit made by a contract is attested and credited to the address it names) | M10 |
| A window that a deferred release does not charge | bucket charged before the push | `test_release_revertingRecipientDoesNotBlockTheQueue`, `test_claim_notHeldByPauseControlsOrWindow` | M18 |
| Another asset configured as this vault's token | constructor accepts the marker only | `test_ctor_onlyTheNativeEtherMarkerIsAToken` | M16 |
| An account whose code changes (EIP-7702 delegation, wallet module) | deferral, then `claimFor` | `test_release_accountWithCodeThatChanges` | M2, M12 |
| A relayer cost that anyone can raise (a fee sweep, or paying out every claim, before a release) | neither sum is ever written into an empty storage slot (ETH-10) | `test_release_costDoesNotDependOnSweptFeesOrOutstandingClaims` | M19, M20 |

## 4. Tests

| Suite | What | Count |
|---|---|---|
| `solidity-tests/NativeEtherVault.t.sol` | the hazards above, construction, limits, pause, the certificate rules that did not change | 38 tests (3 fuzz, 256 runs each) |
| `solidity-tests/NativeEtherVaultStateful.t.sol` | one driver, three uses: a seed-driven sequence (256 seeds x 60 steps), a coverage proof (5 x 120 steps: every one of 19 outcome kinds occurred) and forge's invariant engine (96 runs x 80 calls, fail-on-revert). Every step PREDICTS the outcome (success or the exact error) and requires it. After every step: I1 `totalLocked` == net deposits - released; I2 fees == taken - swept; I3 `totalClaimable` == deferred - claimed == sum of `claimable[]`; I4 balance == `owedWei` + forced ether, exactly (hence balance >= liabilities); I5 `totalLocked` <= cap whatever was forced in; I6 over ANY interval ending at a release the released amounts are at most `windowLimit x (1 + T / windowSeconds)`; I7 the deposit count never falls and the chain recomputed from genesis over every deposit ends at the head; I8 every recipient holds exactly its certified payouts; I9 the treasury holds exactly the swept fees | 3 tests |
| `solidity-tests/NativeEtherVaultDifferential.t.sol` | the same call sequences on this vault and on the frozen Ethereum vault (over a plain six-decimal token): same success, same error selector, same books, same events with the same data, same holdings (units against wei / 1e12) after every call. Amounts are multiples of 10,000 units (both fee rates exact) and recipients plain accounts: where the vaults are meant to differ, the differential does not go | 3 tests |
| `scripts/eth/mutants.py` | 20 one-defence-removed mutants, each killed by its pinned tests | 20 |
| `tools/deploy-pontes/test_native_ether.py` | the launch gate, the numbers, the generated route files, the deploy tools | 26 |
| `tools/deploy-pontes/test_ceremony_kit_native_ether.py` | the owner's ceremony kit on this route (needs `cast` to sign test inputs) | 9 |
| `tools/native-ether/test_bundle_native_ether.py` | the operator bundles of the held route | 9 |
| `tools/native-ether/rehearse_fork.py` | section 6 of `docs/BRIDGE-ETH.md` | see there |

## 5. Gas measured (private anvil, Shanghai rules, committed bytecode, 2026-11-19)

Transaction gas as the receipt states it (`gasUsed`), a 5-of-7 certificate, release amount 1 ETH.

| Transaction | Gas |
|---|---|
| deposit, first of the vault | 75,339 |
| deposit, later | 75,834 |
| release to an existing account | 162,275 |
| the same, right after a fee sweep | 162,199 |
| release to an empty account (25,000 for the new account) | 187,203 |
| release to a reverting recipient, a new claim slot | 190,218 |
| release to a reverting recipient, an existing claim | 173,130 |
| **release to a gas-burning recipient, a new claim slot (the worst case), no claim outstanding, right after a fee sweep** | **222,350** |
| the same with claims outstanding | 222,402 |
| the same right after a fee sweep, claims outstanding | 222,398 |
| release to a gas-burning recipient, an existing claim | 205,322 |
| `sweepFees`, first / later | 69,427 / 44,427 |
| `eth_estimateGas` of any release | 218,000 to 224,400 (the gas check before the push sets the floor) |

The worst case is the same in every state of the vault (ETH-10): 222,402. The route's figures
(`tools/signatario-stable/native_ether.py` `RELAY`) are 162,275 (plain), 187,203 (new account) and **223,000** (worst,
rounded up for the few hundred gas by which the calldata of two certificates differs). The Ethereum USDC vault's
release measures 207,000 (`tools/evm-nets/networks.json`). The fork rehearsal re-measures the releases through the
real relayer and fails if the worst one exceeds 223,000 or a plain one leaves 3% of 162,275. The minimum burn of the
route rests on the worst case (`docs/BRIDGE-ETH.md` section 4).

## 6. Not done / not proven

- No external audit and no independent review of this contract yet; both are conditions of the route's hold.
- The EVM version of the build is Shanghai (the repository's `foundry.toml`). On Ethereum mainnet after Cancun
  SELFDESTRUCT still sends its ether; the forced-ether tests run under Shanghai rules and under forge's cheat codes
  (the block-reward case is a stand-in: forge cannot credit a real coinbase reward).
- EIP-7702 delegated accounts are modelled by an account whose code is replaced (`vm.etch`), not by a real
  delegation on a Prague fork.
- `PUSH_GAS` was checked against two wallet families (Safe 1.4.1, ERC-4337 SimpleAccount v0.6). Other wallets with a
  costlier `receive` are served by `claimFor`, not by the push.
- Gas repricing by a future fork was not modelled. `PUSH_GAS` and the 40,000 reserve are constants of an immutable
  contract. If a fork made a value-carrying call cost more than 40,000 gas before the callee runs (today at most
  36,600), the gas check would no longer guarantee the callee its 30,000: a payable release could then be booked as
  a claim and paid later by `claimFor`. No funds would be at risk; the relayer's worst-case cost would also move, and
  with it the argument for the minimum burn.
