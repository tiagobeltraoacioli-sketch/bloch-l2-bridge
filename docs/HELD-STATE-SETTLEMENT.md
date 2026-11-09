# Held-state settlement (`HeldStateSettlementVerifier`)

Status: **UNAUDITED, not deployed.** Audit Phase 2B. Contract `contracts/usdt/HeldStateSettlementVerifier.sol`,
tests `solidity-tests/R306HeldStateSettlement.t.sol` (20). Written by agent 278 (round 12 draft) and agent 306.

This is a contingency. It is deployed only after an incident, from that incident's numbers. It is written and audited
before launch so that it is not improvised afterwards (agent 172, decision 1).

## 1. The problem it solves

`ProvenanceSourceVault` pays a release only if the burn's mint-chain state equals the vault's own deposit chain
(`_checkRelease`, `ProvenanceMismatch`). If the L2 token ever credits a mint that no deposit backs, every burn made after
that credit carries a head the vault never had. The vault refuses all of them, on the committee path and on the proof
path, for good. This is the **held state** (limit 1 of `docs/AUDIT-SCOPE-BRIDGE-V3.md`, F3). Nothing is stolen, but no
later holder can exit, and bUSDC is fungible, so real tokens are held together with the forged ones.

At T = 0 this needs 5 of 7 mint keys and a forged mint that no guardian cancels for 12 hours.

The vault has exactly one path that can pay such a burn: its one-way verifier switch (`proposeVerifier` with 6 of 7,
14 days, `activateVerifier`). A verifier installed there approves release items; an item that names the vault's own head
passes the provenance check (agent 172, V1b). `HeldStateSettlementVerifier` is the verifier for that use.

**Using it spends the switch.** The vault can never move to the light-client verifier afterwards. A vault settled this
way is wound down. The bridge continues, if at all, on a new vault and token pair.

## 2. What it pays

Three classes. The budgets are fixed in the constructor, from a snapshot taken with deposits closed.

| Class | Who | Paid | Budget | Evidence |
|---|---|---|---|---|
| Clean burn | A burn made before the forged credit and not yet released (its state matches the vault) | In full | `fullBudget` | Evidence of the burn (below) |
| Unminted deposit | A deposit the token never credited: its slot was taken by the forged credit (`displacedNonces`, at most 16), or the token never reached it (every nonce from `unmintedFrom`) | The net deposit, to the depositor's Ethereum address | `fullBudget` | The vault's own deposit chain (`depositMatches`) |
| Held burn | Every other burn of the token | `amount * sharedBudget / heldSupply`, rounded down | `sharedBudget` | Evidence of the burn |

Every held burn gets the same rate, whatever its order. The forged supply cannot be told apart from real supply, so
the shortfall is shared pro rata. The alternative, first come first served, lets whoever exits first take full value and
leaves the last holders with nothing (agent 172).

The vault's own rules still apply to every settled item: one payment per burn nonce and burn id, the release window
(10,000 a day at launch values), `totalLocked`, and the release fee. The release fee (5 bps) is taken from every
settled payment and goes to the treasury through `sweepFees`, as for any release.

## 3. The snapshot

Taken by the operators from public chain data, after deposits are closed (`setControls(false, true)`, 5 of 7) and the
mint committee has stopped signing. All amounts are in token units (6 decimals).

| Value | How to compute it |
|---|---|
| `snapshotDepositCount` | `vault.depositCount()`. The constructor refuses any other value |
| `unmintedFrom` | `token.mintCount()` at the snapshot: the first slot the token never credited |
| `displacedNonces` | Slots below `unmintedFrom` whose credited mint is not the vault's deposit of that nonce (compare each `Minted` log with `vault.depositMatches`) |
| `fullBudget` | Sum of the amounts of the clean burns not yet released, plus the sum of the net amounts of the unminted deposits |
| `sharedBudget` | `vault.totalLocked() - fullBudget` |
| `heldSupply` | `token.totalSupply()` plus the amounts of the held burns already made (burned, not released). Add the amount of every mint still queued on the token that the guardians have not cancelled |

With these values, `heldSupply - sharedBudget` is the forged supply. The constructor checks `fullBudget + sharedBudget
<= totalLocked`, the deposit count, that deposits are closed and that the vault has not switched.

The budgets are hard bounds. If more held supply turns up than `heldSupply` (a forged mint credited after the snapshot,
or an underestimate), the last held claims are refused with `BudgetExhausted`. They never reach `fullBudget`, and the
vault never pays more than the two budgets (`test_BUDGET_supplyCreditedAfterTheSnapshotCannotOverdraw`).

## 4. Evidence of a burn

Fixed at deployment, exactly one of:

- **Light-client mode** (`burnVerifier`): the release verifier the light-client switch would have installed
  (`RecoverableReleaseVerifier` or `SP1ReleaseVerifier`), pinned to its code hash and re-checked on every registration.
  It proves the burn's real release id, with its real mint-chain state.
- **Committee mode** (`attestThreshold`, at least the vault's `switchThreshold`, 6 of 7): the vault's own signers sign
  the burn's real release id under a settlement-only domain (`attestDigest`: tag, chain id, this contract, the vault,
  the L2 token, the release id). These are per-claim signatures during the wind-down, as committee releases are today.
  No checkpoint is signed, and nothing recurs after the wind-down.

The attestation binds every field of the burn. An attestation cannot be used for another burn, another amount or
recipient, another settlement contract, or as a release certificate (`test_EVIDENCE_*`).

A burn the vault already paid is refused (`AlreadyClaimed`): its evidence stays valid for good, so without this check
anyone could register every old burn and use up `fullBudget`.

## 5. Flow

1. Incident: `guardiao` reports `mint-chain`, `reservas` reports `held`. Guardians pause the vault.
2. Operators close deposits and stop mint signing. They take the snapshot (section 3) and publish it.
3. Anyone deploys `HeldStateSettlementVerifier` with the snapshot. It is reviewed against the pinned build
   (`verifier_review.py scan` passes: no DELEGATECALL, CALLCODE, SELFDESTRUCT, CREATE or CREATE2).
4. 6 of 7 vault signers propose it (`proposeVerifier`). 14 days of notice. Anyone activates it.
5. Anyone registers claims (`registerBurn`, `registerDisplaced`) and submits each settled item to
   `vault.releaseWithProof(item, "")`. Holders burn their bUSDC on the L2 to make a claim.

Before activation nothing can be registered (`NotActive`). After it, vault guardians can no longer pause (the vault's
rule for any switch), and the committee release path is retired.

## 6. Trust and limits

- **Who can install it:** only the vault's switch quorum (6 of 7), with 14 days of notice. That quorum can already
  install any verifier; this contract gives it no new power.
- **Committee mode:** 6 of 7 vault signers can attest a burn that never happened. The loss is bounded by the budgets,
  and by the release window per day.
- **Light-client mode:** the trust is the burn verifier's. A `RecoverableReleaseVerifier` whose authority hands it off
  to hostile code can approve invented burns; the loss is bounded by the budgets
  (`test_EVIDENCE_aHostileBurnVerifierIsBoundedByTheBudgets`).
- **The forger shares in the payout.** A forger who still holds forged tokens claims at the same rate as everyone.
  The contract cannot tell forged tokens from real ones.
- **Deposits after the snapshot are outside the settlement.** Five signers can reopen deposits. While deposits are open,
  registration is refused (`DepositsOpen`); approved items still pay. USDC deposited after the snapshot is not in any
  budget and stays locked. Operators keep deposits closed; the frontend refuses a closed vault.
- **Mints after the snapshot dilute nobody beyond the budgets,** but the last held claims are refused (section 3).
  Operators cancel every queued mint before the snapshot.
- **An unminted deposit is refunded net of the deposit fee and of the release fee** (about 0.1% in total).
- **Rounding dust** (below one unit per held claim) stays locked in the vault.
- **Wind-down time:** at least `sharedBudget / windowLimit` days (10 days for a full vault at launch values).
- No owner, setter, upgrade or self-destruct. Nothing can be changed after deployment; a wrong snapshot needs a new
  deployment and a new 14-day proposal, which is possible only before activation.

## 7. Questions for the auditor

- The settled held item: can any registered item be paid for more than `heldPayout`, twice, or to another recipient?
- `claimedBurn` / `claimedNonce` against the vault's `releasedBurn` / `releasedNonce`, and the synthetic nonce range of
  unminted deposits (`DISPLACED_NONCE_FLAG`).
- The class boundary: can a held burn be registered as clean, or an already minted deposit as unminted?
- `_checkAttestation`: ordering, malleability (`HALF_ORDER`), signer set read from the vault.
- The budgets under every order of claims, with supply that appears after the snapshot.
- The constructor's snapshot checks, and what the 14-day notice lets a reader verify.

## 8. Tests

`forge test --match-contract R306HeldStateSettlement`: 20 tests on the mainnet-shaped vault and V3 token (5 of 7,
switch 6 of 7 and 14 d, T = 0, window 10,000 a day, fee 5/5 bps, 3 vault guardians). Gas: `registerBurn` with 6
attestations under 250,000; `releaseWithProof` of a settled item under 200,000 (`test_GAS_registerAndRelease`).

Not done: a run with real signer daemons, an operator tool that computes the snapshot, and a `verifier_review.py` mode
for a settlement proposal (the existing `proposal` mode refuses any held state by design).
