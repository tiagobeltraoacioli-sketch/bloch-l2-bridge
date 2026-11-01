# Light-client exit path: what happens to the vault if the light client stops

Status: proposal for the owner's vault LC switch decision. Nothing here is deployed. Measurements are in
report 47 (`agents/47-lc-prover.md`), which also records which proofs were real and which inputs were synthetic.

## 1. The problem

After `activateVerifier` the vault's only release path is `releaseWithProof`. The committee is retired for
good, and the vault has no owner, rescue or second verifier. `SP1ReleaseVerifier` is immutable and pins
`trustAnchor`, which binds the anchor and the step program. If no step proof can ever be made again, every
locked token and every unreleased burn stays where it is, for ever. Deposits stay open too, unless the signers
close them with `setControls` (they still can: only `releases_ = false` is refused after the switch).

## 2. When a chain of step proofs stops for good

| Case | Trigger | Provable again? | Inside the step rule? |
|---|---|---|---|
| A. Gap, nobody proved | No prover ran for over 256 epochs (68 h), chain healthy | **Yes, not permanent.** Steps can be proven later over history, up to 256 epochs at a time, if a node serves the set source. Needs a replay with `BLOCH_FINALITY_CERT_EPOCHS` covering the range, or kept proof files. Design only; not rehearsed | Rule holds |
| B. Gap, chain stalled | No directly finalized checkpoint within 256 epochs of the last trusted one. From HF1 the leak no longer rescues finality | **No** | `SetSourceDistance` |
| C. Recovery epoch | `NATIVE_FINALITY_SET_RECOVERY_EPOCHS` re-forms the set in a coordinated release, without the old set's handoff | **No**, unless votes also reach two thirds of the old set. By design: the old set did not authorize the new one | `InsufficientWeight` |
| D. Set drift | Between the trusted set and the chain's, from pruning or a dead `pending` set | **No** past one third of drift. Stepping every few epochs avoids it, because the set changes only at finalized handoffs | `InsufficientWeight` |
| E. Rule-changing L1 fork | Any fork changing vote format, signature policy, leaf layout or header layout, not in the compiled guest | **No** | Refusal or decode failure |
| F. Proof-system break | A bug in the guest or SP1, or a retired verifier | **Depends** | Outside the rule |

A guest change cannot rescue B-E on an immutable verifier, because a new step program means a new `trustAnchor`.
Case C is the honest core: a recovery epoch is a social decision by the L1's operators, who pin the surviving
branch with a weak-subjectivity checkpoint. No proof from the old trust root can show it, so someone must decide
on the new root.

## 3. Options

| | Option | Covers | Trust added | Cost | Against the owner's principles |
|---|---|---|---|---|---|
| 0 | No switch: stay in committee mode with the shadow prover and guardians | All (no LC dependence) | The 5-of-7-style committee stays, for every release | None | Recurring signatures stay |
| 1 | Switch to `SP1ReleaseVerifier`, operations only (section 5) | A, D. Not B, C, E, F | None | Prover host | Fully set-once, but a stop locks funds for ever |
| 2 | Raise the hop bound in the guest, for example to 1,024 epochs (11.4 days) | Shrinks B by 4 times. Not C, D, E, F | Weaker weak-subjectivity margin; needs review against the 2,048-epoch post-exit slashing window | New vkeys; a full walk costs about 130 M instructions in the release | Compatible |
| 3 | Dormant committee: committee mode returns after N days with no release | All | Committee can act whenever traffic is quiet, unless a recurring heartbeat runs | Vault change, re-audit; recurring heartbeat transactions | Against: recurring transactions, and committee power stays alive |
| 4 | Pro-rata exit for holders | All | A balance snapshot nobody can prove on Ethereum | Very large | Not workable without an L2 state proof |
| **5** | **`RecoverableReleaseVerifier`: delayed successor that one proof of life stops** | **B, C, D, E; F if no step proof can be made** | **One set-once authority, only when the LC can no longer prove** | **Verifier only; vault unchanged; no gas until used** | **One deliberate exception: a stopped LC's trust root can be replaced** |

Option 2 can be combined with option 5, and is independent of it. It needs a security review I have not done.

## 4. Recommendation: option 5

`contracts/usdt/RecoverableReleaseVerifier.sol` is what the vault switches to. The vault needs no change, and until
a successor is active it verifies releases exactly as `SP1ReleaseVerifier` does.

1. `recoveryAuthority` (fixed at deployment, `TBD-owner`; a cold multisig, not the hot bridge signers) calls
   `proposeSuccessor`, pinned to the successor's code hash.
2. For `recoveryDelay` the old proof path keeps working.
3. Anyone can call `proveLife` with a Groth16 proof of the pinned step program, from the pinned anchor, whose
   checkpoint starts at or after `activatesAt - lifeWindow`. That deletes the proposal, and the authority waits
   `proposalCooldown`.
4. If no such proof appears, anyone calls `activateSuccessor` within 30 days. The old path ends, for good.

Suggested parameters: delay 14 days, life window 3 days, cooldown 14 days. The window must exceed one Groth16 step
proof, the finality lag and Ethereum inclusion; see the measured proof time in report 47.

**Why only the last part of the delay counts.** A fork that will stop the light client (case E) can be prepared in
advance. Propose so that the fork gate falls before `activatesAt - lifeWindow`. No checkpoint inside the window can
then be proven by the old rule, so nobody can stop the proposal, and releases are down only from the gate to
`activatesAt`: at least the window, 3 days with the suggested values. Without this rule, a proof from before the fork
could block it. An attacking authority gains nothing from this: while the light client lives, a proof from inside
the window always exists.

**What it trusts.** While the light client works: nothing new, since one proof from anyone stops a proposal. Honest
provers need only watch `SuccessorProposed` and spend one proof, and the owner's own prover can do this. Once it has
stopped: the authority chooses the next verifier and anchor. The vault's per-window limit is the only bound on a bad
choice. `SP1ReleaseVerifier`'s "no owner, no upgrade" no longer holds in the strict sense. This should be stated to
holders before the 7-day switch delay starts, because they can leave during it.

**Residual risks.**
- An authority plus censorship or absence of every prover during the 3-day window can replace a working light client.
- If step proofs still work and release proofs do not (a change to the L2 settlement wire or a release-guest bug,
  with L1 finality fine), anyone can block the successor by spending a proof each round. That griefer gains nothing,
  but funds wait while it pays. Mitigation: treat any L2 settlement format change as requiring a release guest
  compatible before it, and review. Not solved in the contract.
- If two thirds of the frozen set sign a false fork, proofs of life exist on that fork, and so do false releases. No
  option here helps; it is the light client's base assumption.
- Burns older than the new anchor are provable only within `MAX_HEADERS` = 65,536 L1 headers below a checkpoint,
  about 22.7 days at one block per slot. So anchor the successor at the earliest checkpoint it can trust, and prove
  old burns soon. A burn further down stays stranded unless a guest with a higher limit is deployed.

## 5. Operations (needed with every option)

- **Two independent provers**, on separate hosts, both on `lc_prover.py`, one step at least every 16 epochs. One
  `compressed` step file is enough to continue; copy each off the host.
- **Alert on `hop_margin_epochs`** from `lc_prover.py status`: warn below 128, page below 64. These are 34 and 17
  hours of margin.
- **Follower retention:** `BLOCH_FINALITY_CERT_EPOCHS` at least 300 on the serving node.
- **Before any recovery-epoch release:** step to the last checkpoint the old set can prove, and propose the successor
  before the release ships. Anchor the successor after the recovery epoch.
- **Before any L1 fork that changes the finality rule:** new guest, new anchor after the gate, and a proposal
  at least 11 days before the gate, so the gate falls before the window (section 4).
- **On a stall over 128 epochs:** close deposits with `setControls(false, true, ...)`; the signers keep this power.
  Prepare a proposal, and do not activate it while a chain of proofs is still within reach.
- **Anchor after the KES bind**, as report 25 says.
- **Rehearse yearly** on a private chain. A proof of life costs one Groth16 step.

## 6. Decision needed

1. Choose an option. Recommended: option 5, plus the operations above.
2. If option 5: name `recoveryAuthority`, and confirm delay, window and cooldown.
3. Whether to raise the hop bound (option 2), after a security review. It changes the vkeys.
4. Audit scope: `RecoverableReleaseVerifier` was written in this round and has had no external review.
