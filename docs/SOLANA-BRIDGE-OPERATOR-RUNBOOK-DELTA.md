# Solana bridge (`bUSDC.sol`): operator runbook, what differs

Status: **UNAUDITED. Nothing is deployed.** This is a delta to `docs/BRIDGE-V3-OPERATOR-RUNBOOK.md`, which stays
in force for everything on the L2 side (the pinned follower build, the L2 mint keys, the relayer roles on the L2,
the 6-of-7 unpause of the token, what each role does on a forged mint). Only what Solana changes is written here.
The tools are under `tools/signatario-solana/`; this text was checked against them after they were written, and
the local rehearsal (`rehearse_local.py`) runs the signer, the relayer and the guardian watch described here.
Nothing in this document has been run by an operator.

Specification: `docs/SOLANA-VAULT.md`. Deployment and keys: `docs/SOLANA-BRIDGE-DEPLOY-CEREMONY.md`.

## 1. Who runs what

| Operator | Runs for this bridge, beside the Ethereum bridge stack | Keys on the host |
|---|---|---|
| Signer operator (7) | An own Solana RPC node; `signatario.py` (unchanged) with `sol_half.py` as its source half; `sol_vigia.py sign` | The same L2 mint key and release key as for the Ethereum bridge. No Solana key |
| Relayer (at one or more signer operators) | `sol_vigia.py relay` | One Solana fee-payer key (ed25519, no vault power) and the L2 relayer gas key |
| Guardian operator (3) | An own Solana RPC node; `sol_guardiao.py watch` (the vault and token watch, with the automatic vault pause); by hand `sol_vault.py pause-sign` / `pause-submit`; `sol_vault.py reserves` | The same L2 token guardian key and vault guardian key. One Solana fee-payer key to deliver its own pause |
| Owner | nothing permanent | The deployer fee payer (once) |

## 2. For every operator: an own Solana node, read at `finalized`

- Every signer and every guardian reads Solana from a node that operator runs or contracts alone: an Agave
  validator in RPC mode (non-voting), or a provider that no other operator of this bridge uses. Mint signing trusts
  the operator's node completely: five operators on one provider would let that provider supply five mint
  signatures. This is rule 2.1 of the main runbook, for Solana.
- The node must report the genesis hash `5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d`. The tools derive the
  source chain id from it and refuse another cluster.
- Everything a signer signs is read at `finalized` commitment. A deposit is attested only when its deposit record
  account exists at `finalized` and its slot is at least `finality_margin_slots` (default 150) below the finalized
  slot. Do not lower the margin and do not switch a signer to `confirmed`.
- Signers read **accounts**, not logs and not blocks by number: the vault account gives the deposit count, and
  deposit `n` is the account at the address derived from the vault and `n`. Skipped slots, truncated logs and
  missing block history on the node do not affect this. A node that lacks old transaction history is still
  sufficient for signing.
- A node that falls behind returns older state, never wrong state. The tools pass the last seen slot as
  `minContextSlot` so a lagging node behind a balancer is refused instead of making the view go backwards.

## 3. Signer operators

- The release key signs Solana releases with the same `cast` keystore and the same EIP-191 form as Ethereum
  releases. The digests are the Ethereum vault's formulas with this vault's chain id and identity, so the
  equivocation database of the source half (one release per nonce, one per burn) works the same way. It is a
  separate database file from the Ethereum half's: do not point both halves at one file.
- **Two steps.** A release on Solana is approved by the certificate (`approve_release`) and paid by a second
  transaction (`execute_release`) that needs no signature. A release above `largeReleaseThreshold` is paid only
  `releaseDelay` after its approval.
- **Signing again after a pause.** A guardian pause voids every approval that was not yet paid. After the pause
  the release record still exists in state "approved", but the vault refuses to pay it (`Voided`, error 116). The
  release is then signed again, with a new `validUntil`, and approved again. This is the same release for the same
  burn, so the equivocation guard allows it. `sol_vigia.py sign` does this by itself as soon as the pause is over
  (72 h, or earlier by a 6-of-7 unpause): its Solana half refuses only a paid release or a standing approval. So
  an operator who does not yet know the reason for the pause stops its sign daemon before the pause ends; the
  pause exists so that a wrong approval is looked at first. A pause never loses an exit: the burn stays on the
  L2, no paid record exists for its nonce, and five signers can always certify it again (shown in the rehearsal).
- A certificate lives at most `maxValidSeconds` (3,600 s). If five partial signatures are not collected and
  submitted within that time, the round is repeated with a new `validUntil`.
- A release approval carries exactly the threshold of signatures (5). Six fit a transaction; seven do not.
- The signer refuses a burn whose mint chain does not equal the vault's deposit chain at the same count. The
  vault refuses it too (`ProvenanceMismatch`, error 112). Such a burn is a held exit: page the owner; do not try to
  work around it.

## 4. Guardian operators

- A guardian's power on Solana is its secp256k1 vault guardian key, not a Solana key. `pause-sign` produces the
  pause authorization for the next pause number; `pause-submit` delivers it with any fee payer. Keep the
  guardian's own fee payer funded (section 6) so that it never depends on somebody else to deliver a pause. An
  authorization is valid for at most `maxValidSeconds` and only for the pause number it names: if another guardian
  paused first, sign again for the next number once the chain rules allow it.
- The pause rules are the Ethereum vault's: 72 h, one pause per guardian in a chain of consecutive pauses, 72 h
  cooldown after a committee unpause. New on Solana: a pause voids approvals not yet paid.
- What to watch, on the guardian's own nodes: every release record that appears (approved or paid) must match a
  final burn on the L2 with the same nonce, amount, commitment and burn id; every queued mint on the L2 token must
  match a deposit record at `finalized`. An approval with no matching burn is the reason to pause the vault at
  once: with `releaseDelay` it is still unpaid for 30 minutes if it is above the threshold, and the pause voids it.
  A queued mint with no deposit record is cancelled on the L2 by 2 of 3 guardians, as in the main runbook (2.7).
- Two L2 views before a vault pause (rule 2.4) applies unchanged.
- The automatic watch is `tools/signatario-solana/sol_guardiao.py` (`check`, `watch`): a subclass of
  `tools/guardiao/guardiao.py` that keeps the L2 side, the findings, the grace periods, the token pause and the
  cancel votes of the parent and reads the source side from the vault's accounts at `finalized`. With
  `vault_pause: true` it signs and delivers its own vault pause on a due reserves, release or approval finding.
  A standing approval with no matching burn is a finding of its own (`release-unknown:approval-<nonce>-<seq>`).
  It lists the vault's release records with `getProgramAccounts`: the guardian's own node must serve that method
  for the program (an Agave RPC node with account indexes, or a provider plan that allows it).
  Unlike the Ethereum guardian it shares the Solana encoding library with the signer tools; see section 10.

## 5. Relayers

- The relayer pays, per release: two transaction fees and the rent of the release record, about 0.0021 SOL by the
  rent formula, which is never returned. The 5 bps release fee goes to the fee owner, not to the relayer. Budget
  SOL by the number of releases, not by their size.
- The relayer needs the recipient's wallet to pay a release: it reads the `SolanaRecipient` log of the registry on
  the L2 for the burn's commitment. With no announcement, the release stays approved and unpaid until the wallet is
  known. Anyone who knows the wallet, the user included, can send the payment.
- The relayer does **not** create a recipient's missing USDC token account by default. A user could close the
  account after each payment and collect the rent the relayer paid. The payment waits until the account exists;
  the user creates it or relays their own release. Changing this default is an owner decision
  (deployment checklist item 12).
- Completion is read from state: a release is done when its release record is in state "paid" at `finalized`.
  A Solana transaction that did not land expires with its blockhash (about a minute) and can simply be sent again;
  the program makes a second approval or a second payment of the same nonce fail. There is no account nonce to
  reserve, so the write-ahead journal of the Ethereum relayer has no counterpart here.
- Relay roles and the backup stagger (rule 2.2) apply to the Solana relayers as well. `sol_vigia.py` is a
  subclass of `vigia.py`: rounds, budgets, the signature feed, relay roles and the L2 nonce record are the
  parent's code. The Solana side keeps no `sent` file and no journal: the relayer sends `approve`, reads the
  release record back, and sends `execute` when the record is ready, the vault is not paused and the release
  bucket allows the amount. The feed transport was NOT exercised in the Solana rehearsal (it used a local shared
  directory); treat the feed over this bridge as untested.
- Relayer config beyond the Ethereum one: `sol_half_config`, `sol_fee_payer`, `recipient_registry`,
  `registry_from_block`, `sol_create_recipient_account` (default false). `eth_rpc` and the `eth_relayer_*` keys
  are not used.
- `sweep_fees` is permissionless and cheap. Any relayer may run `sol_vault.py sweep` on a schedule; it fails
  harmlessly while the fee owner's token account does not exist or is frozen.

## 6. SOL balances

| Key | Pays | Alert when below |
|---|---|---|
| Relayer fee payer | fees and about 0.0021 SOL per release | the cost of one day of releases at the bucket rate; at the 10 USDC minimum burn that is at most 1,000 releases, about 2.2 SOL |
| Guardian fee payer | one pause transaction | 0.01 SOL |
| Deployer | the deployment, once | not kept funded afterwards |

A transaction with secp256k1 signatures pays the base fee per verified signature as well as for the fee payer's
own signature. The amounts are small next to the rent.

## 7. Reserves monitor

`sol_vault.py reserves` compares, at `finalized`: the vault token account's balance against
`total_locked + fees_accrued` from the vault state (the balance must be at least the sum; tokens sent to the vault
directly make it larger and change no accounting), and `total_locked` against the L2 token's supply plus pending
mints. A balance below the sum is critical: it means the issuer burned or seized from the vault account, or a
defect.

## 8. Frozen accounts (the issuer's freeze authority)

| Frozen account | Effect | What to do |
|---|---|---|
| The vault's token account | Deposits and payments fail in the token program. Nothing moves, nothing is lost. Approvals still succeed and then wait | Page the owner at once; the owner contacts the issuer. Consider switching deposits off (5 of 7) so users stop sending deposit transactions that fail. Certificates expire and are signed again after the thaw |
| A recipient's token account | That one payment fails; other releases are unaffected. The burn cannot be redirected | Leave it approved. It is paid when the account is thawed |
| The fee owner's token account | `sweep_fees` fails; fees keep accruing in the vault | Tell the owner; nothing else |

## 9. Cluster restart or loss of finalized slots

Solana clusters have been restarted from a snapshot by coordinated validator action. If the cluster halts, or a
restart is announced:

1. Signers stop by themselves when their node's finalized slot stops advancing. Do not restart signing by pointing
   at another node.
2. After the restart, before signing resumes, each operator compares the vault account's deposit count and head at
   `finalized` with the last values its signer recorded. If the count or head went **backwards** or changed for an
   already seen count, a finalized deposit was dropped.
3. In that case a guardian pauses the L2 token's mints and the vault. Every queued L2 mint whose deposit record is
   gone is cancelled by 2 of 3 guardians. Mints are queued for 12 h, so this works for every deposit attested in
   the 12 h before the restart.
4. If such a mint has already credited, the token's mint chain differs from the vault's deposit chain for good and
   the vault refuses every burn made after it. Exits are held; nothing is paid twice. This has no settlement path
   on Solana (the Ethereum bridge's held-state settlement is not ported). Page the owner.
5. If nothing went backwards, resume.

## 10. Not done

- No operator has run any of this. The pre-go-live check of the main runbook (section 3) has no Solana part yet:
  a check that the node reports the right genesis hash, that the program is final with the pinned binary hash,
  that the vault state equals the config, and a dry release refusal.
- No ops templates (systemd units, config templates) for the Solana daemons exist under `deployments/solana/`.
- The signature feed over this bridge is untested (section 5). The guardian watch shares `solana_lib.py` and
  `sol_half.Node` with the signer tools, so it is not an independent implementation of the Solana encodings as
  the Ethereum guardian is of the Ethereum ones.
- The guardian watch was rehearsed for the honest history (no finding) and for an unbacked credited mint
  (reserves and mint-chain findings, automatic vault pause). A forged approval or payment on a live validator
  needs five committee keys; the watch's handling of it is covered only by the code path that the mint case
  shares, not by a rehearsed forged release.
