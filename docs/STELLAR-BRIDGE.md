# Stellar bridge: USDC on Stellar to bUSDC.xlm on the Bloch L2

Status: PROTOTYPE, UNAUDITED. Nothing is deployed. No real key signed anything. This bridge needs its own external
audit before any real funds. Round 16, agent 324, branch `codex/bridge-stellar-r16-20261116`.

Deployment and ceremony: `docs/STELLAR-BRIDGE-DEPLOY.md`. Published interface: `deployments/stellar/bridge.network.json`.

## 1. What it is

The existing bridge model, on Stellar. A Soroban contract (the vault) holds issuer-native USDC through the asset's
Stellar Asset Contract. The same committee as the Ethereum bridge (7 secp256k1 signer keys, 5 of 7; 3 guardians)
attests deposits and releases. The L2 token is `BridgedStablecoinV3`, byte-identical to the Ethereum bridge's launch
token (creation code keccak `0xe560441f…1de7`), with other constructor arguments: name `Bloch Bridged USDC (Stellar)`,
symbol `bUSDC.xlm`. One vault, one token, own cap and own books.

| Piece | File | Lines |
|---|---|---|
| Vault (Soroban, Rust) | `stellar/vault/src/lib.rs` | 1,118 |
| Vault unit tests | `stellar/vault/src/test.rs` | 3,428 |
| L2 exit router (periphery, no power) | `contracts/stellar/StellarBurnRouter.sol` | 80 |
| Network layer, signer half, signer wrapper | `tools/signatario-stellar/stellar_net.py`, `stellar_half.py`, `signatario_stellar.py` | 364, 381, 184 |
| Relayer, watcher daemons | `relay_stellar.py`, `vigia_stellar.py` | 137, 357 |
| Guardian tool, reserves monitor, committee controls | `guardiao_stellar.py`, `reservas_stellar.py`, `comite_stellar.py` | 185, 108, 117 |
| Pairing reader, Wasm import check | `pairing.py`, `wasm_imports.py` | 146, 78 |
| Deploy tool, Stellar source path | `tools/deploy-pontes/source_stellar.py` (+ 16 lines in `deploy_pontes.py`) | 210 |
| Rehearsal driver | `tools/signatario-stellar/rehearse_stellar.py` | 1,094 |

Final vault Wasm: sha256 `@@WASM@@` (33,994 bytes), built on the host with stellar-cli 30.0.1,
soroban-sdk 29.0.1, rustc 1.92.0, target `wasm32v1-none`. It imports no `update_current_contract_wasm`, no
`create_contract` and no `upload_wasm` (`wasm_imports.py`), so its code can never change.

## 2. Flow

Units: Stellar classic assets have 7 decimals and the L2 token 6. The vault keeps its books in the token's units and
moves exactly 10 stroops per unit. A deposit that is not a multiple of 10 stroops is refused; nothing is rounded.

1. Deposit. The user calls `deposit(from, amount_stroops, l2_recipient)` on the vault (no memo, no classic payment).
   The vault takes 5 bps as an accrued fee, books the net amount, and extends a hash chain over
   `(deposit id, net amount, L2 recipient)`. The chain is byte-identical to the one `BridgedStablecoinV3` extends over
   its mints.
2. Credit. After the finality margin (section 7) each signer reads the deposit from the vault's state, not from an
   event feed, and signs the token's EIP-712 mint. Every mint waits 12 hours on the L2 and is cancellable by the L2
   guardians, as on the Ethereum bridge.
3. Exit. The user approves `StellarBurnRouter` and calls `burnTo(amount, "G...")`. The unchanged token's burn names 20
   bytes, so the burn names a commitment: the low 20 bytes of `keccak256(bytes32("BLOCH-XLM-RECIPIENT-v1") ‖ strkey)`.
   The vault pays only an address with that commitment.
4. Release. After L2 finality 5 signers certify the burn, each with its own Stellar half. Anyone relays the
   certificate. The vault checks the committee by secp256k1 recovery, the mint chain, the replay records, the bucket
   and the backing, takes 5 bps and pays the recipient (or queues the release, section 5).
5. Fees. `sweep_fees()` (anyone) pays every accrued fee to the address fixed at deployment,
   `GAF2DTU23X5CFOPOUCUBTFJ5PKTSOV4GLZAJB5VMJW2JUA5KKYF5OLNA`. Fees are never part of the backing.

Identifiers the L2 token takes: `sourceChainId` is the Stellar network id (sha256 of the passphrase) as a uint256,
`55527100184162397446267447655670856106844621679976070008664532462234000271737` on the public network. It does not
fit 64 bits. `sourceVault` is the low 20 bytes of the vault's contract id. `sourceRoute` is the vault's route.

## 3. Differences from the Ethereum vault (`ProvenanceSourceVault`, mode 1)

| Topic | Ethereum | Stellar | Why |
|---|---|---|---|
| Committee check | `ecrecover` | Soroban `secp256k1_recover` + `keccak256`, low-s only, `v` 27 or 28 | Same keys. No Stellar (ed25519) key holds any power. |
| Upgrade, admin | none | none; the Wasm cannot replace itself | Same rule. |
| Light-client switch | one-way switch to a verifier | absent | Out of scope this round (NO-GO). `switch_threshold` remains as the 6-of-7 quorum for unpause and re-certification. |
| Decimals | 6 and 6 | asset 7, books 6; multiples of 10 stroops only | Stellar classic assets have 7 decimals. |
| Deposit recipient | `pqRecipientHash` (padded address) | `BytesN<20>` L2 address | Same content. |
| Release recipient | 20-byte address | Stellar address, bound by a 20-byte commitment in the burn | The frozen token's burn names 20 bytes. |
| Source anchor | recent block hash checked on-chain | none on-chain; `valid_until` at most 24 h ahead, digest binds network id and contract id | Soroban exposes no ledger hash, and Stellar has no forks. |
| Guardian pause | a guardian sends a transaction | a guardian signs a digest; anyone relays it | A secp256k1 key cannot sign a Stellar transaction. Same chain rule, same 6-of-7 unpause, same cooldown. |
| Release queue | none | releases above `large_release_threshold` wait `release_delay`; both fixed at deployment; delay 0 means no queue | Section 5. Owner decision. |
| Guardian cancel | none (pause only) | 2 of 3 guardians cancel a QUEUED release, once per nonce | Section 4. Exists only while the delay is above 0. |
| Closing releases | stops new releases | stops new releases and queued ones (they stay queued) | A queue must obey the committee's switch. |
| A release above `window_limit` | reverts when paid | refused before it is recorded | It could never be paid. |
| Asset failure | the token's revert | always the vault's `InvalidTransfer` (#2) | The asset contract's error numbers overlap the vault's. |
| Issuer powers | blacklist, pause | freeze of any balance (`AUTH_REVOCABLE` is set), clawback only if the issuer enables it later, trustline needed by the recipient | Section 8. |
| Replay records | storage slots, permanent | persistent entries with rent; archived when unpaid, never deleted | Section 9. |
| Storage rent | none | the instance, the Wasm and the vault's balance entry must stay funded | Runbook, section 10. |

## 4. The guardian cancel (difference accepted by the coordinator, 2026-11-17, under three conditions)

On the Ethereum bridge the source-vault guardians can only pause. Here, while the vault is deployed with a release
delay above 0, a majority of the guardians (2 of 3) can also cancel a release that is waiting in the queue.

Reason. The delay exists so that watchers can find a forged release (5 stolen signer keys, no burn on the L2) before
it is paid. Finding it is useless unless something removes it: a pause only holds it, and when the pause chain ends
(3 guardians, 72 h each, then the cooldown) the forged release is payable again. The vault has no administrator and no
upgrade, so nothing else can remove a queued entry. On Stellar there is no cheaper way to stop a release the watchers
found forged during the delay.

The three conditions, and where each is proven:

1. A cancel never loses the user's burn. The cancel removes the queue entry and the burn-id record and marks the nonce
   cancelled. `switch_threshold` signers (6 of 7, the unpause quorum) certify that nonce again, once (`generation` 1),
   for the same burn id or, if a forgery had taken the nonce, for the real one. A real burn whose id a forgery used
   under another nonce is paid by an ordinary certificate under its own nonce.
   Unit tests: `cancel_then_fresh_certificate_for_the_same_burn_pays_exactly_once`,
   `cancel_of_a_forgery_that_used_a_real_burn_id_does_not_lose_that_burn`. Rehearsal: sections "cancel" and
   "false alarm" (cancel of a real release, the same burn certified again by 6 signers with their own tools, paid
   once, four replay attempts refused).
2. Guardians alone never move funds, never change a limit and cannot block a burn for good. A cancel pays no one and
   leaves the configuration, the books and the balance untouched. The re-certified release cannot be cancelled
   (`NotCancellable`). What remains is the pause, which the same 6-of-7 quorum ends as on Ethereum, after which the
   guardians are blocked for the cooldown and the release is paid.
   Unit test: `guardians_alone_cannot_move_funds_change_limits_or_block_a_burn_for_good`.
3. Documented as a difference, with its reason: this section, the table above, `bridge.network.json` notes.

With `release_delay` 0 nothing is ever queued, `cancel_release` can never succeed and the guardians are pause-only in
the strict sense (unit test `without_a_release_delay_guardians_are_pause_only`).

Re-certification is a deliberate act of each operator, never automatic: the operator lists the nonce in
`recertify_nonces` of its half's config. The half then checks that the vault records that nonce as cancelled,
generation 0, and signs `generation` 1; every other check (the burn read from the L2, the mint chain, the backing)
is unchanged. The watcher parks such a burn with the alert `release-needs-recertification`.

## 5. The release delay: an owner parameter

`release_delay` (0 to 14 days) and `large_release_threshold` are constructor values. Nothing is hard-coded and nothing
can change them after deployment. The committed configuration carries a PROPOSAL, not a decision:
`large_release_threshold` 0 and `release_delay` 7,200 s, so every release waits 2 hours.

| Choice | Exit time | A 5-key forgery of a release | Guardians |
|---|---|---|---|
| Delay 0 (Ethereum launch behaviour) | L2 finality only | Paid at once. Loss up to the bucket: 10,000 USDC, then 10,000 a day until a guardian pauses. | Pause only. |
| 2 h on every release (proposed) | L2 finality + 2 h, and one more transaction (`execute_release`, paid by the relayer) | Visible for 2 h. Paid only if no 2 of 3 guardians cancel within 2 h. | Pause, and cancel of queued releases (section 4). |
| 2 h above a threshold T > 0 | Small exits instant, large ones + 2 h | Forged releases of at most T each are paid at once, up to the bucket. The worst case is the same as delay 0. | Pause, and cancel of queued releases. |

The trade-off is exit latency and guardian availability against the loss a signer-key compromise can cause before
anyone reacts. A delay protects only while 2 of 3 guardians run the check (`guardiao_stellar.py check`) more often
than the delay. A longer delay gives them more time and users a slower exit.

## 6. Safety properties kept from the Ethereum bridge

- Books in token units; `balance >= (total_locked + fees_accrued) * 10` is checked before every transfer, and the
  balance difference after it.
- Supply cap, minimum deposit, a release token bucket (`window_limit` per `window_seconds`), deposits above the window
  refused (there is no refund path).
- Provenance: a release is paid only if the burn states the vault's chain head at its mint count.
- Replay: one release per burn nonce and per burn id.
- Controls (open or close deposits and releases): 5 of 7, nonce-ordered, expiring.
- Guardians: fixed at deployment, never signers, one pause per guardian in a chain, 6 of 7 to unpause, cooldown.
- Signers complete from canonical observations (vault state, not events), hold on a stale or diverging node, keep a
  local database against signing two releases for one nonce or burn, and the relayer journals the signed envelope
  before publication.

## 7. Finality rule

Stellar closes a ledger by federated consensus and does not reorganise. A signer attests a deposit when the ledger
that wrote the deposit's chain head is closed and at least `finality_ledgers` (12, about one minute) behind its own
node, the node's latest ledger is at most `max_ledger_age` (60 s) old, and every RPC the signer configures reports
the same hash for that ledger. A stale node or two views that disagree make the signer hold: it signs nothing. There
is no reorganisation after attestation to handle. Every mint still waits 12 hours on the L2, where the L2 guardians
cancel one whose deposit is not in the vault's chain.

## 8. The issuer's powers over the vault (verified read-only on 2026-11-16, sources in `bridge.network.json`)

- Freeze: `AUTH_REVOCABLE` is set on the issuer. A revoked vault can neither receive nor pay. Deposits, releases and
  the sweep fail with `InvalidTransfer` and consume nothing; the same certificate pays after re-authorization.
- Clawback: not enabled today; the issuer's flags are not immutable, and a flag enabled later applies only to balance
  entries created afterwards. If the vault's balance is clawed back, `backing()` shows the shortfall, every transfer
  fails with `InsufficientBacking`, signers refuse to certify, and the reserves monitor alerts. The L2 token is then
  under-backed by the missing amount until someone makes the vault whole.
- Trustline: a `G...` recipient without a USDC trustline cannot be paid. The release fails, records nothing and pays
  after the trustline exists. The fee address needs one too (section 11).

## 9. Storage and archival

Configuration and books live in the contract instance. Deposit-chain heads, replay records and queued releases are
persistent entries. On the public network a new persistent entry lives at least 2,073,600 ledgers (about 120 days,
read 2026-11-16); the vault also extends each record to `RECORD_TTL` (518,400 ledgers) when it writes it. An entry
whose rent runs out is archived, never deleted: it cannot be created again, only restored, and since protocol 23 a
transaction that touches it restores it. So an expired replay record cannot make a release payable again.
Independently a certificate expires at most 24 hours after it is signed. Nothing uses temporary storage.

Proven on a private network whose entries live 20 ledgers, with a Wasm built with `RECORD_TTL` 30 (the
`rehearsal-short-ttl` feature; never deployed): after the record expired, a fresh certificate for the paid burn, the
original certificate and the relayer all fail to pay; the refusal is the vault's own `InvalidRelease`.

## 10. Operator runbook delta (on top of `docs/BRIDGE-V3-OPERATOR-RUNBOOK.md`)

Each operator additionally runs:

- Its own Stellar RPC (stellar-rpc with captive core) and the pinned `stellar` CLI 30.0.1. A second independent RPC
  in `stellar_rpc_others` is recommended; the half holds when they disagree.
- The signer: `signatario_stellar.py` (the Ethereum signer's code with three replaced functions) with
  `stellar_half.py` as its source half. Same key files: the `l2-mint-signer` key and the `eth-release-signer` key.
  Extra config: `network_passphrase`, `vault`, `vault_wasm_hash`, `view_account` (any existing account; views are
  simulated, never sent), `vault_switch_threshold` 6.
- The watcher: `vigia_stellar.py sign` per signer and `vigia_stellar.py relay` for the relayers. It executes queued
  releases that are due. It runs only in the shared-directory mode today (section 13).
- The relayer needs a funded Stellar account (a few XLM; it pays the release, the execution and the sweep) and holds
  no bridge key.
- Guardians: `guardiao_stellar.py check` on a timer shorter than the release delay. Exit 2 is a finding: sign
  `pause`, and for a queued release `cancel` (the second guardian passes the first one's `--valid-until`), then
  `combine-cancel` and any relayer submits it.
- Reserves: `reservas_stellar.py check` on a timer. Alerts: `shortfall`, `frozen`, `oversupply`, `rent`, `archived`.
- Rent: the vault instance, its Wasm and its balance entry must stay live. The vault extends its instance to
  1,555,200 ledgers whenever a call writes state and it is below half. If `rent` alerts, anyone runs
  `stellar contract extend` for the instance and the Wasm; if `archived`, `stellar contract restore`.
- After a guardian cancel: 6 operators review the burn, add the nonce to `recertify_nonces`, sign
  (`signatario_stellar.py release --burn-tx ...`, the first one's certificate passed as `--context` to the others),
  combine and relay. Remove the nonce from the list afterwards.
- Unpause and controls: `comite_stellar.py`, 6 of 7 and 5 of 7.

Users: a recipient needs a USDC trustline before the release; muxed (`M...`) addresses are not accepted.

## 11. Audit scope note

New code an auditor must read first, in this order:

1. `stellar/vault/src/lib.rs` (1,118 lines): `release`, `cancel_release`, `execute_release`, `pay`,
   `check_certificate` and `recover` (low-s, `v`), the replay match in `release`, the digests in `impl Vault`.
2. The hash pairing with the frozen token: `TAG_MINT_CHAIN`, the deposit head, the genesis, against
   `BridgedStablecoinV3`.
3. `tools/signatario-stellar/stellar_half.py` (what a signer checks before it signs) and `signatario_stellar.py`
   (the three replaced functions).
4. `contracts/stellar/StellarBurnRouter.sol` (80 lines; strkey validation and the commitment).
5. `relay_stellar.py` (journal before publication), `vigia_stellar.py`, `source_stellar.py`.

Reused byte-identical: `BridgedStablecoinV3` (L2 token) and every launch contract of the Ethereum bridge; the whole
of `tools/signatario-stable/` (`signatario.py`, `vigia.py`, `bridge_feed.py` are imported, not edited).
`tools/deploy-pontes/deploy_pontes.py` gains 16 lines that route a config with a `stellar` section to
`source_stellar.py`; an Ethereum config does not reach that module (`test_source_stellar.py`).

Questions for the auditor: the Stellar Asset Contract's behaviour for the real USDC issuer (authorization, clawback,
trustline limits); archival and automatic restoration across protocol upgrades; resource limits of a release with 7
signatures; the absence of an on-chain source anchor; the cancel and re-certification state machine.

## 12. Tests and results (final Wasm `@@WASMSHORT@@`)

- Vault unit suite: 168 tests, 168 pass (SDK 29 test host, independent second implementation of every hash,
  randomized rate-limit and books properties).
- Router: 9 forge tests (commit `68ed7e7`, unchanged since).
- Deploy tool: `test_source_stellar.py`, 12 tests pass; the existing deploy tool suites pass unchanged.
- Archival rehearsal (private network, entries live 20 ledgers, Wasm `@@ARCHWASM@@`): 14 of 14 checks pass.
- Main rehearsal (private Stellar network, protocol 29, anvil with the real token bytecode): @@MAIN@@.
  Sections: pairing, controls, limits, deposit and credit, finality margin, release with fee, replay, 11 forged
  certificates, delay, guardian check, cancel and re-certification, false alarm, pause chain and unpause, rate limit,
  issuer freeze, clawback, missing trustline, diverging and stale views held, watcher daemons, deploy tool source
  checks, fee sweep, books, cost.
- Cost of a release with 5 signatures on the private network (testnet limits): @@COST@@.

## 13. Not done, not proven

- No external audit. No run on the public network or on testnet. Nothing deployed, no real key used.
- The authenticated feed (`bridge_feed.py`) is not adapted: it verifies EVM vault digests. `vigia_stellar.py` refuses
  a config with a `feed` block or `l2_pins`, so the watcher cannot run on chain 700770 as it is. The signer and its
  half can; the transport between operators must be adapted and reviewed first.
- The signer's L2 half ran against anvil with the tag `finalized`, not against a Bloch L2 node with `l2_pins`.
- `deploy_pontes.py plan / run / record` were not executed for the Stellar config (they need a forge build at a
  pinned revision). `validate` and the source checks of `run` and `verify` were, the latter against a live vault.
- The asset in the rehearsal is a locally issued classic asset with the revocable and clawback flags, not Circle's
  account. The Stellar Asset Contract is the same built-in contract; the issuer's flags were read from the public
  network.
- Fees and resource limits were measured with the testnet limits of the quickstart image, not the public network's.
  A release with 6 signatures ran; one with 7 did not.
- The final Wasm was built once, on one host. A second, independent reproduction of the hash is an owner step.
- Archival was exercised on protocol 29 only. A change of the archival rules in a later protocol needs a new check.
- The guardian and shadow daemons of the Ethereum bridge (`tools/guardiao/`) are not adapted; `check` is a one-shot
  command run from a timer.
- The schema has no field for the release delay or the cancel quorum; both were requested from agent 320 as optional
  properties and are stated in the notes of `bridge.network.json` meanwhile.
- The release keys sign raw 32-byte digests (`cast wallet sign --no-hash`), as the Ethereum half does. A hardware
  wallet that refuses blind digest signing cannot hold them.
- Muxed accounts are not supported. A recipient that never opens a trustline is never paid; there is no timeout or
  redirect.
