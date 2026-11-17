# Stellar bridge: USDC on Stellar to bUSDC.xlm on the Bloch L2

Status: PROTOTYPE, UNAUDITED. Nothing is deployed. No real key signed anything. This bridge needs its own external
audit before any real funds. Round 16 (agent 324, branch `codex/bridge-stellar-r16-20261116`), revised in round 17
(agent 338, branch `codex/bridge-stellar-r17-20261117`) after the second independent review
(`agents/331-bridge-stellar-review-r17.md`). The vault contract is unchanged since `ffdb9b5`; round 17 changed the
tools, the deployment files and the documents. Revision 4 (after the reviewer's third pass) also changed the L2
exit router, a periphery contract with no power: it gained the claim of a direct burn. Revision 5 (round 18, agent
373) changed the router again (claims kept in order, the latest counts; a held exit is redirected by its burner)
and the tools; the vault is still unchanged.

Deployment and ceremony: `docs/STELLAR-BRIDGE-DEPLOY.md`. Published interface: `deployments/stellar/bridge.network.json`.

## 1. What it is

The existing bridge model, on Stellar. A Soroban contract (the vault) holds issuer-native USDC through the asset's
Stellar Asset Contract. The same committee as the Ethereum bridge (7 secp256k1 signer keys, 5 of 7; 3 guardians)
attests deposits and releases. The L2 token is `BridgedStablecoinV3`, byte-identical to the Ethereum bridge's launch
token (creation code keccak `0xe560441f…1de7`), with other constructor arguments: name `Bloch Bridged USDC (Stellar)`,
symbol `bUSDC.xlm`. One vault, one token, own cap and own books.

| Piece | File | Lines |
|---|---|---|
| Vault (Soroban, Rust; unchanged since `ffdb9b5`) | `stellar/vault/src/lib.rs` | 1,156 |
| Vault unit tests (159 + reviewer 331's four) | `stellar/vault/src/test.rs` | 3,456 |
| L2 exit router (periphery, no power; claims and redirects since revision 5) | `contracts/stellar/StellarBurnRouter.sol` | 166 |
| Network layer, signer half, signer wrapper | `tools/signatario-stellar/stellar_net.py`, `stellar_half.py`, `signatario_stellar.py` | 855, 459, 212 |
| Relayer, watcher daemons | `relay_stellar.py`, `vigia_stellar.py` | 156, 474 |
| Guardian tool, reserves monitor, committee controls | `guardiao_stellar.py`, `reservas_stellar.py`, `comite_stellar.py` | 336, 112, 135 |
| Pairing and deployment-file checks, Wasm import check | `pairing.py`, `wasm_imports.py` | 214, 78 |
| Deploy tool, Stellar source path | `tools/deploy-pontes/source_stellar.py` (+ 16 lines in `deploy_pontes.py`, unchanged) | 288 |
| Offline tests of the tools | `tools/signatario-stellar/test_stellar_tools.py`, `tools/deploy-pontes/test_source_stellar.py` | 692, 342 |
| Rehearsal driver | `tools/signatario-stellar/rehearse_stellar.py` | 1,544 |

Final vault Wasm: sha256 `ebe14e4bbbf513e6a6f8f1c40bcfaea7e9013bb6974b5781dc5211fe8d1f25e9` (34,547 bytes), built on the host with stellar-cli 30.0.1,
soroban-sdk 29.0.1, rustc 1.92.0, target `wasm32v1-none`: by agent 324 twice (two source paths, two target
directories), by reviewer 331 in its own clone, and by agent 338 in its own clone in round 17; the same hash every
time. It imports no `update_current_contract_wasm`, no `create_contract` and no `upload_wasm`
(`wasm_imports.py`), so its code can never change.

Revision 2 (2026-11-17) answers review 325 (`agents/325-bridges-review-r16.md` section 4): the guardian cancel is
gone, a pause voids, signatures are Ethereum personal messages, and a direct burn has a stated claim rule.

Revision 3 (2026-11-17, round 17) answers review 331. The contract and its Wasm hash did not move. In the tools:
a burner's claim and every certificate are verified in process and no outside value reaches a command line (section
4b, 4d); the guardian check has a third answer, "cannot judge", which alerts and never pauses (section 4c); the
asset contract and every constructor value are pinned against the committed deployment file (section 5a); the fee
account must exist with its trustline before anything is deployed. The coordinator confirmed the guardian rule of
section 4.

Revision 4 (2026-11-17, round 17) answers the reviewer's third pass. The vault and its Wasm hash did not move. WHERE
a burn is paid is now one rule over the final L2 (section 4b): the claim of a direct burn is a set-once transaction
of the burner on the L2 router, and claim files, hint files, the re-pin rule and `SHARED/claims` are gone, so no two
parties can hold different claims. The guardian check judges by block numbers and finality only; its two rules that
compared L2 timestamps are replaced by a stall rule that bounds "cannot judge" for a queued release (section 4c).

Revision 5 (2026-11-17, round 18, agent 373, brief task 373) keeps the router transaction as the single source of a
destination and changes what it may say: the LATEST final claim of a direct burn's burner before the vault records a
release wins, none after; a held router exit (its address cannot receive the asset) is redirected by its own burner
on the router the same way; a signer never holds two live signatures for one burn; the guardian accepts any naming
of the burn's own burner and finds an address nobody else could have named at once (section 4b, 4c). The vault and
its Wasm hash did not move.

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
   The signers certify a payment only to an address with that commitment. Exits go through the router; a burn made
   directly on the token is never paid to the 20 bytes it names: it is paid only to the address its burner claims
   on the router (section 4b).
4. Release. After L2 finality 5 signers certify the burn, each with its own Stellar half, under the vault's current
   pause count. Anyone relays the certificate. The vault checks the committee by secp256k1 recovery, the pause
   count, the mint chain, the replay records, the bucket and the backing, takes 5 bps and pays the recipient (or
   queues the release, section 5).
5. Fees. `sweep_fees()` (anyone) pays every accrued fee to the address fixed at deployment,
   `GAF2DTU23X5CFOPOUCUBTFJ5PKTSOV4GLZAJB5VMJW2JUA5KKYF5OLNA`. Fees are never part of the backing.

Identifiers the L2 token takes: `sourceChainId` is the Stellar network id (sha256 of the passphrase) as a uint256,
`55527100184162397446267447655670856106844621679976070008664532462234000271737` on the public network. It does not
fit 64 bits. `sourceVault` is the low 20 bytes of the vault's contract id. `sourceRoute` is the vault's route.

## 3. Differences from the Ethereum vault (`ProvenanceSourceVault`, mode 1)

| Topic | Ethereum | Stellar | Why |
|---|---|---|---|
| Committee check | `ecrecover` | Soroban `secp256k1_recover` + `keccak256`, low-s only, `v` 27 or 28, over an Ethereum personal message (EIP-191) of a digest that starts with a `BLOCH-XLM-…` tag and binds the network id and the contract id | Same keys, same message scheme as the other routes; a Stellar digest can never equal another route's. No Stellar (ed25519) key holds any power. |
| Upgrade, admin | none | none; the Wasm cannot replace itself | Same rule. |
| Light-client switch | one-way switch to a verifier | absent | Out of scope this round (NO-GO). `switch_threshold` remains as the 6-of-7 quorum for the unpause. |
| Decimals | 6 and 6 | asset 7, books 6; multiples of 10 stroops only | Stellar classic assets have 7 decimals. |
| Deposit recipient | `pqRecipientHash` (padded address) | `BytesN<20>` L2 address | Same content. |
| Release recipient | 20-byte address | Stellar address, bound by a 20-byte commitment in the burn | The frozen token's burn names 20 bytes. |
| Source anchor | recent block hash checked on-chain | none on-chain; `valid_until` at most 24 h ahead; the digest binds the network id, the contract id and the vault's pause count | Soroban exposes no ledger hash, and Stellar has no forks. |
| Guardian pause | a guardian sends a transaction | a guardian signs a digest; anyone relays it | A secp256k1 key cannot sign a Stellar transaction. Same chain rule, same 6-of-7 unpause, same cooldown. |
| Release queue | none | releases above `large_release_threshold` wait `release_delay`; both fixed at deployment; delay 0 means no queue | Section 5. Owner decision. |
| What a pause does | stops deposits and releases for its duration | the same, and it VOIDS: every release still queued and every certificate signed before it is dead for good; an unpause revives nothing | Section 4. With a queue, a pause that only held would let a forged release be paid when it ends. Guardians have no other power: there is no cancel. |
| Closing releases | stops new releases | stops new releases and queued ones (they stay queued) | A queue must obey the committee's switch. |
| A release above `window_limit` | reverts when paid | refused before it is recorded | It could never be paid. |
| Asset failure | the token's revert | always the vault's `InvalidTransfer` (#2) | The asset contract's error numbers overlap the vault's. |
| Issuer powers | blacklist, pause | freeze of any balance (`AUTH_REVOCABLE` is set), clawback only if the issuer enables it later, trustline needed by the recipient | Section 8. |
| Replay records | storage slots, permanent | persistent entries with rent; archived when unpaid, never deleted | Section 9. |
| Storage rent | none | the instance, the Wasm and the vault's balance entry must stay funded | Runbook, section 10. |

## 4. Guardians: pause only, and a pause voids (review 325: R325-XLM-1, R325-XLM-4; confirmed in round 17)

THE RULE, as confirmed by the coordinator in round 17 (review 331, R331-XLM-9): guardians are pause-only, and a
pause voids the queue and every certificate signed before it. There is no cancel of any kind. The decision recorded
earlier in round 16 ("a bounded guardian cancel") is superseded; nothing in the code, the configuration or these
documents implements a cancel.

What the rule costs in the worst case, measured by reviewer 331
(`r331_hostile_guardians_with_the_worst_schedule_delay_an_exit_by_one_chain_at_most`): with the proposed values
(pause 72 h, cooldown 72 h, release delay 2 h) all THREE guardian keys, hostile and pausing one second before an
exit matures each time, delay that exit by 3 x (72 h + 2 h) + 2 h = **9 days 8 hours**; two keys by 6 days 6 hours;
one key by 3 days 4 hours. After a chain no guardian can pause for 72 hours, and every exit queued in the first 70
hours of that window is paid. Nobody delays an exit beyond that or voids it for good; a hostile guardian set keeps
the vault closed at most 3 of every 4 days, as on the Ethereum vault, which has the same chain rule.

History. Revision 1 let 2 of 3 guardians cancel a queued release. Reviewer 325 showed that the cancel had no budget: two
guardian keys could cancel every exit for ever, and each cancelled burn needed 6 of 7 signers and a hand step of
every operator. The coordinator asked for a bounded cancel (a budget per window, further cancels only under a pause,
re-certification by the ordinary 5 of 7 with no manual step), or a simpler rule with the same guarantees.

The rule implemented is the simpler one. There is no cancel. Guardians can only pause, exactly as on the Ethereum
bridge and under the same chain rule, and a pause voids:

- The vault counts its pauses (`pause_count`). Every release certificate names the count it was signed under, and
  every queued release records the count it was queued under.
- `release` accepts a certificate only for the current count. `execute_release` pays a queued release only while
  the count is still the one it was queued under; otherwise it answers `Voided`, for good.
- A guardian pause raises the count. So one pause kills every certificate signed before it (submitted or not) and
  every release still in the queue. A 6-of-7 unpause ends the pause early and revives nothing.
- A voided burn loses nothing. Its nonce is open again for one certificate of the ordinary threshold (5 of 7) under
  the new count; it queues and waits the full delay again. The signers' tools do this by themselves: the vault
  answers `burn_status` 0 (open) and they certify the burn like any other. No operator step, no sixth signer.

Why this is simpler and gives the same guarantees:

1. A real forged release can still be stopped during the delay, and by ONE guardian key instead of two: the
   guardian that finds it pauses. That is what a guardian does on evidence of a forged certificate on every route,
   because such a certificate means five signer keys are stolen or fooled, and the whole vault should stop.
2. Honest exits cannot be starved by two keys. All a guardian key has is the pause, and the pause has the Ethereum
   bridge's budget: each guardian once per chain, then at least `pause_cooldown` in which no guardian can pause.
   The constructor refuses a `release_delay` above half the cooldown, so an exit certified in that open window is
   paid in it. Two keys delay exits by at most two pauses per chain; they void, per chain, only what was queued at
   those two moments. Five signers are enough throughout; six can end a pause early, after which the guardians are
   blocked for the cooldown.
3. No new parameter, no window state and no second guardian power to audit: the vault lost `cancel_release`, its
   digest, the generations and the 6-of-7 re-certification. The difference from the Ethereum vault shrinks to "a
   pause voids", which the Solana route also has.

What it costs, stated plainly: a pause also voids the honest releases queued at that moment (they are re-signed
automatically and wait the delay again), so one guardian's false alarm costs every queued exit a new delay and
closes the vault for the pause (deposits too) unless 6 of 7 signers end it; and a single forged release can no
longer be removed without pausing the vault. That is why the guardian check never pauses on a view it cannot trust
(section 4c). A persistent attacker who holds five signer keys can queue a forgery again after each pause; the guardians
then have their pause chain (up to 3 pauses) and after it the cooldown, in which that forgery would be paid. No
set-once committee design survives five stolen keys for long; the delay and the pauses buy days, not safety.

Where each point is proven:

- Reviewer 325's demonstration, turned into a regression: `r325_xlm1_two_guardian_keys_cannot_starve_exits` (30
  exits, every release queued, two guardian keys pausing whenever the vault lets them: 2 exits voided, 30 of 30
  paid, 5-of-7 certificates only).
- `pause_voids_queued_releases_and_no_unpause_revives_them`, `certificate_signed_before_a_pause_is_dead_after_it`
  (R325-XLM-4, also with a pause shorter than the certificate's validity),
  `voided_burn_is_certified_again_by_the_ordinary_threshold_and_paid_exactly_once`,
  `voided_forgery_leaves_its_nonce_to_the_real_burn`,
  `voided_forgery_that_used_a_real_burn_id_does_not_lose_that_burn`,
  `guardians_alone_cannot_move_funds_or_change_limits`,
  `without_a_release_delay_a_pause_voids_unsubmitted_certificates_only`,
  `ctor_refuses_a_release_delay_above_half_the_cooldown`.
- Main rehearsal: a quorum forgery voided by one guardian's pause and the real burn of its nonce certified by 5
  signers with their own tools; a false alarm paid exactly once afterwards; a burn queued by the watcher daemons,
  voided, and certified and paid again by the same daemons with nobody in the loop.

## 4a. Signatures (R325-XLM-3)

Every certificate (release, controls, unpause) and every guardian pause is an Ethereum personal message, EIP-191:
the key signs `keccak256("\x19Ethereum Signed Message:\n32" ‖ digest)`. The Soroban host computes that hash and
recovers from it; nothing in the recovery path changed. The tools call `cast wallet sign` without `--no-hash`, so no
tool path of this route signs bare 32 bytes with a bridge key. `cast` is used for nothing else: every signature a
tool receives (its own keystore's, a partial from another operator) is recovered in the tool's own
process with the repository's secp256k1 and Keccak code (`stellar_net.recover_personal`, low s, `v` 27 or 28), and
compared with the address it must belong to. The digest keeps its own domain: it starts with a
`BLOCH-XLM-…` tag and binds the network id (sha256 of the passphrase) and the contract id. A signature over the bare
digest is refused (`signatures_over_the_bare_digest_are_refused`).

## 4b. A burn made directly on the token (R325-XLM-2)

The frozen token's `burn(uint64,address)` takes any 20 bytes. The router makes the normal path safe; its interface
has the shape of the other routes' routers: `burnTo(uint64 amount, string stellarAddress)` and
`StellarExit(bytes32 indexed burnId, address indexed from, uint64 amount, bytes20 commitment, string stellarAddress)`.

WHERE A BURN IS PAID: one rule, read from the FINAL L2 alone, the same for every signer, watcher and guardian
(`stellar_net.burn_destination`; review 331, third pass, R331-XLM-3P-1; round 18, brief 373):

- A burn made BY THE ROUTER is paid to the address the router checked, committed to and logged. The burn's 20 bytes
  are that address's commitment. The router also records who called `burnTo` (`exitBurnerOf(nonce)`).
- If that exit is HELD, that is, the address given to `burnTo` cannot receive the asset (a `G...` account that does
  not exist, holds no trustline for the asset, or holds one the issuer has not authorized; the vault's transfer then
  fails and nothing is recorded), the account that called `burnTo`, and only it, may name another address with
  `redirectHeldBurn(uint64 burnNonce, string stellarAddress)` (event `HeldBurnRedirected(address indexed burner,
  uint64 indexed burnNonce, uint256 version, bytes20 commitment, string stellarAddress)`; views `redirectOf`,
  `redirectCount`, `redirectAt`). The signers pay the LATEST redirect final on the L2 instead, and only while the
  exit is held on their own Stellar ledger; an exit whose address can receive is paid there whatever redirects exist.
  A `C...` contract address always can receive (no trustline), so such an exit is never redirected.
- A burn made DIRECTLY ON THE TOKEN is never paid to the 20 bytes it names (they may be an Ethereum address, as on
  bUSDC; even when they happen to be a commitment they are not used). It is paid to the address the ACCOUNT THAT
  BURNED claims with a transaction of its own on the router: `claimDirectBurn(uint64 burnNonce, string
  stellarAddress)`. The router keeps every claim of that account for that nonce in order (`claimCount`, `claimAt`,
  event `DirectBurnClaimed(address indexed burner, uint64 indexed burnNonce, bytes20 commitment, string
  stellarAddress)` unchanged) and answers the latest with `claimOf(burner, nonce)`. A claim by another account sits
  under that account and is ignored. A contract that burned can claim. There is no timeout: until a claim is final
  on the L2 the asset stays in the vault. A held direct exit is redirected the same way: the burner claims again.
- THE LATEST FINAL NAMING BEFORE CERTIFICATION WINS, NONE AFTER. "Certification" is the vault recording a release
  for the burn (queued or paid: `burn_status` 1 or 2). From then on the vault refuses any other certificate for the
  burn and every signer refuses to sign (`burn_status` is checked before anything else), so a later claim or
  redirect changes nothing. A pause voids a queued release: the burn is open again and the latest naming applies.
- Both histories are bounded (`MAX_NAMINGS` = 16 per burn; the same address twice in a row reverts), so a reader
  always reads the whole history.

Why the rule stays deterministic although a naming can change (round 17 chose set once for this reason; brief 373
asks for the latest naming, so the property is kept another way). The certificate does not bind the L2 block of
the naming (the vault's digest names the burn's block), so two signers that read different final blocks while the
burner names again could sign for two addresses. What prevents two addresses from both gathering a quorum is the
signer's own database: `stellar_half.resign_allowed` lets a signer sign another release for a burn only if it
differs in the recipient alone and the signer's earlier signature for that burn is DEAD for the vault (its
`validUntil` is before the ledger close time, or a pause moved the count), and only while the vault shows the burn
open. A signer therefore never holds two live signatures for one burn; a split round simply expires (at most
`valid_seconds`, 30 minutes by default) and the signers then agree on the latest naming. The price: a burner who
names again during a signing round delays the exit by up to that long.

How each party applies the rule:

- The signer (`signatario_stellar.py`) reads the destination (and, for a router exit, its latest redirect) from the
  same L2 view it read the burn from (its own, rebuilt, final L2), at the same final block, with the router pinned
  by address and code, and puts it into the intent. The half checks it again: a router address must hash to the
  burn's 20 bytes; a claim or a redirect is read again from the operator's own L2 RPC when one is configured and
  must agree; a redirect is used only if the router address cannot receive the asset on the half's ledger and the
  redirect can (this needs `asset_code` and `asset_issuer`, which must recompute the pinned `asset_contract`; without
  them nothing is redirected). Then `resign_allowed`.
- The watcher combines a partial for an address that is not the burn's commitment only if its own L2's router holds
  it as the LATEST claim (direct burn) or the LATEST redirect (router exit) at its final block.
- The guardian accepts as paid any address the burn's own burner named (the address given to `burnTo`, checked by
  its commitment; any redirect of that exit; any claim of a direct burn's burner), and nothing else; it holds no
  claim file and there is no directory, channel or grace time for claims (section 4c). Accepting an EARLIER naming
  is deliberate: which naming was the latest when the signers signed cannot be read back from the release, and a
  release paid to an address the burner itself named is never a forgery (R331-XLM-3P-1: in revision 3 a guardian
  handed a second valid claim of the same burner read the honest release as a forgery and paused). What five stolen
  keys gain from it is the choice among the burner's own addresses.

History (R331-XLM-1, R331-XLM-5, R331-XLM-3P-1). Revision 2 took a claim as a file signed by the burner and
"verified" it by the exit code of `cast wallet verify`; a file with `"signature": "--help"` paid a stranger. Revision
3 verified the file in process and let a signer move between two claims of one burner once its signature was dead.
Revision 4 removed the files and made the claim a set-once router transaction. Revision 5 (round 18) keeps the
router transaction as the only source, lets the latest final naming before certification win (claims and, for a
held router exit, redirects), and brings back revision 3's dead-signature rule, now over on-chain namings only.

Rehearsed (section 12a and 12b of the driver, and the reviewer's case A1): a direct burn is refused with no claim,
with a claim on the router by another account, and while the burner's claim is not final; the burner claims twice
before certification and five signers pay the latest; a claim after the payment makes no signer sign again; a
router exit to an account without a trustline is held, a stranger cannot redirect it, a signer whose signature for
the old address is live refuses the redirect, and after those signatures died five certify the redirect and it is
paid once; all three guardians judge every paid release ok; an old claim file, an old hint file and a foreign router
claim pay nobody.

## 4c. The guardian check: finding, or cannot judge (review 331, R331-XLM-3 and the third pass)

One guardian's pause is the whole reaction and it voids every queued exit, so the check must not pause on a view it
cannot trust; and it must not leave a forgery unjudged until it is paid. `guardiao_stellar.py check` gives one of
three answers for each release the vault paid or queued:

| Answer | When | Exit | The operator's unit |
|---|---|---|---|
| ok | the token's FINAL history holds the burn of that nonce with that id and amount, and the address paid is the burn's destination by the rule of section 4b | 0 | nothing |
| finding | the release contradicts the final L2, or the stall rule applies (below) | 2 | signs `pause` |
| cannot judge | the guardian's final view does not reach the release yet, or cannot be trusted | 3 | pages a human AT ONCE; does not pause yet |

The view is the final block that ALL configured L2 sources (`l2_rpc`, `l2_rpc_others`) report with the same hash, on
the pinned chain id, with the pinned token and router code. The L2 block a release names is in the certificate's
context (`native_finalized_number`, `native_finalized_hash`: the final block holding the burn); the guardian reads it
from the arguments of the release transaction on its own Stellar RPC and checks them against the release id.

Findings by the final history (block numbers and finality only; no clock of any kind):

- the final history holds another burn id for that nonce, or another amount;
- an address paid that the burn's own burner never named, not even at the guardian's NEWEST block (the lowest head
  of its agreeing sources): for a router burn neither the committed address nor a redirect of that exit; for a
  direct burn no claim of its burner (round 18: also when the burner made no claim at all, which was "cannot judge"
  before). Honest signers sign a naming only once it is final for them, and a final block is older than every
  node's head; so this misfires only if every source of the guardian is behind by more than the L2's finality depth
  (then a false pause: a liveness cost, no loss). An address the burner named in a block that is in the guardian's
  newest blocks but not yet final there is "cannot judge" (bounded by the stall rule);
- the named block is final in the guardian's view and holds no such burn, or the final chain has another hash at
  that height.

The stall rule (R331-XLM-3P-2). A release that is still QUEUED, that the guardian could not judge although its L2
sources answer and agree, and that is older than `stall_deadline` on the Stellar ledger clock (the release event's
ledger to the latest ledger) is a finding. Honest signers certify only what was final before they signed, so a final
view that still does not reach a queued release after that time means one of two things, and both are reasons to
pause before it is paid: the L2's finality stands still while releases land, or the release is forged in a way the
final history cannot contradict yet (under the nonce of the forger's own pending burn; naming a block nobody will
reach; through another contract, which hides the named block; for a direct burn with no claim). `stall_deadline`
defaults to half the vault's `release_delay` (3,600 s with the proposed 7,200 s) and the tool refuses a larger value.

No timestamp decides anything (R331-XLM-3P-3). Revision 3 had two "later block" rules that compared L2 block
timestamps with the release time, and switched them off when the L2's newest block was ahead of the host clock: one
block stamped two minutes ahead disabled them, and without that guard one such block would have produced false
findings on a lagging guardian. Both rules and the host clock are gone. An L2 head stamped more than
`l2_clock_alert_seconds` (120) ahead of the Stellar ledger clock is reported as its own alert (`alerts`, exit 4 when
nothing else is wrong) for a person to look at; no verdict depends on it.

Cannot judge: the final view is behind the burn, or behind the claim of a direct burn; a source does not answer,
serves another chain, or the sources disagree; `require_two_l2_sources` is set and one source is configured; the
token's or the router's code is not the pinned one; the L2 cannot serve the burn's log.

Trade-offs, stated:

1. The stall rule makes a guardian whose OWN follower stands still for longer than `stall_deadline`, while exits
   are queued, pause: 72 hours closed unless 6 of 7 signers end it, every queued exit void and certified again. That
   is the price of not letting a forgery through when finality really stands still; a second independent L2 source
   does not remove it (the lower final block of the two is used). It follows that `release_delay` must be at least
   twice the time the L2 normally needs to finalize a block, plus the check interval; if the L2's normal finality
   lag came near half the delay, honest exits would be paused.
2. "Cannot judge" is bounded only while the L2 sources answer and agree. A guardian whose every L2 source is down,
   or whose sources disagree, pages and never pauses: a forgery then waits for another guardian (one is enough) or
   for the person paged.
3. A release that was PAID before it could be judged (no delay, or an amount below `large_release_threshold`) stays
   exit 3: a pause would not bring it back. With a delay of 0, or a threshold above 0, the check is detection after
   the fact for those releases.

Tested: `test_stellar_tools.py` `GuardianCheck` (23 tests against fake sources, both directions); the rehearsal
(the reviewer's case A2: a view one block before a real, paid burn: exit 3, no finding; a queued quorum forgery:
exit 2; a direct burn and a router burn paid to a stranger; a queued forgery under the forger's own pending nonce:
exit 3 at first, exit 2 by the stall rule after the deadline, still unpaid; the clock alert), in a run whose L2
clock is days ahead of real time; and the reviewer's rig, whose L2 clock is the wall clock: its three checks that
failed at `22ea9a4` pass.

A pause is never signed in advance (R331-XLM-7): the vault accepts a signed pause until its `valid_until` or the
next pause, so `guardiao_stellar.py pause` refuses `valid_seconds` above 3,600 (default 600).

## 4d. No decision from an exit code, no outside value on a command line (review 331, the class behind R331-XLM-1)

Every tool of this route was searched for a decision taken from the exit code of a program, and for text from
outside placed on a command line. What was found and what replaced it:

| Was | Where | Now |
|---|---|---|
| `cast wallet verify` of a claim file, exit code | `stellar_half.py`, `signatario_stellar.py`, `guardiao_stellar.py` | revision 3: verified in process; revision 4: no claim file exists (section 4b) |
| `cast wallet verify --no-hash` of a partial, exit code | `vigia_stellar.py` | `stellar_net.recover_hash`, in process; `signatario_stellar.py` also recovers the half's signature and every signature it combines |
| `cast logs` + `cast abi-decode` with log data from the RPC as an argument | `stellar_half.py` (router log), `guardiao_stellar.py` | `stellar_net.L2`: JSON-RPC in process, every answer checked for its shape, ABI decoded in Python |
| `cast call`, `cast block`, `cast chain-id`, `cast code`, `cast keccak` | `guardiao_stellar.py`, `reservas_stellar.py`, `pairing.py` | the same `L2` class |
| `cast wallet sign` then `cast wallet address`, both trusted as printed | `stellar_half.py`, `comite_stellar.py`, `guardiao_stellar.py` | `cast wallet sign ... -- 0x<digest>` only (the key stays in the keystore); the output must be a well-formed signature that recovers in process to a member of the vault's set |
| function name, argument names and values of a call file passed to `stellar contract invoke` | `stellar_net.py`, `relay_stellar.py` | function names from the vault's 26; argument names plain identifiers; values numbers, booleans, hex or Stellar addresses (none can start with `-`); the relayer accepts six calls with exactly their argument names; journal keys are letters, digits, `-`, `_` |
| the CLI's output used as it came | `stellar_net.py` | accepted only as a base64 envelope, a 64-hex hash, or JSON |
| exit 0 of a child tool read as success | `vigia_stellar.py` | exit 0 AND the tool's own JSON result |

`cast` now runs in three places, only to sign with a keystore. The `stellar` CLI still builds, simulates, signs and
sends transactions and encodes ledger keys; its arguments are restricted as above. A test reads the source of every
tool and fails if another `cast` subcommand, a shell or `--no-hash` appears (`test_stellar_tools.py`). The shared
modules of `tools/signatario-stable/` are not edited on this branch: `vigia.py` checks formats before its own `cast
wallet verify`, and `signatario.py` verifies only this operator's own half, whose signature the Stellar wrapper now
recovers first.

## 5. The release delay: an owner parameter

`release_delay` (0 to 14 days) and `large_release_threshold` are constructor values. Nothing is hard-coded and nothing
can change them after deployment. The committed configuration carries a PROPOSAL, not a decision:
`large_release_threshold` 0 and `release_delay` 7,200 s, so every release waits 2 hours.

| Choice | Exit time | A 5-key forgery of a release | Guardians |
|---|---|---|---|
| Delay 0 (Ethereum launch behaviour) | L2 finality only | Paid at once. Loss up to the bucket: 10,000 USDC, then 10,000 a day until a guardian pauses. | Pause only; a pause voids certificates not yet submitted. |
| 2 h on every release (proposed) | L2 finality + 2 h, and one more transaction (`execute_release`, paid by the relayer) | Visible for 2 h. Paid only if no guardian pauses within 2 h. | Pause only; a pause voids the queue (section 4). |
| 2 h above a threshold T > 0 | Small exits instant, large ones + 2 h | Forged releases of at most T each are paid at once, up to the bucket. The worst case is the same as delay 0. | Pause only; a pause voids the queue. |

The trade-off is exit latency and guardian availability against the loss a signer-key compromise can cause before
anyone reacts. A delay protects only while at least one guardian runs the check (`guardiao_stellar.py check`) more
often than the delay. The delay must be at most half the pause cooldown (the constructor refuses more). A longer delay gives them more time and users a slower exit.

Recommendation of rounds 16 and 17 (the owner decides; revenue is 5 + 5 bps either way): `large_release_threshold` 0
and `release_delay` 7,200 s, with `pause_duration` and `pause_cooldown` 259,200 s. Reasons: with delay 0 a five-key
forgery is paid at once, up to 10,000 USDC a day, and the guardians can only react afterwards; a threshold above 0
leaves the same worst case; 2 hours is long enough for a check that runs every few minutes on three independent
guardians and short enough for users (every exit already waits L2 finality). What the owner accepts with it: every
exit takes L2 finality + 2 hours; a guardian pause (a real alarm or a false one) voids the whole queue and closes
the vault for 72 hours unless 6 of 7 signers end it; hostile guardian keys delay an exit by at most 9 days 8 hours
(section 4). If the owner prefers faster exits over this protection, the value is 0, not a threshold.

## 5a. What is pinned at deployment (review 331, R331-XLM-2)

The vault accepts any asset contract with 7 decimals, and its configuration can never change. In revision 2 nothing
off-chain named the asset: the token config's route was copied from the deployed vault, and the tools compared the
vault with itself. Now:

- `deployments/stellar/busdc-xlm-vault.config.json` carries `asset` (code `USDC`, issuer
  `GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN`, contract
  `CCW67TSZV3SSS2HXMBQ5JFGCKJNXKZM7UQUWUZPUTHXSTZLEO7SJMI75`) with its sources: Circle's own list of USDC contract
  addresses (https://developers.circle.com/stablecoins/usdc-contract-addresses, row Stellar) and Circle's
  `stellar.toml` (https://www.circle.com/.well-known/stellar.toml), both read on 2026-11-17; the issuer account's
  home domain is circle.com. The contract id is not taken from a list: it is the Stellar Asset Contract id the
  protocol derives from (network id, code, issuer), computed by `stellar_net.asset_contract_id` and equal to the id
  Horizon reports.
- `pairing.py preflight` (before the deploy) and `pairing.py vault-check` (after it) compare the vault with that
  file: the Wasm hash and EVERY constructor field, one by one, with the route and genesis recomputed from the
  file's values. `pairing.py args` and `check` run the same comparison first; the token config's `stellar` section
  is built from the file, never copied from the vault.
- `deploy_pontes.py` (`source_stellar.py`): the token config's `stellar` section now carries `asset`, `labels`,
  `vaultWindowSeconds` and `vaultMinDeposit`. `validate` derives the asset contract id, requires Circle's on the
  public network, and requires `route` to be the route the file's own values give. `run` and `verify` refuse a vault
  whose asset contract is not the pinned one and any other difference in a constructor value.
- A signer's half and the reserves monitor require `asset_contract` in their configuration and refuse a vault that
  holds another; on the public network the half accepts only Circle's contract id.
- The fee account: the same tools refuse while `fee_recipient` does not exist on the network or holds no authorized
  trustline for the asset (`docs/STELLAR-BRIDGE-DEPLOY.md` section 2).

Rehearsed on the private network: a vault deployed over a look-alike asset (the same code from another issuer; the
contract accepts it) is refused by `vault-check`, by a signer's half and by the reserves monitor; a token config
naming the look-alike is refused by `validate`; a deployment file that differs from the vault in `window_seconds`,
`min_deposit`, `l2_min_burn`, the release delay, a label or the fee address is refused, naming the field; a fee
account without a trustline and one that does not exist are refused.

## 6. Safety properties kept from the Ethereum bridge

- Books in token units; `balance >= (total_locked + fees_accrued) * 10` is checked before every transfer, and the
  balance difference after it.
- Supply cap, minimum deposit, a release token bucket (`window_limit` per `window_seconds`), deposits above the window
  refused (there is no refund path).
- Provenance: a release is paid only if the burn states the vault's chain head at its mint count.
- Replay: one release per burn nonce and per burn id.
- Controls (open or close deposits and releases): 5 of 7, nonce-ordered, expiring.
- Guardians: fixed at deployment, never signers, pause only, one pause per guardian in a chain, 6 of 7 to unpause,
  cooldown.
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
  Extra config: `network_passphrase`, `vault`, `vault_wasm_hash`, `asset_contract` (required: the pinned asset
  contract), `view_account` (any existing account; views are simulated, never sent), `router` and
  `router_code_keccak` (the pinned StellarBurnRouter: the destination of every burn is read through it).
- The watcher: `vigia_stellar.py sign` per signer and `vigia_stellar.py relay` for the relayers. It executes queued
  releases that are due. It runs only in the shared-directory mode today (section 13). With `paid_file` it keeps
  the set of paid burns across restarts; a paid burn is not asked again (R331-XLM-4), so a pass costs one view per
  burn that is not yet paid.
- The relayer needs a funded Stellar account (a few XLM; it pays the release, the execution and the sweep) and holds
  no bridge key.
- Guardians: `guardiao_stellar.py check` on a timer much shorter than the release delay (every 5 minutes for a
  2-hour delay), against the guardian's own L2 follower and, where it has one, a second independent source
  (`l2_rpc_others`), with `l2_chain_id`, `token`, `router`, `router_code_keccak` and `token_code_keccak` pinned.
  Exit 2 is a finding: sign `pause` and any relayer submits it. Exit 3 is "cannot judge": page a person at once; the
  check itself turns it into a finding (exit 2) for a queued release after `stall_deadline` (section 4c). Exit 4:
  an alert for a person (an L2 block stamped ahead), no pause. Any other non-zero exit: the tool failed; alert. A pause is not a hold: it voids every queued release and every
  certificate signed before it, the honest ones included, and they are certified again by the signers' own tools
  when the pause is over. One guardian is enough; there is nothing to co-sign and nothing to cancel. Never sign a
  pause in advance: a signed pause is usable by whoever holds it until it expires or the next pause.
- Reserves: `reservas_stellar.py check` on a timer, with `asset_contract` pinned. Alerts: `shortfall`, `frozen`,
  `oversupply`, `rent`, `archived`, `wrong-asset`.
- Rent: the vault instance, its Wasm and its balance entry must stay live. The vault extends its instance to
  1,555,200 ledgers whenever a call writes state and it is below half. If `rent` alerts, anyone runs
  `stellar contract extend` for the instance and the Wasm; if `archived`, `stellar contract restore`.
- After a pause: nothing by hand. The watchers find every voided burn open again and certify it; the relayer
  queues it and executes it after the delay. If a forgery had taken a burn's nonce or id, the watcher alerts
  `release-held-nonce-or-id-taken` until a pause voids the forgery.
- A direct burn: nothing for an operator to do and nothing to distribute. The burner calls
  `StellarBurnRouter.claimDirectBurn(burnNonce, "G...")` from the account that burned; once that is final on the L2
  the signers certify it by themselves. A support answer to "I burned directly": make that call; a later call
  replaces the address until the vault records the release, never after.
- A held exit (the address given to `burnTo` has no trustline or does not exist): the account that called `burnTo`
  calls `StellarBurnRouter.redirectHeldBurn(burnNonce, "G...")`, or adds the trustline. Signers need `asset_code`
  and `asset_issuer` in the half config to pay a redirect. A signer that signed the old address pays the redirect
  once its old signature is dead (up to `valid_seconds`).
- Unpause and controls: `comite_stellar.py`, 6 of 7 and 5 of 7.

Users: a recipient needs a USDC trustline before the release; muxed (`M...`) addresses are not accepted.

## 11. Audit scope note

New code an auditor must read first, in this order:

1. `stellar/vault/src/lib.rs` (1,156 lines): `release` (the replay rule and `record_counts`), `execute_release`,
   `guardian_pause` (the pause count), `pay`, `check_certificate` and `recover` (EIP-191, low-s, `v`), `burn_status`,
   the digests in `impl Vault`.
2. The hash pairing with the frozen token: `TAG_MINT_CHAIN`, the deposit head, the genesis, against
   `BridgedStablecoinV3`.
3. `tools/signatario-stellar/stellar_half.py` (what a signer checks before it signs, the pinned asset, the
   held-exit check and the dead-signature rule) and `signatario_stellar.py` (the three replaced functions).
4. `contracts/stellar/StellarBurnRouter.sol` (strkey validation, the commitment, the claims of a direct burn and
   the redirects of a held exit, both bounded histories) and the destination rule over it:
   `stellar_net.burn_destination`, `claim_of`, `claims_of`, `redirects_of`, `router_exit_address`; the half's
   `cannot_receive` and `resign_allowed`;
   signatures: `signature_bytes` and `bridge_feed.recover`.
5. `stellar_net.py`: `cli_value`, `_fn_args`, `VAULT_FUNCTIONS`, `RELAYABLE` (what may reach the `stellar` CLI), the
   `L2` class (what is accepted from an L2 RPC), `asset_contract_id`, `config_differences`.
6. `guardiao_stellar.py` `judge`, `l2_view`, `destination_verdict`, `deadline` and the stall rule in `check` (when a
   guardian pauses and when it must not).
7. `relay_stellar.py` (journal before publication), `vigia_stellar.py`, `source_stellar.py`, `pairing.py`.

Reused byte-identical: `BridgedStablecoinV3` (L2 token) and every launch contract of the Ethereum bridge; the whole
of `tools/signatario-stable/` (`signatario.py`, `vigia.py`, `bridge_feed.py` are imported, not edited).
`tools/deploy-pontes/deploy_pontes.py` gains 16 lines that route a config with a `stellar` section to
`source_stellar.py`; an Ethereum config does not reach that module (`test_source_stellar.py`).

Questions for the auditor: the Stellar Asset Contract's behaviour for the real USDC issuer (authorization, clawback,
trustline limits); archival and automatic restoration across protocol upgrades; resource limits of a release with 7
signatures; the absence of an on-chain source anchor; the pause count and the void and re-certification rule; the
guardian's stall rule (it assumes that an honest signer certifies only a burn that was final before it signed, and
that the L2 normally finalizes well within half the release delay); the latest-naming rule on the router and the
dead-signature rule that keeps it from splitting a quorum (section 4b); the guardian's acceptance of any naming of
the burn's own burner and its "newest block" finding rule (section 4c).

## 12. Tests and results (final Wasm `ebe14e4b…f25e9`; revision 3, code at `8f1d0c4`)

All on the host from a clone of the branch with its own toolchain copy and target directories (agent 338, round 17);
the Python suites also on the Mac. The commit that carries this section differs from `8f1d0c4` in this document only.

- Vault Wasm rebuilt: `ebe14e4bbbf513e6a6f8f1c40bcfaea7e9013bb6974b5781dc5211fe8d1f25e9` (34,547 bytes), unchanged;
  the `rehearsal-short-ttl` build `510ec1010d5b91dfbc5338654500146e8939bc7188a2b903e5c5f07602d32ea3`, unchanged.
- Vault unit suite: 163 tests, 163 pass (SDK 29 test host, independent second implementation of every hash,
  randomized rate-limit and books properties): revision 2's 159 and the four tests of reviewer 331
  (`r331_hostile_guardians_with_the_worst_schedule_delay_an_exit_by_one_chain_at_most`,
  `r331_burn_status_in_every_state`, `r331_a_signed_pause_with_a_far_valid_until_stays_usable`,
  `r331_one_full_window_exit_holds_the_queue_behind_it`).
- Router: 9 of 9 forge tests.
- Tools, offline: `tools/signatario-stellar/test_stellar_tools.py` 42 of 42 (claims 11, command lines 5, guardian
  check 19, pins 1, asset and deployment file 5, paid cache 1); deploy tool `test_source_stellar.py` 15 of 15, with
  the existing deploy tool suites unchanged and passing (35 tests in the four files, 1 skipped as before).
- Archival rehearsal (private network, entries live 20 ledgers, the short-TTL Wasm), run `a2`: 14 of 14 checks.
- Main rehearsal (private Stellar network, protocol 29, testnet limits; anvil with the real token bytecode;
  everything run from a clean git clone of `8f1d0c4`, the L2 token deployed by `deploy_pontes.py`), run `m2`:
  **132 of 132 checks** (revision 2: 114). The same driver one commit earlier (run `m1`, `2ba9d40`): 132 of 132.
  Sections: the deploy tool (the look-alike asset and a wrong contract id refused; validate, plan twice, dry run,
  broadcast, record, verify); pairing; preflight and vault-check against the deployment file (a fee account
  without a trustline or that does not exist, another asset, another window, minimum, delay, label or fee address
  refused; a vault deployed over a look-alike asset refused by vault-check, a signer's half and the reserves
  monitor); controls; limits; deposit and credit; finality margin; release with fee; replay; 11 forged
  certificates; delay; guardian check; pause, void and re-certification; 6-of-7 unpause; pause chain; false alarm;
  rate limit; issuer freeze; clawback; missing trustline; direct burn and claim (run `m2`; revision 5 reruns it as: two claims before
  certification, the latest paid, a later claim ignored; a guardian whose final view is before the paid claim cannot
  judge; section 12a: a held router exit redirected); reviewer 331's case A1 (six forged claim files pay nobody); two claims of
  one burner; case A2 (a guardian behind the burn cannot judge); case A3 (a release with 7 signatures simulates);
  diverging and stale views held; watcher daemons (deposit, instant release, queued release, voided release, the
  paid file); deploy tool source checks; fee sweep; books; cost; two quorum forgeries that pay a stranger, found by
  the guardian check.
- Cost of a release with 5 signatures on the private network (per-transaction limits equal to the public
  network's), from the journaled envelope: 1,800 bytes, 14,458,139 instructions, 116 bytes read, 2,772 bytes
  written, fee bid 191,398 stroops (0.0191 XLM; resource fee 191,298). Simulated (case A3, not sent): 5 signatures
  14,476,459 instructions, 7 signatures 19,430,697 instructions (about 2.5 million per signature) against a
  per-transaction limit of 400,000,000; envelope 1,880 bytes, fee 193,275 stroops.

## 13. Not done, not proven

- No external audit. No run on the public network or on testnet. Nothing deployed, no real key used.
- The authenticated feed (`bridge_feed.py`) is not adapted: it verifies EVM vault digests. `vigia_stellar.py` refuses
  a config with a `feed` block or `l2_pins`, so the watcher cannot run on chain 700770 as it is. The signer and its
  half can; the transport between operators must be adapted and reviewed first.
- The signer's L2 half ran against anvil with the tag `finalized`, not against a Bloch L2 node with `l2_pins`.
- `deploy_pontes.py` deployed the token in the rehearsal on private networks only; never against chain 700770 or the
  public Stellar network.
- The asset in the rehearsal is a locally issued classic asset with the revocable and clawback flags, not Circle's
  account. The Stellar Asset Contract is the same built-in contract; the issuer's flags were read from the public
  network.
- Fees and resource limits were measured with the testnet limits of the quickstart image, not the public network's.
  A release with 7 signatures was simulated (section 12), not sent.
- The final Wasm was built on one host (three independent clones and target directories, same hash). A reproduction
  on a second machine is an owner step.
- Archival was exercised on protocol 29 only. A change of the archival rules in a later protocol needs a new check.
- The guardian and shadow daemons of the Ethereum bridge (`tools/guardiao/`) are not adapted; `check` is a one-shot
  command run from a timer.
- The certificate does not bind which naming (claim version or redirect) it paid; binding it needs a change to the
  shared signer's context or to the vault; not built. Instead a signer never holds two live signatures for a burn
  (`resign_allowed`), so a burner who names again during a signing round delays the exit by up to `valid_seconds`,
  and five stolen keys may choose among the burner's own named addresses; the guardian cannot tell which naming was
  the latest when the signers signed. Whether an exit was held when a redirect was paid is judged by each signer on
  its own Stellar ledger at signing time; the guardian does not re-judge it.
- The guardian's "newest block" finding rule misfires (a false pause, no loss) if every L2 source of that guardian
  is behind by more than the L2's finality depth when it checks; with one source this is one lagging follower.
- The stall rule pauses when a guardian's own follower stands still past the deadline while exits are queued, and
  it does not bound "cannot judge" when every L2 source is down or for a release already paid (section 4c,
  trade-offs). The L2's real finality lag is not known here; the rule's default (half the release delay) must be
  checked against it before launch. The check was never run against a Bloch L2 node.
- `guardiao_stellar.py check` reads the release's L2 block from the release transaction on the guardian's Stellar
  RPC; outside the RPC's transaction window, or for a vault call made from inside another contract, only the
  final history and the stall rule apply. Putting the block into the vault's events would close this, and would move the Wasm
  hash; not done.
- The relayer does not restore an archived chain head a release needs (review 325, R325-XLM-7): after 30 days
  without a deposit a signer refuses until someone restores the entry by hand.
- The three changes to `tools/deploy-pontes/deploy_pontes.py` (EVM networks, Tron, Stellar) are still unmerged; the
  token config's `stellar` section gained `asset`, `labels`, `vaultWindowSeconds` and `vaultMinDeposit` in round 17.
- A persistent holder of five signer keys can queue a forgery again after every pause (section 4). The pauses and the
  delay buy time only.
- Muxed accounts are not supported. A recipient that never opens a trustline is never paid unless the exit's
  burner redirects it (round 18); there is no timeout. A contract that called `burnTo` must itself be able to call
  `redirectHeldBurn`, or its held exits stay held.
