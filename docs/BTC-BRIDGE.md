# bBTC: the Bitcoin bridge (design, differences from the Ethereum bridge, audit note)

STATUS: UNAUDITED PROTOTYPE. Nothing is deployed. Rehearsed only on Bitcoin Core regtest against an anvil L2 stand-in
(section 10). It needs its own external audit before any real coin.

Native BTC is deposited on Bitcoin, `bBTC` is minted on the Bloch L2 (chain 700770), burned there and paid out on
Bitcoin. The model is the Ethereum bridge's (`docs/AUDIT-SCOPE-BRIDGE-V3.md`): a vault on the source network, the
set-once committee of 7 secp256k1 signers (5 of 7) and 3 pause-only guardians, limits fixed at deployment, no admin
key, no recurring checkpoint signature. Code: `tools/signatario-btc/`. Configuration: `deployments/bitcoin/`.
Deployment and ceremony: `docs/BTC-BRIDGE-DEPLOYMENT.md`.

## 1. What is different, in one paragraph

Bitcoin has no contract. On Ethereum the vault contract enforces the window, the pause and the replay rules even
against the committee's own keys. On Bitcoin **5 of the 7 keys can spend the whole vault at once**, and nothing
on-chain stops them: every limit on the Bitcoin side is a rule that each honest signer applies before it signs. What
bounds the vault is the L2 token's supply cap (the vault never holds more than the cap plus fees). **The cap does not
bound the loss**: every deposit address is a script of the same seven keys, so coins that were paid in and not yet
swept (waiting for depth, for lower fees, for the cap, outside the bounds, or never hinted) are spendable by the same
five keys. The true worst case on a five-key compromise is the vault plus everything unswept at that moment; the
refund rule (section 3a) lets each depositor take unswept coins back, but nothing limits how much strangers choose to
send. What detects a breach is the public replay of the vault's history (section 8). This is the first thing an auditor and the owner
must accept or refuse. Everything else in this document is how the rules are made deterministic, replay-proof by
Bitcoin consensus and checkable by anyone from the two chains.

## 2. The vault script

| Option | Decision | Reason |
|---|---|---|
| **P2WSH, `5 <7 keys> 7 OP_CHECKMULTISIG`** | **Chosen** | ECDSA over secp256k1 with the keys the operators already hold. The signing tool does not change: `cast wallet sign --no-hash` on the 32-byte BIP143 digest, from the same encrypted keystore, the same way the Ethereum half signs a release digest. The public keys come from the ceremony's existing proof-of-possession signatures (`btc_deploy.py keys`): no new step for an operator, no key export, no new key type. `cast` emits low-s RFC 6979 signatures (checked against a pure-Python implementation), which is what Bitcoin's standardness rules need |
| Taproot script path (`OP_CHECKSIGADD`) | Refused | Needs BIP340 Schnorr signatures. The operators' tool cannot produce them, so every hot key would have to be exported into new signing code. Smaller witnesses do not pay for that |
| Taproot key path with MuSig2 or FROST; threshold ECDSA | Refused | MuSig2 is n-of-n. FROST and threshold ECDSA need a distributed key generation (new keys, not "the existing keys") and interactive signing rounds between the seven hosts, with nonce state whose loss or reuse leaks the key. Not sound to bolt onto independently generated keystores, and not operable with one-shot signer daemons |
| Guardians as co-signers, or a timelocked second path | Refused for v1 | A guardian co-signature makes the guardians signers (they would have to validate every release). A relative timelock protects only young outputs; the vault's coins are old. Without covenants Bitcoin cannot bind where a spend goes, so no script here limits a 5-key spend |

The keys are sorted (BIP67 order) and compressed, as P2WSH requires. Witness of every vault input: empty item, five
DER signatures in key order, the script.

**Which keys.** The same seven operators, each with a **separate Bitcoin vault key** (role `btc-vault-signer`, same
tool, same keystore format): this is the default in the templates and what the rehearsal runs. The L2 token takes the
operators' L2 mint addresses, as for bUSDC. A digest signed for Bitcoin (double SHA-256 of a BIP143 preimage) cannot
be an Ethereum release digest, so a shared key would add no cross-protocol forgery (review 325, BTC-11), but
`cast wallet sign --no-hash` signs any 32 bytes: one intrusion on a signer host would then forge for both vaults.

## 3. Deposits: one address per L2 recipient

Deposit script: `<vault id (12 bytes) || L2 address (20 bytes)> OP_DROP 5 <7 keys> 7 OP_CHECKMULTISIG`, paid as
P2WSH. The vault id is a hash of the network and the vault's anchor output, so an address belongs to one vault.

| Question | Answer |
|---|---|
| Why not OP_RETURN | Many wallets and every exchange withdrawal cannot add one. A missing or mistyped memo leaves a deposit with no recipient. Here the address *is* the recipient: an ordinary payment from any wallet |
| Why not a key tweak (pay-to-contract) | The signers would have to sign with tweaked keys, which `cast` cannot do |
| Trust in the sender | None. The recipient is read from the script the coins are locked to, which the vault itself reveals on-chain when it sweeps them. A relayer's hint ("output X is a deposit for R") is checked by hashing: a wrong hint is refused by every signer (rehearsal A3) |
| How signers find deposits | They cannot scan for unknown scripts, so a hint (outpoint, recipient) reaches the relayer from the bridge page or the user. Hints are untrusted and permissionless |
| Change | The sender's wallet handles it: change returns to the sender's own address. Every output paying a deposit address is its own deposit, keyed by outpoint |
| Bounds | Below `minDepositSats` (0.001 BTC) or above `maxDepositSats` an output is not swept or credited; it is **refundable** (section 3a). The maximum equals the token's mint bucket: a larger credit could never be minted, and since the token credits strictly in deposit order it would block every later deposit |
| What the deposit was paid from | Anything. Only the output matters; the paying transaction may spend P2PKH, P2SH, P2WPKH, P2WSH or taproot inputs, or be a coinbase. The tools parse every Bitcoin transaction (`btc_core.parse_tx`) and require the vault's own format only of vault transactions (rehearsal S, A: deposits paid from legacy, nested-segwit and taproot inputs) |
| Strangers' coins at the public thread address | Never fatal. A candidate for the thread tip must spend a thread-script output with its first input, which only the committee can do: one lookup, no walk through a stranger's ancestry. Anything else is skipped and logged (rehearsal S1: dust from four input types, a fake marker, a coinbase) |
| Replace-by-fee, double spend | Nothing is read from the mempool. A deposit is swept at `sweepDepth` confirmations (rehearsal A2, D1) |
| Sent to the bare vault address | Names nobody. A vault transaction may take it as a stray input; it joins the fee pool (rehearsal F3) |
| Sent to an address computed for another recipient | Credited to that recipient. Not reversible |

## 3a. Refunds

Any deposit output that has not been swept can be sent back: below the minimum, above the maximum, waiting for the
cap or for lower fees, or simply unwanted. The L2 address the deposit names signs a request (an EIP-191 personal
message, `btc_core.refund_text`: vault id, outpoint, a P2WPKH address); the relayer puts it in a proposal; every
signer checks the outpoint, that it is the deposit address of that L2 address, and the signature, and the vault
transaction pays `value - 5 bps - fee rate x 605 vbytes` to the address named. Nobody is credited. The spend makes it
single-use by consensus (rehearsal J).

- Why the L2 recipient and not "the sender": Bitcoin has no sender. The first input's script is often an exchange's
  hot wallet, which would not credit the user. The L2 address is the one party the depositor named.
- Limits: an L2 address that is a contract and cannot sign cannot ask; an output too small to pay its own charge
  stays. The request is checked by the signers, not carried on Bitcoin: a replay of the chain shows that a refund
  happened and where it went, not who asked.
- Coins sent to the bare thread address name nobody and cannot be refunded by rule; they join the fee pool and reach
  the owner as surplus. Returning them is the owner's manual decision.
- The refund request is the one signature a stranger hands to these tools. It is verified **in process**
  (`btc_core.signer_of`: pure-Python recovery), never by a command-line verifier whose exit code could be made 0 by
  text shaped like an option (the defect class of R331-XLM-1 on another route). Parsing is strict: exactly `0x` and
  130 hex characters, v 27 or 28, low s; the address is decoded in process too. `--help`, `-h` plus 130 characters,
  hex without `0x`, a high-s twin and thirty more shapes are refused (`test_btc_signer.py` `OptionShapedInputs`,
  rehearsal J1b). The route's only subprocess is the signer's own `cast wallet sign --no-hash` over a digest it
  computed itself, whose output is then checked in process against the operator's public key.

## 4. The vault state lives on Bitcoin: the thread

All vault coins sit in one output, the thread. Every vault transaction spends the thread and creates the next one:

```
inputs   [0] thread tip   [1..] deposits swept   [..] deposits refunded   [..] strays at the bare thread script
outputs  [0] new thread   [1] OP_RETURN marker   [2..] one P2WPKH payout per burn, by nonce   [..] refunds   [last] owner fee
```

The marker (at most 80 bytes) is the vault's state after the transaction: next deposit nonce, the set of settled burn
nonces (a base plus a bitmap of the next 320), sats owed for L2 value, fee sats due to the owner, the fee rate the
transaction charged, and one operations byte: whether the transaction **sets burns aside** (and up to which nonce)
and which burns set aside earlier it pays now (**late payments**, at most four). Section 4a.

- **Deposit nonces are the sweep order.** The L2 token credits mints in nonce order and binds the nonce into the
  deposit id; on Ethereum the vault contract assigns the nonce. Here the Bitcoin chain does: input position in the
  thread. The deposit id is `ProvenanceSourceVault`'s formula over (route, nonce, outpoint commitment, credited
  units, recipient), so the Ethereum bridge's signer `signatario.py mint` runs **unchanged** with `btc_half.py` as its
  source half.
- **Replay protection is a consensus fact.** Two transactions that pay the same burn, or sweep the same deposit,
  both spend the same thread output, directly or through an ancestor. Only one can confirm. No signer database is
  needed for safety; a signer that lost its disk re-derives everything from its node.
- **Signers never validate a foreign transaction.** `btc_policy.build_vault_tx` is a pure function from (thread tip,
  items, fee rate) to exactly one transaction. A signer reads the facts on its own nodes, rebuilds, and signs only
  if the proposal is byte-identical (`btc_signer.py`). A relayer chooses which final items go in and the fee rate,
  inside the signers' ceilings; it cannot choose an amount, a recipient or an output.
- **Anyone can replay the vault.** `btc_policy.replay_tx` re-derives every vault transaction from chain data alone
  (the swept scripts reveal the recipients) and requires it to be the builder's output. The reserves monitor and
  every tool do this from the anchor on every run; a transaction outside the rules stops them all (`Held`).
- Burns are paid in any order (the bitmap), so a delayed large release does not block later small ones (rehearsal C4).

## 4a. Burns that are not paid now: set aside, never lost, never blocking

Two kinds of burn can wait without any bound: a burn made directly on the token that its burner never claims
(section 9: it is **never** paid without a claim), and a burn whose burner named a fee ceiling the market stays above
(section 6). In round 16 the marker's window made every such burn a brake: burns more than 328 nonces later waited
with it. With no timeout left, one unclaimed minimum burn (which its maker can always claim back) would have been a
free, permanent stop of every exit. So the rules can **set a burn aside**:

- A vault transaction may name a mark T (`aside_through`): every burn nonce up to T that the thread has not settled
  is set aside. In the marker those nonces now count as settled, so the base and the window move on. **Nobody is
  paid**, no output is created for them, and `liabilities` does not fall: the coins stay in the vault, owed.
- The set of burns set aside and still unpaid is thread state: it is rebuilt by `replay_tx` from the markers of the
  whole thread (`aside_through` adds, `late` removes), exactly as the deposit ledger is. `btc_policy.burn_paid`
  answers "was this burn paid" from the marker and that set; no tool reads the marker alone for it.
- A burn set aside is paid later like any burn, as a **late payment**: the same checks, the same charge, an output
  in the same position rule (ascending nonce), and its nonce in the marker's `late` list (at most four per
  transaction, because each takes 8 of the marker's 80 bytes). It is single-use by consensus like every payment:
  two transactions paying it spend the same thread output, and after the first the replayed set no longer holds it.
- What a signer requires before it signs a set-aside (`btc_signer.py` 4c): T is above this signer's own burn base;
  the proposal names exactly the unsettled burns up to T; each is a burn finalized on the L2 the signer verified;
  and each **cannot be paid in this transaction**: it is a direct burn without a claim on the router, or the fee
  rate of this transaction is above the ceiling its burner named. A burn that can be paid may not be set aside
  (rehearsal K7, L3). A transaction that only sets aside pays no miner charge and is refused by the pool rule, so a
  set-aside always rides with a paying item.
- Who can cause it and what it costs: a relayer could set aside a burn whose ceiling lies between the market and
  the top of the signers' band by proposing a rate above it; that burn is not harmed (it is paid as soon as a
  transaction at or below its ceiling is made), it only moves from the 40-per-transaction queue to the
  4-per-transaction one. Nothing a burner or a relayer does can make another burn wait for it.

Rehearsal K7, K8, L3, L4; unit tests `SetAside` (including a 400-step property test: books, conservation, replay
equality, no burn paid twice).

## 5. Confirmation depth and reorganisations

Rule (`required_confirmations`): a sweep is attestable when it has `max(6, ceil(E / 1 BTC))` confirmations, at most
144, where **E is every sat swept from that block to the tip**. The deposit itself has `sweepDepth` (2) more.

Argument. A reorganisation deep enough to undo one sweep undoes every deposit swept after it, so the value at risk
is the aggregate, not the item: a per-item table can be beaten by splitting. To undo d blocks an attacker must
out-mine the network for d blocks; whatever its hash power costs, it forgoes at least the reward of the d blocks it
orphans if it fails, about 3.125 BTC each plus fees today. Requiring one block per BTC at risk keeps the prize below
a third of that forgone reward at every depth, and six blocks is the floor below which the honest-majority bound
itself is weak. The divisor is fixed in the policy (it is inside the route); after the 2028 halving a new vault
should use 0.5 BTC per block.

Second layer: the L2 token queues every mint for `largeMintDelay` (12 hours, about 72 more blocks) and the guardians
cancel a queued mint that the Bitcoin ledger no longer backs (`btc_reservas.py guard`, rehearsal E7). A credit is
therefore final only about 78 blocks after the sweep, under two independent watchers.

Reorganisation after attestation (rehearsal E): the sweep disappears from every signer's ledger. Then
(a) nobody attests it again; (b) `btc_l2.ledger_prefix_problem` finds a mint on the token that the ledger does not
back, and **every signer holds every attestation and every release** until the guardians have cancelled it; (c) if
the same coins are swept again they get the same nonce, which the stray mint occupies, so the token itself refuses a
second mint. It fails safe: hold, never a second credit. If the stray mint was already credited (a reorganisation
deeper than about 78 blocks with both guardians asleep), the bridge stays held, as the Ethereum bridge does for a
credited forgery, and needs the owner's settlement.

## 6. UTXO management, fees, stuck transactions

- **Consolidation is automatic**: every sweep moves deposits into the single thread output. The vault's UTXO set is
  one output plus not-yet-swept deposits.
- **Miner fees are the users', by a fixed rule.** Every item pays `fee rate x (its own vbytes + the whole fixed
  overhead of 371 vbytes)`: a swept deposit 574 vbytes, a release 402, a refund 605. Because each item pays the whole
  overhead, the items of a transaction always cover its fee: **no transaction lowers the fee pool**
  (`build_vault_tx` refuses one that would), a stray must pay for its own input, and the owner's fees due are never
  part of the pool. Whoever relays cannot spend the pool on miners (rehearsal S2 to S4).
- **Who sets the fee rate.** The relayer proposes it; every signer refuses a rate above 1.5 times its own node's
  estimate, and above the policy ceiling `maxFeerate` (200 sat/vB). The estimate is `estimatesmartfee 2 economical`:
  target and mode are pinned in `btc_signer.py` (`ESTIMATE_TARGET`, `ESTIMATE_MODE`), not left to the node's default,
  which changed between Bitcoin Core releases and can be changed by a start-up option; `economical` follows a falling
  market sooner, and since the band is a ceiling on what users pay, the tighter estimate is the safe side. A mainnet
  signer whose node has no estimate signs nothing, and `btc_signer.py fee-status` reports it (exit 2, an alert line)
  so the operator's monitor sees each such signer before three of them stop the vault. So a relayer cannot make users
  overpay the market (rehearsal I2, N3).
- **The burner bounds its own miner charge.** `BitcoinBurnRouter.burnTo(amount, address, maxFeeRate)` records the
  highest fee rate (sat/vB, 1 to 200) the burner accepts; a direct burn's claim names one too. Every signer reads it
  from the pinned router at the finalized L2 block and refuses to pay the burn in a transaction above it: the burn
  waits (and is set aside if it would hold others, section 4a). The charge of a release is `fee rate x 402`, so a
  burner who names 10 sat/vB pays at most 4,020 sat and knows it before burning; `router.quote(amount, rate)` is the
  vault's own formula. The router refuses a burn whose payout would be dust at the rate it names, so every burn it
  accepts is payable at every rate up to its ceiling. Whoever relays still chooses the moment, but only inside the
  burner's bound (rehearsal L1 to L4).
- **Exits land at any rate up to the ceiling the burner accepts.** A burn has no percentage cap. The token's
  `minBurn` (0.001 BTC) is checked at deployment against the policy ceiling: at 200 sat/vB the smallest burn still
  pays out `100,000 - 50 - 200 x 402 = 19,550 sat` (a burner who does not want that names a lower ceiling and waits).
  Above the 200 ceiling no vault transaction is signed at a higher rate, it is signed at 200 and waits in the
  mempool. Cost at ordinary rates: 5 sat/vB takes 2,010 sat of a release, 20 sat/vB 8,040, 50 sat/vB 20,100.
- **Deposits keep a cap.** A deposit is not swept while its charge exceeds 10% of it (the minimum deposit sweeps up
  to 17 sat/vB); it waits and is refundable meanwhile.
- **Fee pool.** Seeded by the anchor with **exactly** `poolTargetSats` (200,000 sat): `btc_deploy.py vault` refuses
  any other amount and every tool holds on such a vault (`VaultView.load`), because the pool rule only forbids
  falling below `min(pool before, target)`: an anchor above the target could lose the difference to miners once
  (review 325, 2P-6). Charges above the fee paid stay in the thread up to the target; anything above is added to the
  owner's fees due (revenue flows; nothing is burned).
- **Bridge fee**: 5 bps of every deposit and every release, accrued in the marker and paid as an output to the
  owner's address in the next vault transaction once at least `ownerPayoutMinSats` (10,000, far above dust) is due.
- **Stuck release: replace-by-fee.** Every vault transaction signals BIP125. The relayer proposes the same items on
  the same tip at a higher fee rate; signers rebuild and sign it only if it pays more than the pending one and is
  inside their band. The payouts shrink by exactly the rule (rehearsal B5, B6). The replaced transaction can never confirm (B8).
- **Why not CPFP.** The only output the committee could spend is the thread itself, so a child needs the same five
  signatures as a replacement and would chain the vault on an unconfirmed parent. The vault never builds on an
  unconfirmed tip. A recipient is free to CPFP with its own payout.
- A signed transaction that became invalid (a reorganisation removed a deposit it swept) is simply rebuilt on the
  same tip (rehearsal E5).

## 7. The Ethereum vault's limits, translated

| `ProvenanceSourceVault` V3 | bBTC | Enforced by |
|---|---|---|
| `cap` on total locked | `supplyCap` of the token; `capSats` at the sweep | **L2 token** (hard); signers at the sweep |
| Mint bucket, T = 0, 12 h mint delay, guardian cancel, pending cap, 6-of-7 unpause | Same contract, same bytes | **L2 token** |
| Deposit nonce and deposit chain kept by the vault | Sweep order in the thread; the chain is recomputed from Bitcoin (`mint_chain`) | Bitcoin consensus for order; signers and the monitor for the comparison |
| A burn is paid only if its mint chain equals the vault's | The signer compares the burn's `(mintCount, mintedTotal, mintHead)` with the ledger's chain, and requires those deposits final | **Signers** |
| `releasedBurn` (no second payment) | The thread: a second payment conflicts on-chain | **Bitcoin consensus** |
| `windowLimit` per `windowSeconds` | Rolling sum of the releases in the thread's last `windowSeconds`, by block time against the tip's median time past | **Signers** |
| Release delay (`releaseDelay`, 0 at launch) | `largeReleaseSats` / `largeReleaseDelaySeconds`: a large burn waits 12 h from its L2 timestamp | **Signers** |
| Vault guardians pause deposits and releases for 72 h | The token's guardian pause: while `paused()` no signer signs any vault transaction (rehearsal C1). One guardian set, not two | L2 token for mints; **signers** for the vault |
| `minDeposit`, deposit and release fee, immutable `feeRecipient`, `sweepFees()` | `minDepositSats`, `maxDepositSats`, 5 + 5 bps, the owner's address inside the route, paid as an output | **Signers** (and the route binds the values) |
| A release pays the recipient the burn names | Burns go through `BitcoinBurnRouter` (section 9): the destination is a checked P2WPKH address. A burn made directly on the token is paid only to the address its burner claims on the router, never to the 20 bytes it names; there is no timeout | L2 contract for the check and the claim; **signers** for the rule |
| No fee choice for the recipient (gas is the relayer's) | The burner names the highest fee rate its payout may be charged; the burn waits above it | L2 contract records it; **signers** honour it |
| No refund of a deposit (a deposit is credited or reverts) | Refund of any unswept deposit at its L2 recipient's signed request (section 3a) | **Signers** |
| Verifier switch to a light client; `RecoverableReleaseVerifier` | None on the Bitcoin side. The token's mint switch exists in the bytecode and stays unused: there is no Bitcoin mint verifier | - |
| No owner, no setter, no upgrade | The policy hash, keys, anchor and fee address are inside the token's `sourceRoute`; a change is a new vault and a new token | L2 token binding |

What an auditor must accept as signer-enforced: the release window, the large-release delay, the pause on the
Bitcoin side, the mint-chain check, the fee split, the fee-rate band, the burner's fee ceiling, the authorisation of
refunds, the destination of direct burns and which burns are set aside. Each is a deterministic function of the
two chains, so any party can recompute what the signers should have done, and a violation needs five signers. But a
violation is not prevented by any script, and unlike on Ethereum the guardians cannot stop a five-key spend.

## 8. Proof of reserves

`btc_reservas.py check` replays the thread from the anchor and reads the token at the L2 `finalized` block:

```
vault (the thread output)  ==  owed to holders + fees due + fee pool             (pool between 0 and the target)
owed to holders            ==  (L2 supply + finalized unpaid burns + swept-not-yet-minted) x 100 sat
```

Both hold exactly, to the sat, at every point of the rehearsal (A17, E9, F4, K6 to K8, L3, L4). `deficit` if the
vault owes less than supply plus unpaid burns, paid a burn the L2 does not have, or paid a burn anywhere but the key
hash the router burned with (router burn) or the key hash its burner claimed on the router (direct burn): both are L2
state at the finalized block, so every payout's destination is now compared exactly. `held` if the token's mint
chain is not the ledger's, the thread left the rules, or the thread set aside a burn the L2 does not have. `guard`
lists queued mints without a ledger deposit, with the cancel call.

**What is never paid, and where it shows.** A direct burn nobody claims is never paid. Its bBTC has left the L2
supply; its coins stay in the vault. The books still balance because an unpaid burn is still owed: it is inside
`unpaid_burn_units` and `owed_sats`, and the line names it: `unclaimed_direct_burns` (count, units, sats, nonces, and
the sentence why), `set_aside_burns` (every burn set aside and unpaid, with its reason: unclaimed, or the fee ceiling
its burner set) and `set_aside_count`. `btc_relay.py burn status [--nonce N]` shows every finalized burn as `paid`
(with the transaction), `payable`, `waiting-fee-rate` or `unclaimed` (with the 20 bytes that are not paid and the
reason), and totals what is never paid until claimed. The vault therefore holds, by rule and visibly, more than the
L2 supply needs by exactly the unclaimed amount; nobody can take it but its burner, by claiming (rehearsal K6).

## 9. bBTC on the L2: does `BridgedStablecoinV3` fit byte-identical?

Yes, with two consequences that constructor arguments do not cover.

| Point | Finding |
|---|---|
| Decimals | **Not an argument.** `BridgedStablecoinV2`'s constructor passes the literal 6. The byte-identical token therefore has 6 decimals: one unit is 100 sat, 1 bBTC = 1 BTC, smallest amount 0.000001 BTC. Chosen over a copy of the contract with 8 decimals because a copy is new bytecode: a new audit identity, a new DEX gate pin, and a second token line to keep in step. Cost: credits round down to 100 sat (the remainder joins the fee pool) and integrators must read `decimals()`. An 8-decimal variant is one changed literal in a copied V2/V3 pair if the owner prefers it |
| Burn recipient | `burn(uint64, address)` carries any 20 bytes; on bUSDC they are the user's Ethereum address, and here they would be paid as a Bitcoin key hash nobody may hold. So exits go through **`contracts/btc/BitcoinBurnRouter.sol`** (new periphery, no owner, holds nothing): `burnTo(amount, "bc1q…", maxFeeRate)` checks prefix, bech32 checksum, witness version 0 and the 20-byte program, then burns with exactly that program and records the burner's fee ceiling; an Ethereum address string reverts and burns nothing. Signers pin the router's code hash and pay a router burn as named. A burn made **directly** on the token is **never paid to the 20 bytes it names, and there is no timeout** (section 9a): it is paid only after the account that burned calls `claimDirectBurn(nonce, "bc1q…", maxFeeRate)` on the router. Only P2WPKH can be named |
| Issuer blacklist | The token has none (USDC's is on the issuer's own contract). Nothing differs |
| Name, symbol, caps, committee, guardians, delays | Constructor arguments |
| `sourceChainId` | The Bitcoin genesis block hash as an integer (no EVM chain id can collide) |
| `sourceVault` | 20 bytes of the thread script hash; nothing is deployed there |
| `sourceRoute` | Hash of network, script, anchor output, policy hash and the owner's fee script: the token is bound to one vault and one set of rules |
| EIP-712 domain name | The literal "Bloch Bridged Stablecoin". Only the signer daemons sign under it; cosmetic |
| `refillPerSecond` | An integer of units: the slowest refill is 0.0864 BTC a day |

## 9a. Direct burns: claim required, no timeout (review 325, R325-BTC-2P-1)

Round 16 paid an unclaimed direct burn to the 20 bytes it named after three days. Those bytes are unchecked; a
script or contract written for bUSDC passes an Ethereum address there, and the coins would go to a key hash nobody
holds. The rule now:

| Burner | Rule | Why |
|---|---|---|
| An account with a key (no code) | Never paid without a claim. No timeout | It can always claim. Decided by the coordinator |
| A contract | The same: never paid without a claim. No timeout | Decided here; reasons below |

The claim is **a transaction on the L2, not a signature**: `BitcoinBurnRouter.claimDirectBurn(burnNonce, address,
maxFeeRate)`, stored under `msg.sender`, set once. Signers read `claimOf(from, nonce)` on the pinned router at the
finalized block of the L2 they verified, where `from` is the burner in the token's own `Burned` log; a claim made by
anyone else sits under another address and is never read for that burn (rehearsal K3).

Why a transaction and not the signed message of round 16: (1) a contract account (a Safe, a smart account) cannot
sign a personal message but can make a call, so one rule covers both kinds of burner; (2) the claim becomes L2 state
at a finalized block, so all signers see the same claim or none, and the reserves monitor verifies every direct
burn's destination exactly (round 16: "not on either chain"); (3) no off-line intake of signatures by the relayer.
The signed-claim path is removed.

Why no timeout for contracts either (the alternative was to keep the three days for them):
- A timeout pays unchecked bytes. For a contract that passed its own or another Ethereum address, that turns a
  recoverable mistake into a final loss; without a timeout the coins stay in the vault, on the books, and the
  contract (or its owners, through it) can claim at any time.
- The realistic contract burners are accounts that can make arbitrary calls (Safes, smart accounts): they can
  claim. A fixed-logic integration that burns must call the router anyway (cross-area rule of round 16); if one
  calls `token.burn` and cannot call the router, its burn is stuck in the vault, visibly, instead of being paid to
  bytes that are only right if the integration happened to pass a key hash. That case is the cost of this choice.
- "Has code" is not a stable property (a counterfactual account has none until deployed; code can be read at
  different blocks), so a rule that depends on it gives two signers two answers. One rule needs no such test.
- The reason given in round 16 for the timeout, that an unclaimed burn must not hold the marker window, is solved
  where it belongs: such a burn is set aside (section 4a).

What is never paid: a direct burn whose burner never claims. Stated in `burn status`, in the reserves line and in
`bridge.network.json`.

## 10. Rehearsal and tests

`tools/signatario-btc/rehearse_regtest.py`: Bitcoin Core 31.2 regtest with `-acceptnonstdtxn=0` (mainnet relay
policy; release tarball sha256 `2f38996afaa74dfa469a23bf4727887133dfc09784df1f21ddf1c74d0dc82300`, `SHA256SUMS` with
two builders' PGP signatures) and anvil 1.7.1 with the token deployed from the frozen creation code and the router
over it. Seven operators with two throwaway keys each, in separate `cast` keystores (L2 mint key, Bitcoin vault key);
the mint side is the unchanged `signatario.py`. 86 checks:

- S: dust at the thread address from legacy, nested-segwit, segwit and taproot inputs, a fake marker and a coinbase,
  sent first and left there for the whole run; pool-drain attempts.
- A: deposits paid from legacy and nested-segwit inputs, to credit; forged and replayed attestations.
- B: release; a stuck release replaced at a higher fee rate; replayed and forged releases (another recipient, a
  larger amount, a burn that does not exist, four signatures, an outsider's signature refused by Bitcoin itself).
- C: guardian pause; large-release delay; window. D: a deposit double-spent before confirmation.
- E: a reorganisation after attestation. F: a mint forged by five stolen mint keys; strays; proof of reserves.
- I: the fee band and the smallest burn at the highest accepted rate. J: refunds.
- K: the router; a direct burn naming an Ethereum address is not paid, by the relayer or by a hand-made proposal;
  a claim by another account changes nothing; the burner's claim is honoured only once final on the L2; an unclaimed
  direct burn is not paid after four days; `burn status` and the reserves state it; it is set aside by the next
  exit; three weeks later it is claimed and paid late, once; a contract account burns directly, is not paid, claims
  by a call and is paid.
- L: the router refuses a burn that would be dust at its own ceiling; a burn capped at 2 sat/vB is not paid at 5 by
  relayer or signers, is set aside while another exit is paid at 5, cannot be set aside at a rate where it is
  payable, and is paid at 2.
- N: an anchor that is not exactly the target is refused; the router's deployed numbers equal the vault's; the
  fee-status line.
- G: the known limit (five stolen vault keys spend the vault: detected, not prevented).

Unit and property tests: `python3 -m unittest test_btc_policy test_btc_deploy test_btc_signer` in
`tools/signatario-btc/` (parser fuzz, pool invariant, refunds, reviewer 325's demonstrations turned around).
Contract tests: `forge test --offline --match-path solidity-tests/BitcoinBurnRouter.t.sol` (12, one of them a fuzz:
every burn the router accepts pays at least dust at its own ceiling).

## 11. Audit scope note

New Python, standard library only: `btc_core.py` (primitives, 603 lines), `btc_policy.py` (the rules, 404),
`btc_vault.py` (node view and replay), `btc_signer.py`, `btc_half.py`, `btc_l2.py`, `btc_relay.py`,
`btc_reservas.py`, `btc_deploy.py`; tests and the rehearsal beside them. New Solidity:
`contracts/btc/BitcoinBurnRouter.sol`, its test, and a rehearsal helper `solidity-tests/BitcoinRehearsalAccount.sol`
(a contract account; never deployed). Line counts: `wc -l` at the audited commit (the report of each round records
them).

Reused byte-identical: `BridgedStablecoinV3` and its parents (the token); `tools/signatario-stable/signatario.py`
(mint attestation, combine, and the L2 finality and burn decoding that `btc_signer.py` imports: `own_l2`,
`finalized_burn`, the launch pins of `l2_finality.py`); `scripts/btc_observer/rpc.py` (loopback endpoint check and
cookie authentication, from the repository's earlier Bitcoin observation line); the ceremony's `key_inventory.py`
message format. From the earlier UTXO bridge line (wGSMH, `tools/signatario-gnb`) only the pattern was reusable (a
source half behind an argv interface, signing what the signer verified itself): that chain had a consensus vault
with burn markers, which Bitcoin lacks.

Look first at: (1) `build_vault_tx` and `replay_tx`: one transaction per input set, conservation, solvency, the
pool invariant, the marker; (2) `btc_signer.py` checks and that nothing from the proposal is used unverified,
including refund requests and burn claims; (3) the pure-Python secp256k1, DER and BIP143 code (verification and
recovery are in the trust path; signing is test-only); (4) `ledger_prefix_problem` and the reorganisation argument of
section 5; (5) `VaultView._confirmed_tip` and `parse_tx` on hostile input; (6) the charge sizes and their rounding;
(7) `BitcoinBurnRouter.keyHashOf`, `quote` against `release_payout`, and the two mappings the signers read; (8) the
marker's operations byte and the set-aside state in `build_vault_tx` / `replay_tx` (section 4a): that a burn set aside
is never counted as paid, is payable exactly once, and that no encoding of the marker has two readings.

## 12. Known gaps and known issues

1. Five keys move the vault and every unswept deposit (section 1). Not solvable by script on today's Bitcoin.
2. Releases only to P2WPKH.
3. Refund requests are checked by the signers and are not on either chain. Burn claims are now L2 state: the
   reserves monitor compares every payout's destination exactly (router burns and claimed direct burns).
4. Transaction pinning: a recipient can attach a large low-fee child to an unconfirmed payout and make the
   replacement expensive (BIP125 rule 3). It delays one batch; it cannot redirect coins. Version-3 (TRUC)
   transactions would close it and were not tried.
5. No daemon loop for bBTC (`vigia.py` is Ethereum-vault specific), no hint or request intake service, no systemd
   units. `tools/guardiao` is not wired to `btc_reservas.py guard`; the rehearsal casts the votes from its output.
6. The L2 finality path with the launch pins (`l2_source: rebuild`) is reused code but was not exercised here: the
   rehearsal uses anvil's `finalized` tag. A mainnet vault config is refused without the pins.
7. The guardian pause is read from the configured RPC for sweeps and refunds, and additionally from the verified L2
   only when a transaction pays burns (BTC-7 a, part).
8. Every run replays the whole thread and runs `scantxoutset` (about a minute on mainnet, one at a time); no cache
   (BTC-8, part: the stranger-ancestry walk is gone).
9. The sweep takes deposits up to the cap at once while the token mints at most its bucket per refill period, so
   swept coins can wait days for their credit, and one party can fill the cap and the queue for about 0.1% in fees
   (BTC-9). A swept deposit is no longer refundable. The bridge page should show the queue.
10. The marker holds 320 burn nonces above the oldest unsettled one (fewer in a transaction that sets aside or pays
    late). A burn can wait up to 12 h (large) or a day (window) and cannot be set aside for that; burns more than
    320 nonces later wait with it. Burns that wait without bound (unclaimed, under a fee ceiling) are set aside.
11. The fee band was exercised with the regtest node's estimate; a mainnet fee market was not.
12. Round 17 (set-aside, on-chain claim, fee ceiling) has had no independent review yet. Its limits: a
    fixed-logic contract that burns directly and cannot call the router is never paid (section 9a); late payments
    are four per transaction, so a large backlog of burns that were set aside and became payable drains at four per
    vault transaction; a burner who names a fee ceiling the market never returns to waits until it does (the page
    must say so and suggest the current estimate); the claim is set once, so a burner who claims a wrong but
    well-formed address has no second try; every signer verifies each burn it sets aside on its rebuilt L2 (up to
    512 per transaction), not measured at that size.
13. The router is periphery: it can be replaced by a new one (new address, new code hash in every signer config)
    without touching the token or the vault. Claims and fee ceilings recorded in the old router are then not read:
    a replacement needs a migration rule that this line does not have.

## 14. Review 325 (second pass) and what changed in round 17

| Finding | Change |
|---|---|
| R325-BTC-2P-1 Low: an unclaimed direct burn was paid blind after 3 days | Never paid without a claim, for any burner; the claim is a router transaction; no timeout; set aside so it holds nobody (sections 4a, 9a). Rehearsal K2 to K9 |
| R325-BTC-2P-2 Low: a burner could not bound the miner charge | `burnTo` and `claimDirectBurn` take the highest fee rate; signers honour it; the router checks the amount against it (section 6). Rehearsal L1 to L4 |
| R325-BTC-2P-3 Info: estimate mode, signer without an estimate | Mode and target pinned in the signer; `fee-status` alert line (section 6). Rehearsal N3 |
| R325-BTC-2P-5 Info: floating pragma | `pragma solidity 0.8.24;` |
| R325-BTC-2P-6 Info: an anchor above the target | Enforced: deploy tool and every tool require exactly `poolTargetSats` (section 6). Rehearsal N1, N2 |
| Coordinator, round 17: decisions taken from a CLI exit code or from request text passed as an argument (R331-XLM-1 class) | Not present in `tools/signatario-btc`. Hardened anyway: strict in-process parsing of the refund signature; the signed burn claim no longer exists (claims are L2 state). Section 3a; rehearsal J1b |

## 13. Review 325 (first pass) and what changed

| Finding | Change |
|---|---|
| BTC-1 High: a stray from a legacy input stopped every tool | General parser; vault format required only of vault transactions; tip candidates filtered by one lookup; every tool ends in a refusal, never a traceback; rehearsal S and deposits from three input types; parser fuzz |
| BTC-2 Medium: exits froze above 13 sat/vB | No percentage cap on burns; `minBurn` 0.001 BTC checked against the 200 sat/vB ceiling at deployment; numbers in section 6 |
| BTC-3 Medium: the relayer chose the fee rate and could drain the pool | Signers' band of 1.5 times their own estimate; no transaction lowers the pool; strays pay their own input |
| BTC-4 Medium: the cap does not bound the loss; no refund | Stated in section 1; refund rule built (section 3a) for every unswept deposit |
| BTC-5 Medium: a burn naming an Ethereum address was paid to an unspendable key hash | `BitcoinBurnRouter`; direct burns need a claim or wait 3 days |
| BTC-6, -7 b, -8 (walk), -10, -12 | Fixed (reserves compare router payouts; mainnet needs pins; one-lookup filter; `-acceptnonstdtxn=0`; documented) |
| BTC-7 a, -8 (cache), -9 | Partly or not fixed: known issues 7, 8, 9 |
| BTC-11 Info: shared keys | Separate Bitcoin vault keys are the default in templates and rehearsal |
