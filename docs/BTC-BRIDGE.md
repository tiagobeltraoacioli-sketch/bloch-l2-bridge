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
bounds the loss is the L2 token's supply cap (the vault never holds more than the cap plus fees), and what detects a
breach is the public replay of the vault's history (section 8). This is the first thing an auditor and the owner
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

**Which keys.** The coordinator's rule is one committee on every network. The Bitcoin script takes the public keys of
the operators' vault-side (release) keys; the L2 token takes their L2 mint addresses, as for bUSDC. A digest signed
for Bitcoin (double SHA-256 of a BIP143 preimage) cannot be an Ethereum release digest (Keccak of an EIP-191 text),
so one key serving both vaults adds no cross-protocol forgery. It does couple the two vaults' fate: five stolen
release keys empty both. The config takes any seven keys, so the owner can instead have each operator generate a
separate Bitcoin key with the same tool (owner decision 2 in the report).

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
| Dust and bounds | Below `minDepositSats` or above `maxDepositSats` an output is never swept: it stays at the deposit address, which only the committee can spend, and the rules give them no transaction for it. **Not refunded automatically** (gap 3). The maximum equals the token's mint bucket: a larger credit could never be minted, and since the token credits strictly in deposit order it would block every later deposit |
| Replace-by-fee, double spend | Nothing is read from the mempool. A deposit is swept at `sweepDepth` confirmations (rehearsal A2, D1) |
| Sent to the bare vault address | Names nobody. A vault transaction may take it as a stray input; it joins the fee pool (rehearsal F3) |
| Sent to an address computed for another recipient | Credited to that recipient. Not reversible |

## 4. The vault state lives on Bitcoin: the thread

All vault coins sit in one output, the thread. Every vault transaction spends the thread and creates the next one:

```
inputs   [0] thread tip   [1..] deposits swept (sorted by outpoint)   [..] strays at the bare thread script
outputs  [0] new thread   [1] OP_RETURN marker   [2..] one P2WPKH payout per burn, by burn nonce   [last] owner fee
```

The marker (at most 80 bytes) is the vault's state after the transaction: next deposit nonce, the set of paid burn
nonces (a base plus a bitmap of the next 328), sats owed to L2 holders, fee sats due to the owner, and the fee rate
the transaction charged.

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
- **Miner fees are the users', by a fixed rule.** A swept deposit pays `fee rate x (202 + 339) vbytes`; a release
  pays `fee rate x (31 + 339) vbytes` (its own size plus the whole fixed overhead, so the pool can never run dry
  whatever the batch size). An item never pays more than `maxChargeBps` (10%) of itself: above that it waits for
  lower fees. Examples: at 5 sat/vB a deposit pays 2,705 sat and a release 1,850 sat; at 50 sat/vB 27,050 and
  18,500. The fee rate is in the marker, so anyone can recompute every credit and payout.
- **Fee pool.** Charges collected minus fees paid stay in the thread, up to `poolTargetSats`; it pays for
  replacements. Anything above the target is added to the owner's fees due (revenue flows; nothing is burned).
- **Bridge fee**: 5 bps of every deposit and every release, accrued in the marker and paid as an output to the
  owner's address in the next vault transaction once at least `ownerPayoutMinSats` (10,000, far above dust) is due.
- **Stuck release: replace-by-fee.** Every vault transaction signals BIP125. The relayer proposes the same items on
  the same tip at a higher fee rate; signers rebuild and sign it only if it pays more than the pending one and is
  under their ceiling (the larger of a configured 30 sat/vB and three times their own node's estimate, never above the policy's `maxFeerate`). The payouts shrink by exactly
  the rule (rehearsal B5, B6). The replaced transaction can never confirm (B8).
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
| Verifier switch to a light client; `RecoverableReleaseVerifier` | None on the Bitcoin side. The token's mint switch exists in the bytecode and stays unused: there is no Bitcoin mint verifier | - |
| No owner, no setter, no upgrade | The policy hash, keys, anchor and fee address are inside the token's `sourceRoute`; a change is a new vault and a new token | L2 token binding |

What an auditor must accept as signer-enforced: the release window, the large-release delay, the pause on the
Bitcoin side, the mint-chain check, the fee split and the fee-rate ceiling. Each is a deterministic function of the
two chains, so any party can recompute what the signers should have done, and a violation needs five signers. But a
violation is not prevented by any script, and unlike on Ethereum the guardians cannot stop a five-key spend.

## 8. Proof of reserves

`btc_reservas.py check` replays the thread from the anchor and reads the token at the L2 `finalized` block:

```
vault (the thread output)  ==  owed to holders + fees due + fee pool             (pool between 0 and the target)
owed to holders            ==  (L2 supply + finalized unpaid burns + swept-not-yet-minted) x 100 sat
```

Both hold exactly, to the sat, at every point of the rehearsal (A17, E9, F4). `deficit` if the vault owes less than
supply plus unpaid burns or paid a burn the L2 does not have; `held` if the token's mint chain is not the ledger's or
the thread left the rules. `guard` lists queued mints without a ledger deposit, with the cancel call.

## 9. bBTC on the L2: does `BridgedStablecoinV3` fit byte-identical?

Yes, with two consequences that constructor arguments do not cover.

| Point | Finding |
|---|---|
| Decimals | **Not an argument.** `BridgedStablecoinV2`'s constructor passes the literal 6. The byte-identical token therefore has 6 decimals: one unit is 100 sat, 1 bBTC = 1 BTC, smallest amount 0.000001 BTC. Chosen over a copy of the contract with 8 decimals because a copy is new bytecode: a new audit identity, a new DEX gate pin, and a second token line to keep in step. Cost: credits round down to 100 sat (the remainder joins the fee pool) and integrators must read `decimals()`. An 8-decimal variant is one changed literal in a copied V2/V3 pair if the owner prefers it |
| Burn recipient | `burn(uint64, address)` carries 20 bytes. They are read as the witness program of a **P2WPKH** address (`bc1q…`, 42 characters). Taproot, P2WSH and legacy addresses cannot be named. A wrapper contract that carries a full script, committed by its hash160 in those 20 bytes, is possible later without touching the token |
| Issuer blacklist | The token has none (USDC's is on the issuer's own contract). Nothing differs |
| Name, symbol, caps, committee, guardians, delays | Constructor arguments |
| `sourceChainId` | The Bitcoin genesis block hash as an integer (no EVM chain id can collide) |
| `sourceVault` | 20 bytes of the thread script hash; nothing is deployed there |
| `sourceRoute` | Hash of network, script, anchor output, policy hash and the owner's fee script: the token is bound to one vault and one set of rules |
| EIP-712 domain name | The literal "Bloch Bridged Stablecoin". Only the signer daemons sign under it; cosmetic |
| `refillPerSecond` | An integer of units: the slowest refill is 0.0864 BTC a day |

## 10. Rehearsal and tests

`tools/signatario-btc/rehearse_regtest.py`: Bitcoin Core 31.2 regtest (release tarball sha256
`2f38996afaa74dfa469a23bf4727887133dfc09784df1f21ddf1c74d0dc82300`, `SHA256SUMS` with two builders' PGP signatures)
and anvil 1.7.1 with the token deployed from the frozen creation code. Seven throwaway keys in `cast` keystores; the
mint side is the unchanged `signatario.py`. 58 checks: deposit to credit; forged and replayed attestations; release;
a stuck release replaced at a higher fee rate; replayed and forged releases (another recipient, a larger amount, a
burn that does not exist, four signatures, an outsider's signature refused by Bitcoin itself); guardian pause;
large-release delay; window; a deposit double-spent before confirmation; a reorganisation after attestation; a mint
forged by five stolen keys cancelled by the guardians; strays; proof of reserves; and the known limit (five stolen
keys spend the vault: detected, not prevented).

Unit and property tests: `python3 -m unittest test_btc_policy test_btc_deploy` in `tools/signatario-btc/`.

## 11. Audit scope note

New code, all Python, standard library only: `btc_core.py` (primitives, 559 lines), `btc_policy.py` (the rules,
347), `btc_vault.py` (node view and replay, 252), `btc_signer.py` (273), `btc_half.py` (109), `btc_l2.py` (101),
`btc_relay.py` (167), `btc_reservas.py` (131), `btc_deploy.py` (256): 2,195 lines. Tests 403, rehearsal 775.

Reused byte-identical: `BridgedStablecoinV3` and its parents (the token); `tools/signatario-stable/signatario.py`
(mint attestation, combine, and the L2 finality and burn decoding that `btc_signer.py` imports: `own_l2`,
`finalized_burn`, the launch pins of `l2_finality.py`); `scripts/btc_observer/rpc.py` (loopback endpoint check and
cookie authentication, from the repository's earlier Bitcoin observation line); the ceremony's `key_inventory.py`
message format. From the earlier UTXO bridge line (wGSMH, `tools/signatario-gnb`) only the pattern was reusable (a
source half behind an argv interface, signing what the signer verified itself): that chain had a consensus vault
with burn markers, which Bitcoin lacks.

Look first at: (1) `build_vault_tx` and `replay_tx`: one transaction per input set, conservation, solvency, the
marker; (2) `btc_signer.py` checks 1 to 6 and that nothing from the proposal is used unverified; (3) the pure-Python
secp256k1, DER and BIP143 code (verification and recovery are in the trust path; signing is test-only);
(4) `ledger_prefix_problem` and the reorganisation argument of section 5; (5) `VaultView._confirmed_tip` (how the
tip is found and why a stranger's output cannot pose as it); (6) the charge rule's rounding and the pool invariant.

## 12. Known gaps

1. Five keys move the vault (section 1). Not solvable by script on today's Bitcoin.
2. Releases only to P2WPKH (section 9).
3. Deposits outside the bounds are stuck: no refund rule exists. The bridge page must enforce the bounds.
4. Transaction pinning: a recipient can attach a large low-fee child to an unconfirmed payout and make the
   replacement expensive (BIP125 rule 3). It delays one batch; it cannot redirect coins. Version-3 (TRUC)
   transactions would close it and were not tried.
5. `signatario.py` and the relayer are driven by hand or by the rehearsal; there is no daemon loop for bBTC
   (`vigia.py` is Ethereum-vault specific) and no hint intake service. No systemd units.
6. The guardian daemon (`tools/guardiao`) is not wired to `btc_reservas.py guard`; the rehearsal casts the votes
   from its output.
7. The L2 finality path with the launch pins (`l2_source: rebuild`) is reused code but was not exercised here: the
   rehearsal uses anvil's `finalized` tag.
8. `scantxoutset` finds the tip; on mainnet it takes about a minute per call and one call runs at a time.
9. Fee estimation was not exercised (regtest has no estimate; the fixed ceiling applied).
10. No independent review of any of this code.
