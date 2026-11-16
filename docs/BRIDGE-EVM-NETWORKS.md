# Bridges from Linea, Arbitrum One, Base, OP Mainnet and BNB Smart Chain into the Bloch L2

Round 16, agent 320. Branch `codex/bridge-evm-nets-r16-20261116`, from the Ethereum bridge freeze `cc2511a`.

**UNAUDITED. Nothing is deployed, nothing was sent to any public network, no real key was used.** Each of these
bridges needs its own external audit before real funds. The Ethereum bridge documents stay the reference:
`docs/AUDIT-SCOPE-BRIDGE-V3.md` (design, trust model, known limits), `docs/BRIDGE-V3-KEY-CEREMONY.md`,
`docs/BRIDGE-V3-OPERATOR-RUNBOOK.md`, `docs/BUSDC-MAINNET-V2.md` (deployment sequence). This document states only
what differs per network.

## 1. The model, unchanged

One vault per source network holds the asset; the same set-once committee (7 secp256k1 release keys, threshold 5,
6 of 7 to unpause or switch; 3 pause-only guardians) certifies releases; the same 7 mint keys and 3 token guardians
serve one `BridgedStablecoinV3` per network on the L2 (chain 700770), byte-identical, with its own name, symbol,
supply cap and books. Limits are constructor arguments. No admin key, no recurring signature. A pause, a held
state or a loss on one network cannot touch another network's vault or token: nothing is shared but the keys.

The keys can be shared safely because every digest binds its chain and contract: the vault's release, control,
unpause and switch digests hash `block.chainid` and `address(this)`; the token's EIP-712 domain holds the L2 chain
id and the token address, and its mint chain starts from `(sourceChainId, vault, route)`. A certificate for one
network's vault verifies on no other vault (rehearsal step 7 and `R197`/`A123` of the Ethereum suites).

## 2. Networks and assets

Asset addresses were read on-chain (name, symbol, decimals, proxy slots) on 2026-11-16 and compared with Circle's
own table, https://developers.circle.com/stablecoins/usdc-contract-addresses, the same day. Regenerate every file
under `deployments/<network>/` from `tools/evm-nets/networks.json` with `tools/evm-nets/evm_nets.py write`.

| Network (chain id) | Asset | Decimals | Issuer | L2 token | Vault contract |
|---|---|---|---|---|---|
| Arbitrum One (42161) | USDC `0xaf88d065e77c8cC2239327C5EDb3A432268e5831` | 6 | Circle, native | `bUSDC.arb` | `ProvenanceSourceVault`, byte-identical |
| OP Mainnet (10) | USDC `0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85` | 6 | Circle, native | `bUSDC.op` | byte-identical |
| Linea (59144) | USDC `0x176211869cA2b568f2A7D4EE941E073a821EE1ff` | 6 | Circle, native since 2025-03-26 (upgraded in place) | `bUSDC.linea` | byte-identical |
| Base (8453) | USDC `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913` | 6 | Circle, native | `bUSDC.base` | byte-identical (release timing: section 4) |
| BNB Smart Chain (56) | Binance-Peg USD Coin `0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d` (owner decision, section 6) | 18 | Binance peg token, not Circle | `bUSDC.bnb` | byte-identical, over `ScaledUnitToken` (sections 4 and 6) |

Creation-code keccaks (forge 1.7.1, the repository's `foundry.toml`): `BridgedStablecoinV3`
`0xe560441f37e247e387cebd23bb3dd798a29d34174a9fb19a4bb3877c6c721de7` and `ProvenanceSourceVault`
`0x901d52d04b519c826bfb1e82a298d96ab1f33a1aec5721db55a7f9dfe2ce3a74`, both equal to the Ethereum freeze (the
rehearsal checks them before deploying). `git diff cc2511a -- contracts/usdt contracts/stable contracts/bridged
foundry.toml` is empty.

Token names are at most 31 bytes (one storage word): the L2 allows 5,000,000 gas per transaction and the token's
creation uses about 4.82 M.

## 3. What a signer checks, per network

Measured on the public endpoints on 2026-11-16 (`scratchpad/a320/onchain-chain-params-1.txt`); the networks' own
documentation agrees (sources in the agent report, section 3).

| Network | Block time | `finalized` means | `finalized` behind the head | 256 blocks last | `block.number` / `blockhash` |
|---|---|---|---|---|---|
| Arbitrum One | 0.29 s | the batch is in a finalized Ethereum block | about 19 min (3,985 blocks) | 51 min (256 Ethereum blocks) | **Ethereum block number; `blockhash(n)` is ArbOS's value for that number, not a block hash the RPC serves** |
| OP Mainnet | 2.0 s | the batch is in a finalized Ethereum block | about 21 min (639 blocks) | 512 s | own |
| Base | **0.2 s** (since the Denim upgrade, 2026-11-05) | the batch is in a finalized Ethereum block | about 19 min (5,662 blocks) | **51 s** | own |
| Linea | irregular, 1 to 9 s | the proof was verified on Ethereum and that block is finalized | **about 4.6 h** (docs: median 2 h, at most 16 h) | 4 to 40 min | own (not covered by the proof) |
| BNB Smart Chain | 0.45 s | fast finality: two more blocks voted by two thirds of the validators | 1 to 2 blocks, about 1 s | **115 s** | own |

### 3.1 Deposits: the finality rule

A signer attests a deposit only when its own node of that network reports the deposit's block at or below
`finalized`, the block is canonical by number, the receipt holds the log and the vault recomputes the deposit id
(`eth_half.py deposit`, unchanged). Per network:

- **Arbitrum One, OP Mainnet, Base:** `finalized` is Ethereum finality of the batch that carries the transaction.
  Typical wait 15 to 25 minutes. A sequencer reorganisation before the batch is final cannot be attested.
- **Linea:** `finalized` needs the validity proof on Ethereum and Ethereum finality: hours (4.6 h observed).
  Deposits from Linea therefore credit on the L2 after about 12 h + 2 to 16 h. No shorter rule is offered: before
  the proof, Linea's ordering rests on its sequencer alone.
- **BNB Smart Chain:** `finalized` (fast finality) **and** `finalized_margin` 135 blocks below it, about 61 s. The
  margin puts the deposit also past the 120-block depth the network documents as its probabilistic fallback, so a
  defect or outage of the vote layer on the signer's node alone does not lead to an attestation. Typical wait: about
  one minute.

On every network the 12 h mint delay with guardian cancel stands behind this rule.

### 3.2 Releases: the anchor, and exactly what a signer trusts

`ProvenanceSourceVault.release` requires `blockhash(sourceAnchorNumber) == sourceAnchorHash`: the certificate names
a recent block of the fork it was made on, at most 256 blocks back. On Ethereum the signer names its **finalized**
block (64 to 96 blocks back). **On four of the five networks that rule cannot be applied**: `finalized` is 640 to
5,700 blocks back, outside the window (the fork rehearsal shows the Ethereum rule refusing on each), and on
Arbitrum `blockhash` is not a block hash at all (read on the real network, `scratchpad/a320/onchain-anchor-probe-arbitrum.txt`:
the value differs from the hash of the block with that number). So `eth_half.py` takes an explicit per-network
setting, `anchor_policy`; without it (Ethereum) nothing changes:

- `finalized` (Ethereum; BNB Smart Chain, where the finalized block is 1 to 2 blocks back): the Ethereum rule.
  **On chain 1 `probe` is refused by the code** (`eth_half.py`; review R325-EVM-3), not by convention.
- `probe` (Arbitrum One, OP Mainnet, Base, Linea): the anchor is `block.number - 1 - anchor_depth` and its
  `blockhash` **as the signer's own node's EVM returns them at its head** (`evm_anchor.py`: one `eth_call` of 21
  bytes of creation code; nothing is deployed or sent). A proposed anchor is joined only if that EVM returns exactly
  the proposed hash for the proposed number.

**This is a safety-relevant change and this is its exact extent.**

| | Ethereum rule (`finalized`) | `probe` |
|---|---|---|
| What the anchor proves | the certificate was made on a chain containing that finalized block | the certificate was made on a chain containing that recent, NOT yet final block |
| Trust in the anchor | the signer's node's finality | the signer's node's head (on the rollups: the sequencer's ordering, before the batch is final) |
| If the anchor block is reorganised | cannot happen short of a finality failure | `blockhash` no longer returns the signed value: the vault refuses the certificate (`InvalidContext`), nothing is paid, the next round signs a new anchor |
| What the signer requires to be final before signing | (implicitly) everything at or below the anchor | **explicitly:** the burn final on the Bloch L2 (unchanged), and the vault's deposit chain matching the burn's mint chain **at the source network's `finalized` block** (new read; the Ethereum rule reads the head only) |
| Vault state read at the head (releases enabled, not paused, nonce and burn not released, bucket, `totalLocked`) | head, as on Ethereum | head, as on Ethereum |

What a signer therefore trusts, per network, when it signs a release:

| Network | For "the burn is real and final" | For "the deposits behind it are final" | For the anchor (fork binding only) |
|---|---|---|---|
| Arbitrum One | its Bloch L2 rebuild from L1 (unchanged) | its own Nitro node's `finalized` (the batch in a finalized Ethereum block) | its node's ArbOS `blockhash` for an Ethereum block number 3 back; valid for 256 Ethereum blocks |
| OP Mainnet, Base | unchanged | its own op-node / execution node `finalized` (derived from finalized Ethereum data) | its node's head, i.e. the sequencer's unsafe chain |
| Linea | unchanged | its own node's `finalized` (proof verified on Ethereum and finalized there) | its node's head, i.e. the sequencer's chain; Linea's proof does not cover `blockhash` |
| BNB Smart Chain | unchanged | its own node's `finalized` (fast finality) | the same finalized block |

Why a non-final anchor adds no way to lose funds: the vault itself checks, at execution and on whatever fork the
transaction lands, that the burn's mint chain equals its own deposit chain (`ProvenanceMismatch` otherwise), that the
nonce and burn were not released, and the bucket; none of these depends on the anchor. The anchor only narrows where
a valid certificate can be used. A non-final anchor can only make a certificate **unusable** (liveness), never
usable where it should not be. What it cannot protect against is unchanged from Ethereum: a certificate for a burn
that five signers wrongly believed final on the L2.

One thing is weaker than on Ethereum and is stated plainly: with `finalized` the anchor also told every signer
"your node and the other signers' nodes agree on a finalized block"; with `probe` they agree only on the head. A
signer whose node is on a minority fork of a rollup simply fails to join (its EVM returns another hash).

What stays as on Ethereum: the L2 side, the equivocation database (one release per nonce and per burn, whatever
the anchor), the code pin, the digest recomputed and compared with the vault's.

**Anchor depth per network** (review R325-EVM-4; `networks.json`, each with its reason): Arbitrum One 2 Ethereum
block numbers (24 s of 51 min); OP Mainnet 2 blocks (4 s of 512 s); Linea 2 blocks; Base 5 blocks (1 s of 51 s, 2% of
the window). A change of the sequencer's newest blocks shallower than the depth does not void a certificate.

**Which node gives `finalized`** (review R325-EVM-7): the rule is only as good as the node. On Arbitrum, OP Mainnet
and Base `finalized` must come from the operator's own node deriving the chain from its own Ethereum node (a Nitro
node with its own parent-chain RPC; op-node with op-geth or op-reth and the operator's own L1), and on Linea from
the operator's own node reading the proofs' finalization on its own L1; never from an endpoint run by the sequencer
or shared between operators. On BNB Smart Chain: the operator's own full node.

**Deposits are located through a persisted index** (`deposit_cursor`, review R325-EVM-5): one pass over the vault's
`Deposited` logs is kept on disk with a checkpoint (block number and hash, re-checked on every use; a mismatch
drops the index) and later attestations scan only the new blocks. The index only says where to look; the log, its
block, its receipt and the vault's recomputation of the id are then checked exactly as before. Off for Ethereum.

### 3.3 Reorganisations

- **Before finality:** nothing is attested; signers and relayer read `finalized` only (rehearsal step 2).
- **A deposit disappears after attestation** (a reorganisation deeper than the network's finality, i.e. a failure
  of the source network itself): the mint is queued on the L2 for 12 h; the relayer executes a queued mint only if
  it matches the vault's finalized deposit chain, so it never executes it; the guardians see a mint without a
  deposit and cancel it (2 of 3). If all of that failed and it credited, the mint chain no longer equals the
  deposit chain and the vault refuses every later burn (`ProvenanceMismatch`): the bridge holds, it does not pay
  twice. Rehearsal step 10 removes an attested deposit on each fork: the mint never credits and the guardian raises
  the finding.
- **A release anchor is reorganised** (`probe` networks, a sequencer reorganisation of its unsafe head): the
  certificate is void and nothing is paid; the signers sign again on the new chain. Their equivocation database
  allows it because the release (nonce, burn, amount, recipient) is the same; only the context changes.
- **A release transaction is reorganised away:** `releasedBurn` returns to false with it and the relayer pays again
  (the Ethereum suites' `reorg` mode). It cannot be paid twice on one chain.
- **A certificate older than 256 blocks:** refused (`InvalidContext`), nothing paid, a new round (rehearsal step 4).

## 4. The 256-block window on Base and BNB Smart Chain (measured)

Every network takes the byte-identical vault. Its release certificate must land within 256 blocks of the anchor it
names: 51 minutes on Ethereum, **51 s on Base and 115 s on BNB Smart Chain**. Inside that window five signers must
sign the same anchor and a relayer must land the transaction. A round that misses the window pays nothing and is
repeated; this is liveness only.

Measured with `rehearse_fork.py --measure` (2026-11-16, host 45.77.142.123): a fork of the network making blocks at
its real pace (`--block-time`), the real vault and asset, one burn, then five `vigia.py sign` daemons and one
`vigia.py relay` daemon running as daemons, started out of phase (evenly spread over one interval), `anchor_max_age`
250. "Work" is a wait inserted before each signer's source half, standing in for what a production signer does
before it (`--join-delay`).

| Network | Daemon interval | Work before each signature | Result |
|---|---|---|---|
| Base | 60 s (the Ethereum default) | 0 | paid after 51.1 s: fifth signature 40 s after the first, relayed at 50 s. **No margin**: one second later it would have been refused |
| Base | 5 s | 0 | paid after 10.5 s (five signatures in 4 s) |
| Base | 5 s | 10 s | paid after 57.2 s (fifth signature 45 s after the first). **No margin** |
| Base | 5 s | 20 s | **not paid in 301 s**: four rounds opened, at most three signatures in one before its anchor aged out |
| BNB Smart Chain | 60 s | 0 | paid after 51.1 s (window 112 s) |
| BNB Smart Chain | 5 s, daemons in phase | 0 | paid after 6.3 s |
| BNB Smart Chain | 5 s | 15 s | paid after 83.1 s (fifth signature 65 s after the first; window 112 s) |
| BNB Smart Chain | 5 s | 40 s | **not paid in 401 s**: three rounds opened, none reached five signatures (at most three) before its anchor aged out |

### 4.1 The real work per signature: the L2 rebuild, measured (review R325-EVM-1)

A production signer (`l2_source: rebuild`) runs `bloch-l2-produce-dev reconstruct` over its follower's L1 blocks
before every release signature, then starts a private settled RPC on the result. Measured on 45.77.142.123 on the
follower of round 15's settled full-stack run (real proofs, bridge and DEX transactions; 33,324 L1 blocks, 69
settled L2 blocks, 199 transactions; the rig's own `produce` and `settled-rpc` builds, file cache warm, three
repetitions within 1% of each other), with the follower's index cut to its first k blocks for the smaller sizes
(`scratchpad/a320/host/rebuild/`):

| L1 blocks read | L2 blocks rebuilt | L2 transactions | `reconstruct` |
|---|---|---|---|
| 3,936 | 12 | 94 | 0.22 s |
| 7,936 | 16 | 94 | 0.26 s |
| 15,936 | 23 | 94 | 0.36 s |
| 23,936 | 33 | 119 | 0.51 s |
| 33,324 | 69 | 199 | 0.77 s (5.3 s on the first run, cold cache) |

The private settled RPC then serves the finalized level 0.26 s after start. **Today's history costs about 1 s per
signature. But the rebuild starts from genesis every time, so it grows with the chain, without bound.** Model fitted
to the five points (rough: five points, one machine, one transaction mix):

    reconstruct ≈ 0.16 s + 12 µs per L1 block + 2.7 ms per L2 block + 0.7 ms per L2 transaction   (warm cache)

One year of L1 is 1,051,200 blocks (30 s slots), 12.6 s by itself. Per-signature rebuild after one year:

| L2 activity in the year | Rebuild per signature |
|---|---|
| deposit-only pacing, one L2 block per 30 min (17,520 blocks), 50,000 transactions | about 95 s |
| one L2 block per 5 min (105,120), 500,000 transactions | about 11 min |
| one L2 block per L1 slot (1,051,200), 5 million transactions | about 1.8 h |

A cold file cache multiplied the measured time by 7.

### 4.2 Verdict per network, with numbers

Budget: the window is `anchor_max_age` blocks; a round needs every signer's work, the daemons' polling (5 s
intervals: about 10 s for discovery and relay), and inclusion. Signers on separate hosts work in parallel, so the
round costs about one rebuild; the rig above ran them one after another (five rebuilds), which is the pessimistic
case, for example when operators share infrastructure. Days until the rebuild alone uses the budget, at the
quietest plausible L2 (deposit-only pacing: 0.26 s of rebuild added per day by the model):

| Network | Usable window | Budget per signature: parallel / sequential | Quiet L2: budget used up after (parallel / sequential) | Verdict |
|---|---|---|---|---|
| Ethereum (reference) | 1,920 s (160 blocks) | 1,900 s / 380 s | 20 years / 4 years | works; the same growth applies |
| Arbitrum One | 2,400 s (200 Ethereum blocks) | 2,380 s / 470 s | 25 years / 5 years | **fit**; not shown end to end on a Nitro node (section 12) |
| OP Mainnet | 500 s (250 blocks) | 485 s / 95 s | 5 years / 1 year | **fit for v1**, with the rebuild watched |
| Linea | 250 s at its fastest block pace, more usually | 235 s / 45 s | 2.5 years / 6 months | **fit for v1**, with the rebuild watched |
| BNB Smart Chain | 112 s | 100 s / 20 s | 1 year / 11 weeks | not in v1 (section 6) |
| Base | 50 s | **35 s / 8 s** | **4.5 months / 1 month** | **not launchable with the frozen vault as the signer is today** |

With a busier L2 (one block per 5 minutes, 1.8 s added per day) every figure in the "used up" column shrinks about
sevenfold: Base's parallel budget would be gone in 20 days and OP Mainnet's sequential budget in two months.

**Base.** Today a round lands in 10.5 s with 1 s of real work, so the first releases would work. But the vault is
immutable, the window is 51 s for ever, and the signer's work grows every day: within weeks to months, depending on
L2 activity and on whether the operators' work is really parallel, **no release certificate could be completed and
every exit from Base would stop, for good unless the signer software changes.** That is not a safe margin, so:
**Base is not launchable in v1 with the frozen vault.** What would make it launchable, none of it built here:

1. **A bounded rebuild in the signer** (resume from a verified checkpoint instead of genesis, so the work per
   signature is seconds whatever the chain's age). This is a change to the Ethereum bridge's signer path and to its
   reviewed safety argument (the signer would trust its own earlier rebuild), so it needs its own review. It also
   removes the same slow growth from Ethereum, OP Mainnet and Linea. **This is the fix I recommend.**
2. **Rebuild first, anchor last**: the signer already rebuilds before it chooses or checks an anchor; a daemon that
   keeps a rebuilt view warm (rebuilding continuously in the background and signing from the newest finished one)
   takes the rebuild out of the window without changing what is trusted. Smaller than 1, also signer work.
3. **The parked history vault** (EIP-2935, 8,191 blocks: 27 minutes on Base), as a separately audited code identity.
   It moves the limit from 50 s to 27 minutes but the rebuild still grows; it buys years, not a fix.

With 1 or 2 in place Base's round is the measured 10.5 s against 50 s, a margin of five times.

**For every network, Ethereum included:** the rebuild from genesis is a slow leak in release liveness. It is not
urgent on Ethereum, Arbitrum, OP Mainnet or Linea in the first year of a quiet L2, and it should be bounded before
user transactions make the L2 busy. Operators should alert on the rebuild time (proposed: at one fifth of the
network's budget).

### 4.3 Reading the paced measurements

What this shows and what it does not:

- With the defaults sized for Ethereum (60 s passes) the frozen vault releases on these two networks only by luck
  of phase. **With `--interval 5` and little work per signature it releases reliably** (10 s on Base).
- The rounds fail once the work before each signature reaches tens of seconds (40 s on BNB Smart Chain, 20 s on Base; 10 s on Base
  and 15 s on BNB Smart Chain still landed). In this rig the five signers share one signature directory and its lock, so their work ran
  one after another (45 s for five signatures of 10 s each); in production each operator has its own directory and
  the signatures travel by the feed, so the work runs in parallel but the feed adds its own delay. The rig is
  therefore pessimistic about serialisation and optimistic about transport.
- The real work before a signature is measured in 4.1: about 1 s today, growing with the L2's history.

The variant that removes the limit is **not on this line** (coordinator decision: a new code identity, not accepted
on argument alone). It is parked on branch `codex/bridge-evm-nets-r16-history-vault-20261116`:
`ProvenanceSourceVaultHistory`, generated from the frozen source by a script whose three hunks (18 changed lines)
are the whole difference, with 9 forge tests: when `blockhash` returns zero the anchor is read from the EIP-2935
history contract, 8,191 blocks (27 min on Base, 61 min on BNB Smart Chain). EIP-2935 is live on both networks
today, verified on-chain on 2026-11-16: `0x0000F90827F1C53a10cb7A02335B175320002935` has code on Base, BNB Smart
Chain, OP Mainnet and Linea (the 169-byte system contract; Arbitrum has its own 269-byte implementation) and
answered a query for a block 3,000 back on each (`scratchpad/a320/host/`, and the first-hour readings). Other ways
to stay byte-identical if the rebuild proves slow: an incremental rebuild in the signer (the Ethereum bridge's
tooling, outside this task), or not offering Base and BNB Smart Chain in v1.

## 5. Differences from the Ethereum bridge

| Topic | Ethereum | These networks | Why |
|---|---|---|---|
| Vault bytecode | `ProvenanceSourceVault` | the same bytes on all five | coordinator decision; section 4 for the consequence on Base and BNB Smart Chain |
| L2 token bytecode | `BridgedStablecoinV3` | the same bytes; name, symbol and `sourceChainId` differ | isolation per network |
| Asset | Circle USDC | Circle USDC on four; Binance-Peg USDC through a unit token on BNB Smart Chain | no Circle USDC on BNB; the vault requires 6 decimals |
| Committee | 7 release keys + 3 guardians | the same keys | every digest binds chain id and contract |
| Deposit finality | `finalized` | `finalized` of the network; plus 135 blocks on BNB Smart Chain; hours on Linea | section 3.1 |
| Release anchor | the finalized block | `probe` on four networks; `finalized` on BNB Smart Chain | section 3.2 |
| Provenance read by the signer | at the head | at the head and at `finalized` (with `probe`) | the anchor is no longer final |
| Anchor window (time for five signatures and the relay) | 51 min | 51 min (Arbitrum), 512 s (OP), 4 to 40 min (Linea), **51 s (Base), 115 s (BNB)** | block times; section 4 |
| Daemon interval | 60 s | 60 s (Arbitrum), 20 s (OP, Linea), **5 s (Base, BNB)** | section 4 |
| Fee recipient | `0x775a…0544` | the same address, on each network | owner, 2026-11-16 |
| Limits | cap 100,000, window 10,000 / day, min 11, 5 + 5 bps | the same values proposed; the owner confirms | - |
| Gas payer | ETH | ETH on four, BNB on BNB Smart Chain; rollups add an L1 data fee | section 9 |
| Sequencer | none | Arbitrum, OP, Base and Linea have a single sequencer: it can delay or order deposits and releases, not forge them | - |

Not different: the trust model, T = 0 with the 12 h delay, the mint chain and the held state, the one-way verifier
switch (no verifier exists for these networks; the switch stays unused), every known limit of
`docs/AUDIT-SCOPE-BRIDGE-V3.md` section 6. **Limit 3 there (one vault, one token) now matters more**: five more
vaults and tokens are deployed, and each token must be paired with its own network's vault only. The token's
constructor binds `(sourceChainId, vault, route)` and `deploy_pontes.py` checks the pairing.

## 6. BNB Smart Chain: the asset and the decimals

Circle issues no USDC on BNB Smart Chain (its address table has no entry; read 2026-11-16). The candidates are both
Binance peg tokens with 18 decimals and the same owner address (`getOwner()` = `0xF68a4b64…f62d`): Binance-Peg USD
Coin `0x8AC7…580d` (an upgradeable proxy; supply about 1.19 billion) and Binance-Peg BSC-USD (USDT) `0x55d3…7955`
(not a proxy; supply about 9.18 billion). Their backing is Binance's statement, not the issuer's; Binance's
collateral page could not be read by a script, so the per-token collateral is **not confirmed here**.

**Proposed: Binance-Peg USD Coin, as `bUSDC.bnb`.** Reasons: it keeps one unit of account across the five
networks (every pool on the DEX is USDC against USDC); the name already decided is `bUSDC.bnb`. Against it: it is
upgradeable by Binance and its liquidity is about an eighth of the USDT peg token's. **The alternative, Binance-Peg
USDT as `bUSDT.bnb`, needs only the address, labels and names changed in `networks.json`.** Owner decision, with
the statement to users that this token is a Binance liability, not Circle's.

**Status: NOT IN V1 - OWNER DECISION.** Developer, reviewer and coordinator recommend leaving BNB Smart Chain
out of v1; the owner asked for every network, so the decision is the owner's. The files stay on the branch, marked
(`"v1": false` in `networks.json`, a first note in `deployments/bnb/bridge.network.json` and in the vault config), so
that the option is real.

**Owner brief: what BNB support costs in risk, against leaving it out.**

- *What users would hold.* On every other network bUSDC is backed by the issuer's own USDC in a vault. On BNB it
  would be backed by a wrapper token of ours, which holds Binance-Peg USDC, which is Binance's promise to hold
  USDC somewhere else. Three layers instead of one.
- *Who can break it.* Binance alone: the peg token is an upgradeable proxy with one owner (implementation
  `0xba5fe23f…0b5c`, admin `0xd2f93484…d6c4`, read on-chain). An upgrade, a freeze or a failure of Binance's
  custody takes the backing of `bUSDC.bnb`, and neither the vault, the committee nor the guardians can stop or
  repair it. We could not confirm from a Binance document what collateral stands behind this token today.
- *What it costs to build and run.* One more contract in the money path to audit (the wrapper, 153 lines); a
  second transaction for every withdrawal (`unwrap`), which a page must do for the user and which an exchange
  address or a contract recipient cannot do (those withdrawals would deliver a token nobody recognises); one more
  monitor (`unit_backing.py`); a BNB node per signer; and the second-tightest timing after Base (115 s).
- *What leaving it out costs.* BNB users cannot bridge directly in v1; they can still reach the L2 through any of
  the other networks. Nothing else: the four other bridges do not depend on it, and BNB can be added later without
  touching them, for example when Circle issues USDC there.
- *If the owner wants it anyway:* choose the peg token (USDC keeps one unit of account; USDT has about eight times
  the supply and is not upgradeable), state publicly that `bUSDC.bnb` is a Binance liability, give it a small cap of
  its own, and audit the wrapper first.

**What was fixed so that the option is honest (review R325-EVM-2):** `vault_pontes.py` accepts only the unit token
pinned by address in `networks.json` and refuses every BNB vault config until one is pinned; `evm_nets.py unit-hash`
derives the exact runtime code a `ScaledUnitToken` over this asset must have and `evm_nets.py verify-unit` compares a
deployed one with it, read-only (the rehearsal checks the derivation against a really deployed instance);
`unit_backing.py` reports a deficit behind the wrapper (exit 2; the rehearsal takes one token away and sees it);
`bridge.network.json` tells the page to send `unwrap` for the user and to refuse recipients that cannot.

**The alternative of not launching BNB Smart Chain in v1.** BNB is the only one of the five networks that needs
(a) an asset that is not the issuer's own, (b) new contract code in the money path (`ScaledUnitToken`), (c) a second
transaction for every recipient (`unwrap`) and (d) the tightest timing after Base (section 4). Leaving it out of v1
costs the BNB users' access and nothing else: the other four bridges do not depend on it, and it can be added later
without touching them (isolation). **Both are put to the owner:** launch BNB with one of the two Binance peg tokens
through the unit token after its own audit, or launch four networks and decide BNB when Circle issues USDC there
or when a peg token is judged acceptable. My recommendation: v1 without BNB.

**Decimals.** The frozen vault has `decimals = 6`, counts amounts in `uint64` and its constructor refuses a token
whose `decimals()` is not 6 (shown on the fork and in `R320ScaledUnitToken`). Rather than a second vault with
different arithmetic, the vault holds `contracts/evmnets/ScaledUnitToken.sol`: a 6-decimal token, one unit = exactly
10^12 of the asset, wrap and unwrap by anyone at that fixed rate, no fee, owner, upgrade or pause, every asset
movement checked by balance difference. Amounts below 10^-6 cannot be wrapped, so nothing rounds. Consequences:

- a deposit is one transaction, `wrapAndDeposit(vault, amount, l2Recipient)` on the unit token (the vault records
  the unit token as `sender`; the L2 recipient is what is credited);
- **a release pays unit tokens; the recipient calls `unwrap` to receive the asset** (a second transaction). The
  fee recipient likewise receives unit tokens from `sweepFees` and unwraps;
- the unit token is new code in the money path of this network (153 lines), holding the asset for the vault. If
  Binance reduces its balance (seizure, an upgrade), units are under-backed and the unit token cannot repair it.

## 7. Issuer behaviour and what the vault does

Circle's `FiatToken` (the four USDC networks; `doc/tokendesign.md` of `circlefin/stablecoin-evm`): a `blacklister`
blocks an address from sending and receiving, a `pauser` stops all transfers, an `admin` upgrades the proxy. Run on
each fork against the real contract by impersonating the real role holder (rehearsal step 11):

| Event | What happens | Money |
|---|---|---|
| The release recipient is blacklisted | the release transaction reverts (`InvalidTransfer`); the relayer keeps the burn unpaid; other burns are paid; when the issuer lifts the blacklist the same burn is paid | the tokens were burned on the L2; the asset stays locked for that burn. The burn names its recipient and cannot be redirected |
| The vault is blacklisted | deposits, releases and the fee sweep revert | everything stays locked until the issuer lifts it; no way out exists in the vault (no rescue function, by design) |
| The asset is paused | deposits, releases and the sweep revert; they work again after the unpause | nothing lost |
| The fee recipient is blacklisted | only `sweepFees` reverts | fees stay accrued |
| The proxy is upgraded | the vault notices a transfer that moves another amount than asked (balance differences) and refuses it; it does not notice a change of `decimals` or a new rule that reduces its balance | a shortfall makes deposits, releases and the sweep refuse (`InsufficientBacking`) until the balance covers `totalLocked + feesAccrued` |

BNB Smart Chain: the peg token's owner powers are not documented in a page that could be read; on-chain it is an
upgradeable proxy with a single owner and `paused()` does not exist. Treat it as fully controlled by Binance.

A blacklist of the vault is the worst case and it is the issuer's power on Ethereum too; these bridges add four
more vaults under the same issuer.

## 8. Operator runbook delta

Everything in `docs/BRIDGE-V3-OPERATOR-RUNBOOK.md` applies per network, with one instance of each daemon per
network (own configuration directory, own databases, own shared directory, own gas keys):

1. **A node of each source network per signer operator.** The rule "each operator reads only its own node" holds
   for five more networks: an Arbitrum Nitro node, an OP Mainnet and a Base node (each with an Ethereum node for
   derivation, so that `finalized` is the operator's own view), a Linea node, a BNB Smart Chain node. A shared RPC
   provider across operators would make that provider a common point of failure for attestation. Owner input:
   whether operators run all five or the bridges open one network at a time.
2. **Signer source half:** `deployments/<network>/ops/eth-half.template.json` (generated): `eth_chain_id`,
   `anchor_policy`, `anchor_depth`, `anchor_window`, `anchor_max_age`, `finalized_margin`. Signer and relayer
   templates are the Ethereum ones with `eth_chain_id`, `source_chain_id`, `source_vault`, `source_route`, `token`
   of the network and the same `anchor_policy` / `anchor_window` / `anchor_max_age` keys (`vigia.py` reads them).
3. **Timers.** The Ethereum defaults (60 s passes, anchors up to 160 blocks old) assume a 51 minute window. Per
   network (`networks.json`, generated into `ops/eth-half.template.json`): Arbitrum One: defaults, `anchor_depth` 2,
   `anchor_max_age` 200 (Ethereum block numbers); OP Mainnet and Linea: `vigia.py --interval 20`, `anchor_depth` 0,
   `anchor_max_age` 250; **Base and BNB Smart Chain: `vigia.py --interval 5` for both `sign` and `relay`,
   `anchor_max_age` 250, and section 4's limit on the work before each signature.** A relayer that sends a
   certificate too late pays gas for a revert; nothing else is lost.
4. **Relayer gas:** ETH on the four rollups, BNB on BNB Smart Chain; the 300 gwei ceiling of Ethereum is far above
   these networks' prices: set `eth_max_gas_price_gwei` per network (proposed 5 on the rollups, 10 on BNB Smart
   Chain; owner input). Rollup transactions also pay an L1 data fee that the ceiling does not cover.
5. **Guardians:** one `guardiao.py` per network with that network's vault and token; `vault_from_block` set to the
   vault's deployment block (the daemons scan logs from it; on these networks a scan from 0 never ends).
6. **Reserves monitor:** one bridge entry per network in `reservas.py`'s config; on BNB Smart Chain the vault's
   balance is in unit tokens, and the unit token's own asset balance must be watched too
   (`asset.balanceOf(unitToken) >= unitToken.totalSupply() * 10^12`): **not implemented in `reservas.py`**.
7. **Sequencer outage on a rollup:** deposits and releases wait; nothing to do. **Linea finality stall:** deposits
   wait; releases keep working while the head advances.

## 9. Gas and deployment cost

Gas used on the forks (the same bytecode uses the same gas on every network, up to cold-access differences):

| Action | Gas |
|---|---|
| Vault creation, mainnet shape (7 signers, 3 guardians) | 4,597,955 (4,588,669 on BNB Smart Chain) |
| Unit token creation (BNB Smart Chain only) | about 1.2 M (not measured separately on the fork; 5,379 bytes of creation code) |
| `deposit` | 150,771 (USDC); 154,118 on Linea; 228,330 `wrapAndDeposit` on BNB Smart Chain |
| `release`, 5-of-7 certificate | about 207,000 (194,048 on BNB Smart Chain, 210,245 on Linea) |
| L2 token creation | 4,822,736 to 4,822,796 of the 5,000,000 allowed (checked in every rehearsal) |

Cost of the vault creation at the prices read on 2026-11-16 (execution only):

| Network | Gas price | Execution cost | Extra |
|---|---|---|---|
| Arbitrum One | 0.02 gwei | about 0.00009 ETH | L1 data fee for about 25 kB of calldata, at most about 0.0000015 ETH |
| OP Mainnet | about 0.001 gwei | about 0.000005 ETH | L1 data fee at most about 0.0000004 ETH, plus the operator fee |
| Base | about 0.006 gwei | about 0.00003 ETH | L1 data fee at most about 0.00000025 ETH |
| Linea | 0.24 to 0.3 gwei | about 0.0014 ETH | folded into the price; estimate with `linea_estimateGas` |
| BNB Smart Chain | 0.05 gwei | about 0.0003 BNB for the vault and the unit token | none |

Prices move; the owner funds each deployer with a margin of at least 10 times these figures. Block gas limits
(40 M on OP and Base, 70 M on BNB Smart Chain, far more on Arbitrum and Linea) are above the 4.6 M creation.

**Opcodes.** The frozen bytecode is compiled for Shanghai (`PUSH0`) with solc 0.8.24. All five networks execute
`PUSH0`, `MCOPY` and `TSTORE` today (probed with `eth_call` on 2026-11-16; Linea since its Shanghai fork of
2025-10-23, Arbitrum since ArbOS 11). The vault uses `ecrecover`, `sha256`, `keccak256`, `blockhash`, `chainid`,
`extcodehash`, no `SELFDESTRUCT`, no `PREVRANDAO`, no blob opcode. Network-specific behaviour that matters:
`blockhash` and `block.number` on Arbitrum (section 3.2); `blockhash` on Linea is not covered by its proof (the
anchor is not a safety check, section 3.2); `block.timestamp` is the sequencer's on the rollups (the vault uses it
for certificate expiry, the release bucket and pauses: a sequencer could shift it by its allowed drift, minutes at
most, against windows of hours and days).

## 10. Deployment and ceremony (owner)

Order per network: unit token (BNB Smart Chain only), vault, verify at finality, L2 token, operators, enable.
`$NET` is one of `arbitrum-one`, `base`, `op-mainnet`, `linea`, `bnb`. The committee addresses are the ones of the
Ethereum ceremony (`docs/BRIDGE-V3-KEY-CEREMONY.md` section 8): **no new key ceremony, the same 7 + 3 + 7 + 3
addresses are written into each network's two config files.** A fresh deployer per network (nonce 0, no other
role). Every step below is the Ethereum step of `docs/BUSDC-MAINNET-V2.md` section 4 with this network's files.

Check that the generated files are current:

```
python3 tools/evm-nets/evm_nets.py check
```

Rehearse the network on a local fork first (no key, nothing sent):

```
python3 tools/evm-nets/rehearse_fork.py $NET
```

BNB Smart Chain only, dry run of the unit token (add `--broadcast` and the wallet for the one-way creation), then
write its address into `vault.token` of `deployments/bnb/busdc-vault.config.json`:

```
forge create --rpc-url "$SOURCE_RPC" contracts/evmnets/ScaledUnitToken.sol:ScaledUnitToken --constructor-args 0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d "Bloch bridge unit of Binance-Peg USD Coin" "uUSDC.bnb"
```

Validate the filled vault config against the filled token config:

```
python3 tools/deploy-pontes/vault_pontes.py validate --config deployments/$NET/busdc-vault.config.json --token-config deployments/$NET/busdc-token.config.json
```

Print the constructor arguments and the dry-run command:

```
python3 tools/deploy-pontes/vault_pontes.py args --config deployments/$NET/busdc-vault.config.json
```

Run the printed `forge create` line as printed (a dry run), then once more with the wallet and `--broadcast`. After
the network's finality (section 3.1), verify:

```
python3 tools/deploy-pontes/vault_pontes.py verify --config deployments/$NET/busdc-vault.config.json --rpc "$SOURCE_RPC" --address "$VAULT" --unused
```

Copy the `busdcEthereum` object it prints into `ethereum` of `deployments/$NET/busdc-token.config.json`, then
deploy the L2 token with `deploy_pontes.py` exactly as `docs/BUSDC-MAINNET-V2.md` 4.5 does, with
`--config deployments/$NET/busdc-token.config.json` and `--source-rpc "$SOURCE_RPC"`. Enabling deposits and
releases is 4.7 there, with this network's vault and RPC. Finally fill `TBD-deploy` in
`deployments/$NET/bridge.network.json` (vault, code hash, route, deployment block, token) and check it:

```
python3 tools/evm-nets/network_json.py check deployments/$NET/bridge.network.json
```

## 11. Audit scope note

| Item | Lines | Status |
|---|---|---|
| `contracts/usdt/ProvenanceSourceVault.sol`, `contracts/stable/BridgedStablecoinV3.sol` and bases | 0 changed | byte-identical to the Ethereum freeze; in the Ethereum audit |
| `contracts/evmnets/ScaledUnitToken.sol` | 153 | **new**, in the money path on BNB Smart Chain |
| `tools/signatario-stable/evm_anchor.py` | 39 | new: the anchor probe |
| `tools/signatario-stable/eth_half.py` | +58, -1 | changed: optional `anchor_policy`, `anchor_depth`, `finalized_margin`; without them the frozen path, checks and messages (the Ethereum suites pass unchanged, agent report section 5) |
| `tools/signatario-stable/vigia.py` | +7 | changed: round discovery with the probe, only when `anchor_policy` is `probe` |
| `tools/deploy-pontes/vault_pontes.py`, `deploy_pontes.py` | +48 -11, +7 -1 | changed: source networks from the registry; a chain-1 config is validated as before |
| `tools/evm-nets/` (registry, generator, checker, fork rehearsal, tests) | about 1,300 | new tooling, moves no funds |

What an auditor should look at first: (1) the `probe` anchor: that no path lets a non-final anchor stand in for
finality, and the new read of the deposit chain at `finalized` (section 3.2); (2) `ScaledUnitToken`:
`wrapAndDeposit`, the balance-difference checks, reentrancy through a hostile `vault` argument or a hostile asset;
(3) cross-network replay of every digest with shared keys; (4) Arbitrum's `block.number` (an Ethereum block number)
in the vault's `sourceAnchorNumber >= block.number` check and its ArbOS `blockhash`; (5) the vault's fixed 256-block
window against each network's block time (section 4).

## 12. Not done, not proven

The agent report (`agents/320-bridge-evm-nets-r16.md`, last sections) has the full list. The main ones:

- No run on a real network or public testnet; everything is anvil forks with throwaway keys.
- **Release timing on Base and BNB Smart Chain is not established** for production signers (section 4): the L2
  rebuild time is unmeasured.
- **Arbitrum is still not proven end to end** (review R325-EVM-11). anvil does not reproduce Arbitrum after the
  fork block. Tried on 2026-11-16: a local Nitro node in Docker (`offchainlabs/nitro-node:v3.6.8-d6c96a5`, image
  digest `sha256:0a20cd86…be63`, `--dev`, loopback) with `tools/evm-nets/nitro_release.py`: the frozen vault deploys
  and takes a deposit there, but a `--dev` node has no parent chain, so `block.number` inside the EVM stays 0 and
  `blockhash` returns zero: no anchor can exist and the signer has no `finalized`. The evidence needs a Nitro node
  WITH a parent chain (the multi-container `nitro-testnode`: an L1, a sequencer and a batch poster), which was not
  set up. The script is ready for it. What stands today: read-only probes of the real network, and the fork run.
- Signing rounds were measured with one shared signature directory, without the feed transport and without the L2
  rebuild.
- The Ethereum suites were written for one source network; only the fork rehearsal and `test_evm_nets.py` exercise
  the per-network settings. `reservas.py` does not watch the unit token's own backing on BNB Smart Chain.
- Binance's collateral for the peg tokens and their owner powers were not confirmed from a Binance document.
- No frontend change; no independent review of any of this.
