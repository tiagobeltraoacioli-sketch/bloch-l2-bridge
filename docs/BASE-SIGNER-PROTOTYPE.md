# Base: the signer-side fix, prototype (NOT REVIEWED, NOT ON THE AUDIT LINE)

Round 17, agent 337. Branch `codex/bridge-evm-base-signer-r17-20261117`, on top of the working line of
`codex/bridge-evm-nets-r17-audit-20261117`. **Base stays refused by every tool** (`tools/evm-nets/launch.py`): this
branch changes no launch status, no vault and no contract. It changes the Ethereum bridge's signer
(`tools/signatario-stable/signatario.py`, `vigia.py`) and therefore needs its own adversarial review before it goes
anywhere near a release.

## 1. The problem, in numbers

The frozen vault pays a release only within 256 blocks of the certificate's anchor: about 51 s on Base (49 s to
join). Before each release signature a production signer rebuilds the whole L2 from L1 (`l2_source: rebuild`), from
genesis. Measured on the real L1 mainnet follower store (191,319 L1 blocks, no L2 block yet, pinned `produce`): 3.1 s
with a warm file cache, 21 s on the first run (cold), growing every day. Reviewer 329's paced Base fork, signers one
after another: paid at 31.6 s with 4 s of work per signature, never paid with 12 s or 26 s.

## 2. What the prototype does

1. **The rebuild leaves the round** (`signatario.py warm`, `vigia.py warm`, config key `warm_dir`). A daemon beside the
   signer keeps a full rebuild ready: the same binary, arguments and report checks as a release, made from a snapshot
   of the follower's block index. A manifest records the report, the SHA-256 of the snapshot and its line count, the
   SHA-256 of the produce binary, the arguments and a fingerprint of the rebuilt database.
2. **A release uses that rebuild only after checking it again, against the follower as it is at that moment**
   (`warm_stale`): the produce binary's hash; the arguments; the first N lines of today's index hash to the snapshot's
   (the L1 input the rebuild had is a prefix of today's chain, byte for byte); the report reproduces EVERY finalized
   settlement of today's follower status, hash and state root (`l2_finality.check_rebuild` with the fresh status, the
   same call the full path makes); the database is the one fingerprinted. Nothing a later L1 block finalized is
   taken on trust: a settlement the rebuild does not hold fails the fourth check. On any failure the release is
   refused at once ("warm rebuild not ready": no signature, no hourly slot spent, the round is tried again next
   pass) until the daemon has rebuilt. There is no silent fall-back to an unchecked view, and none to the slow path
   inside a round.
3. **Everything after the rebuild is unchanged**: the private settled RPC serves a private copy of that database
   with a frozen copy of today's status; the burn receipt, its block hash, the finalized level and the settlement
   covering the burn are read and checked by the same code.
4. **Parallel signing over the feed** is what production already does; the paced rig can now run it
   (`rehearse_fork.py --feed`: one signature directory and one `sigfeed.py serve` per signer, no shared directory).

## 3. Measurements (host 45.77.142.123, 2026-11-17; logs in `agents/337-evidence/`)

Work that precedes one release signature, real binaries over copies of real follower stores (`base_tests.py`):

| Store | Full rebuild (today's path) | Warm path |
|---|---|---|
| round-15 settled rig: 33,324 L1 blocks, 69 L2 blocks | 1.64 s (reconstruct 1.11 s); whole run 2.13 s | 0.64 s (checks 0.11 s, the rest is the database copy and the RPC start); whole run 1.14 s |
| L1 mainnet: 191,319 L1 blocks, no L2 block, pinned produce | 21.2 s first run (cold cache), then 3.13 s and 3.08 s | 0.68 to 0.70 s (checks 0.15 to 0.17 s) |

The warm path's cost does not grow with the L1 history except for hashing the index (12 MB today: under 0.1 s) and,
with the L2's state, the fingerprint and copy of the database (2.3 MB on disk today inside a 4 GiB sparse file).

Paced Base fork (0.2 s blocks, the frozen vault, the real USDC, anchor depth 5 and 250 blocks, 5 s passes, the
production hourly budgets, FIVE signers in parallel over the feed and a relayer; before each release signature the
signer really does the pre-signature work over the mainnet store copy; run under the rehearsal chain id 900008453):

| Pre-signature work | Paid after | Largest work per signature | Oldest anchor at a signature | Rounds opened |
|---|---|---|---|---|
| full rebuild, warm file cache | 24.0 s of 50 s | 4.96 s | 11.4 s | 5 |
| warm path (prototype), run 1 | **17.7 s of 50 s** | 1.92 s | 11.2 s | 3 |
| warm path (prototype), run 2 | **17.7 s of 50 s** | 1.89 s | 11.0 s | 3 |

`release-window-budget` (the audit line's alert, at 10 s on Base) fired in every run: the anchor is about 11 s old
when the last signers sign, which is two 5 s passes, not work.

Equivalence and binding, on the round-15 store with its real finalized burn (24 of 24 checks): the intent handed to
the source half (release fields, burn block and hash, finalized block, settlement and finality facts, mint list) is
identical on the full and the warm path; a warm rebuild made when 33 L2 blocks were final is refused once 69 are
(same L1 prefix, later settlements) and a release with it is refused; a changed index line, a shortened index, one
flipped bit in the database, an edited manifest, other arguments, another produce binary and a pointer leaving
`warm_dir` are each refused.

## 4. What this does not show

- **Not one process chain end to end.** In the paced runs the burn is read from the stand-in L2 (an anvil); the real
  rebuild path runs before each signature but does not feed that signature. A release whose burn is read from the
  rebuilt L2 AND paid on a paced Base fork needs an L2 whose token is paired with a vault on that fork (the round-15
  rig could be replayed for it: its vault address, route and two deposits recreated on the fork). Not done.
- The mainnet store has no L2 block: the L2 part of the rebuild is absent from these timings. The longest settled L2
  history on the host is 69 blocks.
- Cold file cache: the daemon's rebuild absorbs it outside the round, but the first signature after a new settlement
  waits for the daemon's rebuild; how long that is with a long L2 history is not measured.
- One host: five signers shared its CPUs and its page cache. No network latency between feeds.
- `warm_db_check: "sizes"` skips the content hash of the database (shown: it misses a bit flip). The default hashes
  the allocated extents.

## 5. What an independent review must check before Base is lifted

1. **The binding argument.** Is "the snapshot index is a prefix of today's index, and the report reproduces every
   finalized settlement of today's status" enough for the cached view to equal what a full rebuild would show for
   every block at or below the finalized level? In particular: can an L1 block AFTER the snapshot change the content
   of an L2 block that the follower already reports as a finalized settlement (forced inclusion, fallback
   sequencing, DA eviction, a re-settlement)? If yes, the fourth check must also compare something of those later
   blocks.
2. **What the index binds.** The index lists block hashes and blocks are files named by hash: does `produce
   reconstruct` verify a block's content against its name? The full path has the same exposure.
3. **Local trust.** The manifest, the pointer and the database are files of the signer's own account, like the
   work directory of the full path between its rebuild and its RPC. Who else can write `warm_dir`? Should the
   manifest be bound to the signer (a MAC) or is file ownership enough?
4. **Time of check, time of use.** The checks run, then the database is copied, then served: a writer between them.
   The status used by the checks is the one frozen for the RPC (the same object): confirm.
5. **Fail-safe paths.** Every failure must end in "no signature": the refusal before the rebuild, the daemon dying,
   a half-written rebuild (the pointer moves by rename only after the manifest exists), a full disk.
6. **Liveness and budgets.** The hourly slot handed back on "warm rebuild not ready"; many signers rebuilding at
   the same moment after each settlement; the interplay with the audit line's hold (`release-window-hold`).
7. **The Ethereum bridge.** With no `warm_dir` the release path must be what it was: `reconstruct()` and
   `check_report()` are the old lines moved into functions; the Ethereum suites must be rerun on this branch.
8. **Then the criterion itself**: one release on a paced Base fork with `l2_source: rebuild`, the burn read from
   the rebuilt L2, five signers on separate hosts.

## 6. Review finding R329-EVM-3P-2 (Medium, round 18, reviewer 379): OPEN on this prototype

`warm_stale` checks only values that the writer of `warm_dir` supplies: the stored `produce` report and a database
fingerprint that any writer can recompute. A writer of `warm_dir` that holds no key can therefore replace the database
the release reads (and the report and fingerprint with it) and every check passes (reviewer's demonstration
`tools/evm-nets/r379_warm_forge.py` on `codex/bridge-evm-nets-review-r18-20261117`). The full-rebuild path of the
audit line does not have this exposure in this form (it rebuilds into its own work directory at every signature).

Consequence: **Base must not be lifted on this prototype.** Fix direction (not built): bind the warm view to the
signing process (a MAC under a credential only the signer's own user can read, over the manifest and a hash of the
exact bytes that will be served, checked on the copy that is served, after the copy), or re-derive the state roots
and block hashes of every finalized settlement from the served database itself instead of from the stored report.
Until one of the two is built and reviewed, the prototype's measurements (section 3) stand only as timing evidence.
