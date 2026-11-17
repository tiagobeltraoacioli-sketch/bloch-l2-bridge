# Solana bridge (`bUSDC.sol`): audit scope note

Status: **UNAUDITED. This bridge needs its own external audit before any real funds.** The audit of the Ethereum
bridge (`docs/AUDIT-SCOPE-BRIDGE-V3.md`) does not cover any file listed as new here: the vault is a different
program in a different language on a different runtime.

Branch `codex/bridge-solana-r16-20261116` (from the Ethereum bridge freeze `cc2511a`). Specification:
`docs/SOLANA-VAULT.md`.

## 1. New code

Line counts by `wc -l` on 2026-11-17, after the changes for review 325 (`agents/325-bridges-review-r16.md`,
section 3).

| Path | Lines | What | In scope |
|---|---|---|---|
| `solana/bloch-sol-vault/src/processor.rs` | 782 | The nine instructions, account validation, CPI to the token and system programs, the paid pages and record closing | Yes, first |
| `solana/bloch-sol-vault/src/cert.rs` | 203 | The certificate check: secp256k1 instruction introspection (unchanged since the review) | Yes, first |
| `solana/bloch-sol-vault/src/state.rs` | 604 | Configuration parsing and validation, the four account layouts, the bucket, paid-page bits | Yes |
| `solana/bloch-sol-vault/src/abi.rs` | 219 | Identities and digests in the EVM byte layouts (unchanged) | Yes |
| `solana/bloch-sol-vault/src/error.rs`, `lib.rs` | 63 | Error codes, entrypoint | Yes |
| `contracts/solana/SolanaBurnRouter.sol` | 123 | The L2 burn router: base58 decoding, the Ed25519 curve test, the commitment, `burnTo` | Yes |
| `contracts/solana/SolanaRecipientRegistry.sol` | 39 | The L2 notice board: how a direct burn's wallet is published | Yes (small) |
| `tools/signatario-solana/sol_half.py` | 395 | The source half: what a signer reads before the unchanged `signatario.py` signs a mint (every endpoint, agreeing) or a release (a wallet known, not stale) | Yes, first among the tools |
| `tools/signatario-solana/sol_recipient.py` | 123 | The recipient rule: which wallet stands behind a burn's 20 bytes | Yes |
| `tools/signatario-solana/solana_lib.py` | 825 | Encodings, addresses, digests, account layouts, legacy transactions, RPC; a second implementation of the program's formulas (the rehearsal runs one against the other) | Yes |
| `tools/signatario-solana/sol_vault.py` | 518 | Owner and operator CLI: validate, init, verify, deposit, approve, execute, close, pause, controls, unpause, sweep, reserves | Yes |
| `tools/signatario-solana/sol_vigia.py` | 402 | Sign and relay daemon: a subclass of `tools/signatario-stable/vigia.py` (unchanged) with the Solana source side | Yes: the overridden methods |
| `tools/signatario-solana/sol_guardiao.py` | 333 | Guardian watch: a subclass of `tools/guardiao/guardiao.py` (unchanged) with the Solana source side and the vault pause | Yes: the overridden methods |
| `tools/signatario-solana/sol_deploy_token.py` | 251 | The L2 token's deployment path: `tools/deploy-pontes/deploy_pontes.py` (unchanged) with its source reader answered from the Solana vault | Yes |
| `tools/signatario-solana/test_solana_tools.py` | 497 | 25 unit tests of the tools against fake RPC servers | Supporting |
| `tools/signatario-solana/rehearse_local.py` | 1,399 | The end-to-end rehearsal on a private solana-test-validator and an anvil | Supporting |
| `solana/vault-tests/tests/vault.rs`, `tests/common/mod.rs` | 1,179 and 926 | The SVM test suite (38 tests) and its rig, with encoders written independently of the program | Supporting |
| `solana/test-helper-program/src/lib.rs` | 27 | Test only: a program that accepts anything, and a CPI relay | No (never deployed) |
| `solidity-tests/SolanaBurnRouter.t.sol`, `SolanaRecipientRegistry.t.sol` | 152 and 109 | Router tests (5) and registry tests (6) | Supporting |

On-chain program total: 1,871 lines of Rust in six files, three direct dependencies (`solana-program` 5.2.0,
`solana-keccak-hasher` 3.1.0, `solana-sha256-hasher` 3.1.0), pinned by `Cargo.lock` (unchanged).

## 2. Reused byte-identical

| What | Evidence |
|---|---|
| `BridgedStablecoinV3` and everything it inherits (the L2 token) | No file under `contracts/stable`, `contracts/bridged` or `contracts/usdt` differs from `cc2511a`. Creation code keccak256 rebuilt in this branch on 2026-11-16: `0xe560441f37e247e387cebd23bb3dd798a29d34174a9fb19a4bb3877c6c721de7`, the pinned launch value |
| `tools/signatario-stable/signatario.py` (the L2 half of the signer: `mint`, `release`, `combine`) | Unchanged; it calls the Solana source half through its existing `eth_half_deposit` and `eth_half_release` argv templates, with `"provenance": true` |
| The release, controls and unpause digests, the route, the deposit id and the mint chain | The Ethereum vault's formulas, word for word, with Solana identities in the address and chain id positions (`docs/SOLANA-VAULT.md` sections 1 and 5) |
| The seven release keys, the seven mint keys and the six guardian keys | The same keys as the Ethereum bridge |

Reuse of the token is by constructor arguments only. What the token does not know: its `sourceVault` is a 20-byte
hash, not a contract, and a burn's `ethRecipient` is a commitment to a Solana wallet. Both are the auditor's to
check against section 3, item 5.

## 3. What an auditor must look at first

1. **`cert.rs`: the secp256k1 verification must be the vault's own.** The native secp256k1 program verifies
   whatever its offsets point at, in any instruction of the transaction. The seven rules of
   `docs/SOLANA-VAULT.md` section 6 are the whole defence: top level only, the real instructions sysvar, the
   previous instruction is the native program with no accounts, one canonical layout with no spare byte, every
   instruction index equal to the instruction's own index and every offset canonical, the message equal to the
   prefix and the authorization the program computed, addresses in the set and strictly ascending. Questions to
   answer: is there any transaction shape in which the native program verifies bytes other than the ones the vault
   reads; can the "previous instruction" be anything but what the runtime executed immediately before; does the
   native program accept a signature form (high `s`, recovery id values) that matters here, given that replay is
   by nonce and not by signature.
2. **Account validation in `processor.rs`.** Every account of every instruction: owner, address (stored or
   derived), layout tag, writable and signer flags. The list is in `docs/SOLANA-VAULT.md` section 2. In
   particular: a look-alike vault state owned by another program; a vault-tagged account at an address the
   configuration does not derive; a token account of another mint; the token program replaced by another program;
   the recipient token account (must be the associated account of the wallet that hashes to the commitment, with
   that wallet as owner); the fee token account; the deposit record given for provenance.
3. **The program-derived account helper (`create_pda`)** and its use for the vault, its token account, deposit
   records and release records: an address that already holds lamports, a target not owned by the System program,
   and the branch in `approve_release` that reuses an existing release record (only an approval voided by a pause
   may be overwritten).
4. **Arithmetic and accounting.** `u64` amounts with `u128` intermediates; overflow checks are on in the release
   profile. The invariant: the vault's token balance is at least `total_locked + fees_accrued` before and after
   every instruction; a deposit locks its net amount; a release unlocks the full burned amount and pays it less
   the fee; the bucket never exceeds its capacity; exact balance deltas are required around every transfer.
5. **The commitment scheme.** The burn recipient is `keccak256("BLOCH-SVM-ACCOUNT-ID-v1" || wallet)[12..]`,
   160 bits. Paying another wallet needs a second preimage. A collision between two wallets of the same party
   gives that party nothing. The registry is not trusted. Also: the same 20-byte function is the depositor identity
   inside the deposit id.
6. **Pause, voiding and the delay.** The pause chain logic mirrors the Ethereum vault. New: `void_through_seq`
   and `approval_seq`. Can an approval be paid after it was voided; can a voided approval be replaced by anything
   the committee did not certify; can a guardian's single authorization be used twice.
7. **`initialize`.** Permissionless and configuration-addressed. Is there any second encoding of the same
   configuration, or any configuration value that is not in the hashed bytes; the finality check on the program
   data account; the mint checks.
8. **The source half (`sol_half.py`)**: what a signer reads before it signs a mint or a release, at which
   commitment, and what it does when the node lags or disagrees.
10. **What review 325 changed** (each with its tests in `vault.rs`, at the end of the file, and in the
   rehearsal). (a) `approve_release` refuses a certificate with `valid_until <= last_pause_at +
   max_valid_seconds`: is there any way to approve, after a guardian pause, with a certificate that existed before
   it; does the rule rest on anything but the vault's own state and the signers' bound on `valid_until`. (b) Paid
   pages and `close_release`: the replay state of a nonce is now "a record exists" OR "its bit is set"; can a nonce
   be in neither state after it was paid (the close sets the bit before it empties the record, in one
   instruction); can a record be closed that is not paid, or before the retention, or its rent sent elsewhere; can
   a page be substituted, or a closed record's address be reused. (c) `deposit` with candidate records: can a
   depositor make the program write a record at an address other than the one of the count it found, or touch a
   candidate it did not use. (d) `SolanaBurnRouter`: the base58 decoder (canonical form, overflow), the curve
   test (it must agree with the runtime's own decision for every 32 bytes: the tests compare it with
   `solana_lib.on_curve`, which the rehearsal runs against the validator in every address derivation), and
   whether any input lets `burnTo` burn towards 20 bytes that are not the commitment of the decoded wallet.
9. **The two subclasses and the deployment wrapper.** `sol_vigia.py` and `sol_guardiao.py` inherit from modules
   written for an Ethereum source and replace the methods that read it; `sol_deploy_token.py` replaces
   `deploy_pontes.py`'s source reader and one policy constant inside its own process. Question: is there a parent
   code path that still reaches `eth_rpc`, an Ethereum log scan or the Ethereum finished-item cache for this
   bridge (the rehearsal configs carry no `eth_rpc` at all, so such a path fails rather than reading a wrong chain,
   but only the paths the rehearsal took are shown). The signature feed (`bridge_feed.py`) was not run over this
   bridge.

## 4. Known limits (decided, not defects to rediscover)

- No light-client path and no committee retirement on this vault. Succession is a migration to a new vault.
- Five release keys can approve a release for a burn that never happened, up to the bucket (10,000 USDC, then
  10,000 a day), as on Ethereum. The delay for large releases and the pause that voids approvals give the guardians
  a window for releases above the threshold only.
- One replay key (the burn nonce), where the Ethereum vault has two (nonce and burn id).
- The certificate's source anchor (slot and hash) is signed but not compared with chain history; a certificate's
  life is bounded by `max_valid_seconds`.
- A forged release that uses a future burn nonce makes that honest burn unpayable, as on Ethereum
  (`releasedNonce`).
- The issuer's freeze authority can stop the vault's token account.
- A credited mint with no deposit holds every later exit, and the Ethereum bridge's held-state settlement is not
  ported.
- A threshold above 5 does not fit a transaction without an address lookup table (1,151 bytes at 5 with the paid
  page account).
- A deposit record's rent is never returned (it is the canonical record of the deposit and is never closed). A
  release record's rent returns when the record is closed after `record_retention`; from then on only the nonce's
  paid bit remains, so its amount and recipient can no longer be read from state.
- The test suite runs in litesvm on the Agave 4.3 runtime, which does not enforce the 1,232-byte packet limit;
  sizes are computed by the tests, not enforced by them.

- Signers read at `finalized`, which is some seconds behind an approval or a payment. Inside that interval a
  signer can certify a burn whose release is already approved; the vault refuses the duplicate
  (`AlreadyReleased`), and the certificate is for the same release, so nothing can come of it.
- A burn made directly on the L2 token whose 20 bytes are not the commitment of a wallet (an Ethereum address, a
  token account's commitment) is held for good: the signers do not certify it and nothing is paid. There is no
  refund path: it needs a release whose recipient differs from the burn's, which the unchanged L2 half of the
  signer refuses to sign (`docs/SOLANA-VAULT.md` 11.1).
- The router's curve test refuses program-derived wallets (multisig vaults) and cannot tell whether anyone holds
  the key of an on-curve address. Since review 330 the router also refuses the small-order points, the route's
  mint and three program ids, and every signer holds a burn whose destination is, on Solana at `finalized`, not
  absent and not a plain System account. What remains (stated in `docs/SOLANA-VAULT.md` 11.5): an on-curve
  address nobody holds a key for, absent from the chain or merely funded, cannot be told from a fresh wallet;
  only the page's wallet signature (11.3) covers it, and only for exits made through the page.
- A held exit (no wallet, or a destination that is not a wallet) has no refund path.
- The retention floor, the cluster rule for `rehearsal` and the fee-account gate are tool-side: the program image
  is unchanged (`33f7027d…7316`) and still accepts `record_retention` 0 and pays any 32 bytes that hash to an
  approved burn.
- After a guardian pause ended early by 6 of 7, release signing waits until a certificate dated now can no longer
  predate the pause (`max_valid_seconds` less the certificate life after the pause began).
- Mint signing requires at least two Solana endpoints that agree; nothing in the tool can check that two endpoints
  are independent.

## 4.1 Round 17 additions (review 330), for the auditor

| Path | What | In scope |
|---|---|---|
| `contracts/solana/SolanaBurnRouter.sol` | Constructor gains the SPL mint; `walletOf` refuses small-order points, the mint, three program ids | Yes |
| `tools/signatario-solana/sol_recipient.py` | `destination` (the read at `finalized`), `burn_status`, the fixed list | Yes, first among the tools with `sol_half.py` |
| `tools/signatario-solana/solana_lib.py` | `rehearsal` (cluster rule), `retention_floor`, `small_order`, `ed25519_verify`, `secp256k1_recover` (pure Python, verification only) | Yes: two signature verifiers are new cryptographic code |
| `tools/signatario-solana/sol_proof.py` | Offline key proofs: the fee owner's, and the reference for the page's destination proof | Yes |
| `tools/signatario-solana/sol_vault.py` | `init` gates (fee account, proof, policy), `fee-account`, `burn-status`, `reserves` with held burns, in-process signature checks | Yes |
| `tools/signatario-solana/sol_vigia.py`, `sol_guardiao.py` | Holds and alerts; partials verified in process; the watch interval rule | Yes: the overridden methods |
| `tools/signatario-solana/test_r330_review.py`, `test_untrusted_inputs.py`, `solidity-tests/R330SolanaBurnRouter.t.sol`, `solana/vault-tests/tests/r330_review.rs` | Regression and attack tests | Supporting |

No signature decides anything in the Solana tools through another program's exit code any more: committee and
guardian signatures are recovered in process (`secp256k1_recover`), key proofs are verified in process
(`ed25519_verify`), from strictly parsed bytes. The parents `vigia.py`, `guardiao.py` and `signatario.py` are
byte-identical to `cc2511a` and still call `cast wallet verify` on values they have matched against a fixed-length
hexadecimal pattern (`vigia.py`) or that come from the operator's own source half (`signatario.py`).

## 4.2 Round 17 second half and round 18 additions (agents 336, 371), for the auditor

| Path | What | In scope |
|---|---|---|
| `contracts/solana/SolanaBurnRouter.sol` | `burnTo(amount, recipient, nonce, proof)` (proof shape, per-caller nonce, `exitHash`), `redirectHeldBurn`, `exitMessage` / `redirectMessage` views (the line the destination key signs); creation keccak `0xb6ce6ba3…bea4` | Yes, first: the text the router builds must equal `sol_proof.exit_message` byte for byte |
| `tools/signatario-solana/sol_recipient.py` | `exit_view` (router logs: exit and redirects), `decide` (the rule, latch), `Holds`, `check_router` and `router_runtime_pin` | Yes, first among the tools |
| `tools/signatario-solana/sol_proof.py` | exit / redirect lines, `covered_bytes` (three envelopes), `exit_proof_valid`; fee proof with route, genesis hash, date, 30-day limit | Yes |
| `tools/signatario-solana/sol_half.py` | the rule before signing, redirected partials written by the half, equivocation record across redirects, `release-hold` | Yes |
| `tools/signatario-solana/sol_vigia.py` | redirect rounds (sign and relay), relayer latch, `approved-without-wallet` | Yes |
| `tools/signatario-solana/sol_guardiao.py` | recipient verdict on every approval and payment; `judged_recipient` (round 18: a blind round judges nothing and caches nothing) | Yes |
| `tools/signatario-solana/sol_vault.py` | `approve` always applies the rule; `init` creates the fee account; `router-pin` | Yes |
| `deployments/solana/exit-proof-vectors.json`, `test_exit_rule.py`, `testkit.py`, `solidity-tests/SolanaExitProof.t.sol` | vectors and tests | Supporting |

The registry (`SolanaRecipientRegistry.sol`) and operator hint files are no longer read by any tool.

## 5. Not in this note

Results of the end-to-end rehearsal on `solana-test-validator` and the reproducibility of the program binary are
reported by agent 322 in `agents/322-bridge-solana-r16.md`, by the reviewers in section 3 of
`agents/325-bridges-review-r16.md` and in `agents/330-bridge-solana-review-r17.md`, and for the round-17 line by
agent 336 in `agents/336-bridge-solana-r17.md`, not here. The line counts of section 1 are those of round 16; the
files changed in round 17 are listed in section 4.1.
