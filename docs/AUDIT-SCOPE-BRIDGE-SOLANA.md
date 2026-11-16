# Solana bridge (`bUSDC.sol`): audit scope note

Status: **UNAUDITED. This bridge needs its own external audit before any real funds.** The audit of the Ethereum
bridge (`docs/AUDIT-SCOPE-BRIDGE-V3.md`) does not cover any file listed as new here: the vault is a different
program in a different language on a different runtime.

Branch `codex/bridge-solana-r16-20261116` (from the Ethereum bridge freeze `cc2511a`). Specification:
`docs/SOLANA-VAULT.md`.

## 1. New code

Line counts by `wc -l` on 2026-11-16, refreshed when the Python tools were finished.

| Path | Lines | What | In scope |
|---|---|---|---|
| `solana/bloch-sol-vault/src/processor.rs` | 690 | The eight instructions, account validation, CPI to the token and system programs | Yes, first |
| `solana/bloch-sol-vault/src/cert.rs` | 203 | The certificate check: secp256k1 instruction introspection | Yes, first |
| `solana/bloch-sol-vault/src/state.rs` | 542 | Configuration parsing and validation, the three account layouts, the bucket | Yes |
| `solana/bloch-sol-vault/src/abi.rs` | 219 | Identities and digests in the EVM byte layouts | Yes |
| `solana/bloch-sol-vault/src/error.rs`, `lib.rs` | 61 | Error codes, entrypoint | Yes |
| `contracts/solana/SolanaRecipientRegistry.sol` | 39 | The L2 notice board for burn recipients | Yes (small) |
| `tools/signatario-solana/sol_half.py` | 318 | The source half: what a signer reads on its Solana node before the unchanged `signatario.py` signs a mint or a release | Yes, first among the tools |
| `tools/signatario-solana/solana_lib.py` | 780 | Encodings, addresses, digests, account layouts, legacy transactions, RPC; a second implementation of the program's formulas (the rehearsal runs one against the other) | Yes |
| `tools/signatario-solana/sol_vault.py` | 484 | Owner and operator CLI: validate, init, verify, deposit, approve, execute, pause, controls, unpause, sweep, reserves | Yes |
| `tools/signatario-solana/sol_vigia.py` | 367 | Sign and relay daemon: a subclass of `tools/signatario-stable/vigia.py` (unchanged) with the Solana source side | Yes: the overridden methods |
| `tools/signatario-solana/sol_guardiao.py` | 310 | Guardian watch: a subclass of `tools/guardiao/guardiao.py` (unchanged) with the Solana source side and the vault pause | Yes: the overridden methods |
| `tools/signatario-solana/sol_deploy_token.py` | 251 | The L2 token's deployment path: `tools/deploy-pontes/deploy_pontes.py` (unchanged) with its source reader answered from the Solana vault | Yes |
| `tools/signatario-solana/rehearse_local.py` | 1,067 | The end-to-end rehearsal on a private solana-test-validator and an anvil | Supporting |
| `solana/vault-tests/tests/vault.rs`, `tests/common/mod.rs` | 1,002 and 883 | The SVM test suite and its rig, with encoders written independently of the program | Supporting |
| `solana/test-helper-program/src/lib.rs` | 27 | Test only: a program that accepts anything, and a CPI relay | No (never deployed) |
| `solidity-tests/SolanaRecipientRegistry.t.sol` | 109 | Registry tests | Supporting |

On-chain program total: 1,715 lines of Rust in five files, three direct dependencies (`solana-program` 5.2.0,
`solana-keccak-hasher` 3.1.0, `solana-sha256-hasher` 3.1.0), pinned by `Cargo.lock`.

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
- A threshold above 6 does not fit a transaction without an address lookup table.
- Rent is never returned: deposit and release records are permanent.
- The test suite runs in litesvm on the Agave 4.3 runtime, which does not enforce the 1,232-byte packet limit;
  sizes are computed by the tests, not enforced by them.

- Signers read at `finalized`, which is some seconds behind an approval or a payment. Inside that interval a
  signer can certify a burn whose release is already approved; the vault refuses the duplicate
  (`AlreadyReleased`), and the certificate is for the same release, so nothing can come of it.
- A voided approval can be approved again with the same certificate while it is valid; the mainnet values make the
  pause outlast every certificate, and only the tool (`sol_vault.py validate`) enforces that relation
  (`docs/SOLANA-VAULT.md` section 3.4.1).

## 5. Not in this note

Results of the end-to-end rehearsal on `solana-test-validator` and the reproducibility of the program binary are
reported by agent 322 in `agents/322-bridge-solana-r16.md`, not here. The Python tools have no unit test suite
of their own: they are exercised by the rehearsal only.
