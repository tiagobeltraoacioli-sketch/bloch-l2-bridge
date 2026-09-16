# Local release reconciliation

`scripts/usdt_observer/reconciliation.py` is a separate local observation state
machine. It contains no signing, broadcasting, RPC, key storage or payment API.
It does not reserve funds. Every report keeps payment authorization, native
release authentication, finality, settlement and bridge readiness false.
Transaction/evidence hashes are audit labels, not authenticated evidence.

`register(path, route, expected)` binds immutable normalized release facts to
native domain plus burn, with a second unique constraint on route plus nonce.
Exact registrations are idempotent. Changed recipient, amount, asset or route is
refused; an unavailable result never frees either identity.

`transition` takes the expected revision, a 32-byte operation ID, destination
status and optional transaction/evidence hashes. It records history and updates
the current state in one SQLite transaction. Exact operation retries return the
current state, even if later operations have already completed. Reusing an
operation ID with different arguments fails. Competing revisions cannot both win.

States are `pending_evidence`, `reconciling`, `observed`, `unavailable`, `conflict`
and `frozen`. Reconciling may supersede an earlier reconciliation. Observed and
unavailable can start another reconciliation; conflicts can only freeze, and
frozen is terminal. There is no settled state. A crash can leave reconciling;
a timeout belongs in unavailable, retaining the identity and all history.
Reorganizations require fresh reconciliation or freezing, never deletion or
creation of a replacement claim. This module does not autonomously detect them.

Use a private operator directory. Storage checks owner, permissions, file type,
link count and size; transactions use synchronous FULL and a bounded page count.
Claims and history each have bounded capacity. A failed first initialization
leaves a file that is refused rather than silently reset. Existing observation
journals and tracking databases are refused, never migrated. Local rollback,
operator compromise, concurrent directory substitution and deletion are not
prevented by this database. It does not coordinate independent operator databases.

## Future authenticated settlement interface

Do not extend transition with `authorized=True`, import report flags, or treat
`observed` as permission. A future settlement executor needs a private verified
burn type constructed by the native consensus verifier against an authenticated,
current checkpoint and policy. It must bind native domain/asset, source route,
nonce, amount, recipient and burn identity. Serialized objects must be reverified;
a Python dictionary, saved audit or attestation flag cannot instantiate authority.

Source verification must independently authenticate the configured chain, vault
runtime/configuration, payout/nullifiers and acceptable finality. A durable
execution layer must atomically reserve the verified obligation with an outbox,
then distinguish prepared, broadcast-uncertain, included, finalized and frozen
states. Retries must reconcile the same release identity before any rebroadcast.
Cross-chain execution is not an atomic database transaction. Reorgs, lost responses
and fee replacement must never create a second obligation. Final payout recognition
must consume the obligation once. None of these interfaces is implemented here.

The source vault's nonce and burn nullifiers protect one contract deployment;
relaunching another vault does not migrate them. Committee trust, immutable signer
availability and external token freeze/blacklist behavior remain custody limits.

## BTC and SOL boundaries

BTC currently has transaction/proof inspection, local Core assessment, regtest
coverage and revisioned reorg observations. These do not establish custody,
source spending policy, authenticated native mint/burn or redemption execution.
Bitcoin confirmation depth remains a policy with reorg risk, not deterministic
finality. A future BTC executor must bind outpoint identity independently of its
current containing block and reconcile replacement/conflicting spending attempts.

No SOL custody/settlement adapter is implemented. It requires explicit cluster
identity, finalized account/transaction verification, controlled custody accounts,
recipient binding and replay protection. SPL and Token-2022 policy handling is
also unimplemented. Asset display symbols such as bBTC or bSOL confer no backing.

## Validation

Run `python3 -m unittest discover -s scripts/tests -p test_reconciliation.py -v`.
Tests cover competing workers, exact and conflicting retries, stale completions,
restart during reconciliation, identity conflicts after uncertainty, observation
invalidation followed by freezing, and refusal of authority flags as API inputs.

First initialization has a deliberate fail-closed window between exclusive file
creation and schema commit. Another caller during that window may receive a
foreign/uninitialized database refusal; retry after the creator commits is safe
and idempotent. If the creator is interrupted before schema commit, the remaining
uninitialized file continues to be refused; ordinary retries do not recreate it.
Initialization-race and interruption tests pin this behavior without silently
repairing operator storage.
