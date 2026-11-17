# Solana vault of the Bloch L2 bridge (`bUSDC.sol`): specification

Status: **UNAUDITED. Nothing is deployed. Not for real funds before its own external audit.**

Program source: `solana/bloch-sol-vault/` (native Rust, `solana-program` 5.2.0). This document describes the code
at commit `e4d9018` of branch `codex/bridge-solana-r16-20261116`; where the code and this text differ, the code is
right and this text is the defect.

The vault is the Solana port of `ProvenanceSourceVault` (`contracts/usdt/ProvenanceSourceVault.sol`) in its launch
configuration: committee mode, provenance mode 1. A program-owned classic SPL token account holds the deposited
USDC. A release is paid only on a threshold of the committee's secp256k1 signatures, over the same digest the
Ethereum vault uses, verified by Solana's native secp256k1 program. Signers, thresholds, guardians, limits, fees
and the fee recipient are fixed when a vault is initialized. The program has no owner, no setter, and no
instruction that changes any of them. On the L2 the token is `BridgedStablecoinV3`, byte-identical, with other
constructor arguments (section 11).

## 1. Identities

The EVM-shaped messages of the bridge (deposit id, route, mint chain, release digest) carry 20-byte addresses and
a `uint256` chain id. Solana values are mapped into them as follows. `keccak256` is Ethereum's; `||` is
concatenation of raw bytes; `[12..]` is the last 20 bytes.

| Value | Definition | Used as |
|---|---|---|
| `id20(domain, parts)` | `keccak256(domain || part0 || part1 ...)[12..]` | the Ethereum address rule on a tagged preimage |
| `vault20` | `id20("BLOCH-SVM-VAULT-ID-v1", program id, vault address)` | `address(this)` of the Ethereum formulas; the token's `sourceVault` |
| `mint20` | `id20("BLOCH-SVM-MINT-ID-v1", mint address)` | `token` in `routeId()` |
| account id of a wallet | `id20("BLOCH-SVM-ACCOUNT-ID-v1", wallet address)` | `sender` in the deposit id; the burn recipient commitment |
| source chain id | `keccak256("BLOCH-SVM-CHAIN-ID-v1" || the 32 raw bytes of the cluster genesis hash)`, read as a big-endian `uint256` | `block.chainid` of the Ethereum formulas; the token's `sourceChainId` |

The program cannot read the genesis hash. The source chain id is a configuration value; the tools derive it from
the genesis hash that the operator's own node reports and refuse a node that reports another one. For
mainnet-beta (genesis hash `5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d`, read from the public RPC with
`getGenesisHash` on 2026-11-16) the value is:

```
0x720ef12f64972f1d7a826f17e9d177f041fbca3173c9bce00aa50eac2c22fdec
51590065195979758212148511635863778762156068118565365102773110171893804236268
```

The same seven release keys sign for the Ethereum vault and for this one. A certificate of one cannot be used on
the other, because every digest contains the chain id and the vault identity, and neither can coincide: this
chain id is a 256-bit hash, and `vault20` is a hash that contains the program id and the vault address.

## 2. Accounts and program-derived addresses

| Account | Seeds (under the vault program) | Owner | Size | Created by | Closed |
|---|---|---|---|---|---|
| Vault state | `"vault"`, `sha256("BLOCH-SVM-VAULT-CONFIG-v1" || configuration bytes)` | the program | 1,146 | `initialize` (payer pays rent) | never |
| Vault token account | `"tokens"`, vault address | the classic SPL Token program; token authority = the vault address | 165 | `initialize` | never |
| Deposit record | `"deposit"`, vault address, nonce (u64 little-endian) | the program | 211 | `deposit` (the depositor pays rent) | never |
| Release record | `"release"`, vault address, burn nonce (u64 little-endian) | the program | 208 | `approve_release` (the relayer pays rent) | by `close_release`, once paid for `record_retention`; the rent returns to who paid it |
| Paid page | `"paid"`, vault address, page number = burn nonce / 8,192 (u64 little-endian) | the program | 1,067 | `approve_release`, by the first approval in its range | never |

The vault address is a function of the whole configuration. A vault with any other value (another signer, another
limit, another fee owner) is another vault at another address. `initialize` is therefore permissionless: the only
vault that can exist at an address is the one with exactly that configuration, and nobody can take the address
first with other values. No authority is recorded anywhere.

Fixed program ids the program compares against: classic SPL Token `TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA`,
Associated Token Account `ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL`, System
`11111111111111111111111111111111`, upgradeable loader `BPFLoaderUpgradeab1e11111111111111111111111`, native
secp256k1 `KeccakSecp256k11111111111111111111111111111`.

Every program-derived account is created through one helper (`create_pda`). An address that already holds
lamports (anyone can send some, which makes a plain `CreateAccount` fail) is topped up to the rent-exempt minimum,
allocated and assigned instead. The helper requires the target to be owned by the System program and empty.

### Account validation, per kind

- **Vault state**: owned by the program, writable, length 1,146, tag 1, layout version 2, and its address equals
  `create_program_address("vault", stored config hash, stored bump)`.
- **Vault token account**: its address equals the one stored in the vault state; owned by the token program;
  165 bytes; initialized.
- **Mint**: its address equals the configured mint; owned by the token program. At `initialize` also 82 bytes,
  6 decimals, initialized.
- **Token program**: the classic SPL Token program id, nothing else.
- **Depositor token account**: owned by the token program, 165 bytes, initialized, its mint field equals the
  configured mint, and it is not the vault token account. The token program itself enforces that the signer is its
  owner or delegate.
- **Deposit record (when read for provenance)**: owned by the program, tag 2, its address equals
  `create_program_address("deposit", vault, nonce, stored bump)`, and its stored vault and nonce match.
- **Release record**: at approval its address equals `find_program_address("release", vault, nonce)`; at payment it
  is owned by the program, tag 3, its address is rederived from its stored bump, and its stored vault and nonce
  match.
- **Paid page**: at approval its address equals `find_program_address("paid", vault, nonce / 8192)`; if it exists it
  is owned by the program, 1,067 bytes, tag 4, and its stored vault and page number match; if it does not, the
  approval creates it. At `close_release` it must exist, with the same checks and its address rederived from its
  stored bump.
- **Recipient token account**: equals the associated token account of the named wallet and the configured mint;
  owned by the token program, initialized; its mint and owner fields equal the mint and the wallet.
- **Fee token account**: equals the address stored at initialization (the fee owner's associated token account);
  its mint and owner fields equal the mint and the fee owner.
- **Instructions sysvar**: its address is the sysvar's (checked by `load_current_index_checked` and
  `load_instruction_at_checked`).
- **Program data account (at `initialize`)**: equals `find_program_address(program id)` under the upgradeable
  loader, is owned by that loader, starts with the `ProgramData` tag, and has no upgrade authority.

## 3. Instructions

The first data byte selects the instruction. Integers are little-endian. Every instruction requires its exact
number of accounts (`deposit`: 8 to 15) and refuses trailing data.

| # | Instruction | Accounts, in order | Data after the first byte |
|---|---|---|---|
| 0 | `initialize` | payer (signer, writable); vault (writable); vault token account (writable); mint; program data account; token program; system program | the configuration (section 4.1) |
| 1 | `deposit` | depositor (signer, writable); depositor token account (writable); vault (writable); vault token account (writable); mint; deposit record (writable); token program; system program; then up to 7 more candidate deposit records (writable) | amount u64; L2 recipient (20 bytes) |
| 2 | `approve_release` | payer (signer, writable); vault (writable); release record (writable); deposit record of nonce `mint_count - 1`; paid page of the nonce (writable); instructions sysvar; system program | nonce u64; recipient (20); amount u64; native burn (32); mint count u64; minted total u64; mint head (32); valid until u64; source anchor slot u64; source anchor hash (32); native finalized number u64; native finalized hash (32). 204 bytes |
| 3 | `execute_release` | vault (writable); vault token account (writable); mint; release record (writable); recipient token account (writable); token program | nonce u64; recipient wallet address (32) |
| 4 | `guardian_pause` | vault (writable); instructions sysvar | valid until u64 |
| 5 | `unpause` | vault (writable); instructions sysvar | pause count u64; valid until u64 |
| 6 | `set_controls` | vault (writable); instructions sysvar | deposits u8 (0 or 1); releases u8 (0 or 1); nonce u64; valid until u64 |
| 7 | `sweep_fees` | vault (writable); vault token account (writable); mint; fee token account (writable); token program | none |
| 8 | `close_release` | vault (writable); release record (writable); paid page of the nonce (writable); the account that paid the record's rent (writable) | nonce u64 |

Instructions 2, 4, 5 and 6 need a certificate: the instruction immediately before them in the transaction must be
the canonical secp256k1 instruction of section 6.

### 3.1 `initialize`

Parses and validates the configuration (section 4.1), requires the program to be final (section 9), checks the
mint, derives the vault and token account addresses, creates both accounts, makes the vault address the token
account's authority (`InitializeAccount3`), and stores the state: the derived identities, the route, the mint
chain genesis, the fee token account address (the associated token account of the fee owner, derived here), a full
release bucket, and **deposits and releases disabled**, as on Ethereum. The committee opens the vault with
`set_controls`.

### 3.2 `deposit`

Refused while paused, while deposits are disabled, below `min_deposit`, above `window_limit`, with a zero L2
recipient, or when the net amount would pass `cap`. Refused if the vault's token balance is below
`total_locked + fees_accrued` (`InsufficientBacking`). Transfers `amount` with `TransferChecked` (6 decimals)
signed by the depositor, then requires the vault's balance to have grown by exactly `amount` and the source's to
have fallen by exactly `amount`.

The deposit is its **net** amount from there on: `fee = amount * deposit_fee_bps / 10000` (rounded down),
`net = amount - fee`. `total_locked += net`, `fees_accrued += fee`. The deposit id, the chain step and the record
carry the net amount, which is exactly what the L2 token mints.

**Which record account.** The record of deposit `n` is at the address derived from the vault and `n`, and `n` is
the vault's deposit count when the deposit EXECUTES, not when it was signed. A deposit therefore names the record
addresses of the next counts as it read them (the sixth account, and up to seven more after the system program);
the program derives the address of the count it finds and uses the account with that address, leaving the others
untouched. Deposits signed against the same count then land one after another instead of all but one failing. If
more deposits land in between than the window names, the deposit fails (`InvalidAccount`) and moves nothing; the
tool sends it again against the new count. The order of deposits, their nonces and the hash chain are unchanged:
they are still assigned by the vault at execution, one count each (review 325, R325-SOL-4).

### 3.3 `approve_release`

Refused while paused or while releases are disabled. Checks, in order: validity (`now <= valid_until` and
`valid_until - now <= max_valid_seconds`); amount non-zero, recipient non-zero, native burn non-zero,
`amount <= total_locked`; the anchor slot is below the current slot and both hashes are non-zero; provenance
(`1 <= mint_count <= deposit_count` and the deposit record of nonce `mint_count - 1` has `head_after == mint_head`);
the certificate, with the threshold, over the release authorization (section 5).

**No certificate from before a guardian pause** (review 325, R325-SOL-2). After the validity check the program
requires `valid_until > last_pause_at + max_valid_seconds`, where `last_pause_at` is when the last guardian pause
began (`StaleCertificate`). Signers date `valid_until` at most `max_valid_seconds` ahead (the vault and their own
half both refuse more), so a certificate signed at or before the moment a guardian paused ends at or before that
bound. Whatever such a certificate approved is voided by the pause, and neither it nor any other certificate
from before the pause can approve anything afterwards, whoever ends the pause and however soon. No operator
configuration is involved: the bound is computed from the vault's own state. The configuration additionally
requires `pause_duration > max_valid_seconds`, so that when a pause runs its full length a certificate dated the
moment it ends is already acceptable and signing resumes without a gap; after a 6-of-7 unpause signing resumes
`max_valid_seconds` less the signers' own validity after the pause began (25 s in the rehearsal, 30 minutes with
1,800 s certificates under a 3,600 s limit).

**The paid page.** A set bit for this nonce in its paid page means the release was paid and its record closed
(section 3.9): `AlreadyReleased`. A page that does not exist yet is created here (1,067 bytes, about 0.0083 SOL,
once per 8,192 burn nonces).

Then the release record: created if the address is new. If a record exists, it must be an approval that a guardian
pause voided (`state == approved` and `seq <= void_through_seq`); a standing approval and a paid release are final
for their nonce (`AlreadyReleased`). The record keeps the address that paid its rent at the first approval. It
gets the next approval number and
`ready_at = now + release_delay` when `release_delay != 0` and `amount > large_release_threshold`, else `now`.

### 3.4 `execute_release`

Anyone may call it. Refused while paused, if the record is not an approval, if it was voided, or before
`ready_at`. The wallet given in the data must hash to the record's 20-byte recipient
(`id20("BLOCH-SVM-ACCOUNT-ID-v1", wallet)`), must not be the vault or its token account, and the destination must
be that wallet's associated token account for the mint, with the wallet as its owner.

The release bucket then applies: `available = min(window_limit, bucket + elapsed * window_limit / window_seconds)`;
`amount > available` is `RateLimited`. The bucket and `total_locked` take the full burned amount; the recipient is
paid `amount - fee` with `fee = amount * release_fee_bps / 10000`, and the fee moves to `fees_accrued`. The
vault's balance must fall by exactly the paid amount and the destination's must rise by exactly it.

### 3.4.1 Between the two steps

An approval is a record `(release id, recipient, amount, ready_at, approval number)`. What can happen to it
between `approve_release` and `execute_release`:

| Event between the steps | Effect on the standing approval |
|---|---|
| The committee changes | Cannot happen. The signer set, the threshold and the guardians are part of the configuration, whose hash is in the vault's address; the program has no instruction that changes them and no upgrade authority. A new committee means a new vault with its own token |
| The limits change (cap, window, large threshold, delay, fees) | Cannot happen, for the same reason. The payment applies the bucket, the delay and the fee of the one fixed configuration, at payment time: an approval made when the bucket was full is still `RateLimited` if the bucket is empty when it is paid |
| The committee switches releases off (`set_controls`, 5 of 7) | The approval stays and is still paid: `execute_release` checks the pause, not `releases_enabled` (row 18 of section 8, as on Ethereum). New approvals are refused. Stopping a standing approval takes a guardian pause |
| A guardian pause | The approval is voided and can never be paid: `execute_release` answers `Voided`. Nothing is lost: the record is not a spent replay key. After the pause, `approve_release` accepts a threshold certificate for the same burn nonce again and overwrites the record (new approval number, new `ready_at`); a paid record is never overwritten |
| The certificate's `valid_until` passes | Nothing. `valid_until` bounds `approve_release` only; an approval, once recorded, does not expire |
| The recipient's token account is missing or frozen | The payment fails in that transaction and the approval stays payable |

A guardian pause therefore cannot lose a user's exit. The burn is final on the L2; the vault has no paid record
for its nonce; the signers' own rule refuses a second certificate only for a paid release or a standing approval
(and their local database allows the same release under a new context), so after the pause five signers certify
the burn again and it is approved and paid once. The local rehearsal does exactly this on a real validator: an
approval voided by a pause is refused with `Voided`, the same burn is certified again by the unchanged signer,
approved again and paid once.

A voided approval cannot be approved again with the certificate that approved it, nor with any certificate that
could have been signed before the pause: `approve_release` refuses them for good (`StaleCertificate`, section
3.3). Before review 325 this rested on the configured pause outlasting the configured certificate life, which
only the tool checked, and a 6-of-7 unpause inside the hour re-opened the window. Now the program enforces it
from its own state, and the rehearsal shows it on a validator: after a pause ended early by six signers, the
voided certificate, still inside its validity, is refused, and a certificate signed after the pause is accepted.

### 3.5 `guardian_pause`

The certificate must hold exactly one signature, of a guardian, over the pause authorization for pause number
`pause_count + 1`. Anyone may deliver it: the guardian's power is its secp256k1 key, and the authorization can be
used once because it names the pause it starts. Conditions as on Ethereum: not already paused, not within the
cooldown after a committee unpause, and each guardian starts at most one pause per chain of consecutive pauses.
The pause lasts `pause_duration`, stops deposits, approvals and payments, and **voids every approval not yet paid**
(`void_through_seq = approval_seq`). It records when it began (`last_pause_at`): section 3.3.

### 3.6 `unpause`

`switch_threshold` signers end the current pause (bound to its pause count) early. Guardians then wait
`pause_cooldown`. Voided approvals stay voided.

### 3.7 `set_controls`

`threshold` signers switch deposits and new approvals on or off, with the next control nonce
(`ProvenanceSourceVault.setControls`). A call that changes nothing is refused.

### 3.8 `sweep_fees`

Anyone may call it. Pays all of `fees_accrued` to the fee token account and sets it to zero, after checking that
the balance covers `total_locked + fees_accrued`. It is not stopped by a pause, as on Ethereum. With nothing
accrued it succeeds and does nothing. If the fee token account does not exist the instruction fails and the fees
stay accrued.

### 3.9 `close_release`

Anyone may call it. The release record must be PAID and `now >= paid_at + record_retention`; the fourth account
must be the address the record names as having paid its rent. The program sets the nonce's bit in the paid page,
logs the record, moves the record's lamports to that address and zeroes the record, which the runtime then
removes. From here on the bit is the nonce's replay state: `approve_release` refuses a nonce whose bit is set,
`execute_release` and `close_release` find no record. A record that is approved, waiting or voided cannot be
closed. Lamports sent to a closed record's address do not bring the nonce back (tested).

Why: a release record costs its relayer about 0.0023 SOL of rent, far more than the 5 bps of a small exit, which
go to the fee owner (review 325, R325-SOL-4). With closing, the relayer's cost per release is two transaction fees
and the rent comes back after the retention; what stays is one bit, in a page whose rent (about 0.0083 SOL) is
shared by 8,192 nonces. The retention (7 days proposed, at most 30) is the time a watcher has to read the full
record of a paid release; after it, a watcher can still check that every paid nonce belongs to an L2 burn.

**The retention has a floor outside a rehearsal (review 330, R330-SOL-3).** The program bounds `record_retention`
from above only; with 0 a payment and the closing of its record fit one transaction and no watcher ever reads a
paid record. The program image is unchanged, so the floor is in the tools' mainnet policy and in the deploy
check: `solana_lib.retention_floor` = max(4,320 guardian watch rounds of 60 s, `pauseDuration`) = 259,200 s with
the proposed values. The margin: a guardian watch may be down for three days and still read every paid record in
full when it returns, and what was paid just before a guardian pause stays readable for the whole pause.
`sol_vault.py validate`, `init` and `verify` refuse a configuration below it; `sol_guardiao.py` refuses to watch
such a vault, refuses a watch `--interval` of which 4,320 rounds exceed the vault's retention (140 s at 7 days),
and alerts when its last verified round is further back than the retention (`watch-gap-exceeds-retention`).

## 4. Layouts

Every program account starts with a type tag and a layout version (2). Nothing is reallocated after creation.

### 4.1 Configuration (instruction data of `initialize`, and the bytes hashed into the vault address)

| Offset | Size | Field |
|---|---|---|
| 0 | 32 | `mint` |
| 32 | 32 | `fee_owner` (a wallet address; its associated token account receives the fees) |
| 64 | 32 | `source_chain_id` (big-endian) |
| 96 | 32 | `source_domain` (a label, right-padded with zeros like Solidity `bytes32("...")`) |
| 128 | 32 | `native_domain` |
| 160 | 32 | `native_asset` |
| 192 | 8 | `cap` |
| 200 | 8 | `window_limit` |
| 208 | 8 | `window_seconds` |
| 216 | 8 | `min_deposit` |
| 224 | 8 | `l2_min_burn` |
| 232 | 8 | `large_release_threshold` |
| 240 | 8 | `release_delay` |
| 248 | 8 | `pause_duration` |
| 256 | 8 | `pause_cooldown` |
| 264 | 8 | `max_valid_seconds` |
| 272 | 8 | `record_retention` |
| 280 | 2 | `deposit_fee_bps` |
| 282 | 2 | `release_fee_bps` |
| 284 | 1 | `threshold` |
| 285 | 1 | `switch_threshold` |
| 286 | 1 | `signer_count` (at most 16) |
| 287 | 1 | `guardian_count` (at most 7) |
| 288 | 20 each | the signers, then the guardians; nothing after them |

Validation (the rules of the `ProvenanceSourceVault` constructor, plus the Solana-only values): each fee at most
30 bps; fee owner, mint, chain id, the three labels non-zero; source and native domain different; `cap > 0`;
`2 <= threshold <= signer_count`; `threshold <= switch_threshold <= signer_count`;
`0 < window_limit <= cap`; `window_seconds > 0`; `l2_min_burn > 0`;
`l2_min_burn <= min_deposit <= window_limit`; `min_deposit` less its deposit fee is at least `l2_min_burn`;
`release_delay <= 14 days`, and `large_release_threshold` must be zero when `release_delay` is zero;
`60 <= max_valid_seconds <= 86400`; `record_retention <= 30 days`; without guardians both pause values are zero,
with guardians `max_valid_seconds < pause_duration <= 14 days` (a pause outlasts every certificate) and
`pause_duration <= pause_cooldown <= 14 days`; signers strictly ascending
(so non-zero and distinct); guardians strictly ascending and none of them a signer. At `initialize` also: the fee
owner is not the vault, its token account or the mint.

### 4.2 Vault state (1,146 bytes)

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | tag = 1 |
| 1 | 1 | layout version = 2 |
| 2 | 1 | vault bump |
| 3 | 1 | token account bump |
| 4 | 32 | configuration hash |
| 36 | 288 | the fixed part of the configuration, verbatim |
| 324 | 320 | signers, 16 slots of 20 bytes (unused slots zero) |
| 644 | 140 | guardians, 7 slots of 20 bytes |
| 784 | 20 | `vault20` |
| 804 | 20 | `mint20` |
| 824 | 32 | `route` |
| 856 | 32 | mint chain genesis |
| 888 | 32 | vault token account address |
| 920 | 32 | fee token account address |
| 952 | 32 | `head`: deposit chain head after `deposit_count` deposits |
| 984 | 8 | `deposit_count` |
| 992 | 8 | `total_locked` |
| 1000 | 8 | `fees_accrued` |
| 1008 | 8 | `control_nonce` |
| 1016 | 1 | `deposits_enabled` |
| 1017 | 1 | `releases_enabled` |
| 1018 | 8 | `release_bucket` |
| 1026 | 8 | `bucket_updated_at` |
| 1034 | 8 | `paused_until` |
| 1042 | 8 | `pause_count` |
| 1050 | 8 | `guardian_blocked_until` |
| 1058 | 8 | `pause_chain` |
| 1066 | 56 | `guardian_last_chain`, one u64 per guardian slot |
| 1122 | 8 | `approval_seq` |
| 1130 | 8 | `void_through_seq` |
| 1138 | 8 | `last_pause_at`: when the last guardian pause began (0: never) |

### 4.3 Deposit record (211 bytes)

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | tag = 2 |
| 1 | 1 | layout version |
| 2 | 1 | bump |
| 3 | 32 | vault address |
| 35 | 8 | nonce |
| 43 | 32 | deposit id |
| 75 | 32 | depositor (the signer of the deposit) |
| 107 | 20 | `sender20`, the depositor's account id |
| 127 | 20 | L2 recipient |
| 147 | 8 | net amount |
| 155 | 8 | fee |
| 163 | 32 | `head_after`: the deposit chain head after this deposit |
| 195 | 8 | slot |
| 203 | 8 | timestamp |

A deposit record is written once and never changed or closed. It is the canonical record a watcher reads.

### 4.4 Release record (208 bytes)

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | tag = 3 |
| 1 | 1 | layout version |
| 2 | 1 | bump |
| 3 | 1 | state: 1 approved, 2 paid |
| 4 | 32 | vault address |
| 36 | 8 | burn nonce |
| 44 | 32 | release id |
| 76 | 20 | recipient commitment |
| 96 | 8 | amount (the burned amount) |
| 104 | 32 | native burn id |
| 136 | 8 | `ready_at` |
| 144 | 8 | approval number (`seq`) |
| 152 | 8 | `approved_at` |
| 160 | 8 | `paid_at` |
| 168 | 8 | paid amount (amount less the fee) |
| 176 | 32 | the address that paid the record's rent at the first approval |

### 4.5 Paid page (1,067 bytes)

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | tag = 4 |
| 1 | 1 | layout version |
| 2 | 1 | bump |
| 3 | 32 | vault address |
| 35 | 8 | page number (burn nonce / 8,192) |
| 43 | 1,024 | one bit per burn nonce of the page, least significant bit first: set = paid and closed |

The vault's replay state for releases is the release records that exist plus the paid pages. A page is never
closed and a bit is never cleared.

## 5. Digests

`abi.encode` of static types is a run of 32-byte big-endian words; `bytes32("TAG")` is the text right-padded with
zeros. The program builds these by hand (`abi.rs`).

**Byte-identical to `ProvenanceSourceVault`** (the same tags and the same word order, with the identities of
section 1 in the places of `block.chainid`, `address(this)`, `token` and `msg.sender`):

| Value | Formula |
|---|---|
| route | `sha256(abi.encode("BLOCH-USDT-ROUTE-v1", sourceDomain, nativeDomain, nativeAsset, mint20, vault20, 6, cap))` |
| mint chain genesis | `keccak256(abi.encode("BLOCH-USDT-MINT-CHAIN-v1", chainId, vault20, route))` |
| deposit id | the nonce (big-endian) in the top 8 bytes, then the low 24 bytes of `sha256(abi.encode("BLOCH-USDT-DEPOSIT-v2", route, nonce, sender20, net, l2Recipient))` |
| chain step | `keccak256(abi.encode(head, depositId, net, l2Recipient))` |
| release id | `sha256(abi.encode("BLOCH-USDT-RELEASE-v2", route, nonce, recipient, amount, nativeBurn, mintCount, mintedTotal, mintHead))` |
| release authorization | `keccak256(abi.encode("BLOCH-USDT-RELEASE-AUTH-v2", chainId, vault20, releaseId, validUntil, sourceAnchorSlot, sourceAnchorHash, nativeFinalizedNumber, nativeFinalizedHash))` |
| controls authorization | `keccak256(abi.encode("BLOCH-USDT-CONTROLS-v1", chainId, vault20, route, deposits, releases, nonce, validUntil))` |
| unpause authorization | `keccak256(abi.encode("BLOCH-USDT-UNPAUSE-v1", chainId, vault20, route, pauseCount, validUntil))` |

**New on Solana:**

| Value | Formula |
|---|---|
| guardian pause authorization | `keccak256(abi.encode("BLOCH-SVM-GUARDIAN-PAUSE-v1", chainId, vault20, route, pauseCount + 1, validUntil))` |
| configuration hash | `sha256("BLOCH-SVM-VAULT-CONFIG-v1" || configuration bytes)` |
| the identities of section 1 | `BLOCH-SVM-VAULT-ID-v1`, `BLOCH-SVM-MINT-ID-v1`, `BLOCH-SVM-ACCOUNT-ID-v1`, `BLOCH-SVM-CHAIN-ID-v1` |

What a key signs is the EIP-191 digest of a 32-byte authorization,
`keccak256("\x19Ethereum Signed Message:\n32" || authorization)`, exactly what `cast wallet sign` produces for a
32-byte hash and what the Ethereum vault's `releaseDigest` returns. The native secp256k1 program hashes the
message it is given with keccak256, so the message in the secp256k1 instruction is the 28-byte prefix followed by
the authorization: 60 bytes.

## 6. Certificates: the secp256k1 verification must be the vault's own

The native secp256k1 program proves only this: "these signatures recover to these addresses over these bytes,
wherever the offsets point". Offsets may point into any instruction of the transaction. Everything that makes the
proof belong to the vault's instruction is checked by the vault (`cert.rs`):

1. The vault's instruction runs at the top level of the transaction (not through a CPI), so "the instruction
   before the current one" is a statement about its own position.
2. The instructions sysvar is the real one (`load_*_checked` compare its address).
3. The previous instruction's program id is the native secp256k1 program and it takes no accounts.
4. Its data has exactly one canonical layout for `n` signatures, with no spare byte, so every byte the native
   program verified is a byte the vault reads:

   ```text
   [0]                      n
   [1 .. 1+11n]             n offset structures
   [1+11n .. 1+96n]         n entries of: signature (64) | recovery id (1) | Ethereum address (20)
   [1+96n .. 1+96n+60]      the message: "\x19Ethereum Signed Message:\n32" | authorization (32)
   ```

5. Every offset structure points into that same instruction (all three instruction indexes equal its index) at
   exactly the canonical positions, with message size 60: the native program cannot have verified bytes that live
   in another instruction or at another offset.
6. The message is the prefix followed by the authorization the program computed from its own state and from the
   arguments of its own instruction.
7. The addresses are members of the set, strictly ascending (so distinct), and at least `required` of them
   (`required <= n <= size of the set`).

An offset structure is 11 bytes: signature offset u16, signature instruction index u8, address offset u16, address
instruction index u8, message offset u16, message size u16, message instruction index u8.

The SDK's own single-signature layout (address before signature) is valid for the native program and is refused
by the vault, which accepts the one layout above.

## 7. Errors and logs

Custom error codes (`ProgramError::Custom`):

| Code | Name | Code | Name |
|---|---|---|---|
| 100 | InvalidConfiguration | 111 | Paused |
| 101 | InvalidAccount | 112 | ProvenanceMismatch |
| 102 | InvalidTransfer | 113 | NotApproved |
| 103 | InvalidRelease | 114 | NotReady |
| 104 | InvalidCertificate | 115 | AlreadyReleased |
| 105 | InvalidControls | 116 | Voided |
| 106 | InsufficientBacking | 117 | NotTopLevel |
| 107 | InvalidContext | 118 | ProgramUpgradeable |
| 108 | RateLimited | 119 | WrongRecipient |
| 109 | NotGuardian | 120 | Expired |
| 110 | InvalidPause | 121 | StaleCertificate |

Data logs (`sol_log_data`; the first field is the tag):

| Tag | Following fields |
|---|---|
| `BLOCH-SVM-VAULT-INITIALIZED-v1` | vault address, `vault20`, route |
| `BLOCH-SVM-DEPOSITED-v1` | the 211 bytes of the deposit record |
| `BLOCH-SVM-RELEASE-APPROVED-v1` | the 208 bytes of the release record |
| `BLOCH-SVM-RELEASE-CLOSED-v1` | the release record as it was when closed |
| `BLOCH-SVM-RELEASED-v1` | the release record, the recipient wallet |
| `BLOCH-SVM-GUARDIAN-PAUSED-v1` | guardian address (20), pause count, paused until |
| `BLOCH-SVM-UNPAUSED-v1` | pause count, guardian blocked until |
| `BLOCH-SVM-CONTROLS-v1` | nonce, two bytes (deposits, releases) |
| `BLOCH-SVM-FEES-SWEPT-v1` | amount |

Logs are for explorers and indexers. **Signers and watchers do not rely on logs**: a node may truncate them, and a
log is not state. They read the deposit and release record accounts at `finalized` commitment.

## 8. Every difference from `ProvenanceSourceVault` V3 semantics, and why

| # | Ethereum vault | Solana vault | Why |
|---|---|---|---|
| 1 | `release()` verifies and pays in one call (launch `releaseDelay` 0) | Two steps: `approve_release` (certificate) then `execute_release` (payment), in two transactions | A transaction is at most 1,232 bytes. The certificate of 5 signatures alone is 541 bytes; with the accounts of a payment it does not fit (section 10) |
| 2 | Optional uniform `releaseDelay` with a forged-mint challenge; 0 at launch | `release_delay` applies to releases above `large_release_threshold`; a guardian pause voids every approval not yet paid, and the program then refuses every certificate that could have been signed before that pause (`StaleCertificate`) | The two steps exist anyway, so a waiting period for large items costs nothing. Voiding makes a pause-only guardian effective against a wrong approval: the certificate behind it is dead for good, however the pause ends. Against five keys that stay compromised it delays: they can sign a new certificate after the pause. No forged-mint challenge (`proveForgedMint`) is ported: it belongs to `releaseDelay` mode with a mint verifier, which is not the launch design |
| 3 | One-way light-client switch (`proposeVerifier`, `cancelVerifier`, `activateVerifier`, `releaseWithProof`) | None | The light-client path is out of scope in round 16. Consequence: the committee can never be retired on this vault; the only succession is a migration to a new vault |
| 4 | The certificate binds an Ethereum block hash, checked with `blockhash` (256 blocks) | The certificate carries an anchor slot and hash that are signed but not compared with chain history; the program requires the slot to be below the clock, and bounds a certificate's life with `max_valid_seconds` | The SlotHashes sysvar covers 512 slots (a few minutes), less than the time to collect signatures. The provenance check already binds a release to this vault's own deposit history, which is what the fork binding protects on Ethereum |
| 5 | `validUntil` only has to be in the future | Also at most `max_valid_seconds` ahead, and above `last_pause_at + max_valid_seconds` | Replaces the 256-block lifetime bound of item 4; a certificate cannot be kept for later, and no certificate survives a guardian pause (section 3.3). The configuration must also satisfy `pause_duration > max_valid_seconds` |
| 6 | A guardian pauses by sending the transaction (`msg.sender`) | A guardian signs a pause authorization with its secp256k1 key; anyone delivers it | No new key type for guardians. The authorization names the pause it starts, so it is used once |
| 7 | The burn's `ethRecipient` is the paid address | The burn names a 20-byte commitment to a 32-byte wallet; payment goes to that wallet's associated token account, and the wallet is supplied at payment | The unchanged token's `burn` carries 20 bytes. A wallet other than the committed one needs a second preimage of 160 bits |
| 8 | `releasedNonce` and `releasedBurn`, kept for ever in contract storage | One release record per burn nonce while it is approved or recently paid; after `record_retention` anyone may close a paid record, and one bit in a paid page keeps the nonce spent. The native burn id is stored in the record and bound by the certificate, but is not a second replay key | Each replay key on Solana is an account with rent; the record's rent returns to the relayer and the bit costs about 0.000001 SOL. The burn nonce is the token's own counter. Consequence: if the committee certified one burn id under two nonces, the Ethereum vault would refuse the second and this vault would not |
| 9 | Deposits are events; the chain head per count is a mapping | Each deposit is an account (the depositor pays its rent); the head after each deposit is stored in it | A release must be checked against the head at an earlier count, and state is what a watcher can read reliably at `finalized` |
| 10 | `feeRecipient` is an address | The fee owner is a wallet; fees go to its associated token account, which must exist before the first sweep | A token account is needed to receive SPL tokens. Fees are swept separately, so a missing or frozen fee account never blocks a release |
| 11 | The constructor deploys one vault | `initialize` is permissionless and configuration-addressed | No deployer power, no front-running of the address |
| 12 | `depositsEnabled` and `releasesEnabled` start false | The same | Unchanged: a 5-of-7 `set_controls` opens the vault |
| 13 | The issuer can blacklist addresses and pause or upgrade the token | The issuer's freeze authority can freeze any USDC token account | Section 12 |
| 14 | No storage cost for the user | Rent: the deposit record is paid by the depositor and stays (about 0.00236 SOL); the release record is paid by the relayer and returns to it when the record is closed (about 0.00233 SOL, section 3.9); a paid page per 8,192 nonces (about 0.0083 SOL) stays | Section 10 |
| 15 | `nonReentrant` guard | None | The runtime refuses reentrancy into a program that is already on the call stack (other than direct self-recursion, which the program never does), and the classic token program calls no other program |
| 16 | `transferMode` for tokens that return nothing | Classic SPL Token only | Section 12 |
| 17 | Up to 16 signers with any threshold | Up to 16 signers; in practice the release threshold is at most 5 | A 5-signature approval is 1,151 bytes with the paid page account; a sixth signature makes 1,247. An address lookup table would lift this; none is used. The tool refuses a configuration with a threshold above 5 |
| 18 | `executeRelease` of a queued release checks only the pause | The same: `execute_release` does not check `releases_enabled` | Kept as on Ethereum |
| 19 | A deposit cannot conflict with another one | A deposit names up to 8 candidate record addresses; the program uses the one of the count it finds | The record address depends on the count at execution (section 3.2). Order, nonces and the hash chain are unchanged |
| 20 | The burn's recipient is checked by nobody, and need not be: it is an address | Exits go through `SolanaBurnRouter` on the L2, which refuses what is not a wallet address; signers certify a burn only when a wallet (on the curve, hashing to the 20 bytes) is published | The frozen token takes any 20 bytes; section 11 |
| 21 | A signer reads one Ethereum node | A signer attests a deposit only when every configured Solana endpoint, at least two on a public cluster, shows the same record at `finalized` | A mainnet Solana RPC node is costly and operators will use providers; one provider must not be able to supply five mint signatures (section 13) |

## 9. No upgrade authority

The program is deployed with `solana program deploy --final`: the upgradeable loader (v3) writes the program data
account with no upgrade authority, and the program can never be changed or closed. An upgradeable program would
be an administrator key over every vault, and the owner's rule is none.

The program enforces this itself: `initialize` requires the program data account of the running program
(`find_program_address(program id)` under the upgradeable loader, owned by the loader, tag `ProgramData`) to have
no upgrade authority, and fails with `ProgramUpgradeable` otherwise. A vault of this program therefore exists only
under final code.

## 10. Size, compute and rent

Measured in the in-process SVM of the test suite (litesvm 0.18.2, Agave 4.3 runtime), program image sha256
`33f7027d1c378a1695de309a93448b2763175baf54eb3412bc9a7439401c7316` (106,984 bytes). The secp256k1 verification
itself runs in the native program and is not counted in these compute units.

| Instruction | Signatures | Transaction bytes (limit 1,232) | Compute units |
|---|---|---|---|
| `approve_release` (the first of a paid page: it creates the page) | 5 | 1,151 | 26,014 |
| `approve_release` | 6 | 1,247, does not fit | not sent |
| `execute_release` | 0 | 408 | 14,038 |
| `deposit` (one record address; each further candidate adds 32 bytes) | 0 | 430 | 21,715 |
| `guardian_pause` | 1 | 437 | 6,149 |
| `unpause` | 6 | 925 | 6,499 |
| `set_controls` | 5 | 831 | 6,473 |
| `initialize` (7 signers, 3 guardians) | 0 | 858 | not measured |

On a real validator (solana-test-validator of Agave v4.4.1, the local rehearsal, `computeUnitsConsumed` of the
transaction): `approve_release` with 5 signatures 17,555 and 18,514 (1,151 bytes); `execute_release` 14,074 and
14,076; `deposit` with four record addresses 16,534; `close_release` 8,773; `set_controls` with 5 signatures
6,473; `guardian_pause` 6,149; `unpause` with 6 signatures 6,499. `approve_release`, `execute_release` and
`deposit` vary in steps of about 1,500 units: each searches the bump of program-derived addresses (the release
record and the paid page of the nonce, the recipient's associated token address, the deposit record), and every
miss costs that much. Each further miss has probability one half; a wallet ground to cost 40 misses would still
keep `execute_release` under 80,000. The figures of each run are in the rehearsal's `result.json`.

All are far below the default limit of 200,000 compute units per instruction; no compute budget instruction is
needed. The canonical certificate is `61 + 96 n` bytes for `n` signatures.

Rent-exempt minimums by the standard formula, `(128 + bytes) * 3480 * 2` lamports (the release record's was
confirmed with `getMinimumBalanceForRentExemption` on the rehearsal validator: 2,338,560):

| Account | Bytes | Lamports | Paid by | Returned |
|---|---|---|---|---|
| Deposit record | 211 | 2,359,440 (about 0.00236 SOL) | the depositor, per deposit | never: it is the canonical record of the deposit |
| Release record | 208 | 2,338,560 (about 0.00234 SOL) | the relayer, per release | in full, to the relayer, when the record is closed after `record_retention` |
| Paid page | 1,067 | 8,317,200 (about 0.0083 SOL) | the relayer whose approval is the first of the page's 8,192 nonces | never (about 0.000001 SOL per release) |
| Vault state | 1,146 | 8,867,040 | whoever initializes, once | never |
| Vault token account, or any associated token account | 165 | 2,039,280 | whoever creates it | not by this program |

**What a release costs its relayer** (review 325, R325-SOL-4): two transaction fees (the approval carries five
secp256k1 signatures besides the fee payer's; about 0.00004 SOL in all at the base fee), one more for the close,
and the share of a paid page. The record's rent is a float that returns after the retention, not a cost. Before
the change it was a cost of 0.0021 SOL per release against 0.005 USDC of bridge income on a minimum burn. The
5 bps release fee is unchanged and goes to the fee owner; no minimum fee was added.

## 11. The L2 side

`BridgedStablecoinV3` is used byte-identical (creation code keccak256
`0xe560441f37e247e387cebd23bb3dd798a29d34174a9fb19a4bb3877c6c721de7`, rebuilt on 2026-11-16 in this branch).
Its semantics fit with constructor arguments alone: 6 decimals, `sourceChainId_` = the source chain id of
section 1, `sourceVault_` = `vault20`, `sourceRoute_` = the vault's route. Its mint chain genesis
`keccak256(abi.encode(MINT_CHAIN_TAG, sourceChainId_, sourceVault_, sourceRoute_))` is then the vault's.

### 11.1 The burn recipient (review 325, R325-SOL-1)

The one place where 20 bytes are not enough is the burn recipient. `burn(uint64,address)` takes ANY 20 bytes. On
bUSDC they are the holder's Ethereum address; here they must be the commitment of a Solana wallet,
`keccak256("BLOCH-SVM-ACCOUNT-ID-v1" || wallet)[12..]`, and the frozen token cannot check that. Two mistakes
follow from it: a burn to an Ethereum address (typed by habit, or sent by an integration written for bUSDC)
names 20 bytes no wallet hashes to and can never be paid; a commitment to a token account's address would be
paid into the associated token account OF that token account, which no key controls.

**Where the destination is checked: `contracts/solana/SolanaBurnRouter.sol`.** Exits are made with
`approve(router, amount)` on the token, then `router.burnTo(uint64 amount, string recipient)`, the recipient being
the base58 text a Solana wallet shows. The router decodes it, requires 32 bytes in canonical base58, not zero and
ON the Ed25519 curve, computes the commitment itself, burns through the token and logs
`SolanaExit(bytes32 indexed burnId, address indexed from, uint64 amount, address commitment, string recipient)`
in the same transaction. Every associated token account, and every other program-derived address, is off the
curve by construction, so pasting a token account's address is refused before anything is burned; so is an
Ethereum address, in any spelling. The router has no owner, no storage and holds nothing between calls. It has
the shape of `StellarBurnRouter` and `BitcoinBurnRouter`: `token()`, a pure function from the destination text to
the 20 bytes (`commitment(string)`), `burnTo(uint64, string)`, and one `<Network>Exit` log.

What the curve check does not do: it does not prove that anyone holds the key (a mistyped address fails base58
canonical form or the curve check with probability about one half, not always); a token account created at a
keypair address is on the curve; and a wallet that is itself a program-derived address (a multisig vault) is
refused, so such a holder exits to a key wallet.

**Review 330, R330-SOL-1: "on the curve" is not "a wallet".** Half of all 32-byte values are curve points. Among
them are the USDC mint itself (`EPjFWdd5…Dt1v`, the answer to "what is the USDC address on Solana"), the token
programs' ids, every mint and token account created at a keypair address, and the eight points of small order,
for which no private key can exist. Three layers now stand in front of such a destination, sections 11.2 to 11.4:
the router refuses what it can know without reading Solana, every signer reads the destination on Solana and
holds what is not a wallet there, and the bridge page proves the key with a wallet signature before it calls the
router. Section 11.5 says what remains.

Since round 17 the router (constructor `SolanaBurnRouter(token, bytes32 solanaMint)`; `walletOf` and `commitment`
are `view`, no longer `pure`, because they read the immutable mint) also refuses, with the same error
`NotASolanaWallet` and before anything is burned:

- the eight small-order points, in every spelling the curve test accepts (y = 0, 1, p - 1 and the two order-8
  values, either sign bit, y written unreduced);
- `solanaMint`, the SPL mint this route's vault holds;
- the program ids the bridge itself names: classic SPL Token, Token-2022, Associated Token Account.

**What the signers do: a burn is certified only when a wallet is known for it** (`tools/signatario-solana/
sol_recipient.py`, applied by the Solana half before it signs, by the sign daemon before it rebuilds anything, by
the relayer before it pays). A wallet is 32 bytes, not zero, on the curve, not of small order, not on the list of
addresses known not to be wallets, hashing to the burn's 20 bytes; and what the chain shows at it must be a wallet
(11.2). It is
looked for in the router's `SolanaExit` log of that burn id, then in a `SolanaRecipient` log of
`SolanaRecipientRegistry` for those 20 bytes, then in an operator's hint file. Where it comes from does not
matter, because the hash decides. On a public cluster the Solana half refuses to run without `l2_rpc` and
`burn_router`.

**A burn made directly on the token** (outside the router) is therefore one of three things:

| Its 20 bytes | What happens |
|---|---|
| The commitment of a wallet, and the wallet is announced on the registry (by the burner or anyone: `announce(bytes32)`) | Certified, approved and paid like any other exit. This is the recovery rule: announce the wallet |
| The commitment of a wallet nobody has published | HELD: not certified, not approved, alerted by every sign daemon (`release-held-no-wallet`). Paid once the wallet is announced |
| Not a commitment of any wallet (an Ethereum address, the commitment of a token account) | HELD for good by the same rule. Nothing is paid to anyone, the amount stays in the vault's `total_locked`, and it is visible: the alert names the burn. It is not silently approved, and it cannot be paid into an account nobody controls |
| The commitment of an on-curve address that is not a wallet on Solana (a mint, a token account or a program at a keypair address), or of a small-order point, announced or not | HELD by the destination rule of 11.2, for as long as the chain shows that. The same holds for such a burn made THROUGH the router, when the router could not know |

The third row is a loss for the holder that this design does not undo: paying it would need a release whose
recipient differs from the one in the burn, and the unchanged signer (`signatario.py`) refuses to sign a release
that is not exactly the burn's (`the Ethereum half signed another release`). A recovery path (a signed claim by
the burner naming a wallet, certified as a release with a substituted recipient, and accepted by the guardian
watch) is a change to the frozen signer and is not built; until it is, the defence is that no interface of the
bridge calls `token.burn` and the router refuses the mistake. The rehearsal shows all four rows on a validator.
Whether to build that refund path is an owner decision (ceremony checklist 15).

### 11.2 The destination is read on Solana (review 330, R330-SOL-1)

Before a signer certifies a burn, its Solana half reads the address the release would be paid for
(`sol_recipient.destination`), at `finalized`, on every Solana endpoint that signer is configured with. The burn
is HELD (not certified, alerted, nothing paid, the amount stays in `total_locked`) unless every endpoint shows
the address either

- absent from the chain, or
- an account owned by the System program, with no data and not executable.

A mint, a token account, a program, a sysvar, a nonce account, a stake account, any account owned by another
program: held, for as long as that is what the chain shows. The vault's own accounts (its mint, program, vault,
token account, the fee owner's token account) and a short fixed list of well-known non-wallets are refused by
name without a read. An endpoint that does not answer is not "absent": the signer signs nothing.

Each of the seven signers applies the rule on its own node(s); five must agree before anything can be approved.
The sign daemon applies it before it opens a round (`release-held-destination`), and the relayer applies it twice:
before it delivers a certificate (`certificate-withheld-destination`) and before it pays
(`approved-destination-not-a-wallet`). No tool creates the associated token account of an address that is not a
FUNDED System account at `finalized` (`sol_vault.py execute --create-account` refuses; `sol_vigia.py` with
`sol_create_recipient_account` waits), and `sol_create_recipient_account` stays false at launch.

Why "absent" passes: a wallet that was never funded has no account, and it must be payable (anyone can create its
token account). An account can be created AT an on-curve address only with that address's signature, so an
address that is absent when the signers read it cannot later become a mint or a token account unless somebody
holds its key. The payment itself is permissionless once approved (`execute_release`), so the signers' read is
the gate; the relayer's checks are a second look, not a lock.

**A hold is visible with its reason.** `sol_vault.py burn-status --l2-rpc URL --token 0x.. --router 0x..
--registry 0x.. (--burn 0xID | --nonce N | --all)` prints, per L2 burn: `state` (`paid`, `approved`, `waiting`,
`held`), and for a held one `hold` (`no-wallet` or `destination-not-a-wallet`) and `reason` in words (for
example "the destination exists on Solana and is not a wallet: an account owned by the classic SPL Token program
with 82 bytes of data"). `sol_vault.py reserves` with the same options lists every held burn with its reason and
`heldTotal`, which explains that part of `lockedMinusSupply`. The sign daemons' alerts carry the same text.

### 11.3 Proof of the destination key (the bridge page; for the frontend)

The only proof that somebody holds the key of an address is a signature made with it. The bridge page therefore:

1. takes the destination from a CONNECTED Solana wallet (never from a text field);
2. asks that wallet to sign, with `signMessage`, exactly this one line of printable ASCII (no trailing newline):

   `Bloch bridge exit: pay bUSDC.sol exits to my Solana wallet <WALLET>. L2 account <0x…>. Router <0x…>. Chain 700770. Issued <UNIX>.`

   `<WALLET>` the base58 address; `<0x…>` the user's L2 account and the router address, lowercase, 0x + 40 hex;
   `<UNIX>` the current time in seconds. Reference text and verification:
   `python3 tools/signatario-solana/sol_proof.py exit-message --wallet W --l2-account 0x.. --router 0x.. --issued T`
   and `sol_proof.py verify --address W --message TEXT --signature SIG`;
3. verifies the 64-byte Ed25519 signature itself, in the page, against the wallet's public key over the UTF-8
   bytes of the line (a wallet that signs the Solana off-chain message envelope instead, as hardware wallets
   through the Solana app do, signs `0xff "solana offchain"`, a zero byte for the version, a zero byte for the
   format, the length as two little-endian bytes, then the line: accept both, as `sol_proof.py` does), and refuses
   a signature older than 10 minutes;
4. only then calls `approve` and `SolanaBurnRouter.burnTo(amount, <WALLET>)`.

The page should also read the address on Solana and refuse anything that exists and is not a System account
without data, so that the user is told before burning what the signers would hold afterwards. A wallet that
cannot sign a message cannot use the page for an exit. The signature is checked by the page only: the L2 cannot
verify Ed25519, the router does not see it, and the signers do not ask for it.

### 11.4 Cases that are the recipient's own doing (review 330, R330-SOL-6)

The payment requires the account at the wallet's associated token address to exist, to be of the mint, and to be
owned by the wallet. A recipient who gave that account to another owner (`SetAuthority`, which the classic token
program allows on associated accounts) can never be paid at this wallet: the address cannot be created again
while the account exists. The same holds while the issuer freezes the recipient's account. The burn stays
approved and unpaid; nothing is lost from the vault. Tested (`r330_sol_6_…` in the SVM suite).

### 11.5 What remains, said plainly

An on-curve address for which NOBODY holds a key, that is not of small order and not on a list, looks to every
reader of the chain exactly like a wallet that was never used: it is absent, or, since anyone may send lamports
to any address, a System account with a balance and no data. The signers cannot tell the two apart, and neither
can the router, the relayer or the vault. A burn through the router to such an address is certified and paid into
a token account nobody can spend from.

The wallet signature of 11.3 closes this for exits made through the bridge page, and only for those: a user who
calls the router from another interface, a script or an integration gets the router's checks and the signers'
read, not the proof of a key. This is the residual of R330-SOL-1 and it is not closed by anything in this
repository. (Requiring on-chain evidence of a key, such as a transaction the address signed, would close it for
used wallets and would refuse every fresh one; it also needs transaction history that many nodes prune. Not
adopted.)

## 12. Token-2022 versus classic SPL Token; the issuer's powers

Read on mainnet-beta on 2026-11-16 (`getAccountInfo` at `finalized`, slot 470242302) and against Circle's address
table (https://developers.circle.com/stablecoins/usdc-contract-addresses):

| Fact | Value |
|---|---|
| USDC mint | `EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v` |
| Owner program | `TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA`, the classic SPL Token program, not Token-2022 |
| Decimals | 6 |
| Mint authority | `BJE5MMbqXjVwjAF7oxwPYXnTXDyspzZyt4vwenNw5ruG` |
| Freeze authority | `7dGbd2QZcCKcTndnHcTL8q7SMVXAkp688NTQYwrRCrar` |

The program accepts the classic token program only, by its id, in every instruction and at initialization. A
Token-2022 mint is refused: transfer fees, transfer hooks and permanent delegates live there and would break the
exact-balance accounting. Agave carries a feature (`replace_spl_token_with_p_token`) that replaces the
implementation at the classic program's address with a compatible one; the account layouts and instruction
encodings this program uses (`TransferChecked`, `InitializeAccount3`, the 165-byte account and 82-byte mint) are
part of that compatibility. Whether that feature is active on mainnet-beta was not checked.

The freeze authority is Circle's. It can freeze any USDC token account:

- the vault's token account: deposits and payments fail until it is thawed; nothing is lost and nothing moves;
- a recipient's account: only that release waits; it cannot be redirected;
- the fee account: only `sweep_fees` fails; fees keep accruing.

## 13. Finality rule and reorganisation

A signer attests a deposit only when its deposit record account is read at `finalized` commitment and the record's
slot is at least `finality_margin_slots` (default 150) below the finalized slot, on EVERY Solana endpoint the
signer is configured with, at least two on a public cluster (`sol_rpc` a list, `sol_rpc_min`; review 325,
R325-SOL-3), and all of them show the same record, field for field. One endpoint that fails, lags, serves another
cluster or disagrees stops the signature. The endpoints should be of different operators (an own node and a
provider, or two providers no other signer shares): the tool can require two answers, not their independence,
which the ceremony inventory records. Skipped
slots do not matter: the signer reads account state at a commitment, not blocks by number.

**Which cluster this is, is decided by the genesis hash (review 330, R330-SOL-2).** `solana.rehearsal: true` in a
vault file relaxes rules that exist for real funds: two agreeing endpoints for a mint, the burn router and an L2
endpoint for a release, the mainnet policy of the configuration. The flag is not part of the vault's address, so
it is REFUSED, not obeyed, whenever the genesis hash (the file's, and the one the node reports) is that of
mainnet-beta, devnet or testnet, and whenever any configured endpoint is not on loopback (`localhost` or a
literal loopback IP): a rehearsal is a local private cluster and nothing else. With the flag false or absent
every production rule applies, whatever the cluster. `solana_lib.rehearsal` is the one place that decides it;
`sol_half.py` (both commands and every `Node`), `sol_vault.py validate` and `init` call it.

Facts read on mainnet-beta at `finalized` by reviewer 330 on 2026-11-16 (review 330, R330-SOL-7), for the external
auditor: (a) the feature "SIMD-0326: Alpenglow: new consensus algorithm" is active since epoch 1064 (slot
459,648,000); the signers' rule above (`finalized`, a margin of 150 slots, every endpoint) does not depend on
which consensus produces `finalized`, but the timing figures of this document were written without naming it and
the guarantee of `finalized` under Alpenglow was not analysed here. (b) Rent per byte is scheduled to change
(SIMD-0437 steps, inactive on that date): the program reads the rent sysvar and returns whatever a record holds,
so nothing breaks; the SOL figures of section 10 will age. (c) The fee owner's address and its USDC account did
not exist on that date: see the ceremony document, section 4.1.

The L2 token's 12-hour queue with guardian cancel is the second line. If a deposit vanishes after it was attested
(a cluster restart that drops finalized slots), the mint has no backing record: the guardians cancel it within the
12 hours. If it credits anyway, the token's mint chain no longer equals the vault's deposit chain, and the vault
refuses every burn made after it (`ProvenanceMismatch`). The failure is a hold, never a second credit and never a
payment without a deposit.

## 14. Toolchain pins

| Tool | Version | Pin |
|---|---|---|
| Agave release (CLI, `cargo-build-sbf` 4.5.0, `solana-test-validator`) | v4.4.1 | `solana-release-x86_64-unknown-linux-gnu.tar.bz2`, sha256 `5b0f0fc7e4eedace05f6455de00aa1f2f3d1642068f1e8d50760ba49112c3941` (the digest GitHub publishes for the asset) |
| Platform tools (the SBF compiler) | v1.57 | downloaded by `cargo-build-sbf` |
| Rust, host | 1.95.0 for the program's unit tests; 1.97.1 for the SVM test crate (litesvm 0.18.2 needs it), `solana/rust-toolchain.toml` | rustup |
| `solana-program` | 5.2.0 | `Cargo.lock` |
| `solana-keccak-hasher`, `solana-sha256-hasher` | 3.1.0 | `Cargo.lock` |

Mainnet-beta's public RPC reported `solana-core` 4.4.0 on 2026-11-16.

## 15. Why native Rust

- Account validation is written out, one check per line, with no macro-generated checks to trust or to read
  through.
- Three direct dependencies: `solana-program` and the two hasher crates. The token and system instructions are
  built by hand from their frozen encodings, so no token crate is linked.
- No framework runtime in the audited binary, and no IDL or discriminator convention to audit.
- Fixed hand-written layouts, shared byte for byte with the Python tools and with the tests, which build every
  instruction and recompute every digest with their own code.
- Anchor (1.2.2 stable, 2.0 in release candidates on 2026-11-14) would add a moving framework and implicit
  behaviour of the `init_if_needed` kind. Pinocchio 0.12 is younger and changes its API between minor versions.

Recorded alternative for the certificate: the syscall `sol_secp256k1_recover` recovers a key inside the program,
needs no instruction introspection and makes the transaction smaller. The coordinator decided the native
secp256k1 program, and that is what is built; the audit should weigh the two.
