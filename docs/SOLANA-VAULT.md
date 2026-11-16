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
| Vault state | `"vault"`, `sha256("BLOCH-SVM-VAULT-CONFIG-v1" || configuration bytes)` | the program | 1,130 | `initialize` (payer pays rent) | never |
| Vault token account | `"tokens"`, vault address | the classic SPL Token program; token authority = the vault address | 165 | `initialize` | never |
| Deposit record | `"deposit"`, vault address, nonce (u64 little-endian) | the program | 211 | `deposit` (the depositor pays rent) | never |
| Release record | `"release"`, vault address, burn nonce (u64 little-endian) | the program | 176 | `approve_release` (the relayer pays rent) | never |

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

- **Vault state**: owned by the program, writable, length 1,130, tag 1, layout version 1, and its address equals
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
number of accounts and refuses trailing data.

| # | Instruction | Accounts, in order | Data after the first byte |
|---|---|---|---|
| 0 | `initialize` | payer (signer, writable); vault (writable); vault token account (writable); mint; program data account; token program; system program | the configuration (section 4.1) |
| 1 | `deposit` | depositor (signer, writable); depositor token account (writable); vault (writable); vault token account (writable); mint; deposit record (writable); token program; system program | amount u64; L2 recipient (20 bytes) |
| 2 | `approve_release` | payer (signer, writable); vault (writable); release record (writable); deposit record of nonce `mint_count - 1`; instructions sysvar; system program | nonce u64; recipient (20); amount u64; native burn (32); mint count u64; minted total u64; mint head (32); valid until u64; source anchor slot u64; source anchor hash (32); native finalized number u64; native finalized hash (32). 204 bytes |
| 3 | `execute_release` | vault (writable); vault token account (writable); mint; release record (writable); recipient token account (writable); token program | nonce u64; recipient wallet address (32) |
| 4 | `guardian_pause` | vault (writable); instructions sysvar | valid until u64 |
| 5 | `unpause` | vault (writable); instructions sysvar | pause count u64; valid until u64 |
| 6 | `set_controls` | vault (writable); instructions sysvar | deposits u8 (0 or 1); releases u8 (0 or 1); nonce u64; valid until u64 |
| 7 | `sweep_fees` | vault (writable); vault token account (writable); mint; fee token account (writable); token program | none |

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

### 3.3 `approve_release`

Refused while paused or while releases are disabled. Checks, in order: validity (`now <= valid_until` and
`valid_until - now <= max_valid_seconds`); amount non-zero, recipient non-zero, native burn non-zero,
`amount <= total_locked`; the anchor slot is below the current slot and both hashes are non-zero; provenance
(`1 <= mint_count <= deposit_count` and the deposit record of nonce `mint_count - 1` has `head_after == mint_head`);
the certificate, with the threshold, over the release authorization (section 5).

Then the release record: created if the address is new. If a record exists, it must be an approval that a guardian
pause voided (`state == approved` and `seq <= void_through_seq`); a standing approval and a paid release are final
for their nonce (`AlreadyReleased`). The record gets the next approval number and
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

A voided approval can be approved again with the SAME certificate while that certificate is still valid. With the
mainnet values the pause (259,200 s) outlasts every certificate (`max_valid_seconds` 3,600 s), so a voided
certificate is dead when the pause ends; `sol_vault.py validate` refuses a mainnet configuration in which
`pauseDuration` is not above `maxValidSeconds`. The program itself does not enforce that relation. A 6-of-7
unpause that ends a pause within the hour re-opens the window for a still valid certificate: the six signers who
end a pause early are stating that the voided approvals may stand.

### 3.5 `guardian_pause`

The certificate must hold exactly one signature, of a guardian, over the pause authorization for pause number
`pause_count + 1`. Anyone may deliver it: the guardian's power is its secp256k1 key, and the authorization can be
used once because it names the pause it starts. Conditions as on Ethereum: not already paused, not within the
cooldown after a committee unpause, and each guardian starts at most one pause per chain of consecutive pauses.
The pause lasts `pause_duration`, stops deposits, approvals and payments, and **voids every approval not yet paid**
(`void_through_seq = approval_seq`).

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

## 4. Layouts

Every program account starts with a type tag and a layout version (1). Nothing is reallocated after creation.

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
| 272 | 2 | `deposit_fee_bps` |
| 274 | 2 | `release_fee_bps` |
| 276 | 1 | `threshold` |
| 277 | 1 | `switch_threshold` |
| 278 | 1 | `signer_count` (at most 16) |
| 279 | 1 | `guardian_count` (at most 7) |
| 280 | 20 each | the signers, then the guardians; nothing after them |

Validation (the rules of the `ProvenanceSourceVault` constructor, plus the Solana-only values): each fee at most
30 bps; fee owner, mint, chain id, the three labels non-zero; source and native domain different; `cap > 0`;
`2 <= threshold <= signer_count`; `threshold <= switch_threshold <= signer_count`;
`0 < window_limit <= cap`; `window_seconds > 0`; `l2_min_burn > 0`;
`l2_min_burn <= min_deposit <= window_limit`; `min_deposit` less its deposit fee is at least `l2_min_burn`;
`release_delay <= 14 days`, and `large_release_threshold` must be zero when `release_delay` is zero;
`60 <= max_valid_seconds <= 86400`; without guardians both pause values are zero, with guardians
`0 < pause_duration <= 14 days` and `pause_duration <= pause_cooldown <= 14 days`; signers strictly ascending
(so non-zero and distinct); guardians strictly ascending and none of them a signer. At `initialize` also: the fee
owner is not the vault, its token account or the mint.

### 4.2 Vault state (1,130 bytes)

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | tag = 1 |
| 1 | 1 | layout version = 1 |
| 2 | 1 | vault bump |
| 3 | 1 | token account bump |
| 4 | 32 | configuration hash |
| 36 | 280 | the fixed part of the configuration, verbatim |
| 316 | 320 | signers, 16 slots of 20 bytes (unused slots zero) |
| 636 | 140 | guardians, 7 slots of 20 bytes |
| 776 | 20 | `vault20` |
| 796 | 20 | `mint20` |
| 816 | 32 | `route` |
| 848 | 32 | mint chain genesis |
| 880 | 32 | vault token account address |
| 912 | 32 | fee token account address |
| 944 | 32 | `head`: deposit chain head after `deposit_count` deposits |
| 976 | 8 | `deposit_count` |
| 984 | 8 | `total_locked` |
| 992 | 8 | `fees_accrued` |
| 1000 | 8 | `control_nonce` |
| 1008 | 1 | `deposits_enabled` |
| 1009 | 1 | `releases_enabled` |
| 1010 | 8 | `release_bucket` |
| 1018 | 8 | `bucket_updated_at` |
| 1026 | 8 | `paused_until` |
| 1034 | 8 | `pause_count` |
| 1042 | 8 | `guardian_blocked_until` |
| 1050 | 8 | `pause_chain` |
| 1058 | 56 | `guardian_last_chain`, one u64 per guardian slot |
| 1114 | 8 | `approval_seq` |
| 1122 | 8 | `void_through_seq` |

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

### 4.4 Release record (176 bytes)

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
| 110 | InvalidPause | | |

Data logs (`sol_log_data`; the first field is the tag):

| Tag | Following fields |
|---|---|
| `BLOCH-SVM-VAULT-INITIALIZED-v1` | vault address, `vault20`, route |
| `BLOCH-SVM-DEPOSITED-v1` | the 211 bytes of the deposit record |
| `BLOCH-SVM-RELEASE-APPROVED-v1` | the 176 bytes of the release record |
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
| 2 | Optional uniform `releaseDelay` with a forged-mint challenge; 0 at launch | `release_delay` applies to releases above `large_release_threshold`; a guardian pause voids every approval not yet paid, which then needs a new certificate | The two steps exist anyway, so a waiting period for large items costs nothing. Voiding makes a pause-only guardian effective against a wrong approval that honest signers will not sign again; against five compromised keys it only delays. No forged-mint challenge (`proveForgedMint`) is ported: it belongs to `releaseDelay` mode with a mint verifier, which is not the launch design |
| 3 | One-way light-client switch (`proposeVerifier`, `cancelVerifier`, `activateVerifier`, `releaseWithProof`) | None | The light-client path is out of scope in round 16. Consequence: the committee can never be retired on this vault; the only succession is a migration to a new vault |
| 4 | The certificate binds an Ethereum block hash, checked with `blockhash` (256 blocks) | The certificate carries an anchor slot and hash that are signed but not compared with chain history; the program requires the slot to be below the clock, and bounds a certificate's life with `max_valid_seconds` | The SlotHashes sysvar covers 512 slots (a few minutes), less than the time to collect signatures. The provenance check already binds a release to this vault's own deposit history, which is what the fork binding protects on Ethereum |
| 5 | `validUntil` only has to be in the future | Also at most `max_valid_seconds` ahead | Replaces the 256-block lifetime bound of item 4; a certificate cannot be kept for later, and a certificate voided by a 72 h pause is dead when the pause ends |
| 6 | A guardian pauses by sending the transaction (`msg.sender`) | A guardian signs a pause authorization with its secp256k1 key; anyone delivers it | No new key type for guardians. The authorization names the pause it starts, so it is used once |
| 7 | The burn's `ethRecipient` is the paid address | The burn names a 20-byte commitment to a 32-byte wallet; payment goes to that wallet's associated token account, and the wallet is supplied at payment | The unchanged token's `burn` carries 20 bytes. A wallet other than the committed one needs a second preimage of 160 bits |
| 8 | `releasedNonce` and `releasedBurn` | One release record per burn nonce; the native burn id is stored in it and bound by the certificate, but is not a second replay key | Each replay key on Solana is an account with rent. The burn nonce is the token's own counter. Consequence: if the committee certified one burn id under two nonces, the Ethereum vault would refuse the second and this vault would not |
| 9 | Deposits are events; the chain head per count is a mapping | Each deposit is an account (the depositor pays its rent); the head after each deposit is stored in it | A release must be checked against the head at an earlier count, and state is what a watcher can read reliably at `finalized` |
| 10 | `feeRecipient` is an address | The fee owner is a wallet; fees go to its associated token account, which must exist before the first sweep | A token account is needed to receive SPL tokens. Fees are swept separately, so a missing or frozen fee account never blocks a release |
| 11 | The constructor deploys one vault | `initialize` is permissionless and configuration-addressed | No deployer power, no front-running of the address |
| 12 | `depositsEnabled` and `releasesEnabled` start false | The same | Unchanged: a 5-of-7 `set_controls` opens the vault |
| 13 | The issuer can blacklist addresses and pause or upgrade the token | The issuer's freeze authority can freeze any USDC token account | Section 12 |
| 14 | No storage cost for the user | Rent: deposit record paid by the depositor, release record by the relayer | Section 10 |
| 15 | `nonReentrant` guard | None | The runtime refuses reentrancy into a program that is already on the call stack (other than direct self-recursion, which the program never does), and the classic token program calls no other program |
| 16 | `transferMode` for tokens that return nothing | Classic SPL Token only | Section 12 |
| 17 | Up to 16 signers with any threshold | Up to 16 signers; in practice the release threshold is at most 6 | A 7-signature approval is 1,310 bytes. An address lookup table would lift this; none is used |
| 18 | `executeRelease` of a queued release checks only the pause | The same: `execute_release` does not check `releases_enabled` | Kept as on Ethereum |

## 9. No upgrade authority

The program is deployed with `solana program deploy --final`: the upgradeable loader (v3) writes the program data
account with no upgrade authority, and the program can never be changed or closed. An upgradeable program would
be an administrator key over every vault, and the owner's rule is none.

The program enforces this itself: `initialize` requires the program data account of the running program
(`find_program_address(program id)` under the upgradeable loader, owned by the loader, tag `ProgramData`) to have
no upgrade authority, and fails with `ProgramUpgradeable` otherwise. A vault of this program therefore exists only
under final code.

## 10. Size, compute and rent

Measured in the in-process SVM of the test suite (litesvm 0.18.2, Agave 4.3 runtime). The secp256k1 verification
itself runs in the native program and is not counted in these compute units.

| Instruction | Signatures | Transaction bytes (limit 1,232) | Compute units |
|---|---|---|---|
| `approve_release` | 5 | 1,118 | 15,550 |
| `approve_release` | 6 | 1,214 | 17,171 |
| `approve_release` | 7 | 1,310, does not fit | not sent |
| `execute_release` | 0 | 408 | 12,456 |
| `deposit` | 0 | 430 | 14,139 |
| `guardian_pause` | 1 | 437 | 6,120 |
| `unpause` | 6 | 925 | 6,473 |
| `set_controls` | 5 | 831 | 6,448 |
| `initialize` (7 signers, 3 guardians) | 0 | 850 | not measured |

On a real validator (solana-test-validator of Agave v4.4.1, the local rehearsal, `computeUnitsConsumed` of the
transaction): `approve_release` with 5 signatures 15,550; `execute_release` 13,994 for the wallet of one run (the
program searches the bump of the recipient's associated token address, about 1,500 units per miss, so the figure
depends on the wallet: each further miss has probability one half, and a wallet ground to cost 40 misses would
still stay under 80,000); `guardian_pause` 6,120; `unpause` with 6 signatures 6,473. The figures of each run are
in the rehearsal's `result.json`.

All are far below the default limit of 200,000 compute units per instruction; no compute budget instruction is
needed. The canonical certificate is `61 + 96 n` bytes for `n` signatures.

Rent-exempt minimums by the standard formula, `(128 + bytes) * 3480 * 2` lamports. These are formula values, to
be confirmed with `getMinimumBalanceForRentExemption` on the cluster:

| Account | Bytes | Lamports | Paid by |
|---|---|---|---|
| Deposit record | 211 | 2,359,440 (about 0.00236 SOL) | the depositor, per deposit |
| Release record | 176 | 2,115,840 (about 0.00212 SOL) | the relayer, per release |
| Vault state | 1,130 | 8,755,440 | whoever initializes, once |
| Vault token account, or any associated token account | 165 | 2,039,280 | whoever creates it |

None of these accounts is ever closed, so the rent is a cost, not a deposit that returns. The release record is an
operating cost of the relayer for every release, larger than the 5 bps fee of a small release, which goes to the
fee owner and not to the relayer.

## 11. The L2 side

`BridgedStablecoinV3` is used byte-identical (creation code keccak256
`0xe560441f37e247e387cebd23bb3dd798a29d34174a9fb19a4bb3877c6c721de7`, rebuilt on 2026-11-16 in this branch).
Its semantics fit with constructor arguments alone: 6 decimals, `sourceChainId_` = the source chain id of
section 1, `sourceVault_` = `vault20`, `sourceRoute_` = the vault's route. Its mint chain genesis
`keccak256(abi.encode(MINT_CHAIN_TAG, sourceChainId_, sourceVault_, sourceRoute_))` is then the vault's.

The one place where 20 bytes are not enough is the burn recipient. A holder burns to the commitment of their
Solana wallet, and publishes the wallet once on `contracts/solana/SolanaRecipientRegistry.sol`
(`announce(bytes32 solanaWallet)`), a stateless notice board with no owner, no funds and no approvals. The
registry is a convenience for relayers. Safety rests on the vault's own hash check: an announcement by anyone, true
or false, cannot redirect a payment.

A burn to a commitment whose wallet nobody knows cannot be paid until the wallet is supplied. A burn to a
commitment computed wrongly (for example the hash of a token account instead of the wallet) is paid to the
associated token account of whatever 32 bytes hash to it, if anyone ever finds them: in practice it is lost.
Frontends must compute the commitment with the registry's `commitmentOf`.

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

A signer attests a deposit only when its deposit record account is read at `finalized` commitment on the signer's
own node and the record's slot is at least `finality_margin_slots` (default 150) below the finalized slot. Skipped
slots do not matter: the signer reads account state at a commitment, not blocks by number.

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
