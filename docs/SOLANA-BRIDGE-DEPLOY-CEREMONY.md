# Solana bridge (`bUSDC.sol`): deployment and key ceremony

Status: **UNAUDITED. Nothing is deployed. Do not run this on mainnet before the Solana vault has had its own
external audit.** No command here was run on a public network. The tool commands (`sol_vault.py`, `sol_half.py`)
are named as agreed while the tools were being written; check each against the tool's `--help` before use.

Read first: `docs/SOLANA-VAULT.md` (what the program does) and `docs/BRIDGE-V3-KEY-CEREMONY.md` (how every
secp256k1 key is generated, attested and taken in). This document adds only what Solana changes.

Commands are one per block, without comments. Values in capitals are set first, in the same shell.

## 1. Keys: what is new and what is reused

**New key type: none for signers or guardians.** One thing is unavoidable on Solana: every transaction needs an
ed25519 fee payer. Fee-payer keys pay SOL for transactions and rent and have **no power over the vault**: every
vault instruction is either permissionless or authorized by secp256k1 signatures inside the transaction. They are
the Solana equivalent of the `eth-relayer-gas` keys.

| Role | Count | Key type | Reused from | Power on Solana | Holder |
|---|---|---|---|---|---|
| Release signer | 7, threshold 5, unpause 6 | secp256k1 | the seven `eth-release-signer` keys of the Ethereum bridge | 5 of 7 approve releases and set controls; 6 of 7 end a pause early | signer operators 1 to 7 |
| L2 mint signer | 7, threshold 5 | secp256k1 | the seven `l2-mint-signer` keys | mints on the `bUSDC.sol` token (L2 only) | the same operators |
| Vault guardian | 3 | secp256k1 | the three `eth-vault-guardian` keys | one signature pauses the vault for 72 h and voids approvals not yet paid | guardian operators 1 to 3 |
| L2 token guardian | 3 | secp256k1 | the three `l2-token-guardian` keys | pause and cancel on the L2 token | the same operators |
| Relayer fee payer | 1 per relayer | ed25519 (new, no vault power) | none | pays fees and release-record rent | relayer operators |
| Guardian fee payer | 1 per guardian operator | ed25519 (new, no vault power) | none | pays the fee of delivering that guardian's pause | guardian operators |
| Deployer fee payer | 1 | ed25519 (new, no vault power after the deployment) | none | pays the program deployment and `initialize` | owner |
| Program keypair | 1 | ed25519, throwaway | none | fixes the program id at the first deployment; after `--final` it has no power at all | owner, discarded after the deployment is verified |
| Fee owner | 1 | the owner's existing Solana address | `BMnorAB28mGPthJkbC2iLxbEpWYRCHafgNzV3o8eAJL8` | receives the fees; no power over the vault | owner |
| L2 token deployer | 1 | secp256k1, hardware wallet | as `docs/BRIDGE-V3-KEY-CEREMONY.md` 3.3, a new derivation index | creates the token, then nothing | owner |

Reusing the release and guardian keys across the Ethereum vault and this vault is safe against replay: every
digest contains the source chain id and the vault identity (`docs/SOLANA-VAULT.md` section 1). It does mean that
one exposed key is exposed on both bridges, and the migration rule of the key ceremony (section 6 there) then
applies to both.

The signers sign with the same `cast` keystores as today. Solana never sees a signer or guardian private key.

A relayer or guardian fee payer is generated on the host where it will live:

```
solana-keygen new --no-bip39-passphrase --outfile /etc/bloch-busdc-sol-relayer/fee-payer.json
```
```
chmod 600 /etc/bloch-busdc-sol-relayer/fee-payer.json
```
```
solana-keygen pubkey /etc/bloch-busdc-sol-relayer/fee-payer.json
```

`solana-keygen` writes the key unencrypted. Keep the balance small (a few days of fees and rent), the file mode
600 under a dedicated service user, and replace the key rather than back it up.

## 2. Toolchain, pinned and hash-checked

On a Linux x86_64 build host, in an empty directory, never system-wide:

```
curl -sSL -o solana-release-x86_64-unknown-linux-gnu.tar.bz2 https://github.com/anza-xyz/agave/releases/download/v4.4.1/solana-release-x86_64-unknown-linux-gnu.tar.bz2
```
```
echo "5b0f0fc7e4eedace05f6455de00aa1f2f3d1642068f1e8d50760ba49112c3941  solana-release-x86_64-unknown-linux-gnu.tar.bz2" | sha256sum -c -
```
```
tar -xjf solana-release-x86_64-unknown-linux-gnu.tar.bz2
```
```
export PATH="$PWD/solana-release/bin:$PATH"
```
```
solana --version
```
```
cargo-build-sbf --version
```

Expected: `solana-cli 4.4.1 (src:5bb30402; ...)` and `cargo-build-sbf 4.5.0`, `Default platform-tools: v1.57`.
The sha256 is the digest GitHub publishes for the release asset; it proves the download is the published file,
not who published it.

Rust comes from rustup (check `rustup-init` against the `.sha256` file published beside it):

```
rustup toolchain install 1.95.0 --profile minimal
```
```
rustup toolchain install 1.97.1 --profile minimal
```

## 3. Build and the program hash

At the reviewed git revision (`source.revision` of the vault config), in a clean checkout:

```
git status --porcelain
```
```
cd solana/bloch-sol-vault
```
```
cargo build-sbf -- --locked
```
```
sha256sum target/deploy/bloch_sol_vault.so
```

The first command must print nothing. A second person builds on a second machine and both compare the hash; it
goes into `program.elfSha256` of the vault config. Whether the build is byte-reproducible across machines and
directories has not been established in this document; if two builds differ, stop and find out why before
deploying. The whole test suite is `solana/run-tests.sh`.

`cargo build-sbf` also writes `target/deploy/bloch_sol_vault-keypair.json`. Do not use it; generate the program
keypair yourself (section 5).

## 4. The vault configuration

Fill `deployments/solana/busdc-sol-vault.config.json` from the key inventory of
`docs/BRIDGE-V3-KEY-CEREMONY.md` section 4.2: `vault.signers.set` with the seven `eth-release-signer` addresses
and their operators, `vault.guard.guardians` with the three `eth-vault-guardian` addresses, both ascending;
`source.revision`; `program.elfSha256`. `program.id` and `deployer.address` are filled in section 5.

The fee owner is already filled: `BMnorAB28mGPthJkbC2iLxbEpWYRCHafgNzV3o8eAJL8`. It is part of the vault's
address and can never be changed. Confirm it on the second channel before `init`.

```
python3 tools/signatario-solana/sol_vault.py validate --config deployments/solana/busdc-sol-vault.config.json
```
```
python3 tools/deploy-pontes/legacy_digests.py scan deployments/solana/busdc-sol-vault.config.json deployments/solana/busdc-sol-token.config.json
```

The second command must end with `0 of 2 file(s) hold a refused address`.

## 5. Deploy the program, final

Generate the deployer fee payer and the throwaway program keypair on the deploying machine:

```
solana-keygen new --no-bip39-passphrase --outfile deployer.json
```
```
solana-keygen new --no-bip39-passphrase --outfile program-keypair.json
```
```
solana-keygen pubkey program-keypair.json
```
```
solana-keygen pubkey deployer.json
```

Write the two addresses into `program.id` and `deployer.address`. Fund the deployer with SOL for the program's
rent (the program data account holds the binary: by the rent formula about 0.7 SOL for the current 99,744-byte
binary), the vault and token accounts, the fee account and fees; 1.5 SOL leaves a margin. Then:

```
export RPC=https://YOUR-OWN-NODE
```
```
solana genesis-hash --url $RPC
```

It must print `5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d`.

```
solana program deploy --final --program-id program-keypair.json --keypair deployer.json --url $RPC solana/bloch-sol-vault/target/deploy/bloch_sol_vault.so
```
```
export PROGRAM_ID=$(solana-keygen pubkey program-keypair.json)
```
```
solana program show $PROGRAM_ID --url $RPC
```

`show` must report the upgradeable loader as owner and **no upgrade authority** (`Authority: none`). If it shows
an authority, the program is not final: do not initialize anything on it (the program would refuse anyway), and
start again with a new program keypair.

Compare the deployed binary with the built one:

```
solana program dump $PROGRAM_ID deployed.so --url $RPC
```
```
cmp --bytes=$(stat -c %s solana/bloch-sol-vault/target/deploy/bloch_sol_vault.so) deployed.so solana/bloch-sol-vault/target/deploy/bloch_sol_vault.so
```

`cmp` must print nothing. (The dump can be longer than the file, padded with zeros.)

After this the program keypair has no power. Delete `program-keypair.json` once section 6 has passed.

## 6. Initialize and verify the vault

```
python3 tools/signatario-solana/sol_vault.py address --config deployments/solana/busdc-sol-vault.config.json --program-id $PROGRAM_ID
```

This prints the vault address, its token account, `vault20`, the route and the fee token account, all derived
offline. A second reviewer derives them on their own machine. They do not exist on chain yet.

```
python3 tools/signatario-solana/sol_vault.py init --config deployments/solana/busdc-sol-vault.config.json --program-id $PROGRAM_ID --rpc $RPC --fee-payer deployer.json
```
```
python3 tools/signatario-solana/sol_vault.py verify --config deployments/solana/busdc-sol-vault.config.json --program-id $PROGRAM_ID --rpc $RPC
```

`initialize` is permissionless: if anyone else sends it first with the same configuration, the result is the same
vault, and `init` then has nothing to do. `verify` reads the vault at `finalized` and compares every stored value
with the config, the program's finality and the binary hash. Its output gives `vault20` and `route` for the token
config.

Create the fee owner's USDC account (anyone may; the deployer pays about 0.00204 SOL of rent):

```
spl-token create-account EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v --owner BMnorAB28mGPthJkbC2iLxbEpWYRCHafgNzV3o8eAJL8 --fee-payer deployer.json --url $RPC
```

It must print `2VMpYFjydEYUu1Jw8KhfxBGDT7zRUkBqjKc6DZziqayg`, the associated token account of the fee owner for
the USDC mint (seeds: fee owner, token program, mint; bump 253), which is also the address `verify` shows as the
vault's fee token account. `sol_vault.py create-fee-account` does the same through the tool.

The vault is now initialized with deposits and releases **off**.

## 7. The L2 token

The token is `BridgedStablecoinV3`, byte-identical, with the constructor arguments of
`deployments/solana/busdc-sol-token.config.json`:

| Argument | Value |
|---|---|
| `name_`, `symbol_` | `Bloch Bridged USDC (Solana)`, `bUSDC.sol` |
| `sourceChainId_` | `51590065195979758212148511635863778762156068118565365102773110171893804236268` |
| `sourceVault_` | `vault20` from `sol_vault.py verify` |
| `sourceRoute_` | the route from `sol_vault.py verify` |
| `signers_`, `threshold_` | the seven `l2-mint-signer` addresses, ascending; 5 |
| `limits` | supply cap 100,000 USDC; bucket 10,000 USDC, refill 115,740 units per second; large mint threshold 0; large mint delay 43,200 s; min burn 10 USDC |
| `guard` | the three `l2-token-guardian` addresses, ascending; 259,200 s pause and cooldown |
| `mintSwitch` | 6, 1,209,600 s |

**What of `tools/deploy-pontes/deploy_pontes.py` applies, and what is not built.** The tool's stable-bridge
schema requires an `ethereum` section (`chainId`, `vault`, `route`, `vaultCodeHash`, `vaultCap`, `vaultGuard`),
its mainnet policy requires `ethereum.chainId` to be 1, and its `run` and `verify` steps read the source vault
over an Ethereum JSON-RPC given as `--source-rpc`: the vault's code hash, `routeId()`, `cap()`, and that the vault
was never used. None of that can be answered by a Solana vault. What carries over unchanged is everything on the
L2 side: the plan (constructor arguments, init code hash, the CREATE address from deployer and nonce, the linked
runtime code), the single offline-signed creation, the record, and the L2 half of `verify` (runtime code hash,
immutables, signer and guardian sets, domain separator).

**Not built:** a Solana source mode for `deploy_pontes.py` that accepts
`deployments/solana/busdc-sol-token.config.json` and replaces the Ethereum vault checks by these, read from the
owner's own Solana node at `finalized`: the program is final and its binary hash is `program.elfSha256`; the
vault account exists at the derived address with exactly the config's values; `vault20`, the route and the cap
equal the token's `sourceVault`, `sourceRoute` and supply cap; the guardians match; and the vault is unused
(deposit count 0, total locked 0, control nonce 0), because a second token over a used vault would mint its old
deposits again. Until that mode exists and is reviewed, the token for this bridge must not be deployed: doing the
same checks by hand is the kind of step the tool exists to remove.

## 8. The registry

`contracts/solana/SolanaRecipientRegistry.sol` has no constructor argument, no owner and no state. It is deployed
once on the L2 by any funded account, and its address goes into `registry.address` of the token config and into
the frontend:

```
forge create contracts/solana/SolanaRecipientRegistry.sol:SolanaRecipientRegistry --rpc-url $L2_RPC --legacy --ledger --mnemonic-derivation-path "$REGISTRY_PATH" --broadcast
```

Check it after deployment against the vector of the test suite:

```
cast call $REGISTRY "commitmentOf(bytes32)(address)" 0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20 --rpc-url $L2_RPC
```

It must print `0xAb01517717adDE67e6faD935048BFcdF8FD4c364`.

## 9. Open the vault (5 of 7)

Only after the token is deployed and verified and the signers, guardians and relayers run. Each of five signer
operators signs the same controls message on their own host; one of them, or anyone, submits the five partials:

```
python3 tools/signatario-solana/sol_vault.py controls-sign --config deployments/solana/busdc-sol-vault.config.json --program-id $PROGRAM_ID --rpc $RPC
```
```
python3 tools/signatario-solana/sol_vault.py controls-submit --config deployments/solana/busdc-sol-vault.config.json --program-id $PROGRAM_ID --rpc $RPC --fee-payer /etc/bloch-busdc-sol-relayer/fee-payer.json
```
```
python3 tools/signatario-solana/sol_vault.py show --config deployments/solana/busdc-sol-vault.config.json --program-id $PROGRAM_ID --rpc $RPC
```

`show` must report deposits and releases enabled and control nonce 1. A controls certificate is valid for at most
`maxValidSeconds` (3,600 s), so the five signatures are collected within the hour.

## 10. Owner checklist (TBD-owner)

| # | Item | Answer |
|---|---|---|
| 1 | External audit of the Solana program, the registry and the Solana tools: firm, scope (`docs/AUDIT-SCOPE-BRIDGE-SOLANA.md`), report | TBD-owner |
| 2 | Fee owner on Solana, immutable in the vault address: confirm on the second channel | `BMnorAB28mGPthJkbC2iLxbEpWYRCHafgNzV3o8eAJL8` (round 16 brief, 2026-11-16); fee account `2VMpYFjydEYUu1Jw8KhfxBGDT7zRUkBqjKc6DZziqayg` |
| 3 | Confirm that the seven release keys and three vault guardian keys of the Ethereum bridge are reused here (coordinator decision), and that one exposed key then migrates both bridges | TBD-owner |
| 4 | `largeReleaseThreshold` 1,000 USDC and `releaseDelay` 1,800 s (the Ethereum vault has no delay), or 0 and 0 | TBD-owner |
| 5 | Cap 100,000 USDC and window 10,000 USDC per day for this bridge | TBD-owner |
| 6 | Each signer and guardian operator's own Solana RPC node (an Agave validator in RPC mode, or a provider contract per operator that no two operators share) | TBD-owner |
| 7 | Relayer operators, their fee-payer addresses, SOL top-up amount and alert level | TBD-owner |
| 8 | Deployer fee payer funded; program keypair deleted after verification; `solana program show` output with no authority, kept | TBD-owner |
| 9 | Build hash from two machines, equal | TBD-owner |
| 10 | The Solana source mode of `deploy_pontes.py` (section 7) built and reviewed before the token is deployed | TBD-owner |
| 11 | Registry address on the L2 | TBD-deploy |
| 12 | Who creates a recipient's missing token account: the user (default), or the relayer under a stated limit | TBD-owner |
