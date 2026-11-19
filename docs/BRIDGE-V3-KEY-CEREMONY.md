# bUSDC bridge V3: key ceremony runbook

Scope: every key of the bUSDC bridge V3 launch design (`BridgedStablecoinV3` on Bloch L2 700770 over
`ProvenanceSourceVault` on Ethereum, branch `codex/bridge-v3-r7-20261102`), plus the keys around it that the deploy
needs: the deployers, the Bloch Inc Safe, the light-client `recoveryAuthority` and the relayer gas keys.

This runbook comes before `docs/BUSDC-MAINNET-V2.md` section 4.1. The public result of the ceremony is the
inventory (`deployments/mainnet/busdc-keys.inventory.json`) that `tools/deploy-pontes/key_inventory.py check`
accepts. Every address in both deploy configs comes from that inventory.

The executable, rehearsed form of this runbook (every command block run end to end on loopback stand-ins, the vault
and token deployment, the handover, the first round trip and the pause drills) is `docs/BRIDGE-OWNER-CEREMONY.md`
(round 18); this file keeps the rules, the attack table, the backup and the loss policy it relies on.

Nothing here has run with a real key. The generation, attestation, backup and intake commands were rehearsed with
throwaway keys in a temporary directory, which was then deleted (section 9).

## 1. Rules for every key

1. **One key, one role, one holder.** No address appears twice in the inventory. A signer operator holds one L2 mint
   key and one Ethereum release key, and they are different keys. Guardian operators run no signer.
   `recoveryAuthority` owners run no signer.
2. **A key is generated where it lives,** by the person who holds it. The owner never generates, receives or stores
   another holder's key. No key, keystore, password or seed phrase passes through chat, email, a repository, a shared
   drive, an AI agent or the owner's Mac.
3. **Only public data travels:** role, index, operator, address, date and the attestation signature. The address is
   then confirmed on a second channel (section 4.2).
4. **Never reuse a committed address.** `busdc-mainnet.config.json` and `wgnb-mainnet.config.json` carry addresses
   committed on 2026-10-14 (`d3f8a1f`, `0315afd`): the deployers `0x703a12b4…0F3b` and `0xa64b47b0…504A`, 14 signer
   and 6 guardian addresses. They were generated in one place and nobody has recorded who holds them, so a 5-of-7
   threshold over them means nothing. `key_inventory.py` refuses all 22 unless each one is named with
   `--allow-legacy-address`, which this runbook does not recommend.
5. **No on-chain rotation exists** for signers, guardians or limits (`docs/AUDIT-SCOPE.md` V7). The vault and the
   token have no owner, no setter and no upgrade. A lost or exposed key of the bridge sets is handled by a migration
   (section 6).
6. **Pinned tools.** Use Foundry `cast` 1.7.1 (commit `4072e487`), the version the suites and this rehearsal used.
   Every holder checks the binary's SHA-256 against the value the owner publishes in the checklist (section 8).

## 2. Inventory

| Role (`key_inventory.py`) | Count | Chain | Contract power | Holder | Custody | Online? |
|---|---|---|---|---|---|---|
| `l2-mint-signer` | 7 | L2 700770 | 5 of 7 queue mints and remints; 6 of 7 unpause the token, locked remint, propose or cancel the mint verifier switch | Signer operator 1..7 | Encrypted keystore on the signer host | Hot (`signatario.py`, `vigia.py sign`) |
| `eth-release-signer` | 7 | Ethereum | 5 of 7 certify releases and `setControls`; 6 of 7 end a vault pause and propose or cancel the verifier switch | Same operator 1..7 | Encrypted keystore on the signer host | Hot (`eth_half.py`) |
| `l2-token-guardian` | 3 | L2 | One pauses mints 72 h; 2 of 3 cancel a queued mint | Guardian operator 1..3 | Encrypted keystore on the guardian host | Hot (`guardiao.py`) |
| `eth-vault-guardian` | 3 | Ethereum | One pauses the vault 72 h (deposits and releases) | Guardian operator 1..3 | Encrypted keystore on the guardian host | Hot (`guardiao.py`, later `sombra.py`) |
| `eth-vault-deployer` | 1 | Ethereum | Creates the vault at nonce 0, then nothing | Owner | Hardware wallet, fresh account | Once |
| `l2-token-deployer` | 1 | L2 | Creates the token at nonce 0, then nothing | Owner | Hardware wallet, fresh account | Once |
| `bloch-inc-safe` + 5 `bloch-inc-safe-owner` | 1 + 5 | Ethereum and L2 | No bridge power; funds the deployers' gas | 5 people, 3 of 5 | Hardware wallets | Cold |
| `recovery-authority` + its owners | 1 + n | Ethereum | `RecoverableReleaseVerifier`: proposes a successor verifier after the switch to the light client | Owner-chosen people, m of n | Safe of hardware wallets | Cold |
| `l2-relayer-gas`, `eth-relayer-gas` | 1 each (or one per relayer) | L2, Ethereum | None: pays gas for relayed mints and releases | Relayer operator | Encrypted keystore, password through systemd `LoadCredential=` (what `vigia.py relay` reads) | Hot |

**Guardian mapping (owner decision 2026-11-02, BR-6).** The vault config now has 3 Ethereum guardian slots, and
`vault_pontes.py validate` requires exactly 3 on mainnet: 3 Ethereum vault guardians, held by the same 3
independent guardian operators as the L2 token guardians, with a separate key per chain. Each operator's
`guardiao.py` uses its L2 key as `keystore` and its Ethereum key as `eth_keystore`. When `sombra.py` is ported to the
HF line, it runs at one of the three operators with that operator's Ethereum guardian key: the vault set is
immutable, so a fourth, independent sombra operator would have had to be in the vault from day one; the owner chose 3
(4 would need a change to the mainnet policy in both tools). The L2 shape stays frozen at 7 signers and
3 guardians (token creation 4,822,592 gas against the 5,000,000 `max_tx_gas`, agent 194 at 8d988ce).

**Hardware choice for hot keys.** The signer and guardian keys sign automatically, so they cannot sit in a hardware
wallet that needs a button press. The daemons call `cast` with `--keystore` and `--password-file` only. `cast` also
supports `--aws` and `--gcp` KMS signing, but the daemons have no code path for it, so an HSM or KMS would be a tool
change and a new review. With today's tools the protection is: a dedicated host per operator, full-disk encryption,
a dedicated service user, files with mode 600 and the password in a separate file. The keystore encryption (scrypt,
AES-128-CTR, checked in the rehearsal) protects a copied disk or backup. It does not protect against someone who
controls the running host, because the password file sits next to it.

## 3. Generation

Each holder runs these commands on the host where the key will live. Commands are one per block, without comments.
Values in capitals are set first, in the same shell.

### 3.1 Signer operator (one L2 mint key and one Ethereum release key)

On the signer host, as root, with the disk already encrypted, the service user created
(`bloch-busdc` here) and `cast` 1.7.1 at `/opt/foundry/bin/cast`:

```
export OP=signer-op3 IDX=3 DAY=2026-11-10 D=/etc/bloch-busdc-signer
```
```
install -d -m 0700 -o bloch-busdc -g bloch-busdc /etc/bloch-busdc-signer
```
```
sudo -u bloch-busdc sh -c 'umask 077; openssl rand -base64 32 > /etc/bloch-busdc-signer/l2-mint.password'
```
```
sudo -u bloch-busdc sh -c 'CAST_PASSWORD="$(cat /etc/bloch-busdc-signer/l2-mint.password)" /opt/foundry/bin/cast wallet new /etc/bloch-busdc-signer l2-mint.keystore'
```
```
sudo -u bloch-busdc sh -c 'umask 077; openssl rand -base64 32 > /etc/bloch-busdc-signer/eth-release.password'
```
```
sudo -u bloch-busdc sh -c 'CAST_PASSWORD="$(cat /etc/bloch-busdc-signer/eth-release.password)" /opt/foundry/bin/cast wallet new /etc/bloch-busdc-signer eth-release.keystore'
```

`cast wallet new` prints `Created new encrypted keystore file` and `Address:`. It never prints the private key. The
password goes through the `CAST_PASSWORD` environment variable, not through argv, so `ps` does not show it.
The file names are those of `signer.template.json` and `eth-half.template.json`.

Read the two addresses back from the files:

```
sudo -u bloch-busdc /opt/foundry/bin/cast wallet address --keystore $D/l2-mint.keystore --password-file $D/l2-mint.password
```
```
sudo -u bloch-busdc /opt/foundry/bin/cast wallet address --keystore $D/eth-release.keystore --password-file $D/eth-release.password
```

Set them with `export MINT_ADDR=0x… REL_ADDR=0x…`, then make the two attestations (proof of possession, section 4.1):

```
MSG=$(python3 /opt/bloch-bridge/tools/deploy-pontes/key_inventory.py message --role l2-mint-signer --index $IDX --operator $OP --address $MINT_ADDR --date $DAY)
```
```
sudo -u bloch-busdc /opt/foundry/bin/cast wallet sign --keystore $D/l2-mint.keystore --password-file $D/l2-mint.password "$MSG"
```
```
MSG=$(python3 /opt/bloch-bridge/tools/deploy-pontes/key_inventory.py message --role eth-release-signer --index $IDX --operator $OP --address $REL_ADDR --date $DAY)
```
```
sudo -u bloch-busdc /opt/foundry/bin/cast wallet sign --keystore $D/eth-release.keystore --password-file $D/eth-release.password "$MSG"
```

### 3.2 Guardian operator (one L2 token guardian key and one Ethereum vault guardian key)

Same steps on the guardian host with the paths of `guardiao.template.json`: directory `/etc/bloch-guardiao`, files
`busdc.keystore` and `busdc.pw` (L2) and `busdc-eth.keystore` and `busdc-eth.pw` (Ethereum), roles
`l2-token-guardian` and `eth-vault-guardian`, `OP=guard-op1` and so on. The guardian host is not a signer host and is
run by a different person and hosting account.

### 3.3 Deployers (owner, hardware wallet)

Two fresh accounts on the owner's hardware wallet, one per chain, at derivation indexes never used before. The device
seed is the backup, so no extra copy exists. Pick the two indexes and write them in the checklist.

```
export VAULT_PATH="m/44'/60'/41'/0/0" TOKEN_PATH="m/44'/60'/42'/0/0" DAY=2026-11-10
```
```
cast wallet address --ledger --mnemonic-derivation-path "$VAULT_PATH"
```
```
cast wallet address --ledger --mnemonic-derivation-path "$TOKEN_PATH"
```

Set them with `export VAULT_DEPLOYER=0x… TOKEN_DEPLOYER=0x…`. Each must have nonce 0 on its chain (`validate` and `run` check it again later):

```
cast nonce $VAULT_DEPLOYER --rpc-url "$ETH_RPC"
```
```
cast nonce $TOKEN_DEPLOYER --rpc-url "$L2_RPC"
```

Attest each one as in 3.1, with `--ledger --mnemonic-derivation-path "$VAULT_PATH"` (or `"$TOKEN_PATH"`) in place of
`--keystore` and `--password-file`, and roles `eth-vault-deployer` and `l2-token-deployer`.

**Not rehearsed with a device:** the L2 token creation is a legacy transaction on chain 700770 with large init code
(4,787,273 gas of creation), which the device must blind-sign. Before mainnet, run `tools/deploy-pontes/rehearse_anvil.py` on a private
anvil with chain id 700770 and pass `--ledger --mnemonic-derivation-path` as the wallet arguments of
`deploy_pontes.py run`, using a third, throwaway index. If the device refuses, the fallback is an air-gapped keystore
(`air-gapped-keystore` custody), carried to the broadcasting machine only for the one `run --broadcast`.

After each deployment is verified: send the deployer's remaining balance back to the Safe, record the final nonce
(1) in the checklist, and never use that derivation index again. A deployer that has sent anything other than its
one creation is burned: the deployment restarts with a new index and a new plan (`BUSDC-MAINNET-V2.md` 4.3).

### 3.4 Bloch Inc Safe owners and the `recoveryAuthority`

Each owner initializes their own hardware wallet: the seed is generated on the device and written on paper or metal,
then stored away from the device. Each owner attests their owner address with `cast wallet sign --ledger` and the
roles `bloch-inc-safe-owner` or `recovery-authority-owner`.

The `recoveryAuthority` is a **separate** Safe on Ethereum. It holds no other role, and no signer or guardian
operator is among its owners (`key_inventory.py` refuses that). It is needed only when the vault switches to the
light client, but its address is immutable in `RecoverableReleaseVerifier`, so it must exist and pass these checks
before that verifier is deployed:

```
cast call "$RA_SAFE" "getOwners()(address[])" --rpc-url "$ETH_RPC"
```
```
cast call "$RA_SAFE" "getThreshold()(uint256)" --rpc-url "$ETH_RPC"
```
```
cast call "$RA_SAFE" "getModulesPaginated(address,uint256)(address[],address)" 0x0000000000000000000000000000000000000001 10 --rpc-url "$ETH_RPC"
```

The owners must equal the attested `recovery-authority-owner` addresses, the threshold must equal the agreed m, and
the module list must be empty. Run the same three checks on the Bloch Inc Safe on every chain where it exists.
A Safe as authority has one benefit: owners can be replaced inside the Safe (`swapOwner`, m of n) while the
authority address that the verifier pins stays the same.

### 3.5 Relayer gas keys

`vigia.py relay` takes each gas key as an encrypted keystore (`l2_relayer_keystore`, `eth_relayer_keystore`) and its
password file (`l2_relayer_password_file`, `eth_relayer_password_file`). On chains 700770 and 1 it refuses a raw hex
key file, because `cast` would carry a raw key in argv; it refuses any key, keystore or password file that its group or
other users can read. In the unit (`deploy/signatario/bloch-busdc-relay.service`) the passwords come through systemd
`LoadCredential=`, written `credential:NAME` in the config. Generate the keys on the relayer host; the key is never shown:

```
install -d -m 0700 -o bloch-relayer -g bloch-relayer /etc/bloch-busdc-relayer
```
```
sudo -u bloch-relayer sh -c 'umask 077; openssl rand -base64 32 > /etc/bloch-busdc-relayer/l2-gas.password'
```
```
sudo -u bloch-relayer sh -c 'umask 077; CAST_PASSWORD="$(cat /etc/bloch-busdc-relayer/l2-gas.password)" /opt/foundry/bin/cast wallet new /etc/bloch-busdc-relayer l2-gas.keystore'
```
```
sudo -u bloch-relayer sh -c 'umask 077; openssl rand -base64 32 > /etc/bloch-busdc-relayer/eth-gas.password'
```
```
sudo -u bloch-relayer sh -c 'umask 077; CAST_PASSWORD="$(cat /etc/bloch-busdc-relayer/eth-gas.password)" /opt/foundry/bin/cast wallet new /etc/bloch-busdc-relayer eth-gas.keystore'
```

Attest with `cast wallet sign --keystore … --password-file …` as the relayer user, roles `l2-relayer-gas` and
`eth-relayer-gas`. Keep balances small: a few days of gas, topped up by the Safe.

The earlier weakness (agent 174, Low: `vigia.py` passed a raw hex key to `cast` as `--private-key <hex>`, readable in the
process list) is closed on the public chains by this keystore form. Raw hex files remain for throwaway rehearsal keys only.

## 4. From key to deploy config

### 4.1 Attestation (proof of possession)

The attestation is an EIP-191 signature over a fixed text that names the role, index, operator, address and date:

```
bloch.bridge.key-inventory.v1 attestation: I generated and hold this key. role=l2-mint-signer index=3 operator=signer-op3 address=0x… date=2026-11-10
```

It proves the holder controls the key, and that the address belongs to that role and that operator. An address
copied into the wrong role or slot fails, and so does a signature made by another key (both refused in the
rehearsal).

### 4.2 Intake

1. Each holder sends one record per key (role, index, operator, address, date, signature) on a first channel
   (for example a signed message).
2. The owner calls the holder on a second channel (voice or video) and both read the first 6 and last 6 hex
   characters of each address aloud.
3. The owner adds the record to `deployments/mainnet/busdc-keys.inventory.json`, starting from
   `busdc-keys.inventory.template.json`. Contract accounts (`bloch-inc-safe`, `recovery-authority`) have no
   attestation.
4. The owner fills the configs from the inventory: `signers.set` and `guardians.set` of `busdc-mainnet.config.json`
   with the `l2-*` keys and their operators; `vault.signers.set` and `vault.guard.guardians` of
   `busdc-vault-mainnet.config.json` with the `eth-*` keys; `ethereum.vaultGuard.guardians` of the L2 config with the
   `eth-vault-guardian` addresses, ascending; both `deployer.address` values; both `deployer.fundedBy.safe`.
5. The checks, which a second reviewer repeats on their own machine:

```
python3 tools/deploy-pontes/key_inventory.py check --inventory deployments/mainnet/busdc-keys.inventory.json --token-config deployments/mainnet/busdc-mainnet.config.json --vault-config deployments/mainnet/busdc-vault-mainnet.config.json
```
```
python3 tools/deploy-pontes/vault_pontes.py validate --config deployments/mainnet/busdc-vault-mainnet.config.json --token-config deployments/mainnet/busdc-mainnet.config.json
```
```
python3 tools/deploy-pontes/legacy_digests.py scan deployments/mainnet/busdc-mainnet.config.json deployments/mainnet/busdc-vault-mainnet.config.json
```

The first must print `"decision": "ok"` with `"signaturesChecked": true`. The third must end with
`0 of 2 file(s) hold a refused address` (all 22 retired addresses are checked, by digest).
Then continue with `BUSDC-MAINNET-V2.md` 4.1 (`deploy_pontes.py validate` needs the vault fields from 4.4 too).

What `key_inventory.py check` refuses: a role count outside policy (7, 7, 3, 3, 1, 1, at least 1 relayer key per
chain), an address in two roles, a legacy address, a guardian or `recoveryAuthority` owner who also runs a signer,
release operators that differ from the mint operators, two keys of one role for one operator, a custody class the
role does not allow, an attestation that does not verify, and any difference between the inventory and the two
configs (addresses, operators, deployers, Safe, ascending vault guard).

## 5. Backup

| Key | Backup | Where | Restore test |
|---|---|---|---|
| Mint, release, guardian keystores | One copy of the encrypted keystore on an encrypted USB drive | The operator's own safe, not at the host's site | `cast wallet address --keystore <copy> --password-file <file>` prints the same address |
| Their passwords | Paper, one sheet per key | A different place from the USB drive | The same command |
| Deployers | The device seed | Owner's existing seed storage | None needed after the deployment |
| Safe and authority owners | The device seed on paper or metal | Away from the device, one place per owner | Restore to a spare device once, compare the address |
| Relayer gas keys | None | - | Generate a new key instead |

A backup does not save a key that was exposed. Its purpose is to avoid a migration when a host dies. Each extra copy
is an extra place to steal from, so there is one copy, never in the cloud and never on the owner's Mac. The
rehearsal checked that the backup copy is byte-identical and opens with the password.

Deleting a file on an SSD or APFS volume does not reliably erase it. Generate keys directly on the encrypted target
volume, never on a scratch disk that is later "cleaned".

## 6. Loss, exposure and rotation

**Policy (BR-2): one vault and one token for life.** The first key of a bridge set that is lost, or suspected to be
exposed, starts a migration to a **new vault and a new token** with a new ceremony and new deployers. Never a new
token over the old vault (`BUSDC-MAINNET-V2.md` 4.5). Do not wait for a second loss: at two lost release keys the old
vault can no longer end a pause early or switch to the light client.

| Key | Rotation on chain | On first loss or exposure |
|---|---|---|
| Mint or release key (any of 14) | None | Migrate. The other operators keep the old pair running until its supply is zero |
| L2 or Ethereum guardian key (any of 6) | None | Migrate. With one L2 guardian gone, both remaining guardians must cancel every forgery, so one more loss ends the cancel defence |
| Deployer, before its creation | - | New derivation index, new plan, new review |
| Deployer, after its verified creation | - | Nothing on the bridge. Sweep its balance and record it |
| Bloch Inc Safe owner | `swapOwner` inside the Safe | Swap at once with the other owners |
| `recoveryAuthority` owner | `swapOwner` inside the Safe | Swap at once. If m owners are lost before the switch, the authority must be replaced before `RecoverableReleaseVerifier` is deployed |
| Relayer gas key | Config change | New key, new config, restart the relayer, move the balance |

Migration steps (from `BUSDC-MAINNET-V2.md` 4.10):

1. Five release signers stop new deposits on the old vault and keep releases on
   (`setControls(false, true, …)`).
2. A new ceremony (this runbook) and a new deployment (section 4 of `BUSDC-MAINNET-V2.md`).
3. Announce the new pair. Holders burn on the old token and deposit into the new vault.
4. The old signers, relayer, guardians and reserves monitor keep running until the old token's supply is zero. Who
   runs them is a TBD-owner item in the checklist.

**Exposed vs lost.** An exposed key may be in an attacker's hands. Treat it as lost for the policy, and also alert
every guardian operator and watch for the attacks in section 7.

## 7. What an attacker gains

k is the contract threshold of the set. Claims about mint keys and guardians come from the audits
(`docs/AUDIT-SCOPE-BRIDGE-V3.md` section 4 and 6, agents 108, 109, 111, 123, 129). Claims about release keys,
deployers and the Safes are from reading the contracts on this branch and were not tested by this runbook.

### L2 mint keys (n = 7, k = 5, switch 6)

| Keys | Gain |
|---|---|
| 1 | Nothing on chain. Can withhold its own partials (liveness needs 5 of the other 6) and publish junk on its feed, which the other signers ignore |
| 4 (k-1) | Nothing on chain. By withholding, any 3 keys stop all mints |
| 5 (k) | Queue forged mints and remints. At T = 0 each waits 12 h and 2 of 3 guardians cancel it. Loss through the vault is 0: a forged unit cannot be paid out (provenance). Real damage is liveness: deposits delayed (F2), and if the forger adds more candidates than the guardians cancel (about 32 per round, F129-B) for 12 h, a forged unit credits and every later exit is held with no settlement path (F3) |
| 6 | All of the above, plus a locked remint that guardians cannot cancel, token unpause, and a mint verifier proposal after 14 days that the guardians cannot stop. Still 0 loss through the vault, but exits can be held for good: treat as a bridge loss for holders |

### Ethereum release keys (n = 7, k = 5, switch 6)

| Keys | Gain |
|---|---|
| 1 | Nothing on chain |
| 4 (k-1) | Nothing on chain. By withholding, any 3 keys stop all releases and `setControls` |
| 5 (k) | Sign a release for a burn that never happened. The vault checks the mint chain head, which an attacker can copy from the chain, so this pays out up to the bucket (50,000 USDC at once, then 50,000 a day; launch limits of 2026-11-19, before: 10,000) until a guardian pauses the vault. Each of the 3 guardians pauses once per chain: about 9 days paused, then 3 days open, in which about 200,000 more can leave (before: 40,000). It can also switch deposits and releases off, and a forged release that uses a future burn nonce makes that honest burn unpayable (`releasedNonce`). This is the set that holds the funds |
| 6 | End every guardian pause early, which blocks all vault guardians for 72 h each time, so about 50,000 a day flows without a stop; and propose a verifier of its choice, which activates after 14 days unless 6 keys cancel it. Through either path the bucket still applies, so the whole cap (500,000 since 2026-11-19; before: 100,000) leaves in about 9 days |

The audit treats 5 release keys plus 5 mint keys as out of model. The table shows that 5 release keys alone are
enough for the bucket rate. That is why they are hot keys on separate hosts of separate people, and why the
guardians' release watch matters.

### Guardians (L2: n = 3, cancel quorum 2; Ethereum: n = 3, any one pauses)

| Keys | Gain |
|---|---|
| 1 L2 key | Pause mints for 72 h (burns are never paused). Cast one cancel vote (not enough). Spend the guardian's gas so the honest daemon cannot act. 6 of 7 mint keys can end the pause |
| 2 L2 keys (k) | Cancel honest queued mints. The deposit comes back through a remint (5 of 7), or a locked remint (6 of 7) that guardians cannot cancel. Availability only, no theft |
| 3 L2 keys | No honest guardian left: a forger with 5 mint keys credits a forged unit, and exits are held (F3) |
| 1 Ethereum key | Pause the vault for 72 h. 6 of 7 release keys end it early |
| 3 Ethereum keys | Pause for about 9 days, then 3 days open, repeated. No funds move. Spending their gas also removes the defence against the release-key attack above |

### Deployers

| State | Gain |
|---|---|
| Before the creation | Use nonce 0 first: the planned address is lost or holds other code. `vault_pontes.py verify` and `deploy_pontes.py verify` catch it if run. Restart with a new index |
| After the verified creation | No power over the contracts (no owner, no setter). The remaining gas, and the ability to deploy look-alike contracts from the "official" deployer address, so the site must pin the addresses, never "whatever this deployer created" |

### Bloch Inc Safe (3 of 5) and `recoveryAuthority` (m of n)

| Keys | Gain |
|---|---|
| Safe, 1 or 2 owners | Nothing |
| Safe, 3 owners | Everything the Safe holds (DEX fees, gas funds) and its owner set. No bridge power: `validate` refuses the Safe in any bridge role |
| Authority, below m | Nothing |
| Authority, m (before the light-client switch) | Nothing: the authority has no power until `RecoverableReleaseVerifier` is the vault's verifier |
| Authority, m (after the switch) | Propose a successor verifier. If the light client still works, one proof of life from anyone cancels a recovery proposal. With handoff on, a handoff cannot be stopped by proofs: after `handoffDelay` the authority's rules apply, and a bad release program drains at the vault's bucket rate. With the light client stopped or provers silenced for the life window, it chooses the verifier outright |
| Authority lost (fewer than m left) | A stopped light client then locks the vault for good |

### Relayer gas keys

Any number: the gas balance only. Anyone can relay, so the attacker cannot block mints or releases.

## 8. Owner checklist (TBD-owner)

Fill every line before the deploy. Each answer is public data only.

| # | Item | Answer |
|---|---|---|
| 1 | Foundry `cast` 1.7.1 binary SHA-256 that every holder checks (per platform) | TBD-owner |
| 2 | 7 signer operators: name, host, hosting account, country; each different | TBD-owner |
| 3 | 3 guardian operators: name, host, hosting account; none runs a signer | TBD-owner |
| 4 | Vault guardians: 3, one per guardian operator (decided 2026-11-02, enforced by `vault_pontes.py validate`): confirm the mapping | TBD-owner |
| 5 | Ethereum release keys different from L2 mint keys (required by `key_inventory.py`): confirm | TBD-owner |
| 6 | Second-channel method for address confirmation, and who calls whom | TBD-owner |
| 7 | Hardware wallet model and firmware for the deployers; the two derivation indexes | TBD-owner |
| 8 | Device rehearsal of the L2 token creation on a private anvil (section 3.3): date and result | TBD-owner |
| 9 | Bloch Inc Safe address on Ethereum and on L2 700770; owners and threshold verified (section 3.4) | TBD-owner |
| 10 | `recoveryAuthority`: Safe address, owners, m of n, overlap with the Bloch Inc Safe owners (recommended: none); `handoffDelay` on or off | TBD-owner |
| 11 | Relayer operator, host, who pays its gas, top-up amount and alert level | TBD-owner |
| 12 | Backup places per operator (USB drive and paper apart), confirmed by a restore test | TBD-owner |
| 13 | Who runs the old stack until its supply is zero after a migration, and the announcement channel | TBD-owner |
| 14 | Committed 2026-10-14 addresses: confirm all are replaced (recommended), or name each kept one with its holder's attestation | TBD-owner |
| 15 | `key_inventory.py check` output with `"signaturesChecked": true`, run by the owner and by a second reviewer | TBD-owner |
| 16 | Each deployer's balance swept and final nonce 1 recorded after verification | TBD-owner |
| 17 | Ceremony dates, outside the hour around L1 fork activations (KES at e8620) | TBD-owner |
| 18 | Bridge fee treasury on Ethereum (`vault.provenance.fees.recipient`, immutable; receives the 5 bps deposit and release fees through `sweepFees()`): an owner-controlled address, not a signer, guardian, deployer, the token or the vault. **It is a constructor argument and can never be changed after the vault is deployed: whoever holds this key receives the bridge fee for the life of the vault. Confirm it on the second channel before the deploy** | `0x775a993F09Bd80aeCF8F8c2ADe0C84158E3a0544` (owner, 2026-11-16; a single externally owned address by the owner's choice, not a multisig) |

## 9. Rehearsal (2026-11-02, throwaway keys)

Run on the owner's Mac by agent 174, in a temporary directory under the session scratchpad, with `cast` 1.7.1. The
script followed sections 3 to 4: 30 keystores, 2 relayer key files and 2 stand-in Safe addresses (34 records),
inventory, attestations, filled copies of both configs, the tool checks, ten refusal cases, a nonce check on a
loopback anvil, then deletion of the directory. Result: 24 of 24 checks passed.

- `cast wallet new` with `CAST_PASSWORD` wrote scrypt / AES-128-CTR keystores with mode 600 and printed no private
  key. A wrong password did not open them. Backup copies were identical and opened.
- Relayer key files were written with mode 600 without the key reaching the terminal. (Since agent 200 the relayer
  keys are keystores like the others; the rehearsal predates that change.)
- `key_inventory.py check` accepted the 34 records and verified 32 attestations against both filled configs.
  `vault_pontes.py validate` accepted 3 vault guardians, and `deploy_pontes.py validate` accepted the L2 config.
- Refused as expected: the legacy deployer `0x703a…`, a mint key reused as a release key, a guardian operator who
  runs a signer, an attestation by another key, an attestation for another role, 2 vault guardians, a config signer
  missing from the inventory, a hot key with hardware-wallet custody, a `recoveryAuthority` owner who runs a signer,
  and a different Safe in the vault config.
- A fresh deployer had nonce 0 on a loopback anvil.
- The temporary directory was deleted and checked absent.

Not rehearsed: hardware wallets (deployers, Safe owners), Safe creation and its checks, the Linux service-user
commands (`install`, `sudo -u`), and anything on a public chain.
