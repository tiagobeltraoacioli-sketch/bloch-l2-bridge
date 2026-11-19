# Bridge key ceremony and deployment kit (owner-run): the Ethereum bUSDC route first

Status: kit of round 18 (agent 380), branch `codex/bridge-ceremony-r18-20261117`. **Nothing here has run with a
real key or on a public network.** Every command block of sections 3 to 14 was executed, as written, by
`deploy/ceremony/rehearse_ceremony.py` on a loopback anvil fork of Ethereum mainnet (chain 1, the real USDC) and a
loopback anvil standing in for the Bloch L2 (chain 700770), with throwaway keys generated during the run and deleted
after it (section 17 lists the result and every place where the rehearsal had to stand in for something).

**The contracts and tools are UNAUDITED.** This kit does not replace the external audit. Until 2026-11-19 it was the
sequence to run after the audit, from the audited revision. **Owner decision of 2026-11-19: the external audit is done
AFTER launch**, and the owner goes ahead with the key ceremony and the
real-key rehearsal. So this kit now runs BEFORE any external audit, from the reviewed launch revision of `main`
(section 0, item 1); what is deployed with it is unaudited code holding real funds, and the cap decided the same day
(500,000 USDC, section 0, item 3) is the most this route can lose.

Round 20 (agent 410, 2026-11-19) changed in this document: the audit wording (this paragraph, sections 0, 2, 11, 16 and
"Not done"), the decided windows and caps, the state of the L2 (section 0, item 2), the numbers of the rehearsal run
with the new limits (sections 8 and 17), and one prerequisite found on the way (section 0, item 5). No command block
changed.

How to read the blocks:

- One command per block. No comments inside blocks. Values in capitals are shell variables set by an earlier block.
- **Run every block in `bash`**, not `zsh` (type `bash` first): some blocks pass wallet options through one variable,
  which only `bash` splits into words.
- Each block starts with a marker comment in the source of this file (`<!-- step ROLE ID -->`), invisible when
  rendered; the rehearsal runs the blocks by those markers and fails if any marked block is not run. A block whose
  marker is `params` holds only `export NAME=value` lines: each person writes their own values there.
- The outcome a command must print is written under it. If it prints anything else, stop (section 15).

Related documents: `docs/BRIDGE-V3-KEY-CEREMONY.md` (the key rules, the attack table, backup and loss policy: still in
force; this kit is its executable form), `docs/BUSDC-MAINNET-V2.md` section 4 (the deployment sequence and the launch
decisions), `docs/BRIDGE-V3-OPERATOR-RUNBOOK.md` (daily operation), `docs/SIG-TRANSPORT.md` (the signature feeds).

## 0. Before anything: prerequisites (all must hold)

1. **The launch revision is named** (`source.revision`): the commit of `main` that carries the launch limits of
   2026-11-19 and that the independent reviewer cleared. **It is NOT an audited revision.** Until 2026-11-19 this item
   read "the external audit of the Ethereum route is complete"; the owner decided on 2026-11-19 that the external audit
   is done after launch. The audit is still owed, and the audited revision is expected to need a new vault and a new
   token (section 4.10 of `docs/BUSDC-MAINNET-V2.md`: a limit or a contract never changes in place).
2. **The Bloch L2 is live and settling.** The L2 token is deployed on chain 700770 and a release can only be
   certified once its burn is in an accepted, finalized settlement (`docs/BUSDC-MAINNET-V2.md` section 3). Until
   2026-11-17 the L2 had never settled. On 2026-11-19 the owner reported the first mainnet L2 settlement accepted on
   L1 at 03:01 UTC; read at 03:47 UTC on two public L1 RPCs (80.240.16.185, 199.247.22.8), `getl2settlement` shows
   chain 700770 with `accepted.commitment` `e8a5ffa7…5705` (before: `accepted` null). The L1 finality of that
   settlement was still pending when this was written: **before section 9, read `getl2settlement` on your own L1 node
   and go on only when the accepted settlement is in a finalized L1 block and the L2 keeps settling.** Sections 3 to 8
   (keys and the Ethereum vault, with deposits and releases OFF) do not depend on it.
3. Owner decisions recorded (section 7 of `docs/BRIDGE-V3-KEY-CEREMONY.md`, the "Owner inputs" of this kit's report):
   the 7 signer operators, the 3 guardian operators, the relayer operators, the L2 gas price cap, the ceremony dates
   (not in the hour around an L1 fork activation). **The bridge windows and caps are decided** (2026-11-19: the owner
   delegated them to the coordinator): cap and L2 supply cap **500,000 USDC**, window and L2 bucket **50,000 USDC per
   24 h** each way (before: 100,000 and 10,000). They are constructor values and can never change; the tools refuse
   any other value (`docs/BRIDGE-ALLNETS.md` section 7 has the reasons).
4. Every holder has Foundry 1.7.1 (`cast --version` shows commit `4072e487`), Python 3.9 or newer and a checkout of
   the launch revision of this repository (item 1) at `/opt/bloch-bridge` (operators) or in the owner's working
   directory.
5. **Before section 11 (not before the keys or the vault): the signers' L2 build pins must name the L2 release that
   is live.** `tools/signatario-stable/l2_finality.py` `MAINNET_V2` (operator key `l2_pins: mainnet-v2`) pins the
   release of 2026-11-03 (follower `cdf5da5c…`, producer `e3f1a290…`, settled RPC `53e88565…`); the L2 went live with
   the release of 2026-11-17 (`bloch-l2-2026-11-17-launch-native-906336fd`: follower `d4d2b99a…`, producer `598873ae…`
   by the L2 review record). A signer started with other binaries than the pinned ones refuses to sign anything for
   chain 700770, so no mint and no release could be certified. The pins are changed only by a reviewed commit (as in
   round 11); that commit does not exist yet (finding F410-2 of round 20, not part of this kit).

## 1. Who generates which key, where

No key, keystore, password or seed ever passes through chat, e-mail, a repository, a shared drive, an AI agent or the
owner's Mac. Each key is generated on the machine where it will live, by the person who holds it. Only public data
travels: the record printed in sections 3 to 6 (role, index, operator, address, date, proof-of-possession signature).

| Key | How many | Generated by, where | Custody | Used |
|---|---|---|---|---|
| L2 mint signer | 7 | each signer operator, on its signer host (dedicated, encrypted disk) | encrypted keystore, service user `bloch-busdc` | automatically (`vigia.py sign`) |
| Ethereum release signer | 7 (a different key from the same 7 operators) | same | same | automatically (`eth_half.py`) and for control, unpause and switch signatures |
| L2 token guardian | 3 | each guardian operator, on its guardian host (another person, another hosting account) | encrypted keystore, service user `bloch-guardiao` | automatically (`guardiao.py`): pause only |
| Ethereum vault guardian | 3 (a different key from the same 3 guardian operators) | same | same | same |
| L2 and Ethereum relayer gas | 1 pair per relayer (primary + up to 6 backups) | each relayer, on its relayer host | encrypted keystore, service user `bloch-relayer`, passwords by systemd `LoadCredential=` | automatically: pays gas only, no bridge power |
| Vault deployer (Ethereum) | 1 | the owner, on a hardware wallet, fresh derivation index | device | once: the vault creation |
| L2 token deployer | 1 | the owner, on a hardware wallet, another fresh index | device | once: the token creation |
| Bloch Inc Safe owners | 5 (3 of 5) | each owner, on their own hardware wallet | device seed on paper or metal | funds the deployers' gas; no bridge power |
| `recoveryAuthority` owners | m of n | owner-chosen people, hardware wallets | device | only after a light-client switch (not part of this launch) |

Hot keys (signers, guardians, relayers) cannot use a hardware wallet: they sign without a button press. The protection
is one dedicated host per operator, full-disk encryption, a dedicated service user, mode 600 files and the password in
a separate file (`docs/BRIDGE-V3-KEY-CEREMONY.md` section 2). An "offline machine" is used for the deployers only (the
air-gapped keystore fallback of section 6 when the device refuses the large L2 creation).

## 2. The owner's preparation

Check the Foundry binary every holder uses (the owner publishes the SHA-256 of the release archive per platform in the
checklist of `docs/BRIDGE-V3-KEY-CEREMONY.md` section 8, item 1):

<!-- step owner cast-version -->
```
cast --version
```

It must show `1.7.1` and `4072e48705af9d93e3c0f6e29e93b5e9a40caed8`.

Work from a clean checkout of the launch revision (section 0, item 1; unaudited); the tools refuse anything else:

<!-- step owner git-clean -->
```
git status --porcelain -- contracts foundry.toml tools
```

It must print nothing.

<!-- step owner params -->
```
export ETH_RPC=http://127.0.0.1:8545 L2_RPC=http://127.0.0.1:18955 SAFE=0xTBD-owner L2_MAX_GAS_PRICE_WEI=50000000000 ETH_MAX_GWEI=30 DAY=2026-11-20
```

`ETH_RPC` is the owner's own Ethereum node, `L2_RPC` the owner's own settled L2 RPC (never a public gateway for the
checks), `SAFE` the Bloch Inc Safe, `L2_MAX_GAS_PRICE_WEI` the reviewed L2 gas price cap of the token creation
(proposed 50 gwei), `ETH_MAX_GWEI` the most the owner pays per gas for the vault creation.

<!-- step owner workdir -->
```
mkdir -p ceremony-out/records ceremony-out/sigs
```

## 3. Each signer operator (7 times, one per operator, on that operator's signer host)

As root on the signer host, with the disk encrypted, the service user `bloch-busdc` created and `cast` 1.7.1 at
`/opt/foundry/bin/cast`:

<!-- step signer params -->
```
export OP=signer-op1 IDX=1 DAY=2026-11-20 D=/etc/bloch-busdc-signer
```

<!-- step signer mkdir -->
```
install -d -m 0700 -o bloch-busdc -g bloch-busdc /etc/bloch-busdc-signer
```
<!-- step signer mint-password -->
```
sudo -u bloch-busdc sh -c 'umask 077; openssl rand -base64 32 > /etc/bloch-busdc-signer/l2-mint.password'
```
<!-- step signer mint-new -->
```
sudo -u bloch-busdc sh -c 'umask 077; CAST_PASSWORD="$(cat /etc/bloch-busdc-signer/l2-mint.password)" /opt/foundry/bin/cast wallet new /etc/bloch-busdc-signer l2-mint.keystore'
```
<!-- step signer release-password -->
```
sudo -u bloch-busdc sh -c 'umask 077; openssl rand -base64 32 > /etc/bloch-busdc-signer/eth-release.password'
```
<!-- step signer release-new -->
```
sudo -u bloch-busdc sh -c 'umask 077; CAST_PASSWORD="$(cat /etc/bloch-busdc-signer/eth-release.password)" /opt/foundry/bin/cast wallet new /etc/bloch-busdc-signer eth-release.keystore'
```

Each `cast wallet new` prints `Created new encrypted keystore file` and an address, never the key. Read the addresses
back from the files:

<!-- step signer mint-addr -->
```
export MINT_ADDR=$(sudo -u bloch-busdc /opt/foundry/bin/cast wallet address --keystore $D/l2-mint.keystore --password-file $D/l2-mint.password)
```
<!-- step signer release-addr -->
```
export REL_ADDR=$(sudo -u bloch-busdc /opt/foundry/bin/cast wallet address --keystore $D/eth-release.keystore --password-file $D/eth-release.password)
```

The proof of possession of each key (an EIP-191 signature over a fixed text naming role, index, operator, address and
date), checked at once by the kit, which prints the public record to send to the owner:

<!-- step signer mint-msg -->
```
export MSG=$(python3 /opt/bloch-bridge/tools/deploy-pontes/key_inventory.py message --role l2-mint-signer --index $IDX --operator $OP --address $MINT_ADDR --date $DAY)
```
<!-- step signer mint-sig -->
```
export SIG=$(sudo -u bloch-busdc /opt/foundry/bin/cast wallet sign --keystore $D/l2-mint.keystore --password-file $D/l2-mint.password "$MSG")
```
<!-- step signer mint-record -->
```
python3 /opt/bloch-bridge/tools/deploy-pontes/ceremony_kit.py record --role l2-mint-signer --index $IDX --operator $OP --address $MINT_ADDR --date $DAY --custody hot-keystore --signature $SIG > $OP-l2-mint-signer.json
```
<!-- step signer release-msg -->
```
export MSG=$(python3 /opt/bloch-bridge/tools/deploy-pontes/key_inventory.py message --role eth-release-signer --index $IDX --operator $OP --address $REL_ADDR --date $DAY)
```
<!-- step signer release-sig -->
```
export SIG=$(sudo -u bloch-busdc /opt/foundry/bin/cast wallet sign --keystore $D/eth-release.keystore --password-file $D/eth-release.password "$MSG")
```
<!-- step signer release-record -->
```
python3 /opt/bloch-bridge/tools/deploy-pontes/ceremony_kit.py record --role eth-release-signer --index $IDX --operator $OP --address $REL_ADDR --date $DAY --custody hot-keystore --signature $SIG > $OP-eth-release-signer.json
```

Send the two files `$OP-l2-mint-signer.json` and `$OP-eth-release-signer.json` to the owner on the first channel (for
example a signed message). They hold public data only. Then make the one backup of `docs/BRIDGE-V3-KEY-CEREMONY.md`
section 5 (encrypted USB drive and paper, in two places) and test the restore.

## 4. Each guardian operator (3 times, on that operator's guardian host)

Not a signer host, another person, another hosting account. Service user `bloch-guardiao`.

<!-- step guardian params -->
```
export OP=guard-op1 IDX=1 DAY=2026-11-20 G=/etc/bloch-guardiao
```
<!-- step guardian mkdir -->
```
install -d -m 0700 -o bloch-guardiao -g bloch-guardiao /etc/bloch-guardiao
```
<!-- step guardian l2-password -->
```
sudo -u bloch-guardiao sh -c 'umask 077; openssl rand -base64 32 > /etc/bloch-guardiao/busdc.pw'
```
<!-- step guardian l2-new -->
```
sudo -u bloch-guardiao sh -c 'umask 077; CAST_PASSWORD="$(cat /etc/bloch-guardiao/busdc.pw)" /opt/foundry/bin/cast wallet new /etc/bloch-guardiao busdc.keystore'
```
<!-- step guardian eth-password -->
```
sudo -u bloch-guardiao sh -c 'umask 077; openssl rand -base64 32 > /etc/bloch-guardiao/busdc-eth.pw'
```
<!-- step guardian eth-new -->
```
sudo -u bloch-guardiao sh -c 'umask 077; CAST_PASSWORD="$(cat /etc/bloch-guardiao/busdc-eth.pw)" /opt/foundry/bin/cast wallet new /etc/bloch-guardiao busdc-eth.keystore'
```
<!-- step guardian l2-addr -->
```
export L2G_ADDR=$(sudo -u bloch-guardiao /opt/foundry/bin/cast wallet address --keystore $G/busdc.keystore --password-file $G/busdc.pw)
```
<!-- step guardian eth-addr -->
```
export ETHG_ADDR=$(sudo -u bloch-guardiao /opt/foundry/bin/cast wallet address --keystore $G/busdc-eth.keystore --password-file $G/busdc-eth.pw)
```
<!-- step guardian l2-msg -->
```
export MSG=$(python3 /opt/bloch-bridge/tools/deploy-pontes/key_inventory.py message --role l2-token-guardian --index $IDX --operator $OP --address $L2G_ADDR --date $DAY)
```
<!-- step guardian l2-sig -->
```
export SIG=$(sudo -u bloch-guardiao /opt/foundry/bin/cast wallet sign --keystore $G/busdc.keystore --password-file $G/busdc.pw "$MSG")
```
<!-- step guardian l2-record -->
```
python3 /opt/bloch-bridge/tools/deploy-pontes/ceremony_kit.py record --role l2-token-guardian --index $IDX --operator $OP --address $L2G_ADDR --date $DAY --custody hot-keystore --signature $SIG > $OP-l2-token-guardian.json
```
<!-- step guardian eth-msg -->
```
export MSG=$(python3 /opt/bloch-bridge/tools/deploy-pontes/key_inventory.py message --role eth-vault-guardian --index $IDX --operator $OP --address $ETHG_ADDR --date $DAY)
```
<!-- step guardian eth-sig -->
```
export SIG=$(sudo -u bloch-guardiao /opt/foundry/bin/cast wallet sign --keystore $G/busdc-eth.keystore --password-file $G/busdc-eth.pw "$MSG")
```
<!-- step guardian eth-record -->
```
python3 /opt/bloch-bridge/tools/deploy-pontes/ceremony_kit.py record --role eth-vault-guardian --index $IDX --operator $OP --address $ETHG_ADDR --date $DAY --custody hot-keystore --signature $SIG > $OP-eth-vault-guardian.json
```

Send both files to the owner; back up as in section 3.

## 5. Each relayer (the primary, then each backup, on its relayer host)

Service user `bloch-relayer`. The gas keys pay gas only; anyone can relay, so they hold no bridge power.

<!-- step relayer params -->
```
export OP=relay-op1 IDX=1 DAY=2026-11-20 R=/etc/bloch-busdc-relayer
```
<!-- step relayer mkdir -->
```
install -d -m 0700 -o bloch-relayer -g bloch-relayer /etc/bloch-busdc-relayer
```
<!-- step relayer l2-password -->
```
sudo -u bloch-relayer sh -c 'umask 077; openssl rand -base64 32 > /etc/bloch-busdc-relayer/l2-gas.password'
```
<!-- step relayer l2-new -->
```
sudo -u bloch-relayer sh -c 'umask 077; CAST_PASSWORD="$(cat /etc/bloch-busdc-relayer/l2-gas.password)" /opt/foundry/bin/cast wallet new /etc/bloch-busdc-relayer l2-gas.keystore'
```
<!-- step relayer eth-password -->
```
sudo -u bloch-relayer sh -c 'umask 077; openssl rand -base64 32 > /etc/bloch-busdc-relayer/eth-gas.password'
```
<!-- step relayer eth-new -->
```
sudo -u bloch-relayer sh -c 'umask 077; CAST_PASSWORD="$(cat /etc/bloch-busdc-relayer/eth-gas.password)" /opt/foundry/bin/cast wallet new /etc/bloch-busdc-relayer eth-gas.keystore'
```
<!-- step relayer l2-addr -->
```
export L2GAS_ADDR=$(sudo -u bloch-relayer /opt/foundry/bin/cast wallet address --keystore $R/l2-gas.keystore --password-file $R/l2-gas.password)
```
<!-- step relayer eth-addr -->
```
export ETHGAS_ADDR=$(sudo -u bloch-relayer /opt/foundry/bin/cast wallet address --keystore $R/eth-gas.keystore --password-file $R/eth-gas.password)
```
<!-- step relayer l2-msg -->
```
export MSG=$(python3 /opt/bloch-bridge/tools/deploy-pontes/key_inventory.py message --role l2-relayer-gas --index $IDX --operator $OP --address $L2GAS_ADDR --date $DAY)
```
<!-- step relayer l2-sig -->
```
export SIG=$(sudo -u bloch-relayer /opt/foundry/bin/cast wallet sign --keystore $R/l2-gas.keystore --password-file $R/l2-gas.password "$MSG")
```
<!-- step relayer l2-record -->
```
python3 /opt/bloch-bridge/tools/deploy-pontes/ceremony_kit.py record --role l2-relayer-gas --index $IDX --operator $OP --address $L2GAS_ADDR --date $DAY --custody hot-keystore --signature $SIG > $OP-l2-relayer-gas.json
```
<!-- step relayer eth-msg -->
```
export MSG=$(python3 /opt/bloch-bridge/tools/deploy-pontes/key_inventory.py message --role eth-relayer-gas --index $IDX --operator $OP --address $ETHGAS_ADDR --date $DAY)
```
<!-- step relayer eth-sig -->
```
export SIG=$(sudo -u bloch-relayer /opt/foundry/bin/cast wallet sign --keystore $R/eth-gas.keystore --password-file $R/eth-gas.password "$MSG")
```
<!-- step relayer eth-record -->
```
python3 /opt/bloch-bridge/tools/deploy-pontes/ceremony_kit.py record --role eth-relayer-gas --index $IDX --operator $OP --address $ETHGAS_ADDR --date $DAY --custody hot-keystore --signature $SIG > $OP-eth-relayer-gas.json
```

Relayer gas keys have no backup: a lost one is replaced by a new one (`docs/BRIDGE-V3-KEY-CEREMONY.md` section 6).

## 6. The owner: the two deployer accounts

Two fresh accounts on the owner's hardware wallet, at derivation indexes never used before (write them in the
checklist). The device shows each signature; the L2 token creation has a large init code that the device must
blind-sign (enable "blind signing" on the Ethereum app for that one transaction only). If the device refuses it,
the fallback is an air-gapped keystore generated on an offline machine and carried to the broadcasting machine only
for the one broadcast (custody `air-gapped-keystore`); write `--keystore FILE` instead of `--ledger ...` below.

<!-- step owner wallet-params -->
```
export VAULT_WALLET="--ledger --mnemonic-derivation-path m/44'/60'/41'/0/0" TOKEN_WALLET="--ledger --mnemonic-derivation-path m/44'/60'/42'/0/0"
```
<!-- step owner vault-deployer -->
```
export VAULT_DEPLOYER=$(cast wallet address $VAULT_WALLET)
```
<!-- step owner token-deployer -->
```
export TOKEN_DEPLOYER=$(cast wallet address $TOKEN_WALLET)
```

Each must have sent nothing on its chain (the tools check it again before the creation):

<!-- step owner vault-deployer-nonce -->
```
cast nonce $VAULT_DEPLOYER --rpc-url $ETH_RPC
```
<!-- step owner token-deployer-nonce -->
```
cast nonce $TOKEN_DEPLOYER --rpc-url $L2_RPC
```

Both must print `0`. The attestations, as for every other key:

<!-- step owner vdep-msg -->
```
export MSG=$(python3 tools/deploy-pontes/key_inventory.py message --role eth-vault-deployer --index 1 --operator owner --address $VAULT_DEPLOYER --date $DAY)
```
<!-- step owner vdep-sig -->
```
export SIG=$(cast wallet sign $VAULT_WALLET "$MSG")
```
<!-- step owner vdep-record -->
```
python3 tools/deploy-pontes/ceremony_kit.py record --role eth-vault-deployer --index 1 --operator owner --address $VAULT_DEPLOYER --date $DAY --custody hardware-wallet --signature $SIG > ceremony-out/records/owner-eth-vault-deployer.json
```
<!-- step owner tdep-msg -->
```
export MSG=$(python3 tools/deploy-pontes/key_inventory.py message --role l2-token-deployer --index 1 --operator owner --address $TOKEN_DEPLOYER --date $DAY)
```
<!-- step owner tdep-sig -->
```
export SIG=$(cast wallet sign $TOKEN_WALLET "$MSG")
```
<!-- step owner tdep-record -->
```
python3 tools/deploy-pontes/ceremony_kit.py record --role l2-token-deployer --index 1 --operator owner --address $TOKEN_DEPLOYER --date $DAY --custody hardware-wallet --signature $SIG > ceremony-out/records/owner-l2-token-deployer.json
```

The Bloch Inc Safe (`SAFE`) and its owners are checked with the three `cast call` lines of
`docs/BRIDGE-V3-KEY-CEREMONY.md` section 3.4 on both chains (not rehearsed: section 17).

## 7. The owner: intake, the configs, the second reviewer

Put every operator's record file into `ceremony-out/records/` (7 x 2 signer records, 3 x 2 guardian records, 2 per
relayer). Then build the inventory; the kit re-verifies every attestation and refuses a role count, a reused address,
a guardian operator who runs a signer, a release operator who is not a mint operator, and a 2026-10-14 address:

<!-- step owner collect -->
```
python3 tools/deploy-pontes/ceremony_kit.py collect --records ceremony-out/records --safe $SAFE --out deployments/mainnet/busdc-keys.inventory.json
```

It must print `"decision": "collected"` and `"signaturesChecked": true`. The second channel: call each holder (voice
or video) and read aloud, both ways, the six first and six last hex digits of each of their addresses:

<!-- step owner fingerprints -->
```
python3 tools/deploy-pontes/ceremony_kit.py fingerprints --inventory deployments/mainnet/busdc-keys.inventory.json
```

Then write the keys, operators, deployers, the Safe and the revision into both deploy configs (no hand copying; a
field that already holds another value is refused):

<!-- step owner fill -->
```
python3 tools/deploy-pontes/ceremony_kit.py fill --inventory deployments/mainnet/busdc-keys.inventory.json --token-config deployments/mainnet/busdc-mainnet.config.json --vault-config deployments/mainnet/busdc-vault-mainnet.config.json --revision $(git rev-parse HEAD) --l2-max-gas-price-wei $L2_MAX_GAS_PRICE_WEI
```

It must print `"decision": "filled"`. The checks, which the second reviewer repeats on their own machine from the
same files:

<!-- step owner inventory-check -->
```
python3 tools/deploy-pontes/key_inventory.py check --inventory deployments/mainnet/busdc-keys.inventory.json --token-config deployments/mainnet/busdc-mainnet.config.json --vault-config deployments/mainnet/busdc-vault-mainnet.config.json
```

`"decision": "ok"` and `"signaturesChecked": true`.

<!-- step owner vault-validate -->
```
python3 tools/deploy-pontes/vault_pontes.py validate --config deployments/mainnet/busdc-vault-mainnet.config.json --token-config deployments/mainnet/busdc-mainnet.config.json
```

`"decision": "config-valid"`. It refuses, among others, a minimum burn below the relayer's cost of a release at the
gas ceiling: `l2MinBurn >= ceil(releaseGas x gasCeilingGwei x 1e-9 x ETH/USD x 1e6 / (1 - releaseBps / 10000))`
(`tools/evm-nets/networks.json` `relayCost`; 0.75 USDC today against the 100 USDC minimum).

<!-- step owner legacy-scan -->
```
python3 tools/deploy-pontes/legacy_digests.py scan deployments/mainnet/busdc-mainnet.config.json deployments/mainnet/busdc-vault-mainnet.config.json
```

It must end with `0 of 2 file(s) hold a refused address`.

The decided fee schedule (2026-11-17), value by value: 5 bps on deposit and 10 bps on release to
`0x775a993F09Bd80aeCF8F8c2ADe0C84158E3a0544`, minimum deposit 101 USDC, minimum exit 100 USDC, relayer ceiling 2 gwei:

<!-- step owner schedule -->
```
python3 tools/deploy-pontes/ceremony_kit.py schedule --token-config deployments/mainnet/busdc-mainnet.config.json --vault-config deployments/mainnet/busdc-vault-mainnet.config.json --relayer-template deployments/mainnet/busdc-ops/relayer.template.json
```

`"decision": "schedule-ok"`. The same command holds both configs to the launch limits decided on 2026-11-19 and prints
them as `launchLimits`: vault cap and token supply cap `500000000000` (500,000 USDC), window and bucket `50000000000`
(50,000 USDC per 24 h), `refillPerSecond` `578703`; a config with any other limit is refused. Read them now: they are
constructor values and can never change, and with no audit before launch the cap is the most this route can lose.

**Fee recipient: immutable.** `0x775a993F09Bd80aeCF8F8c2ADe0C84158E3a0544` receives every bridge fee of this vault for
its whole life. Confirm it on the second channel before section 8.

## 8. The Ethereum vault (deposits and releases start OFF)

The Safe sends the vault deployer the gas only: the creation used 4,598,052 to 4,598,088 gas in the rehearsals (section 17); the
kit's gas limit is 5,000,000 and it signs at up to twice the node's gas price quote, capped at `ETH_MAX_GWEI`, and
refuses to sign unless the balance covers `5,000,000 x that price`. At 30 gwei that is 0.15 ETH; at today's 0.11 gwei
quote (0.23 gwei paid) about 0.0012 ETH. Send `5,000,000 x 2 x the current quote` plus a margin.

The dry run (read-only: validate, the pinned revision, the frozen creation code keccak `0x901d52d0…3a74`, the
predicted address, nonce 0, balance, gas price, a simulated creation):

<!-- step owner vault-dry -->
```
python3 tools/deploy-pontes/ceremony_kit.py vault-run --vault-config deployments/mainnet/busdc-vault-mainnet.config.json --token-config deployments/mainnet/busdc-mainnet.config.json --rpc $ETH_RPC --max-gas-price-gwei $ETH_MAX_GWEI > ceremony-out/vault.dry.json
```
<!-- step owner vault-sha -->
```
export VAULT_SHA=$(python3 tools/deploy-pontes/ceremony_kit.py get --file ceremony-out/vault.dry.json --key configSha256)
```

A second reviewer runs the same dry run and compares `configSha256`, `plannedAddress` and `initCodeHash`. Then the
**one-way** creation (the device shows a contract creation from `VAULT_DEPLOYER` at nonce 0; the kit checks the signed
transaction before publishing it):

<!-- step owner vault-broadcast -->
```
python3 tools/deploy-pontes/ceremony_kit.py vault-run --vault-config deployments/mainnet/busdc-vault-mainnet.config.json --token-config deployments/mainnet/busdc-mainnet.config.json --rpc $ETH_RPC --max-gas-price-gwei $ETH_MAX_GWEI --broadcast --confirm $VAULT_SHA --write ceremony-out/vault.broadcast.json -- $VAULT_WALLET > ceremony-out/vault.sent.json
```
<!-- step owner vault-address -->
```
export VAULT=$(python3 tools/deploy-pontes/ceremony_kit.py get --file ceremony-out/vault.sent.json --key contractAddress)
```
<!-- step owner vault-block -->
```
export VAULT_BLOCK=$(python3 tools/deploy-pontes/ceremony_kit.py get --file ceremony-out/vault.sent.json --key blockNumber)
```

A creation that lands anywhere but `plannedAddress` is not repaired: new deployer index, new review. Wait for Ethereum
finality (about 13 minutes), then verify every immutable, the signer and guardian sets, the fee values, and that the
vault is unused:

<!-- step owner vault-verify -->
```
python3 tools/deploy-pontes/vault_pontes.py verify --config deployments/mainnet/busdc-vault-mainnet.config.json --rpc $ETH_RPC --address $VAULT --unused > ceremony-out/vault.verify.json
```
<!-- step owner vault-verified -->
```
python3 tools/deploy-pontes/ceremony_kit.py get --file ceremony-out/vault.verify.json --key decision
```

It must print `verified`. Copy the vault's public values into the L2 token config (refused if the vault guard or cap
differs from what the token config already says):

<!-- step owner token-ethereum -->
```
python3 tools/deploy-pontes/ceremony_kit.py ethereum --token-config deployments/mainnet/busdc-mainnet.config.json --vault-verify ceremony-out/vault.verify.json
```

## 9. The L2 token on chain 700770 (only once the L2 is live: section 0)

<!-- step owner token-validate -->
```
python3 tools/deploy-pontes/deploy_pontes.py validate --config deployments/mainnet/busdc-mainnet.config.json > ceremony-out/token.validate.json
```
<!-- step owner token-sha -->
```
export TOKEN_SHA=$(python3 tools/deploy-pontes/ceremony_kit.py get --file ceremony-out/token.validate.json --key configSha256)
```
<!-- step owner token-plan -->
```
python3 tools/deploy-pontes/deploy_pontes.py plan --config deployments/mainnet/busdc-mainnet.config.json --write deployments/mainnet/busdc.plan.json
```

The second reviewer regenerates the plan and compares it byte for byte. The Safe sends the token deployer the gas only
(the creation uses about 4.82 M gas; at the L2 gas price cap that is `4.82e6 x L2_MAX_GAS_PRICE_WEI` wei). The dry run
(chain id, genesis hash `632e45ae…f468`, nonce 0, empty address, balance, gas price, the vault unused, a simulated
creation that returns the planned runtime code):

<!-- step owner token-dry -->
```
python3 tools/deploy-pontes/deploy_pontes.py run --config deployments/mainnet/busdc-mainnet.config.json --plan deployments/mainnet/busdc.plan.json --rpc $L2_RPC --source-rpc $ETH_RPC
```

`"decision": "dry-run"`. Then the one-way creation:

<!-- step owner token-broadcast -->
```
python3 tools/deploy-pontes/deploy_pontes.py run --config deployments/mainnet/busdc-mainnet.config.json --plan deployments/mainnet/busdc.plan.json --rpc $L2_RPC --source-rpc $ETH_RPC --broadcast --confirm $TOKEN_SHA --write ceremony-out/busdc.broadcast.json -- $TOKEN_WALLET
```
<!-- step owner token-record -->
```
python3 tools/deploy-pontes/deploy_pontes.py record --config deployments/mainnet/busdc-mainnet.config.json --plan deployments/mainnet/busdc.plan.json --rpc $L2_RPC --broadcast-file ceremony-out/busdc.broadcast.json --write deployments/mainnet/busdc.deployment.json
```
<!-- step owner token-address -->
```
export TOKEN=$(python3 tools/deploy-pontes/ceremony_kit.py get --file deployments/mainnet/busdc.deployment.json --key address)
```

After L2 finality (an accepted, finalized settlement that covers the deployment block):

<!-- step owner token-verify -->
```
python3 tools/deploy-pontes/deploy_pontes.py verify --config deployments/mainnet/busdc-mainnet.config.json --plan deployments/mainnet/busdc.plan.json --rpc $L2_RPC --record deployments/mainnet/busdc.deployment.json --source-rpc $ETH_RPC
```

`"decision": "verified"`.

## 10. Post-deployment verification

Both chains at their finalized blocks, value by value against the configs and the fee schedule (pass a second
Ethereum and a second L2 RPC of another operator with a second `--eth-rpc` / `--l2-rpc`: every RPC must serve the
same finalized block hash):

<!-- step owner onchain -->
```
python3 tools/deploy-pontes/ceremony_kit.py onchain --vault-config deployments/mainnet/busdc-vault-mainnet.config.json --token-config deployments/mainnet/busdc-mainnet.config.json --eth-rpc $ETH_RPC --l2-rpc $L2_RPC --vault $VAULT --token $TOKEN
```

`"decision": "onchain-ok"`. The inventory against the final configs, once more:

<!-- step owner inventory-final -->
```
python3 tools/deploy-pontes/key_inventory.py check --inventory deployments/mainnet/busdc-keys.inventory.json --token-config deployments/mainnet/busdc-mainnet.config.json --vault-config deployments/mainnet/busdc-vault-mainnet.config.json
```

Each deployer has sent exactly its one creation:

<!-- step owner vault-deployer-done -->
```
cast nonce $VAULT_DEPLOYER --rpc-url $ETH_RPC
```
<!-- step owner token-deployer-done -->
```
cast nonce $TOKEN_DEPLOYER --rpc-url $L2_RPC
```

Both must print `1`. Then send each deployer's remaining balance back to the Safe from the wallet application, record
the final nonce, and never use those two derivation indexes again.

## 11. Operator handover

The public values every operator needs, in one file the owner sends to all of them:

<!-- step owner handover -->
```
python3 tools/deploy-pontes/ceremony_kit.py handover --vault-config deployments/mainnet/busdc-vault-mainnet.config.json --token-config deployments/mainnet/busdc-mainnet.config.json --vault-verify ceremony-out/vault.verify.json --token-record deployments/mainnet/busdc.deployment.json --token-plan deployments/mainnet/busdc.plan.json --vault-block $VAULT_BLOCK --out ceremony-out/handover.json
```

Each operator fills its role templates (`deployments/mainnet/busdc-ops/`: `signer.template.json` and
`eth-half.template.json` for signers, `relayer.template.json`, `guardiao.template.json`, `reservas.template.json`)
from `handover.json` and its own key paths, installs its bundle (agent 381's operator packages:
`codex/bridge-operator-pkg-r18-20261117`), runs `tools/signatario-stable/preflight_signer.py` until it ends with `OK`
(`docs/BRIDGE-V3-OPERATOR-RUNBOOK.md` section 3), and starts the daemons: `vigia.py sign` (7 signers), `vigia.py
relay` (primary and backups), `guardiao.py watch` (3 guardians), `reservas.py watch`. Nothing in the handover is
secret; nothing secret ever travels the other way.

The commit of the public records: the inventory, the filled configs, the plan, the deployment record and
`ceremony-out/handover.json` go into a later commit on top of the launch revision (`docs/BUSDC-MAINNET-V2.md` 4.1:
the tools pin `source.revision`, so they cannot be committed at it).

## 12. Enable deposits and releases (5 of 7 release signers)

Only after every daemon runs and `preflight_signer.py` said `OK` on every signer host.

<!-- step owner valid-until -->
```
export VALID_UNTIL=$(( $(date +%s) + 3600 ))
```
<!-- step owner control-digest -->
```
export CONTROL_DIGEST=$(cast call $VAULT "controlDigest(bool,bool,uint64,uint256)(bytes32)" true true 0 $VALID_UNTIL --rpc-url $ETH_RPC)
```

The owner sends `VAULT`, `VALID_UNTIL` and `CONTROL_DIGEST` to five signer operators. Each recomputes the digest on
its own Ethereum node and signs only if it is the same (the release key signs nothing else by hand):

<!-- step signer control-params -->
```
export VAULT=0xTBD-deploy VALID_UNTIL=0 CONTROL_DIGEST=0xTBD ETH_RPC=http://127.0.0.1:8545
```
<!-- step signer control-check -->
```
test "$(/opt/foundry/bin/cast call $VAULT "controlDigest(bool,bool,uint64,uint256)(bytes32)" true true 0 $VALID_UNTIL --rpc-url $ETH_RPC)" = "$CONTROL_DIGEST"
```
<!-- step signer control-sign -->
```
sudo -u bloch-busdc /opt/foundry/bin/cast wallet sign --no-hash --keystore $D/eth-release.keystore --password-file $D/eth-release.password $CONTROL_DIGEST > $OP-control.sig
```

Each sends `$OP-control.sig` to the owner, who puts them in `ceremony-out/sigs/`. The kit checks each signature in the
contract form and that it recovers to a distinct release signer, and orders them by signer address:

<!-- step owner control-sigs -->
```
python3 tools/deploy-pontes/ceremony_kit.py sigs --digest $CONTROL_DIGEST --config deployments/mainnet/busdc-vault-mainnet.config.json --need 5 --format list -- $(cat ceremony-out/sigs/*-control.sig) > ceremony-out/control.sigs.json
```
<!-- step owner control-value -->
```
export CONTROL_SIGS=$(python3 tools/deploy-pontes/ceremony_kit.py get --file ceremony-out/control.sigs.json --key value)
```

Anyone may submit; the primary relayer does, with its Ethereum gas key (the owner sends it `CONTROL_SIGS`):

<!-- step relayer control-params -->
```
export VAULT=0xTBD-deploy VALID_UNTIL=0 CONTROL_SIGS=TBD ETH_RPC=http://127.0.0.1:8545
```
<!-- step relayer control-send -->
```
sudo -u bloch-relayer /opt/foundry/bin/cast send $VAULT "setControls(bool,bool,uint64,uint256,bytes[])" true true 0 $VALID_UNTIL "$CONTROL_SIGS" --keystore $R/eth-gas.keystore --password-file $R/eth-gas.password --rpc-url $ETH_RPC
```
<!-- step owner controls-on -->
```
cast call $VAULT "depositsEnabled()(bool)" --rpc-url $ETH_RPC
```

It must print `true`. To switch them off again (for a failed first round trip, section 13): the same steps with
`false false` and the next nonce (`cast call $VAULT "controlNonce()(uint64)"`).

## 13. The first small deposit and exit (the owner as a user, with a small amount)

From the owner's own wallet (not a bridge key; the same account on both chains), the smallest deposit (101 USDC: it
nets 100.9495 bUSDC) to that account on the L2, and later the smallest exit (100 bUSDC, paid 99.90 USDC on Ethereum to
`ETH_ME`, any address of the owner's):

<!-- step user params -->
```
export USER_WALLET="--ledger --mnemonic-derivation-path m/44'/60'/43'/0/0" ETH_ME=0xTBD-owner USDC=0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48
```
<!-- step user l2-me -->
```
export L2_ME=$(cast wallet address $USER_WALLET)
```
<!-- step user approve -->
```
cast send $USDC "approve(address,uint256)" $VAULT 101000000 $USER_WALLET --rpc-url $ETH_RPC
```
<!-- step user deposit -->
```
cast send $VAULT "deposit(uint64,bytes32)" 101000000 $(cast abi-encode "f(address)" $L2_ME) $USER_WALLET --rpc-url $ETH_RPC
```

After Ethereum finality the signers attest it, the relayer queues the mint, and after the 12 h mint delay (T = 0:
every mint waits and stays cancellable by 2 of 3 guardians) the relayer executes it:

<!-- step user l2-balance -->
```
cast call $TOKEN "balanceOf(address)(uint256)" $L2_ME --rpc-url $L2_RPC
```

It must print `100949500`. The exit:

<!-- step user burn -->
```
cast send $TOKEN "burn(uint64,address)" 100000000 $ETH_ME $USER_WALLET --rpc-url $L2_RPC
```

After L2 finality (a finalized settlement that covers the burn) the signers certify the release and the relayer sends
it (while Ethereum's gas price is above the 2 gwei ceiling the release waits; nothing is lost):

<!-- step user paid -->
```
cast call $USDC "balanceOf(address)(uint256)" $ETH_ME --rpc-url $ETH_RPC
```

It must have grown by `99900000`. Anyone pays the accrued fees to the fee address:

<!-- step user sweep -->
```
cast send $VAULT "sweepFees()" $USER_WALLET --rpc-url $ETH_RPC
```

Reserves, from any machine (`reservas.json` from `deployments/mainnet/busdc-ops/reservas.template.json` and
`handover.json`): `python3 tools/reservas/reservas.py --config reservas.json check` exits 0 (`ok`).

## 14. Pause drills (before announcing the bridge)

One Ethereum vault guardian pauses the vault (deposits and releases) for 72 h:

<!-- step guardian drill-params -->
```
export VAULT=0xTBD-deploy TOKEN=0xTBD-deploy ETH_RPC=http://127.0.0.1:8545 L2_TX_RPC=https://l2rpc.blochl1.com
```
<!-- step guardian vault-pause -->
```
sudo -u bloch-guardiao /opt/foundry/bin/cast send $VAULT "guardianPause()" --keystore $G/busdc-eth.keystore --password-file $G/busdc-eth.pw --rpc-url $ETH_RPC
```
<!-- step owner vault-paused -->
```
cast call $VAULT "paused()(bool)" --rpc-url $ETH_RPC
```

`true`. Ending it early takes 6 of 7 release signers (and blocks every vault guardian for 72 h afterwards: in a real
incident, end a pause only once its cause is understood):

<!-- step owner unpause-count -->
```
export PAUSE_COUNT=$(cast call $VAULT "pauseCount()(uint64)" --rpc-url $ETH_RPC)
```
<!-- step owner unpause-until -->
```
export VALID_UNTIL=$(( $(date +%s) + 3600 ))
```
<!-- step owner unpause-digest -->
```
export UNPAUSE_DIGEST=$(cast call $VAULT "unpauseDigest(uint64,uint256)(bytes32)" $PAUSE_COUNT $VALID_UNTIL --rpc-url $ETH_RPC)
```

Six signer operators check and sign it as in section 12:

<!-- step signer unpause-params -->
```
export VAULT=0xTBD-deploy PAUSE_COUNT=0 VALID_UNTIL=0 UNPAUSE_DIGEST=0xTBD ETH_RPC=http://127.0.0.1:8545
```
<!-- step signer unpause-check -->
```
test "$(/opt/foundry/bin/cast call $VAULT "unpauseDigest(uint64,uint256)(bytes32)" $PAUSE_COUNT $VALID_UNTIL --rpc-url $ETH_RPC)" = "$UNPAUSE_DIGEST"
```
<!-- step signer unpause-sign -->
```
sudo -u bloch-busdc /opt/foundry/bin/cast wallet sign --no-hash --keystore $D/eth-release.keystore --password-file $D/eth-release.password $UNPAUSE_DIGEST > $OP-unpause.sig
```
<!-- step owner unpause-sigs -->
```
python3 tools/deploy-pontes/ceremony_kit.py sigs --digest $UNPAUSE_DIGEST --config deployments/mainnet/busdc-vault-mainnet.config.json --need 6 --format list -- $(cat ceremony-out/sigs/*-unpause.sig) > ceremony-out/unpause.sigs.json
```
<!-- step owner unpause-value -->
```
export UNPAUSE_SIGS=$(python3 tools/deploy-pontes/ceremony_kit.py get --file ceremony-out/unpause.sigs.json --key value)
```
<!-- step relayer unpause-params -->
```
export VAULT=0xTBD-deploy PAUSE_COUNT=0 VALID_UNTIL=0 UNPAUSE_SIGS=TBD ETH_RPC=http://127.0.0.1:8545
```
<!-- step relayer unpause-send -->
```
sudo -u bloch-relayer /opt/foundry/bin/cast send $VAULT "unpause(uint64,uint256,bytes[])" $PAUSE_COUNT $VALID_UNTIL "$UNPAUSE_SIGS" --keystore $R/eth-gas.keystore --password-file $R/eth-gas.password --rpc-url $ETH_RPC
```
<!-- step owner vault-unpaused -->
```
cast call $VAULT "paused()(bool)" --rpc-url $ETH_RPC
```

`false`. One L2 token guardian pauses mints (burns are never paused):

<!-- step guardian token-pause -->
```
sudo -u bloch-guardiao /opt/foundry/bin/cast send $TOKEN "pause()" --keystore $G/busdc.keystore --password-file $G/busdc.pw --rpc-url $L2_TX_RPC
```
<!-- step owner token-paused -->
```
cast call $TOKEN "paused()(bool)" --rpc-url $L2_RPC
```

`true`. Ending it early takes 6 of 7 MINT signers, with the six signatures concatenated into one `bytes` value:

<!-- step owner token-unpause-digest -->
```
export TOKEN_UNPAUSE_DIGEST=$(cast call $TOKEN "unpauseDigest()(bytes32)" --rpc-url $L2_RPC)
```
<!-- step signer token-unpause-params -->
```
export TOKEN=0xTBD-deploy TOKEN_UNPAUSE_DIGEST=0xTBD L2_RPC=http://127.0.0.1:18955
```
<!-- step signer token-unpause-check -->
```
test "$(/opt/foundry/bin/cast call $TOKEN "unpauseDigest()(bytes32)" --rpc-url $L2_RPC)" = "$TOKEN_UNPAUSE_DIGEST"
```
<!-- step signer token-unpause-sign -->
```
sudo -u bloch-busdc /opt/foundry/bin/cast wallet sign --no-hash --keystore $D/l2-mint.keystore --password-file $D/l2-mint.password $TOKEN_UNPAUSE_DIGEST > $OP-token-unpause.sig
```
<!-- step owner token-unpause-sigs -->
```
python3 tools/deploy-pontes/ceremony_kit.py sigs --digest $TOKEN_UNPAUSE_DIGEST --config deployments/mainnet/busdc-mainnet.config.json --need 6 --format concat -- $(cat ceremony-out/sigs/*-token-unpause.sig) > ceremony-out/token-unpause.sigs.json
```
<!-- step owner token-unpause-value -->
```
export TOKEN_UNPAUSE_SIGS=$(python3 tools/deploy-pontes/ceremony_kit.py get --file ceremony-out/token-unpause.sigs.json --key value)
```
<!-- step relayer token-unpause-params -->
```
export TOKEN=0xTBD-deploy TOKEN_UNPAUSE_SIGS=0xTBD L2_TX_RPC=https://l2rpc.blochl1.com
```
<!-- step relayer token-unpause-send -->
```
sudo -u bloch-relayer /opt/foundry/bin/cast send $TOKEN "unpause(bytes)" $TOKEN_UNPAUSE_SIGS --keystore $R/l2-gas.keystore --password-file $R/l2-gas.password --rpc-url $L2_TX_RPC
```
<!-- step owner token-unpaused -->
```
cast call $TOKEN "paused()(bool)" --rpc-url $L2_RPC
```

`false`. The drills are done; announce the pair only now.

## 15. When a step fails midway

| Where it stopped | State | What to do |
|---|---|---|
| Sections 3 to 7 (keys, intake, configs) | nothing on chain | Fix and repeat. A key whose record fails to verify, or whose fingerprint does not match on the second channel, is discarded: the holder generates a new one. Never edit an inventory record by hand |
| `vault-run` dry run refused | nothing on chain | Read `reason`: wrong revision, creation code, nonce, balance, gas price. Fix the cause; never pass another config |
| `vault-run --broadcast` refused before publishing | nothing on chain, `vault.broadcast.json` may hold an unsent signed transaction | Do not publish it by hand. Find the cause; the next attempt needs a new `--write` file |
| Vault creation published, no receipt | a transaction in flight at nonce 0 | Do not resend. Wait; read its hash in `vault.broadcast.json`; `cast receipt` it |
| Vault landed elsewhere, reverted, or `verify` refuses | deployer burned or vault wrong | Never use it. New vault deployer index, new configs, new review: back to section 6. Nothing else is on chain yet |
| Vault verified, L2 not live | vault deployed, deposits and releases OFF | Safe: nothing can enter or leave. Wait for the L2; do not enable controls |
| Token `run` dry run refused | nothing on L2 | Read `reason` (a used vault, genesis, nonce, gas price) and fix. A used vault is never reused: new vault and new token |
| Token creation landed wrong or `verify` refuses | the token is unusable | Never point a second token at the same vault if it took a deposit; with an unused vault, a new token deployer index and a new plan |
| Controls enabled, first round trip fails | deposits possible | Switch controls off (section 12 with `false false` and the next nonce); releases keep the vault payable. Find the cause before any announcement |
| A drill pause cannot be ended (fewer than 6 signers available) | vault or token paused 72 h | It ends by itself after 72 h. Two lost release keys mean migration (`docs/BRIDGE-V3-KEY-CEREMONY.md` 6) |

## 16. The other routes

The committee of sections 3 and 4 serves every route: the same 7 L2 mint keys and 3 L2 token guardian keys on every
L2 token, and (except Bitcoin) the same 7 `eth-release-signer` and 3 `eth-vault-guardian` secp256k1 keys on every
source-side vault (BRIEF-ROUND16 architecture, point 5; every digest binds the chain id and the vault, so a signature
for one route is refused by every other). What each route adds is its deployer, its source-network fee payer or gas
keys, and its own config. Each route's own document holds its exact commands; none is rehearsed by this kit.

| Route | Status (2026-11-17; the first row as of 2026-11-19) | New keys (all generated by their holder as in sections 3 to 6) | Route document |
|---|---|---|---|
| Arbitrum One `bUSDC.arb`, OP Mainnet `bUSDC.op`, Linea `bUSDC.linea` | `launch.v1` true, unaudited (owner decision of 2026-11-19: audit after launch); limits decided 2026-11-19: cap 250,000 USDC, window 25,000 USDC per 24 h on each | per network: a fresh vault deployer (hardware wallet, nonce 0), a fresh L2 token deployer, relayer gas keys on that network. No new committee key | `docs/BRIDGE-EVM-NETWORKS.md` (audit line `codex/bridge-evm-nets-r17-audit-20261117`, agents 337/372): same tools (`vault_pontes.py`, `deploy_pontes.py`) with `deployments/<network>/`; fees and minimums per network (Linea: exit 0.15%, minimums 601 / 600 USDC; Arbitrum One and OP Mainnet: 0.05% each way, 21 / 20); relayer ceilings 2 / 0.5 gwei; anchor policy `probe` |
| Base `bUSDC.base` | held (`launch.v1` false): every tool refuses chain 8453, no flag lifts it | none | same; do not run |
| BNB Smart Chain | out of v1 | none | do not run |
| Bitcoin `bBTC` | under review (agents 370, 378: R342-BTC-1..3) | **7 separate Bitcoin vault keys** (role `btc-vault-signer`, one more keystore per signer operator; a compromise of the Ethereum release keys does not open the Bitcoin vault), a fresh L2 token deployer; no Bitcoin guardian key (guardians pause bBTC on the L2), no relayer key that moves coins | `docs/BTC-BRIDGE-DEPLOYMENT.md` on `codex/bridge-btc-r17-20261117` (section 1: ceremony delta; fee output to `bc1qjpnq…etkyk`) |
| Tron `bUSDT.trx` | under review (agents 370, 378: R342-TRX-1..4) | a fresh TRON deployer account (600 TRX, a keystore on an offline-prepared machine: `cast` cannot sign a TRON transaction with a hardware wallet), TRX for the 3 vault guardian addresses (about 100 TRX each, a pause is a transaction they pay), relayer TRX | `docs/BRIDGE-TRON-USDT.md` on `codex/bridge-tron-r17-20261117`; the fixed release fee from the worst-case energy measurement (14 USDT, minimums 70 / 71); TRX price read at the ceremony from two sources (owner input) |
| Solana `bUSDC.sol` | under review (agents 371, 376) | ed25519 fee payers only (deployer, each relayer, each guardian operator; no vault power) and a throwaway program keypair discarded after `--final`; a fresh L2 token deployer | `docs/SOLANA-BRIDGE-DEPLOY-CEREMONY.md` on `codex/bridge-solana-r17-20261117`; the owner signs the fee-address proof (route, cluster genesis hash, purpose) with the fee key `BMnorAB2…eAJL8`; the USDC associated token account is created by the deployment |
| Stellar `bUSDC.xlm` | under review (agents 373, 377) | a fresh Stellar deployer account (about 30 XLM; it holds nothing after the deployment) and a relayer account (about 20 XLM) | `docs/STELLAR-BRIDGE-DEPLOY.md` on `codex/bridge-stellar-r17-20261117`; burn destinations named by a router transaction on the L2 |

For every route: the inventory of section 7 already holds the committee; the route's new keys are attested the same
way and added to that route's inventory. No held route (Base, Bitcoin, Tron, Solana, Stellar) launches before its own
external audit, its reviewer's final verdict and its merge into `main` by the integrator, and BNB Smart Chain is out of
v1. For Arbitrum One, OP Mainnet and Linea the owner decided on 2026-11-19 that the external audit is done after
launch: they launch UNAUDITED, after their own ceremony, with the caps above. No route launches before the L2 is live.

## 17. Rehearsal record

`deploy/ceremony/rehearse_ceremony.py` (round 18) runs sections 2 to 14 as written; run it with
`FOUNDRY_BIN=<directory of cast, forge, anvil 1.7.1> python3 deploy/ceremony/rehearse_ceremony.py` (this file has no
code block that is not a marked step, and the rehearsal checks that).

Result on 2026-11-17 at `c0aa0d5` (agent 380; details in `agents/380-bridge-ceremony-r18.md`), from a clean clone with
no build cache: 128 of 128 marked blocks run, 50 of 50 checks pass, `CEREMONY REHEARSAL OK`: 27 key records from 12 hosts and the owner re-verified; configs filled
and every tool's mainnet-policy check passed with no rehearsal flag; the vault created on a fork of Ethereum mainnet
over the real USDC at the planned address (4,598,052 gas) and verified at finality; the token created on the 700770
stand-in (4,822,592 gas, under the 5,000,000 limit) and verified with its vault; both chains equal the configs and
the fee schedule; 5-of-7 controls (4 signatures and a non-member's refused); 101 USDC in, 100.9495 bUSDC after the
12 h delay, 100 bUSDC out, 99.90 USDC paid, 0.1505 USDC of fees swept to `0x775a…0544`, reserves `ok`; vault and token
paused by one guardian each and unpaused by 6 of 7 (5 refused). Adversarial checks with the document's own commands:
a forged record, a wrong `--confirm`, too few and foreign signatures.

The rehearsal had to stand in for these things, and only these:

- the hosts: each operator is a directory; `/etc`, `/opt`, `/var` in operator blocks are rewritten under that
  directory, `sudo -u USER` runs as the current user, and `install -o/-g` drops the owner and group (the Mac has no
  service users; agent 381's bundles exercise the users, permissions and units in containers);
- the hardware wallets: `VAULT_WALLET`, `TOKEN_WALLET` and `USER_WALLET` are throwaway keystores (the device path is
  not rehearsed; section 3.3 of `docs/BRIDGE-V3-KEY-CEREMONY.md` keeps the device rehearsal as an owner item);
- Ethereum: a loopback anvil fork of mainnet (chain 1, real USDC); time and finality advance by mining;
- the L2: a loopback anvil with chain id 700770 (not the real L2: its genesis hash is the stand-in's own, written into
  the token config by the rehearsal; no settlement, so "L2 finality" is anvil's `finalized` tag);
- the daemons run from configs built from `handover.json` in the test form the suites use (`l2_source: rpc` and a
  local shared directory instead of the pinned L2 binaries and the network feeds). `signatario.py` refuses to sign
  anything for chain 700770 without the pinned L2 binaries (`l2_pins`), and the rehearsal checks that it does; for the
  daemon leg (section 13) the L2 stand-in therefore switches its chain id to 700771 (`anvil_setChainId`; the token
  derives its EIP-712 domain and burn ids from `block.chainid`). The owner's and the user's commands are unchanged;
- the Safe: a throwaway address (its owner checks are not rehearsed); funding of the deployers and the user by
  `anvil_setBalance` and a USDC balance write.

## Not done / not proven

- No real key, no hardware wallet, no public network: everything above is rehearsed on loopback stand-ins only.
- The L2: its first settlement was accepted on L1 on 2026-11-19 (section 0, item 2); that it is in a finalized L1
  block and that the L2 keeps settling was not established here. Section 9 onwards needs it.
- The signers' L2 build pins name the release of 2026-11-03, not the release the L2 went live with (section 0, item 5):
  section 11 onwards cannot work on mainnet until a reviewed commit re-pins them.
- The signer daemons on the real L2 path (`l2_pins: mainnet-v2`, the rebuild, the feeds) are not part of this
  rehearsal; their own suites and agent 381's bundles cover them.
- Safe creation, Safe owner checks and the deployer balance sweep are not rehearsed.
- The other routes (section 16) are pointers to their own documents and lines, not rehearsed here.
- The external audit has not happened, and by the owner's decision of 2026-11-19 it will not happen before launch:
  everything this kit deploys is unaudited. The bridge windows and caps are decided (2026-11-19; section 0, item 3).
