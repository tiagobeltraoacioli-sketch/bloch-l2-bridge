# Bridge operator packages

Agent 381, round 18 (2026-11-17). Branch `codex/bridge-operator-pkg-r18-20261117` of bloch-l2-bridge, from `main`
`cc2511a`. Nothing here is deployed; no real key was generated, read or used. Every address and every operator choice is
`TBD-owner`.

One installable bundle per (route, role). A bundle holds the route's daemons at a pinned git revision, generated systemd
units, config templates rendered from the route's committed templates, a health check with an alert hook, a logrotate
file, a journald drop-in, and a manifest with the SHA-256 and mode of every file. The on-host tool `ops/bridgectl.py`
(inside every bundle) installs, checks, seals secrets, starts, health-checks, upgrades and rolls back.

| File | What it is |
|---|---|
| `ops/routes.json` | the routes and roles: payload paths, units, credentials, config templates and the keys a bundle changes, heartbeats, preflight, ports, host size |
| `ops/bundle.py` | builds a bundle from git objects (never the working tree), deterministic; `lint` checks every (route, role) |
| `ops/bridgectl.py` | the on-host tool (install, credentials, seal, check, preflight, start, stop, status, health, upgrade, rollback, verify) |
| `ops/alert-hook.example` | the alert hook contract, with a journal-only body |
| `ops/test_bundle.py`, `ops/test_bridgectl.py` | offline tests (scratch root, no systemd) |
| `ops/rehearse_containers.py` | the Ethereum route's four bundles installed and exercised under real systemd in containers (section 8) |

## 1. Routes and roles

| Route | Source revision | Roles packaged | State |
|---|---|---|---|
| `ethereum` (bUSDC) | `cc2511a` (main, the audit candidate) | signer, relayer, guardian (guardiao + optional sombra), reserves | rehearsed under systemd (section 8) |
| `arbitrum-one` (bUSDC.arb), `op-mainnet` (bUSDC.op), `linea` (bUSDC.linea) | `9187656` (audit line `codex/bridge-evm-nets-r17-audit-20261117`) | signer, relayer, guardian (guardiao), reserves | built and checked offline; same daemons as Ethereum; not rehearsed in containers |
| `base`, `bnb` | none | none | refused by the route's own launch status (Base held, BNB Smart Chain out of v1) |
| `bitcoin`, `tron`, `solana`, `stellar` | none | none | not packaged: see section 9 |

The EVM networks inherit the Ethereum roles (`inherit` in `ops/routes.json`) with their own committed templates
(`deployments/<network>/ops/*.template.json`), their own feed port, no sombra (the light client is Ethereum's), and the
signer started without `--interval` (their templates: "a longer one is refused"). Their guardian and reserves configs
are rendered from the Ethereum templates with the network's chain id and bridge name, because the audit line has no
guardian or reserves template of its own: the route owner should confirm or commit its own.

## 2. Build and verify a bundle

On any machine with git and Python 3.9 or later, from a checkout of this repository:

```
python3 ops/bundle.py list
```

```
python3 ops/bundle.py build --route ethereum --role signer --out dist
```

The bundle name carries both revisions: `bloch-bridge-<route>-<role>-<route rev 12>-<ops rev 12>.tar.gz`, with a
`.sha256` file. Two builds of the same revisions are byte-identical (tested, and checked in the rehearsal); an operator
rebuilds from the published revisions and compares the SHA-256 with the release record before installing. The
manifest names every file with its SHA-256 and mode, the units, the credentials, the ports and the host size.

```
python3 ops/bundle.py render --route ethereum --role signer --out review
```

writes the units, the config templates and the manifest of a bundle for review.

## 3. Install, one operator host (the commands an operator runs)

Every command is one block; run as root on the operator's host. `BUNDLE` is the file name, `SHA` the SHA-256 from the
release record (never from the bundle itself). The first command runs the bridgectl inside the bundle without unpacking
it anywhere.

```
sha256sum BUNDLE
```

```
tar -xzOf BUNDLE ops/bridgectl.py | python3 -E -s - install BUNDLE --sha256 SHA
```

For each credential the install prints (signer: `l2-mint.keystore`, `l2-mint.password`, `eth-release.keystore`,
`eth-release.password`), seal the file the key ceremony produced on this machine (on tmpfs), then shred it:

```
python3 -E -s /opt/bloch-bridge/ethereum-signer/current/ops/bridgectl.py seal ethereum-signer l2-mint.keystore --from /run/ceremony/l2-mint.keystore
```

```
shred -u /run/ceremony/l2-mint.keystore
```

Fill every `TBD-owner` value in `/etc/bloch-bridge/<inst>/*.json`, write the cast pin and the alert hook:

```
sha256sum /opt/foundry/bin/cast
```

(compare with the key ceremony record, line 1, then write that value to `/etc/bloch-bridge/cast.sha256`)

```
install -m 0755 YOUR-HOOK /etc/bloch-bridge/alert-hook
```

```
python3 -E -s /opt/bloch-bridge/ethereum-signer/current/ops/bridgectl.py check ethereum-signer
```

```
python3 -E -s /opt/bloch-bridge/ethereum-signer/current/ops/bridgectl.py preflight ethereum-signer
```

```
python3 -E -s /opt/bloch-bridge/ethereum-signer/current/ops/bridgectl.py start ethereum-signer
```

`start` refuses while `check` reports anything. `preflight` runs the role's own preflight (`preflight_signer.py` for the
signer and the relayer, `guardiao.py check --dry-run`, `reservas.py check`) as a oneshot unit with exactly the daemon's
user, sandbox and staged credentials (`Conflicts=` the daemon, so it refuses while the daemon runs). After `start`:
`systemctl restart systemd-journald` once if the install said the journald drop-in was new.

The guardian's proof-path daemon (sombra) is optional and off by default; when its light client exists:
`bridgectl.py check ethereum-guardian --with sombra`, then `start ethereum-guardian --with sombra`.

## 4. Layout and hardening

| Path | Owner, mode | Holds |
|---|---|---|
| `/opt/bloch-bridge/<inst>/releases/<id>/` | root, 0755 / 0644 | the bundle's files; `<id>` = first 16 hex of the bundle SHA-256 |
| `/opt/bloch-bridge/<inst>/current`, `previous` | root symlinks | swapped with rename(2) |
| `/etc/bloch-bridge/<inst>/` | root:bb-`<inst>` 0750, files 0640 | configs: the service reads, never writes; templates in `templates/` |
| `/etc/credstore.encrypted/bloch-bridge-<inst>/` | root 0700, files 0600 | secrets, encrypted by `systemd-creds` (host key, TPM2 when present) |
| `/run/bloch-bridge-<inst>[-<unit>]/` | bb-`<inst>` 0700, files 0400 | the unit's staged secrets, tmpfs, removed when it stops |
| `/var/lib/bloch-bridge/<inst>/` | bb-`<inst>` 0700 (0750 where a monitor reads a health file) | daemon state |
| `/var/lib/bloch-bridge/<route>-feed/publish/` | bb-`<route>-signer` 0755, default ACL `u::rwx,g::r-x,o::r-x` | the signer's public signatures, served by the feed |
| `/var/log/bloch-bridge/<inst>/health.log` | bb-`<inst>` 0640 | one JSON line per health check, rotated daily, 90 kept |

**Secrets.** No key, keystore or password is ever in a config. A config names the staged path
(`/run/bloch-bridge-<inst>/<id>`); the unit loads `<id>` with `LoadCredentialEncrypted=` from the credential store, and
one privileged `ExecStartPre=+/usr/bin/install -m 0400 -o bb-<inst> ...` per credential copies it into the unit's
RuntimeDirectory. The copy is needed because systemd 255 hands a credential to a `User=` service as mode 0440 root:root
with an ACL (measured again here, and by agent 204 in round 11), and the tools refuse a key file readable by a group:
see F381-1. These copies are the only privileged steps of any unit (tested). The builder refuses a config key that
names a key, keystore, password, secret, seed or mnemonic unless it points at a staged path of a unit that loads it;
`check` refuses the same on the host, and also `credential:NAME`.

**Users.** One system user per instance, `bb-<route>-<role>` (no home, `nologin`), so two roles on one host never share
files; the feed runs as a `DynamicUser` that sees only its publish directory (`TemporaryFileSystem=/var/lib:ro` plus one
read-only bind; the configs, credential store and staged secrets are inaccessible paths).

**Common unit hardening** (`ops/routes.json` `hardening`; a role may add lines, never override one): `UMask=0077`,
`NoNewPrivileges`, empty capability sets, `ProtectSystem=strict` (the whole file system read-only but the state and
runtime directories), `ProtectHome`, `PrivateTmp`, `PrivateDevices`, `PrivateIPC`, the kernel, clock, hostname and
cgroup protections, `ProtectProc=invisible`, `RestrictNamespaces`, `RestrictRealtime`, `RestrictSUIDSGID`,
`LockPersonality`, `MemoryDenyWriteExecute`, `SystemCallFilter=@system-service ~@privileged @resources` (EPERM),
`RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`, `RemoveIPC`, `LimitCORE=0` (no core dump of a process holding a
key), `KeyringMode=private`, and `InaccessiblePaths=` for both credential stores and every other unit's staged secrets.
`systemd-analyze security` rates every daemon unit 1.2 OK (rehearsal). Resource caps per unit (`MemoryMax`, `TasksMax`).
`StartLimitBurst=10` in 900 s, then `OnFailure=` the health check.

## 5. Health checks and alerts

`bloch-bridge-<inst>-health.timer` runs `bridgectl.py health <inst> --alert` every 60 s as the instance's user, with the
staged secrets and both credential stores inaccessible, in the `systemd-journal` group. Levels: OK, WARN, CRIT, UNKNOWN
(exit 0 to 3). It reports CRIT for an enabled unit that is not active, a heartbeat older than its bound or newer than
nothing since a restart, a health file with `healthy` false, and a last fully verified round (`verified_t`) older than
30 min (alive but blind); WARN for a restart since the last check and for daemon JSON lines with `kind` `alert` (CRIT
when its severity is critical or hard, or `kind` is `pause`), `...-failed` or an `error`. Every result is appended to
`health.log`. On a change of state, and once an hour while CRIT stays, it runs `/etc/bloch-bridge/alert-hook LEVEL INST
SUMMARY_JSON` (30 s timeout); a daemon unit that fails for good starts the health check at once (`OnFailure=`).

| Role | Heartbeat | Bound |
|---|---|---|
| signer, relayer | `feed-status.json` (`bridge_feed.py`, every pass) | 600 s |
| guardian | `guardiao-health.json`: `t`, `healthy`, `verified_t` | 300 s; verified 1,800 s |
| reserves | `reservas-health.json`: `t`, `healthy`, `verified_t` | 900 s; verified 1,800 s |

The guardian's and the reserves monitor's own `alert_command` stay an owner input (`TBD-owner`): `[]` relies on the
health timer, which forwards their alert lines and health files within 60 s and also notices a dead daemon, which an
`alert_command` cannot. The `l2_monitor.py --guardian-health` monitor of `deploy/guardiao/` still works with these
units (the guardian state directory is 0750 for it).

## 6. Host size and network ports (per role)

Exact sizes for a host that runs one role of one route with its own nodes. Sources: agents/347-fee-economics-r17.md
(N1: ethereum.org run-a-node and reth system requirements; N2: Arbitrum node documentation), bloch-l2-evm
`docs/L2-MAINNET-GO-LIVE.md` D3 (L2 follower 4 vCPU, 8 GiB, 80 GB), and the daemon peaks measured in the rehearsal
(section 8). The daemons themselves are small; the nodes dominate.

| Route, role | Cores | RAM (GiB) | Disk | Why |
|---|---|---|---|---|
| ethereum signer | 8 | 32 | 2.5 TB NVMe | own Ethereum full node (16 to 32 GB, 1.2 to 2 TB) + L2 follower (4 / 8 / 80 GB) + daemons |
| ethereum guardian | 8 | 32 | 2.5 TB NVMe | own Ethereum node sized for 2.3 million `eth_getLogs` a day while a finding is open (runbook 2.5) + own L2 follower and settled RPC + daemons |
| ethereum relayer | 2 | 4 | 40 GB | no node; may share a signer host under its own user |
| ethereum reserves | 1 | 1 | 10 GB | read-only; usually on the guardian host under its own user |
| EVM network signer, guardian | 16 | 96 | not sourced: measure | own network node and its own Ethereum parent node (N1) + L2 follower; Arbitrum Nitro 64 GB minimum (N2); OP Mainnet and Linea figures not retrieved by me |
| EVM network relayer, reserves | as Ethereum | | | |

| Role | Inbound | Outbound |
|---|---|---|
| signer | TCP 8787 (ethereum), 8788 (arbitrum-one), 8789 (op-mainnet), 8790 (linea): the feed, from the other signer operators' and the relayers' fixed IPs only | Bloch L1 RPC 8080 (80.240.16.185, 199.247.22.8), the other operators' feeds, an L2 RPC, own source-network node (loopback) |
| relayer | none | the operators' feeds, `https://l2rpc.blochl1.com` (L2 sends), the source network RPC |
| guardian | none | own L2 settled RPC, own source node, `https://l2rpc.blochl1.com` (second L2 view and its sends) |
| reserves | none | the L2 RPC and source RPC of its config |

The feed ports differ per route so one operator can run several routes on one host (tested: users, units, paths and
ports never collide across routes). The routes' own templates still say `http://IP:8787` in their peer placeholders.

## 7. Upgrade and rollback

```
python3 -E -s /opt/bloch-bridge/ethereum-signer/current/ops/bridgectl.py upgrade ethereum-signer NEW-BUNDLE --sha256 SHA
```

Refused: another instance's bundle, the current release again, a lower `state_epoch` (older code may not read newer
state), new config files, or changed config templates without `--config-reviewed` (the diff is printed: update the
configs first). It installs the release next to the current one, swaps `current`, installs that release's units,
restarts the units that were running and waits up to 180 s for a health check with every heartbeat newer than the
restart; if it does not pass it swaps back, restarts the previous code and exits 2 ("rolled back"). Configs, state and
credentials are never touched.

```
python3 -E -s /opt/bloch-bridge/ethereum-signer/current/ops/bridgectl.py rollback ethereum-signer
```

Refused without a previous release, when the previous release's files changed since install, or across a state epoch.
`verify` re-hashes the installed release and compares the live units with it.

## 8. Rehearsal under real systemd

`ops/rehearse_containers.py` on 45.77.142.123: Docker `--internal` network, image Ubuntu 24.04 with systemd 255
(`a381-sysd:r18` = agent 203's `a203-sysd:r11` + logrotate, acl, git). Throwaway keys generated in each container,
sealed, shredded. The launch design on two anvils: ProvenanceSourceVault mode 1 with a 5 bps fee to a throwaway
recipient, BridgedStablecoinV3 (T = 0, 12 h mint queue). Two signer operators of four (threshold 2; signers 3 and 4 are
offline keys held by the driver, used only for the forged-mint drill), one relayer, one guardian, one reserves monitor.
Rehearsal-only config changes (chain ids 11155111 and 700771, thresholds 2, `l2_source: rpc`, no mainnet pins, local
RPC URLs, `vault_pause` off because the rehearsal vault has no guardians) are written to `rehearsal-config-diff.txt`.
Docker's root mount is private, which hides each unit's credentials mount; the rig runs `mount --make-rshared /` in
each container (a host has it shared).

**Result, run 8 (`29b71a7`, with 374's F381-1 fix cherry-picked): 72 of 72 checks PASS in 947 s** (run 6, before the fix: 68 of 68, the F381-1 refusal then demonstrated; run 8 adds the committed relayer unit relaying with `credential:`, the cc2511a control, and runs the upgrade drills before the incident drills). Run 6 figures below (evidence in the coordinator's folder,
`agents/381-evidence/run6/`, including every unit's journal). Checked, in order: each bundle rebuilt byte-identical;
install refused with a wrong SHA-256 and when already installed; `check` refuses each fresh install (TBD-owner values,
no credentials, no cast pin, no hook) and `start` refuses with it; layout permissions; keys generated and sealed in each
container, no keystore left in clear, the credential store encrypted (no keystore JSON) and 0600 root; `check` passes
once filled; `check --with sombra` refuses unsealed credentials; all five daemons active; the signer's four staged
credentials 0400 owned by its user and gone after `stop`; no secret on the command line or in the environment; the
service user cannot read the credential store nor change its config, another user cannot read the staged secrets; the
feed sees neither secrets nor configs; `systemd-analyze security` 1.2 OK for every daemon unit.

| Flow step, driven only by the daemons under systemd | Seconds |
|---|---|
| deposits 100 + 50 USDC: both signers sign, the feeds carry the partials, the relayer queues both mints | 101 |
| after the 12 h queue (anvil time warp): the relayer executes both, Alice holds 149.925 bUSDC (5 bps each) | 60 |
| burn 30: both signers certify, the relayer releases, Bob receives 29.985 USDC | 182 |
| relayer killed with SIGKILL: systemd restarts it, the health timer calls the hook with WARN restarted | 70 |
| forged mint by the two offline keys: the guardian finds it, pauses the token (its pause-only key) and the hook gets CRIT | 80 |

Then: health OK on all five; the timer appends to `health.log`; logrotate rotates it and the timer writes a new 0640
file; reserves upgraded to a second release while running (health passed after the restart), rolled back, upgraded
again, then given a release that dies at import: `upgrade` rolled back by itself and the previous code runs; `verify`
clean afterwards; F381-1 demonstrated.

Peak memory (`MemoryPeak` of each unit's cgroup, children included): signer 61 MiB, feed 11 MiB, relayer 42 MiB,
guardian 33 MiB, reserves 26 MiB. Earlier runs found F381-2 (run 1, 46 of 48), the template-provenance refusal on
upgrade (run 3, 64 of 68, fixed in `75dbba2`) and an upgrade that left a release which failed to restart current
(run 5, 67 of 68, fixed in `004e0fd`: a failed restart now rolls back).

## 9. Findings

| ID | Severity | Where | Defect | Failure scenario | Demonstration | Fix |
|---|---|---|---|---|---|---|
| F381-1 | Medium | `deploy/signatario/bloch-busdc-relay.service` with `relayer.template.json` `credential:` values; `tools/signatario-stable/vigia.py:147-162` (`private_file` after `credential`) | Under a real `LoadCredential=` systemd 255 hands the password over as 0440 root:root + ACL; vigia resolves `credential:NAME` to it and `private_file` refuses any group bit | Every relayer installed as the committed unit and template describe exits at start: no mint and no release is relayed (no value at risk; liveness) | Test: `f381_1()` in `ops/rehearse_containers.py` (real systemd: `440 root:root` and "has mode 0440") | Packaging: the bundles stage each credential 0400 into the RuntimeDirectory; `check` refuses `credential:`. **Tool fixed by 374 in `b4ff916`, cherry-picked here (`f79c7f5`)**: vigia.py accepts a 0440 root file inside `$CREDENTIALS_DIRECTORY`. Run 8 (72/72): the committed `bloch-busdc-relay.service`, unchanged, with `credential:` passwords starts and relays a mint with its own gas key; the cc2511a code (control) still refuses |
| F381-2 | Medium | any signer unit with `UMask=0077` (the guardian unit of `deploy/guardiao` already uses it); `sigfeed.atomic_write` creates parent directories with the process umask and chmods only the file | The publish subdirectories are 0700, so the feed (another user) answers 404 for every partial | No partial signature leaves any operator that hardens its signer this way: no quorum, the bridge halts (liveness) | Test: the container rehearsal before `85d8b2a` (relayer `accepted: 0`, feed 404; 46 of 48) and after it (mints queued in 101 s) | Packaging: default ACL `u::rwx,g::r-x,o::r-x` on the publish directory (install sets, `check` verifies); `sigfeed.py` is pinned and unchanged |

## 10. Not done / not proven

- Bitcoin, Tron, Solana and Stellar are not packaged. Only Bitcoin has committed operator templates, its vault-signing
  is a per-proposal command (not a daemon) and is being changed this round (R342-BTC-1..3, agent 370); Tron, Solana and
  Stellar have no committed operator templates. The builder takes config templates only from the route's own commits
  (one source of truth), so each route owner commits `deployments/<net>/ops/*.template.json` and its daemon entry
  points; adding the route is then an entry in `ops/routes.json` like the EVM ones.
- The EVM networks' bundles were built and checked offline only; their daemons were not run in containers, and their
  guardian and reserves configs are derived from the Ethereum templates (route owner to confirm).
- The mainnet signer path (`l2_source: rebuild` with the follower and the pinned launch binaries) did not run: the rig
  uses `l2_source: rpc`. Under `ProtectSystem=strict` the signer reads `/var/lib/bloch-l2-mainnet-follower` read-only;
  whether `bloch-l2-produce-dev reconstruct --l1-follower` needs to write a lock file there (as MDBX readers do, F204-5)
  is not verified: the owner's `bridgectl.py preflight` on the real host (which runs `preflight_signer.py` in the
  daemon's sandbox, including the dry release) is where it shows. `MemoryDenyWriteExecute` with the L2 binaries is
  likewise unverified there.
- sombra did not run (needs the HF-line light client). The guardian's vault pause did not run (rehearsal vault without
  guardians).
- Host sizes for the EVM networks' nodes are not sourced (Arbitrum's RAM is); disk sizes there are "measure".
- No egress allow-list (`IPAddressAllow=`) in the units: the peers' addresses are owner inputs.
- The bundles are not signed. Their SHA-256 must come from a release record the owner signs (as the L2 release with
  `rsign`); the procedure for that record is not written here.
