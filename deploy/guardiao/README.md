# A bridge guardian machine

The guardian (`tools/guardiao`) is the bridge's second, independent check. It must not share anything
with the signers but the public contracts:

| Item | Rule |
| --- | --- |
| Operator | a party that operates no signer of this bridge (CCIP RMN model); 2–3 guardians per bridge, each a different operator |
| Machine | its own host and provider; never a signer machine, never the L2 sequencer host |
| Nodes | its own L2 RPC (ideally its own follower), its own GnB-SMH node (wGSMH) or Ethereum node (stablecoin) |
| Key | one EVM key, generated on the machine, imported as a `cast` keystore under `/etc/bloch-guardiao/` (mode 0400, user `bloch-guardiao`) with a password file; its address goes into the token constructor as a guardian. It only needs L2 gas |
| Code | `tools/guardiao` only, installed under `/opt/bloch-guardiao` (read-only); `cast` in `/opt/bloch-guardiao/bin` (config `cast`, because `ProtectHome=yes`) |

Layout: `/etc/bloch-guardiao/<bridge>.json` (config), `/etc/bloch-guardiao/<bridge>.keystore` +
`<bridge>.pw`, state in `/var/lib/bloch-guardiao/<bridge>-state.json`. Enable with
`systemctl enable --now bloch-ponte-guardiao@<bridge>`. Every line on stdout (journald) is JSON;
alert on `kind == "alert"` and `kind == "pause"` (e.g. a journald forwarder to the operator's pager).

Health: `bloch-ponte-guardiao-monitor@<bridge>.timer` runs `l2_monitor.py --guardian-health` every minute under the user
`bloch-guardiao-monitor`, a member of the group `bloch-guardiao`. It reads `/var/lib/bloch-guardiao/<bridge>-health.json`, so
`health_file` must be that path. The monitor cannot read the keys in `/etc/bloch-guardiao`. Install `l2_monitor.py` at
`/opt/bloch-guardiao/monitor/`, copy `guardiao-monitor.env.example` to `/etc/bloch-guardiao-monitor/<bridge>.env`, and write
`/etc/bloch-guardiao-monitor/alert.json` from `alert.json.example` in bloch-l2-evm. The monitor raises alerts even if the guardian
process is dead, which `alert_command` cannot do, so run both. The units have passed `systemd-analyze verify` only.

The guardian key can only pause, and a pause expires by itself after `pauseDuration`; the cooldown
bounds a malicious guardian to delaying mints at most half the time. Losing the key costs nothing but
that guardian's vote; replacing it requires a new token contract (no setters).
