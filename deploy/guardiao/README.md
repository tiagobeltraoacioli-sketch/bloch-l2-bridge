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

The guardian key can only pause, and a pause expires by itself after `pauseDuration`; the cooldown
bounds a malicious guardian to delaying mints at most half the time. Losing the key costs nothing but
that guardian's vote; replacing it requires a new token contract (no setters).
