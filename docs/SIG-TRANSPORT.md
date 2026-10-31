# Signature transport: per-operator read-only feeds

The common transport for bUSDC signer partials (`tools/signatario-stable`) and L2 withdrawal attestations
(`deployment/mainnet/attestor` in the L2 repo). Both use the same `sigfeed.py`, byte for byte
(`sigfeed.sha256`). No operator signs by hand, and no signature needs the transport to be honest.

## Design

Each operator serves its signatures as static files. Everyone else polls with GET.

| | Per-operator read-only feed (built) | One append-only drop (rejected) |
| --- | --- | --- |
| Availability | k of n feeds must be reachable, the same as the signing threshold, and any feed can relay another's signatures | The drop is a single point of failure for every signer |
| Withholding | A feed can hide only what no other feed holds | One party can stall all signing by withholding |
| Write credential | None exists | A token per operator, to issue and rotate |
| Disk filling | Readers take only verified items they asked for; a server holds only its own operator's files | The drop accepts writes, so it needs its own abuse controls |
| Who runs it | Each operator, for itself | A permanent new role, in conflict with set-once operation |
| Cost | One inbound port per operator | No inbound port on operators |

Only reads travel over the network, so the attack surface is a static GET handler with a path allow-list.

## Paths

```
bridge/<token>/mint/<depositId>/<signer>.json       one mint partial
bridge/<token>/release/<burnId>/<signer>.json       {"certs": [...]}, at most 4 live certificates
700770/<root>/attestor-<i>.partial                  one attestor partial
```

Paths are computed, never listed. A reader asks only for deposits, burns and roots it found on its own
nodes, and only for the pinned signers, so an attacker cannot make a reader want anything new.

## Why the transport can be untrusted

A bridge reader stores a body only if all of these hold:

- the fields name this token, vault, route and chain, and the item and signer named by the path;
- the digest recomputes locally from the fields;
- the signature recovers to the path's signer (low-s, v 27/28), a pinned signer checked against `isSigner`;
- a release certificate is unexpired and within `max_valid_seconds`.

`vigia.py` then checks each partial against the chain again before using it: the signature, `isSigner`, and the digest as
the token's `mintDigest` or the vault's `releaseDigest` computes it.

Fields outside the signature are dropped before storing, so a relay cannot attach anything to a signature.
Verified items live in the operator's private `shared_dir` and are re-exported, so each feed also relays
the others. A server can withhold or delay, but it cannot forge, and it cannot evict what a
reader holds. Signing checks are unchanged: `signatario.py` still verifies every deposit and burn itself.

Attestor partials need post-quantum verification, which only the native binary does, and only over a full
set. `aggregate_attestation.py` keeps every distinct well-formed candidate per signer and lets
`bloch-pos l2-claim verify-attestation` choose (at most 1024 sets), so a forged partial cannot displace a
real one. A partial above the claim's 4593-byte signature bound is refused before that, and the agent re-signs until its own
fits. Attestors do not read each other: only the aggregator and the monitor are readers.

## Limits

| Threat | Limit |
| --- | --- |
| Oversized reply | 64 KiB per fetch; the declared length is refused unread, endless or chunked bodies stop at the cap, compressed replies are refused |
| Slow server | Wall-clock deadline per fetch (default 5 s), budget per peer per cycle (default 20 s), one thread per peer |
| Redirects, proxies, other schemes | Not followed, not used, refused |
| Disk filling | `max_store_bytes` over open items (default 256 MiB), `min_free_bytes` (default 1 GiB), 4 certificates per signer per file, 8 rounds per signer per burn, 512 open items per cycle (half the oldest, half the newest). A full store refuses ingest and logs `feed-store-full`; signing carries on |
| Operator down | Backoff per peer, 30 s doubling to 600 s; the others are unaffected. `feed.status_file` reports each peer. A peer that accepts and then drops a connection, answers 503 or runs out of cycle budget is busy, not down: no backoff |
| Long backlog | At most 120 paths per peer per pull, resumed on the next cycle, so a large backlog is covered over several passes |
| Server abuse | GET and HEAD only, allow-listed paths, regular files only (no symlinks), 64 connections, 4 per IP (per /64 on IPv6), 600 connections per IP per minute, 2 s to send the request and 10 s per connection, 4 KiB request head. When all slots are taken, the longest-idle connection makes room. **Owner item:** a firewall allow-list of operator and relayer IPs is the stronger control; code cannot tell a peer from a stranger |

## Rounds without a shared lock

Certificates combine only within one round (same anchor, `validUntil` and digest), and `flock` now protects only the
operator's own directory. A signer stays in its round unless a live round holds more distinct signers, or as many with a higher
name (the newest `validUntil`). Concurrent openers therefore converge, and a lone key cannot pull signers away
from a growing round. Before any rebuild, a round must name the burn's fields as the signer's own log shows them and an anchor
its Ethereum node knows, so junk rounds from a real key cost a read. `max_release_signs_per_hour` (default 6 per burn)
bounds a signer's certificates and own rounds. Joins refused after a rebuild have a separate budget of the same size, and
once it is spent, rounds with a single signer are not tried. A round this signer's Ethereum half refused is skipped for
`refused_retry` seconds, and if every live round was refused, the signer opens its own.

A relayer groups chain-verified partials by digest and combines only a group with k distinct signers, so one dissenting or
corrupt partial no longer vetoes the others. Joins come before new rounds, and a pass opens at most `max_new_rounds`.

## The owner's setting

`feed.peers`: the base URL of each operator's feed, one inbound port on each host.

**Recommendation:** plain HTTP on TCP 8787 to a fixed IP, one feed per operator, every operator listing all
the others. TLS adds no integrity here, and an expired certificate would take a feed down. A list change
touches only delivery, never trust, so it can be edited by any operator at any time. An operator that cannot
open a port pushes to its own static host, and its URL goes in the list instead.

## Not covered

- The transport cannot deliver what fewer than k operators publish. The bridge then waits, and rounds expire
  and are replaced. Alert on `feed.status_file`.
- A signer needs its L2 rebuild to finish within a round's life (`valid_seconds` minus `round_margin`).
- `tools/signatario-gnb` (wGSMH) still uses a plain `shared_dir`, and it is low priority while GnB-SMH is stopped.
