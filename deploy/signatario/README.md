# A bridge signer machine (mainnet layout)

Each of the n signers runs on its own machine, operated by a different party, and trusts nothing it
did not verify there:

| Process | Why |
| --- | --- |
| Bloch native node + L2 follower (`bloch-l2-native-follower`) | FFG finality from the pinned genesis (no checkpoint signatures) |
| L2 rebuild tools (`bloch-l2-produce`, `bloch-l2-settled-rpc`) | burns are read from an L2 rebuilt from L1 data |
| Source-chain node (GnB-SMH `gnb`, later `bitcoind` / an Ethereum node) | locks and deposits at depth N / finality |
| `bloch-ponte-vigia@<bridge>` | signs (EVM keystore + GnB-SMH/Bitcoin/Ethereum key, never in argv) |

`bloch-ponte-relay@<bridge>` can run anywhere (several is fine): it only pays L2 gas and broadcasts.
The shared directory is untrusted storage (object store, git, rsync); every reader verifies.

Keys: generated on the signer machine, never copied; EVM keystore + password file readable only by
`bloch-ponte`; the public keys/addresses go into the contract constructor and the vault once.
