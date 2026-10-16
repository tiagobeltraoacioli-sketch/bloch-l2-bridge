# Ethereum execution-header vector

`mainnet-genesis.rlp.hex` is the canonical 535-byte historical Ethereum mainnet
genesis header. Its independently published block hash is
`0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3`.

The header fields come from the pinned Reth source
[`crates/chainspec/res/genesis/mainnet.json`](https://github.com/paradigmxyz/reth/blob/8eb210175687c9f0c889a3b6795c16781d830e3a/crates/chainspec/res/genesis/mainnet.json).
It was encoded independently with viem's RLP implementation and checked with
its Keccak-256 implementation before being retained. Empty transaction/receipt
tries and the empty ommer list use their canonical RLP commitments. The nonce
remains an eight-byte string; zero-valued integers use empty RLP strings.

The Rust integration test decodes these fixed bytes, recomputes the pinned hash,
checks the genesis fields and refuses a changed header under the same anchor.
No current RPC request was made. A historical genesis fixture does not qualify
deployment, native settlement, present consensus finality or operational trust.
