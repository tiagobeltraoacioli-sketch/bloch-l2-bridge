#!/usr/bin/env python3
"""What `block.number` and `blockhash(n)` return inside a contract of this network, read with one eth_call.

ProvenanceSourceVault.release checks its certificate's source anchor with `blockhash(sourceAnchorNumber)`, so the
anchor must be a value the EVM of that network returns, inside its 256-entry window. On Ethereum that is the hash of
the block with that number, and the finalized block is inside the window, which is what eth_half.py assumes by default
(`anchor_policy: finalized`). On other networks neither holds (measured 2026-11-16, agents/320-bridge-evm-nets-r16.md):

  Arbitrum One  `block.number` is an Ethereum block number and `blockhash(n)` is ArbOS's value for that number, not
                the hash of any block the RPC serves by number; the window is 256 Ethereum blocks.
  OP Mainnet, Base, Linea  the hash by number, but `finalized` is 600 to 5,000 blocks behind the head.

`anchor_policy: probe` therefore asks the node itself: an eth_call with no `to` runs the bytes below as creation code
at a named block and returns what they return, on geth, Nitro, op-geth/op-reth, Besu (Linea), BSC and anvil alike.
Nothing is deployed and nothing is sent. The answer is only as good as the signer's own node, like every other read.

An anchor is NOT a finality claim. It binds a certificate to one fork for a short time: if the anchor block is
reorganised away, `blockhash` no longer returns the signed value and the vault refuses the certificate
(`InvalidContext`). What must be final before a signature is checked separately, at `finalized`.
"""

WINDOW = 256


def _code(number=None):
    """Creation code returning abi.encode(block.number, blockhash(number or block.number - 1), block.chainid)."""
    target = ('7f' + f'{number:064x}') if number is not None else '6001430 3'.replace(' ', '')
    # NUMBER PUSH1 0 MSTORE | <target> BLOCKHASH PUSH1 0x20 MSTORE | CHAINID PUSH1 0x40 MSTORE | PUSH1 0x60 PUSH1 0 RETURN
    return '0x' + '43600052' + target + '40602052' + '46604052' + '60606000f3'


def evm_view(rpc, block, number=None):
    """(block.number, blockhash(number), chain id) as a contract executing on top of `block` sees them.

    `rpc(method, params)` is the caller's own JSON-RPC function; `block` is a tag or a hex block number. With
    `number` None the hash is that of `block.number - 1`."""
    out = rpc('eth_call', [{'data': _code(number)}, block])
    if not isinstance(out, str) or len(out) != 2 + 64 * 3:
        raise ValueError(f'the node did not answer the anchor probe: {str(out)[:120]}')
    return int(out[2:66], 16), '0x' + out[66:130].lower(), int(out[130:194], 16)

