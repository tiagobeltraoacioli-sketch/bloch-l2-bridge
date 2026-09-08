# Vendored ERC-20 dependency

Unmodified files from OpenZeppelin Contracts v5.0.2, commit
`dbb6104ce834628e473d2173bbc9d47f81a9eec3`:

- `contracts/token/ERC20/ERC20.sol`
- `contracts/token/ERC20/IERC20.sol`
- `contracts/token/ERC20/extensions/IERC20Metadata.sol`
- `contracts/utils/Context.sol`
- `contracts/interfaces/draft-IERC6093.sol`
- `LICENSE`

Upstream: https://github.com/OpenZeppelin/openzeppelin-contracts/tree/dbb6104ce834628e473d2173bbc9d47f81a9eec3

These files retain their MIT license. The Chameleon adapter adds its own
mint/burn authorization and origin accounting. The existing solc 0.8.24 pin
can compile this release; no floating package install is used by the tests.
