# Legacy: the three-of-five custody line

Every `*.pending.json` here belongs to the earlier three-of-five custody and authority line for a Bloch L1 bUSDC asset. They
are not on the path to mainnet and do not apply to the 5-of-7 vault, whose configuration is
`deployments/mainnet/busdc-mainnet.config.json` and `deployments/mainnet/busdc-vault-mainnet.config.json`.

The files are kept unchanged because the legacy checkers in `scripts/` read them with strict schemas.
See `docs/MAINNET-USDC-ACTIVATION-HANDOFF.md`, "Superseded: the 3-of-5 line".
