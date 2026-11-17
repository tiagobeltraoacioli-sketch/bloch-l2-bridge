// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// A minimal contract account for the bBTC rehearsal (tools/signatario-btc/rehearse_regtest.py, section K): its owner
/// makes it call anything. It stands for a smart account or a Safe that holds bBTC, burns it directly on the token and
/// cannot sign a message, but can send a transaction to `BitcoinBurnRouter.claimDirectBurn`. TEST HELPER, not deployed.
contract BitcoinRehearsalAccount {
    address public immutable owner;

    constructor() {
        owner = msg.sender;
    }

    function exec(address to, bytes calldata data) external returns (bytes memory out) {
        require(msg.sender == owner, "owner");
        bool ok;
        (ok, out) = to.call(data);
        require(ok, "call failed");
    }
}
