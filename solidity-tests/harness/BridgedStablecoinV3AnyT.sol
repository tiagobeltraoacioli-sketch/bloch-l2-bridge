// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.24;

import {SignerMintedToken} from "../../contracts/bridged/SignerMintedToken.sol";
import {BridgedStablecoinV2} from "../../contracts/stable/BridgedStablecoinV2.sol";
import {BridgedStablecoinV3} from "../../contracts/stable/BridgedStablecoinV3.sol";

/// TEST HARNESS ONLY, never deployed. BridgedStablecoinV3 refuses any largeMintThreshold other than 0 (owner decision
/// 2026-11-02, F171-5). The suites written before that rule also ran at T = 100 and T = 1,000, which exercises code V3
/// inherits from V2 (instant bucket, credit-order queue without delay, resumed candidate scan). This harness is V3 with
/// only that constructor rule removed, so those suites keep their coverage. The deployed contract is tested by the T = 0
/// suites and by R194BridgeDecisions.t.sol, which asserts the refusal.
contract BridgedStablecoinV3AnyT is BridgedStablecoinV3 {
    constructor(
        string memory name_,
        string memory symbol_,
        uint256 sourceChainId_,
        address sourceVault_,
        bytes32 sourceRoute_,
        address[] memory signers_,
        uint256 threshold_,
        SignerMintedToken.Limits memory limits,
        SignerMintedToken.Guard memory guard,
        BridgedStablecoinV2.MintSwitch memory mintSwitch
    )
        BridgedStablecoinV3(
            name_, symbol_, sourceChainId_, sourceVault_, sourceRoute_, signers_, threshold_, limits, guard, mintSwitch
        )
    {}

    function _launchThreshold(uint256) internal pure override {}
}

/// Deploys the real V3 at T = 0 and the harness at T > 0.
library V3Deploy {
    function make(
        string memory name_,
        string memory symbol_,
        uint256 sourceChainId_,
        address sourceVault_,
        bytes32 sourceRoute_,
        address[] memory signers_,
        uint256 threshold_,
        SignerMintedToken.Limits memory limits,
        SignerMintedToken.Guard memory guard,
        BridgedStablecoinV2.MintSwitch memory mintSwitch
    ) internal returns (BridgedStablecoinV3 token) {
        if (limits.largeMintThreshold == 0) {
            token = new BridgedStablecoinV3(
                name_, symbol_, sourceChainId_, sourceVault_, sourceRoute_, signers_, threshold_, limits, guard, mintSwitch
            );
        } else {
            token = new BridgedStablecoinV3AnyT(
                name_, symbol_, sourceChainId_, sourceVault_, sourceRoute_, signers_, threshold_, limits, guard, mintSwitch
            );
        }
    }
}
