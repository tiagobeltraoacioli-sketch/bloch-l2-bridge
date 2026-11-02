// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.24;

import {SignerMintedToken} from "../contracts/bridged/SignerMintedToken.sol";
import {BridgedStablecoinV2} from "../contracts/stable/BridgedStablecoinV2.sol";
import {BridgedStablecoinV3} from "../contracts/stable/BridgedStablecoinV3.sol";
import {V3Deploy} from "./harness/BridgedStablecoinV3AnyT.sol";
import {R194Base, r194id} from "./R194Base.sol";

/// Agent 194, owner decision item 1 (2026-11-02): T = 0 is a hard rule in BridgedStablecoinV3's constructor (F171-5).
contract R194T0RuleTest is R194Base {
    /// F171-5 at T > 0 now reverts: agent 171's T = 1,000 USDC (the old mainnet value), T = 100, T = 1 unit, and T = max
    /// ("no delay" on V2) are all refused at deployment.
    function test_F171_5_v3RefusesEveryThresholdAboveZero() public {
        uint256[4] memory ts = [uint256(1_000 * U), 100 * U, 1, type(uint256).max];
        for (uint256 i; i < ts.length; ++i) {
            try this.deploy(ts[i]) returns (address) {
                revert("F171-5: V3 deployed at T > 0");
            } catch (bytes memory err) {
                require(selectorOf(err) == SignerMintedToken.BadConfig.selector, "refused with BadConfig");
            }
        }
    }

    function deploy(uint256 large) external returns (address) {
        return address(newToken(large));
    }

    /// At T = 0 the instant capacity is 0 and a 1-unit forged mint queues for 12 h and is cancellable: it never credits.
    function test_T0_instantCapacityZeroAndEveryMintQueues() public {
        require(token.largeMintThreshold() == 0, "T = 0");
        require(token.instantCapacity() == 0 && token.availableInstant() == 0, "instant capacity 0");
        bytes32 f = r194id(keccak256("forged unit"), 0);
        mint(f, 0, 1, MALLORY);
        require(token.totalSupply() == 0 && token.balanceOf(MALLORY) == 0, "nothing credits at once");
        (, uint64 amount, uint64 readyAt) = token.pendingMints(f);
        require(amount == 1 && readyAt == block.timestamp + 12 hours, "queued for the 12 h delay");
        cancel(f);
        vm.warp(block.timestamp + 12 hours);
        (bool ok,) = address(token).call(abi.encodeCall(SignerMintedToken.executeMint, (f)));
        require(!ok && token.mintCount() == 0, "a cancelled forgery never credits");
    }

    /// Control: agent 171's F171-5 credit reproduces on the test harness (V3 without the rule), so the refusal above is
    /// what removes it. At T = 1,000 USDC the instant capacity is the whole bucket and a 1-unit forged mint credits at once.
    function test_control_harnessAtT1000CreditsAForgedUnitAtOnce() public {
        BridgedStablecoinV3 t = V3Deploy.make(
            "Bloch Bridged USDC", "bUSDC", block.chainid, address(vault), vault.routeId(), addrs(mintKeys), 5,
            limits(1_000 * U), guard(), BridgedStablecoinV2.MintSwitch(6, 14 days)
        );
        token = t;
        require(t.instantCapacity() == BUCKET, "harness: instant capacity is the bucket");
        mint(r194id(keccak256("forged unit"), 0), 0, 1, MALLORY);
        require(t.balanceOf(MALLORY) == 1 && t.mintCount() == 1, "harness: the forged unit credits at once");
    }
}
