// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity 0.8.24;

/// TEST ONLY. An L2 bridged token reduced to its supply views (tools/reservas tests).
contract MockSupplyV2 {
    uint256 public totalSupply;
    uint256 public pendingSupply;

    function set(uint256 supply, uint256 pending) external {
        totalSupply = supply;
        pendingSupply = pending;
    }
}

/// TEST ONLY. A v1 token: no pendingSupply().
contract MockSupplyV1 {
    uint256 public totalSupply;

    function set(uint256 supply) external {
        totalSupply = supply;
    }
}
