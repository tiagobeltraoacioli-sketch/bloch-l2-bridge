// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity 0.8.24;

import {NativeEtherSourceVault} from "../../contracts/eth/NativeEtherSourceVault.sol";

/// Recipients, depositors and attackers for the NativeEtherSourceVault suites (agent 412, round 20). Test code only.

/// A recipient that refuses ether.
contract EthReverter {
    receive() external payable {
        revert("no");
    }
}

/// A recipient that never returns: it spends all the gas it is given.
contract EthGasBurner {
    receive() external payable {
        while (true) {}
    }
}

/// A recipient that answers with `size` bytes of return data (a "return bomb"), accepting the ether.
contract EthReturnBomb {
    uint256 public immutable size;

    constructor(uint256 size_) {
        size = size_;
    }

    fallback() external payable {
        uint256 n = size;
        assembly {
            return(0, n)
        }
    }
}

/// A recipient that reverts with `size` bytes of revert data.
contract EthRevertBomb {
    uint256 public immutable size;

    constructor(uint256 size_) {
        size = size_;
    }

    fallback() external payable {
        uint256 n = size;
        assembly {
            revert(0, n)
        }
    }
}

/// A recipient whose `receive` spends about `burn` gas and then accepts: a smart-contract wallet with a costly hook.
contract EthHungryAcceptor {
    uint256 public immutable burn;

    constructor(uint256 burn_) {
        burn = burn_;
    }

    receive() external payable {
        uint256 stop = gasleft() > burn ? gasleft() - burn : 0;
        while (gasleft() > stop) {}
    }
}

/// A recipient that refuses until `open()` is called; and one that can never receive but can redirect its claim.
contract EthToggle {
    bool public accepting;

    function open() external {
        accepting = true;
    }

    function close() external {
        accepting = false;
    }

    receive() external payable {
        require(accepting, "closed");
    }
}

contract EthClaimRedirect {
    function redirect(NativeEtherSourceVault vault, address to) external returns (uint64) {
        return vault.claim(to);
    }
}

/// Re-enters the vault from inside a payment. During a release push (PUSH_GAS only) it tries the cheap entry points
/// and ACCEPTS the ether only if every one of them was refused with `Reentrancy()`; otherwise it reverts. So "the push
/// was paid, not deferred" proves the guard refused each re-entry. With `deep` set (a claim or a fee sweep, which
/// forward all gas) it also replays a prepared release and a deposit, and records each selector in storage.
contract EthReentrant {
    NativeEtherSourceVault public immutable vault;
    bool public deep;
    bytes public preparedRelease;
    bytes4[] public seen;
    bool public allRefused;

    constructor(NativeEtherSourceVault vault_) {
        vault = vault_;
    }

    function arm(bytes calldata releaseCall) external {
        deep = true;
        preparedRelease = releaseCall;
    }

    function seenCount() external view returns (uint256) {
        return seen.length;
    }

    function claimTo(address to) external returns (uint64) {
        return vault.claim(to);
    }

    function _try(bytes memory data, uint256 value) private returns (bytes4 e) {
        (bool ok, bytes memory ret) = address(vault).call{value: value}(data);
        if (ok) return bytes4(0);
        if (ret.length >= 4) e = bytes4(ret);
        else e = bytes4(0xffffffff);
    }

    receive() external payable {
        bytes4 want = NativeEtherSourceVault.Reentrancy.selector;
        if (!deep) {
            require(_try(abi.encodeCall(NativeEtherSourceVault.claimFor, (address(this))), 0) == want, "claimFor");
            require(_try(abi.encodeCall(NativeEtherSourceVault.sweepFees, ()), 0) == want, "sweepFees");
            require(_try(abi.encodeCall(NativeEtherSourceVault.claim, (address(this))), 0) == want, "claim");
            require(_try(abi.encodeCall(NativeEtherSourceVault.guardianPause, ()), 0) == want, "guardianPause");
            return;
        }
        delete seen;
        seen.push(_try(preparedRelease, 0));
        seen.push(_try(abi.encodeCall(NativeEtherSourceVault.deposit, (20_000, bytes32(uint256(1)))), 20_000 * 1e12));
        seen.push(_try(abi.encodeCall(NativeEtherSourceVault.claimFor, (address(this))), 0));
        seen.push(_try(abi.encodeCall(NativeEtherSourceVault.claim, (address(this))), 0));
        seen.push(_try(abi.encodeCall(NativeEtherSourceVault.sweepFees, ()), 0));
        seen.push(_try(abi.encodeCall(NativeEtherSourceVault.executeRelease, (bytes32(uint256(1)))), 0));
        bool all = true;
        for (uint256 i; i < seen.length; ++i) {
            if (seen[i] != want) all = false;
        }
        allRefused = all;
    }
}

/// Destroys itself in favour of `target`, forcing its ether in without a call.
contract EthForcer {
    constructor(address payable target) payable {
        selfdestruct(target);
    }
}

/// A contract depositor (a smart-contract wallet, a router): it deposits for an L2 recipient it states.
contract EthContractDepositor {
    function depositFor(NativeEtherSourceVault vault, uint64 amount, address l2) external payable returns (bytes32) {
        return vault.deposit{value: msg.value}(amount, bytes32(uint256(uint160(l2))));
    }

    receive() external payable {}
}
