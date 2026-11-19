// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity 0.8.24;

import {TronUSDTLike, ITronUSDTUpgraded} from "./TronUSDTLike.sol";

/// TEST ONLY (round 20). USDT on ETHEREUM (TetherToken, 0xdAC17F958D2ee523a2206206994597C13D831ec7) as it matters to a
/// vault. It is the same TetherToken design as on TRON (`TronUSDTLike`: blacklist of the sender side only,
/// `destroyBlackFunds`, pause, the `setParams` fee below 20 bps and below 50 USDT, `deprecate`) with the three
/// differences measured on a loopback fork of Ethereum on 2026-11-18 (agent 409) and 2026-11-19 (agent 411):
///   1. `transfer`, `transferFrom` and `approve` return NO data (TRON: `false`, `true`, `true`);
///   2. `approve` reverts when the current allowance and the new value are both non-zero;
///   3. `approve` is not stopped by the pause.
/// `tools/evm-nets/rehearse_route.py ethereum-usdt` deploys this contract beside the real token on the fork and
/// compares their answers call by call.
contract EthereumUSDTLike is TronUSDTLike {
    function transfer(address to, uint256 value) public virtual override returns (bool) {
        _req(!paused);
        _req(!_blackListed[msg.sender]);
        if (_deprecated) ITronUSDTUpgraded(upgradedAddress).transferByLegacy(msg.sender, to, value);
        else _move(msg.sender, to, value);
        assembly {
            return(0, 0) // measured: no return data
        }
    }

    function transferFrom(address from, address to, uint256 value) public virtual override returns (bool) {
        _req(!paused);
        _req(!_blackListed[from]);
        if (_deprecated) {
            ITronUSDTUpgraded(upgradedAddress).transferFromByLegacy(msg.sender, from, to, value);
        } else {
            uint256 allowed_ = _allowed[from][msg.sender];
            _req(value <= allowed_);
            if (allowed_ < type(uint256).max) _allowed[from][msg.sender] = allowed_ - value;
            _move(from, to, value);
        }
        assembly {
            return(0, 0) // measured: no return data
        }
    }

    function approve(address spender, uint256 value) public virtual override returns (bool) {
        if (_deprecated) {
            ITronUSDTUpgraded(upgradedAddress).approveByLegacy(msg.sender, spender, value);
        } else {
            _req(!(value != 0 && _allowed[msg.sender][spender] != 0)); // measured: 5 -> 7 and 5 -> 5 revert
            _allowed[msg.sender][spender] = value;
            emit Approval(msg.sender, spender, value);
        }
        assembly {
            return(0, 0) // measured: no return data
        }
    }
}

/// TEST ONLY. `EthereumUSDTLike` that remembers who ever called `approve`: the vault must never be one of them.
contract EthereumUSDTApproveSpy is EthereumUSDTLike {
    mapping(address => uint256) public approveCalls;

    function approve(address spender, uint256 value) public override returns (bool) {
        ++approveCalls[msg.sender];
        return super.approve(spender, value);
    }
}

/// TEST ONLY (round 20). USD₮0 on ARBITRUM ONE (proxy 0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9, implementation
/// 0x3263CD78…A3F4) as it matters to a vault, measured on a loopback fork on 2026-11-19: every call returns `true`;
/// a blocked CALLER cannot `transfer` or `transferFrom`; `transferFrom` also refuses a blocked `from`; a blocked
/// RECIPIENT is paid; a transfer to the token contract itself reverts; the owner blocks, unblocks and destroys a
/// blocked balance; only `oftContract` mints and burns. There is no fee and no pause in the implementation of today.
/// `setImplementationFee` stands for what the proxy admin could do by replacing the implementation: after it, a
/// transfer delivers less than it takes.
contract Usdt0Like {
    string public constant name = unicode"USD₮0";
    string public constant symbol = unicode"USD₮0";
    uint8 public constant decimals = 6;
    address public owner;
    address public oftContract;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    mapping(address => bool) public isBlocked;
    /// TEST ONLY: basis points a replaced implementation would keep from every transfer (0 = the code of today).
    uint256 public implementationFeeBps;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    constructor(address oft) {
        owner = msg.sender;
        oftContract = oft;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Ownable: caller is not the owner");
        _;
    }

    modifier onlyNotBlocked() {
        require(!isBlocked[msg.sender], "Blocked: msg.sender is blocked");
        _;
    }

    function transfer(address to, uint256 value) external onlyNotBlocked returns (bool) {
        require(to != address(this), "ERC20: transfer to the contract address");
        _move(msg.sender, to, value);
        return true;
    }

    function transferFrom(address from, address to, uint256 value) external onlyNotBlocked returns (bool) {
        require(to != address(this), "ERC20: transfer to the contract address");
        require(!isBlocked[from], "Blocked: sender is blocked");
        uint256 a = allowance[from][msg.sender];
        require(a >= value, "ERC20: insufficient allowance");
        if (a != type(uint256).max) allowance[from][msg.sender] = a - value;
        _move(from, to, value);
        return true;
    }

    function approve(address spender, uint256 value) external returns (bool) {
        allowance[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
        return true;
    }

    function _move(address from, address to, uint256 value) private {
        require(balanceOf[from] >= value, "ERC20: transfer amount exceeds balance");
        uint256 kept = value * implementationFeeBps / 10_000;
        balanceOf[from] -= value;
        balanceOf[to] += value - kept;
        balanceOf[owner] += kept;
        emit Transfer(from, to, value - kept);
    }

    function addToBlockedList(address who) external onlyOwner {
        isBlocked[who] = true;
    }

    function removeFromBlockedList(address who) external onlyOwner {
        isBlocked[who] = false;
    }

    function destroyBlockedFunds(address who) external onlyOwner {
        require(isBlocked[who], "not blocked");
        totalSupply -= balanceOf[who];
        balanceOf[who] = 0;
    }

    function mint(address to, uint256 value) external {
        require(msg.sender == oftContract, "Only OFT can call");
        balanceOf[to] += value;
        totalSupply += value;
    }

    function burn(address from, uint256 value) external {
        require(msg.sender == oftContract, "Only OFT can call");
        balanceOf[from] -= value;
        totalSupply -= value;
    }

    /// TEST ONLY: what an upgrade by the proxy admin could introduce.
    function setImplementationFee(uint256 bps) external onlyOwner {
        implementationFeeBps = bps;
    }
}

/// TEST ONLY (round 20). Bridged USDT on OP MAINNET (0x94b008aA00579c1307B0EF2c499aD98a8ce58e58, L2StandardERC20) as it
/// matters to a vault, measured on a loopback fork on 2026-11-19: a plain token that returns `true`, with no owner,
/// blocklist, pause or fee; its `l2Bridge` may `mint(address,uint256)` and `burn(address,uint256)` ANY holder's
/// balance without an allowance. A transfer to the token contract itself succeeds.
contract OpBridgedUsdtLike {
    string public constant name = "Tether USD";
    string public constant symbol = "USDT";
    uint8 public constant decimals = 6;
    address public immutable l1Token;
    address public immutable l2Bridge;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    constructor(address l1Token_, address l2Bridge_) {
        l1Token = l1Token_;
        l2Bridge = l2Bridge_;
    }

    function transfer(address to, uint256 value) external returns (bool) {
        _move(msg.sender, to, value);
        return true;
    }

    function transferFrom(address from, address to, uint256 value) external returns (bool) {
        uint256 a = allowance[from][msg.sender];
        require(a >= value, "ERC20: transfer amount exceeds allowance");
        allowance[from][msg.sender] = a - value;
        _move(from, to, value);
        return true;
    }

    function approve(address spender, uint256 value) external returns (bool) {
        allowance[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
        return true;
    }

    function _move(address from, address to, uint256 value) private {
        require(balanceOf[from] >= value, "ERC20: transfer amount exceeds balance");
        balanceOf[from] -= value;
        balanceOf[to] += value;
        emit Transfer(from, to, value);
    }

    function mint(address to, uint256 value) external {
        require(msg.sender == l2Bridge, "Only L2 Bridge can mint and burn");
        balanceOf[to] += value;
        totalSupply += value;
    }

    function burn(address from, uint256 value) external {
        require(msg.sender == l2Bridge, "Only L2 Bridge can mint and burn");
        balanceOf[from] -= value;
        totalSupply -= value;
    }
}
