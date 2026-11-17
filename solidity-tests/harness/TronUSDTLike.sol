// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity 0.8.24;

/// TEST ONLY. The target a deprecated TetherToken forwards to (from the published TetherToken design, not measured).
interface ITronUSDTUpgraded {
    function transferByLegacy(address from, address to, uint256 value) external returns (bool);
    function transferFromByLegacy(address sender, address from, address to, uint256 value) external returns (bool);
    function approveByLegacy(address from, address spender, uint256 value) external returns (bool);
    function balanceOf(address who) external view returns (uint256);
    function totalSupply() external view returns (uint256);
    function allowance(address owner, address spender) external view returns (uint256);
}

/// TEST ONLY. USDT on TRON (TetherToken, TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t) as it matters to a vault.
/// The real creation bytecode cannot run in forge (TVM-only opcodes), so this mock reproduces its behaviour as agent 323
/// measured it on a private TVM. Every non-standard behaviour is tagged:
///   "measured"                   observed with the real bytecode;
///   "from the published design"  taken from the published TetherToken source, not measured.
/// Every failed requirement reverts with EMPTY data (measured), hence `_req` and no checked-arithmetic panics.
/// `solidity-tests/TronUSDTLike.t.sol` asserts each row of the measured table against this contract.
contract TronUSDTLike {
    string public constant name = "Tether USD";
    string public constant symbol = "USDT";
    uint8 public constant decimals = 6;

    address public owner;
    bool public paused;
    uint256 public basisPointsRate;
    uint256 public maximumFee;
    address public upgradedAddress;

    bool internal _deprecated;
    uint256 internal _totalSupply;
    mapping(address => uint256) internal _balances;
    mapping(address => mapping(address => uint256)) internal _allowed;
    mapping(address => bool) internal _blackListed;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event AddedBlackList(address indexed user);
    event RemovedBlackList(address indexed user);
    event DestroyedBlackFunds(address indexed user, uint256 balance);
    event Issue(uint256 amount);
    event Redeem(uint256 amount);
    event Deprecate(address newAddress);
    event Params(uint256 feeBasisPoints, uint256 maxFee);
    event Pause();
    event Unpause();

    constructor() {
        owner = msg.sender;
    }

    function _req(bool condition) internal pure {
        if (!condition) revert(); // measured: empty revert data
    }

    modifier onlyOwner() {
        _req(msg.sender == owner);
        _;
    }

    // ------------------------------------------------------------------ getters

    /// The real token exposes this as a public mapping getter; a function here so that a test variant can break it.
    function isBlackListed(address who) public view virtual returns (bool) {
        return _blackListed[who];
    }

    function getBlackListStatus(address who) external view returns (bool) {
        return _blackListed[who];
    }

    function deprecated() public view virtual returns (bool) {
        return _deprecated;
    }

    /// From the published design: once deprecated, the legacy contract answers with the upgraded contract's value.
    function balanceOf(address who) public view returns (uint256) {
        if (_deprecated) return ITronUSDTUpgraded(upgradedAddress).balanceOf(who);
        return _balances[who];
    }

    /// From the published design: forwarded once deprecated.
    function totalSupply() public view returns (uint256) {
        if (_deprecated) return ITronUSDTUpgraded(upgradedAddress).totalSupply();
        return _totalSupply;
    }

    /// From the published design: forwarded once deprecated.
    function allowance(address holder, address spender) public view returns (uint256) {
        if (_deprecated) return ITronUSDTUpgraded(upgradedAddress).allowance(holder, spender);
        return _allowed[holder][spender];
    }

    // ---------------------------------------------------------------- transfers

    /// Measured: a successful `transfer` does NOT revert, emits Transfer and returns 32 bytes of zero (ABI `false`).
    /// Measured: reverts while paused, from a blacklisted `msg.sender`, and above the balance. A blacklisted RECIPIENT
    /// is paid. Self-transfers and zero-value transfers succeed.
    /// From the published design: once deprecated the call is forwarded and the upgraded contract's answer is returned
    /// (the pause and the sender's blacklist entry are still checked here first).
    function transfer(address to, uint256 value) public virtual returns (bool) {
        _req(!paused);
        _req(!_blackListed[msg.sender]);
        if (_deprecated) return ITronUSDTUpgraded(upgradedAddress).transferByLegacy(msg.sender, to, value);
        _move(msg.sender, to, value);
        return false; // measured
    }

    /// Measured: returns ABI `true`; reverts while paused, when `from` is blacklisted, above the allowance or the
    /// balance. A blacklisted RECIPIENT is paid and a blacklisted SPENDER (`msg.sender`) may still move the funds of a
    /// clean `from`. An allowance of 2^256-1 is not decremented.
    /// From the published design: forwarded once deprecated.
    function transferFrom(address from, address to, uint256 value) public virtual returns (bool) {
        _req(!paused);
        _req(!_blackListed[from]);
        if (_deprecated) return ITronUSDTUpgraded(upgradedAddress).transferFromByLegacy(msg.sender, from, to, value);
        uint256 allowed_ = _allowed[from][msg.sender];
        _req(value <= allowed_);
        if (allowed_ < type(uint256).max) _allowed[from][msg.sender] = allowed_ - value; // measured: max is kept
        _move(from, to, value);
        return true; // measured
    }

    /// Measured: returns true, nonzero -> nonzero is allowed, reverts while paused.
    /// From the published design: forwarded once deprecated.
    function approve(address spender, uint256 value) public virtual returns (bool) {
        _req(!paused);
        if (_deprecated) return ITronUSDTUpgraded(upgradedAddress).approveByLegacy(msg.sender, spender, value);
        _allowed[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
        return true;
    }

    /// Measured: fee = min(value * basisPointsRate / 10000, maximumFee); the sender loses `value`, the recipient gets
    /// `value - fee`, the fee goes to `owner`. Applies to transfer and transferFrom alike.
    function _move(address from, address to, uint256 value) internal {
        _req(_balances[from] >= value);
        uint256 fee = value * basisPointsRate / 10_000;
        if (fee > maximumFee) fee = maximumFee;
        uint256 sent = value - fee;
        _balances[from] -= value;
        _balances[to] += sent;
        emit Transfer(from, to, sent);
        if (fee > 0) {
            _balances[owner] += fee;
            emit Transfer(from, owner, fee);
        }
    }

    // ------------------------------------------------------------- issuer powers

    function addBlackList(address who) external onlyOwner {
        _blackListed[who] = true;
        emit AddedBlackList(who);
    }

    function removeBlackList(address who) external onlyOwner {
        _blackListed[who] = false;
        emit RemovedBlackList(who);
    }

    /// Measured: only for a blacklisted account; its balance becomes 0 and the total supply decreases.
    function destroyBlackFunds(address who) external onlyOwner {
        _req(_blackListed[who]);
        uint256 dirty = _balances[who];
        _balances[who] = 0;
        _totalSupply -= dirty;
        emit DestroyedBlackFunds(who, dirty);
    }

    function pause() external onlyOwner {
        _req(!paused);
        paused = true;
        emit Pause();
    }

    function unpause() external onlyOwner {
        _req(paused);
        paused = false;
        emit Unpause();
    }

    /// Measured: requires bps < 20 and maxFee < 50; stores maximumFee = maxFee * 10**decimals.
    function setParams(uint256 newBasisPoints, uint256 newMaxFee) external onlyOwner {
        _req(newBasisPoints < 20);
        _req(newMaxFee < 50);
        basisPointsRate = newBasisPoints;
        maximumFee = newMaxFee * 10 ** uint256(decimals);
        emit Params(basisPointsRate, maximumFee);
    }

    function issue(uint256 amount) external onlyOwner {
        _balances[owner] += amount;
        _totalSupply += amount;
        emit Issue(amount);
    }

    function redeem(uint256 amount) external onlyOwner {
        _req(_totalSupply >= amount);
        _req(_balances[owner] >= amount);
        _totalSupply -= amount;
        _balances[owner] -= amount;
        emit Redeem(amount);
    }

    /// From the published design (not measured): sets `deprecated()` and `upgradedAddress()`; afterwards transfer,
    /// transferFrom, approve, balanceOf, totalSupply and allowance are forwarded to the upgraded contract.
    function deprecate(address upgraded) external onlyOwner {
        _deprecated = true;
        upgradedAddress = upgraded;
        emit Deprecate(upgraded);
    }

    // ------------------------------------------------------------------ test only

    /// TEST ONLY (not in the real token): credit `to` out of thin air, so tests can fund accounts in any issuer state.
    function mint(address to, uint256 amount) external {
        _balances[to] += amount;
        _totalSupply += amount;
    }
}

/// TEST ONLY. A minimal upgraded token for the deprecate path (from the published design, not measured): it keeps its
/// own balances and accepts the three `*ByLegacy` calls from the legacy contract only. `shortfall` makes it misbehave:
/// the recipient receives that much less than the sender loses.
contract TronUSDTUpgraded is ITronUSDTUpgraded {
    address public immutable legacy;
    uint256 public totalSupply;
    uint256 public shortfall;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    constructor(address legacy_) {
        legacy = legacy_;
    }

    /// TEST ONLY: stands for the balance migration of a real upgrade.
    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        totalSupply += amount;
    }

    /// TEST ONLY: misbehave (deliver `amount` less than was sent).
    function setShortfall(uint256 amount) external {
        shortfall = amount;
    }

    function transferByLegacy(address from, address to, uint256 value) external returns (bool) {
        if (msg.sender != legacy) revert();
        _move(from, to, value);
        return true;
    }

    function transferFromByLegacy(address sender, address from, address to, uint256 value) external returns (bool) {
        if (msg.sender != legacy) revert();
        uint256 allowed_ = allowance[from][sender];
        if (value > allowed_) revert();
        if (allowed_ < type(uint256).max) allowance[from][sender] = allowed_ - value;
        _move(from, to, value);
        return true;
    }

    function approveByLegacy(address from, address spender, uint256 value) external returns (bool) {
        if (msg.sender != legacy) revert();
        allowance[from][spender] = value;
        return true;
    }

    function _move(address from, address to, uint256 value) private {
        if (balanceOf[from] < value) revert();
        uint256 lost = shortfall > value ? value : shortfall;
        balanceOf[from] -= value;
        balanceOf[to] += value - lost;
        totalSupply -= lost;
    }
}

/// TEST ONLY. TronUSDTLike plus switches that no real USDT has; with every switch off it IS TronUSDTLike.
///   getter modes (per getter): 0 faithful, 1 revert, 2 return 0 bytes, 3 return 64 bytes of zero,
///                              4 return one word holding 2 (a non-boolean, read as "set" by the vault);
///   `lie`:  transfer/transferFrom return `true` and move nothing;
///   hook:   one call to an arbitrary target from inside the next transfer/transferFrom (reentrancy).
contract TronUSDTFaulty is TronUSDTLike {
    uint8 public blackListGetterMode;
    uint8 public deprecatedGetterMode;
    bool public lie;
    address public hookTarget;
    bytes public hookData;
    bool public hookCalled;
    bool public hookOk;
    bytes4 public hookResult;

    function setGetterModes(uint8 blackListMode, uint8 deprecatedMode) external {
        blackListGetterMode = blackListMode;
        deprecatedGetterMode = deprecatedMode;
    }

    function setLie(bool on) external {
        lie = on;
    }

    function setHook(address target, bytes calldata data) external {
        hookTarget = target;
        hookData = data;
        hookCalled = false;
        hookOk = false;
        hookResult = bytes4(0);
    }

    function isBlackListed(address who) public view override returns (bool) {
        _malformed(blackListGetterMode);
        return super.isBlackListed(who);
    }

    function deprecated() public view override returns (bool) {
        _malformed(deprecatedGetterMode);
        return super.deprecated();
    }

    function transfer(address to, uint256 value) public override returns (bool) {
        _hook();
        if (lie) return true;
        return super.transfer(to, value);
    }

    function transferFrom(address from, address to, uint256 value) public override returns (bool) {
        _hook();
        if (lie) return true;
        return super.transferFrom(from, to, value);
    }

    function _malformed(uint8 mode) private pure {
        if (mode == 1) revert();
        if (mode == 2) {
            assembly {
                return(0, 0)
            }
        }
        if (mode == 3) {
            assembly {
                mstore(0, 0)
                mstore(32, 0)
                return(0, 64)
            }
        }
        if (mode == 4) {
            assembly {
                mstore(0, 2)
                return(0, 32)
            }
        }
    }

    function _hook() private {
        address target = hookTarget;
        if (target == address(0)) return;
        hookTarget = address(0);
        (bool ok, bytes memory ret) = target.call(hookData);
        hookCalled = true;
        hookOk = ok;
        hookResult = ret.length >= 4 ? bytes4(ret) : bytes4(0);
    }
}

/// TEST ONLY. A well-behaved six-decimal token WITHOUT `isBlackListed` and `deprecated` (USDC-like, no fallback).
contract TronPlainToken {
    uint8 public constant decimals = 6;
    mapping(address => uint256) public balanceOf;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}
