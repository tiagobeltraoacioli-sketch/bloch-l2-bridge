// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity 0.8.24;

interface IUnitVault {
    function deposit(uint64 amount, bytes32 pqRecipientHash) external returns (bytes32 id);
}

/// @notice Six-decimal unit token over an asset with more than six decimals, for networks whose asset does not fit
///         ProvenanceSourceVault's fixed six decimals (BNB Smart Chain: the Binance-Peg tokens have 18).
///         One unit is exactly `scale` = 10^(assetDecimals - 6) of the asset, held by this contract. Anyone wraps and
///         unwraps at that fixed rate; there is no fee, owner, upgrade, pause, signer or rescue.
///         The vault holds units and counts units. It stays byte-identical: this contract is the `token` it is
///         deployed with.
/// @dev PROTOTYPE, UNAUDITED, not for deployment (round 16, agent 320).
///      - Amounts below one unit (10^-6 of the asset) cannot be wrapped; nothing rounds, so no dust is created.
///      - Every pull and payment of the asset is checked by balance difference: an asset that takes a fee on
///        transfer, or pays less than asked, is refused rather than leaving units under-backed.
///      - `asset.balanceOf(this) >= totalSupply * scale` holds while the asset keeps balances as it reports them.
///        If the asset's issuer reduces this contract's balance (seizure, a rebasing upgrade), units are
///        under-backed and the last unwraps fail; this contract cannot prevent or repair that.
///      - A release from the vault pays units; the recipient calls `unwrap`. `wrapAndDeposit` does the wrap and the
///        vault deposit in one transaction, with this contract as the vault's `sender` (the L2 recipient is named
///        by the caller and is what the vault records and the L2 token credits).
contract ScaledUnitToken {
    string public name;
    string public symbol;
    uint8 public constant decimals = 6;
    address public immutable asset;
    uint256 public immutable scale;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    bool private entered;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event Wrapped(address indexed payer, address indexed to, uint256 units);
    event Unwrapped(address indexed holder, address indexed to, uint256 units);

    error BadConfig();
    error BadAsset();
    error BadAddress();
    error Reentrancy();
    error DepositIncomplete();

    constructor(address asset_, string memory name_, string memory symbol_) {
        if (asset_.code.length == 0) revert BadConfig();
        (bool ok, bytes memory data) = asset_.staticcall(abi.encodeWithSignature("decimals()"));
        if (!ok || data.length != 32) revert BadConfig();
        uint256 assetDecimals = abi.decode(data, (uint256));
        if (assetDecimals <= 6 || assetDecimals > 36) revert BadConfig();
        asset = asset_;
        scale = 10 ** (assetDecimals - 6);
        name = name_;
        symbol = symbol_;
    }

    modifier nonReentrant() {
        if (entered) revert Reentrancy();
        entered = true;
        _;
        entered = false;
    }

    function approve(address spender, uint256 value) external returns (bool) {
        allowance[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
        return true;
    }

    function transfer(address to, uint256 value) external returns (bool) {
        _move(msg.sender, to, value);
        return true;
    }

    function transferFrom(address from, address to, uint256 value) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        if (allowed != type(uint256).max) allowance[from][msg.sender] = allowed - value;
        _move(from, to, value);
        return true;
    }

    /// @notice Pulls `units * scale` of the asset from the caller (who approved this contract) and mints `units` to `to`.
    function wrap(address to, uint256 units) external nonReentrant {
        _wrap(to, units);
    }

    /// @notice Burns `units` of the caller and pays `units * scale` of the asset to `to`.
    function unwrap(address to, uint256 units) external nonReentrant {
        if (to == address(0) || to == address(this)) revert BadAddress();
        balanceOf[msg.sender] -= units;
        totalSupply -= units;
        emit Transfer(msg.sender, address(0), units);
        uint256 amount = units * scale;
        uint256 beforeThis = _assetBalance(address(this));
        uint256 beforeTo = _assetBalance(to);
        _assetCall(abi.encodeWithSignature("transfer(address,uint256)", to, amount));
        if (_assetBalance(address(this)) + amount != beforeThis || _assetBalance(to) != beforeTo + amount) {
            revert BadAsset();
        }
        emit Unwrapped(msg.sender, to, units);
    }

    /// @notice Wraps `amount` units from the caller's asset and deposits them into `vault` for `l2Recipient` in one
    ///         transaction. `vault` is the caller's choice and is trusted by the caller only: the units minted here
    ///         are the caller's own, and the call fails unless the vault took exactly all of them.
    function wrapAndDeposit(address vault, uint64 amount, bytes32 l2Recipient)
        external
        nonReentrant
        returns (bytes32 id)
    {
        if (vault == address(0) || vault == address(this) || vault == asset) revert BadAddress();
        uint256 held = balanceOf[address(this)];
        _wrap(address(this), amount);
        allowance[address(this)][vault] = amount;
        emit Approval(address(this), vault, amount);
        id = IUnitVault(vault).deposit(amount, l2Recipient);
        if (allowance[address(this)][vault] != 0 || balanceOf[address(this)] != held) revert DepositIncomplete();
    }

    function _wrap(address to, uint256 units) private {
        if (to == address(0)) revert BadAddress();
        uint256 amount = units * scale;
        uint256 beforeThis = _assetBalance(address(this));
        uint256 beforePayer = _assetBalance(msg.sender);
        _assetCall(abi.encodeWithSignature("transferFrom(address,address,uint256)", msg.sender, address(this), amount));
        if (_assetBalance(address(this)) != beforeThis + amount || _assetBalance(msg.sender) + amount != beforePayer) {
            revert BadAsset();
        }
        totalSupply += units;
        balanceOf[to] += units;
        emit Transfer(address(0), to, units);
        emit Wrapped(msg.sender, to, units);
    }

    function _move(address from, address to, uint256 value) private {
        if (to == address(0)) revert BadAddress();
        balanceOf[from] -= value;
        balanceOf[to] += value;
        emit Transfer(from, to, value);
    }

    function _assetBalance(address owner) private view returns (uint256) {
        (bool ok, bytes memory data) = asset.staticcall(abi.encodeWithSignature("balanceOf(address)", owner));
        if (!ok || data.length != 32) revert BadAsset();
        return abi.decode(data, (uint256));
    }

    function _assetCall(bytes memory payload) private {
        (bool ok, bytes memory data) = asset.call(payload);
        if (!ok || (data.length != 0 && (data.length != 32 || !abi.decode(data, (bool))))) revert BadAsset();
    }
}
