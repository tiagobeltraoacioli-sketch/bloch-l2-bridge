// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title BridgedStablecoin — an Ethereum stablecoin on the Bloch EVM L2 (bridge v1: set-once k-of-n signers)
/// @notice 1:1 with the six-decimal token held by one Ethereum `ContextBoundSourceVault` route.
///         `mint` needs k distinct secp256k1 signatures from the n signer programs fixed here;
///         each signer verifies the vault's `Deposited` event on its own Ethereum node at the
///         `finalized` level before signing. `burn` destroys tokens and emits the nonce and
///         `burnId` the vault's `Release` uses (`nonce = burnNonce`, `nativeBurn = burnId`); the
///         signers certify the release only after the burn is `finalized` on the L2.
///
///         Everything is fixed in the constructor: signers, threshold, the source chain, vault and
///         route, the per-period and outstanding-supply caps, the minimum burn. No owner, no setter,
///         no pause, no upgrade. A new signer set or new caps is a new contract.
///
///         Same structure as `WrappedGnB` (kept byte-identical to its devnet4 deployment).
///         Message format: INTERFACE-PONTE-STABLE-ETH-L2.md, section "L2".
/// STATUS: UNAUDITED. Devnet rehearsal only.
contract BridgedStablecoin {
    uint8 public constant decimals = 6;
    uint256 public constant MAX_SIGNERS = 16; // matches ContextBoundSourceVault
    uint256 private constant SECP256K1_HALF_N =
        0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

    bytes32 public constant MINT_TYPEHASH = keccak256(
        "Mint(uint256 sourceChainId,address sourceVault,bytes32 sourceRoute,bytes32 depositId,uint64 depositNonce,uint64 amount,address recipient)"
    );
    bytes32 private constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant NAME_HASH = keccak256("Bloch Bridged Stablecoin");
    bytes32 private constant VERSION_HASH = keccak256("1");

    string public name;
    string public symbol;
    uint256 public immutable sourceChainId;
    address public immutable sourceVault;
    bytes32 public immutable sourceRoute;
    uint256 public immutable threshold;
    uint256 public immutable periodLength;
    uint256 public immutable periodMintCap;
    uint256 public immutable supplyCap;
    uint256 public immutable minBurn;

    address[] private _signers;
    mapping(address => bool) public isSigner;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    /// @notice vault depositId => already minted.
    mapping(bytes32 => bool) public minted;
    /// @notice period index (timestamp / periodLength) => amount minted in it.
    mapping(uint256 => uint256) public mintedInPeriod;
    uint64 public burnNonce;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event Minted(bytes32 indexed depositId, uint64 depositNonce, address indexed recipient, uint64 amount);
    event Burned(
        bytes32 indexed burnId, uint64 indexed burnNonce, address indexed from, uint64 amount, address ethRecipient
    );

    error BadConfig();
    error AlreadyMinted();
    error ZeroAmount();
    error ZeroRecipient();
    error BadSignatureCount();
    error BadSignature();
    error NotSigner();
    error SignersNotAscending();
    error PeriodCapExceeded();
    error SupplyCapExceeded();
    error BurnTooSmall();
    error BadEthRecipient();
    error InsufficientBalance();
    error InsufficientAllowance();

    constructor(
        string memory name_,
        string memory symbol_,
        uint256 sourceChainId_,
        address sourceVault_,
        bytes32 sourceRoute_,
        address[] memory signers_,
        uint256 threshold_,
        uint256 periodLength_,
        uint256 periodMintCap_,
        uint256 supplyCap_,
        uint256 minBurn_
    ) {
        uint256 n = signers_.length;
        if (sourceChainId_ == 0 || sourceVault_ == address(0) || sourceRoute_ == 0) revert BadConfig();
        if (n == 0 || n > MAX_SIGNERS || threshold_ == 0 || threshold_ > n) revert BadConfig();
        if (periodLength_ == 0 || periodMintCap_ == 0 || periodMintCap_ > supplyCap_) revert BadConfig();
        if (supplyCap_ > type(uint64).max || minBurn_ == 0 || minBurn_ > type(uint64).max) revert BadConfig();
        if (bytes(name_).length == 0 || bytes(symbol_).length == 0) revert BadConfig();
        for (uint256 i; i < n; ++i) {
            address s = signers_[i];
            if (s == address(0) || isSigner[s]) revert BadConfig();
            isSigner[s] = true;
            _signers.push(s);
        }
        name = name_;
        symbol = symbol_;
        sourceChainId = sourceChainId_;
        sourceVault = sourceVault_;
        sourceRoute = sourceRoute_;
        threshold = threshold_;
        periodLength = periodLength_;
        periodMintCap = periodMintCap_;
        supplyCap = supplyCap_;
        minBurn = minBurn_;
    }

    function signers() external view returns (address[] memory) {
        return _signers;
    }

    function DOMAIN_SEPARATOR() public view returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_TYPEHASH, NAME_HASH, VERSION_HASH, block.chainid, address(this)));
    }

    /// @notice The EIP-712 digest each signer signs for one vault deposit.
    function mintDigest(bytes32 depositId, uint64 depositNonce, uint64 amount, address recipient)
        public
        view
        returns (bytes32)
    {
        bytes32 structHash = keccak256(
            abi.encode(
                MINT_TYPEHASH, sourceChainId, sourceVault, sourceRoute, depositId, depositNonce, amount, recipient
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR(), structHash));
    }

    function burnIdOf(uint64 nonce) public view returns (bytes32) {
        return keccak256(abi.encode(block.chainid, address(this), nonce));
    }

    function currentPeriod() public view returns (uint256) {
        return block.timestamp / periodLength;
    }

    /// @notice Mint for one vault deposit. Anyone may submit; `signatures` is exactly `threshold`
    ///         65-byte (r, s, v) signatures over `mintDigest`, ordered by strictly ascending signer.
    function mint(bytes32 depositId, uint64 depositNonce, uint64 amount, address recipient, bytes calldata signatures)
        external
    {
        if (amount == 0) revert ZeroAmount();
        if (recipient == address(0)) revert ZeroRecipient();
        if (minted[depositId]) revert AlreadyMinted();
        _checkSignatures(mintDigest(depositId, depositNonce, amount, recipient), signatures);

        uint256 period = currentPeriod();
        uint256 inPeriod = mintedInPeriod[period] + amount;
        if (inPeriod > periodMintCap) revert PeriodCapExceeded();
        uint256 supply = totalSupply + amount;
        if (supply > supplyCap) revert SupplyCapExceeded();

        minted[depositId] = true;
        mintedInPeriod[period] = inPeriod;
        totalSupply = supply;
        balanceOf[recipient] += amount;
        emit Transfer(address(0), recipient, amount);
        emit Minted(depositId, depositNonce, recipient, amount);
    }

    /// @notice Burn to receive the token from the vault at `ethRecipient` on the source chain once
    ///         the burn is finalized on the L2. The vault's release uses (burnNonce, burnId).
    function burn(uint64 amount, address ethRecipient) external returns (bytes32 burnId) {
        if (amount < minBurn) revert BurnTooSmall();
        if (ethRecipient == address(0) || ethRecipient == sourceVault) revert BadEthRecipient();
        uint256 balance = balanceOf[msg.sender];
        if (balance < amount) revert InsufficientBalance();
        unchecked {
            balanceOf[msg.sender] = balance - amount;
            totalSupply -= amount;
        }
        uint64 nonce = ++burnNonce;
        burnId = burnIdOf(nonce);
        emit Transfer(msg.sender, address(0), amount);
        emit Burned(burnId, nonce, msg.sender, amount, ethRecipient);
    }

    function approve(address spender, uint256 value) external returns (bool) {
        allowance[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
        return true;
    }

    function transfer(address to, uint256 value) external returns (bool) {
        _transfer(msg.sender, to, value);
        return true;
    }

    function transferFrom(address from, address to, uint256 value) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        if (allowed != type(uint256).max) {
            if (allowed < value) revert InsufficientAllowance();
            unchecked {
                allowance[from][msg.sender] = allowed - value;
            }
        }
        _transfer(from, to, value);
        return true;
    }

    function _transfer(address from, address to, uint256 value) private {
        uint256 balance = balanceOf[from];
        if (balance < value) revert InsufficientBalance();
        unchecked {
            balanceOf[from] = balance - value;
        }
        balanceOf[to] += value;
        emit Transfer(from, to, value);
    }

    function _checkSignatures(bytes32 digest, bytes calldata signatures) private view {
        uint256 k = threshold;
        if (signatures.length != k * 65) revert BadSignatureCount();
        address previous;
        for (uint256 i; i < k; ++i) {
            uint256 o = i * 65;
            bytes32 r = bytes32(signatures[o:o + 32]);
            bytes32 s = bytes32(signatures[o + 32:o + 64]);
            uint8 v = uint8(signatures[o + 64]);
            if (uint256(s) > SECP256K1_HALF_N || (v != 27 && v != 28)) revert BadSignature();
            address signer = ecrecover(digest, v, r, s);
            if (signer == address(0)) revert BadSignature();
            if (!isSigner[signer]) revert NotSigner();
            if (signer <= previous) revert SignersNotAscending();
            previous = signer;
        }
    }
}
