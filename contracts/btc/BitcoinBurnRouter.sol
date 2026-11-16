// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

interface IBridgedBitcoin {
    function transferFrom(address from, address to, uint256 value) external returns (bool);
    function burn(uint64 amount, address recipient) external returns (bytes32 burnId);
}

/// @title BitcoinBurnRouter — the exit door of bBTC: a burn that names a checked Bitcoin address
/// @notice `BridgedStablecoinV3.burn(uint64, address)` takes any 20 bytes as the recipient. For bBTC those bytes are a
///         Bitcoin P2WPKH key hash, and a caller who passes an Ethereum address there (as on bUSDC) would be paid to a
///         key nobody holds. This router is the only burner the Bitcoin signers pay without a further claim: it takes the
///         destination as a bech32 string, verifies the checksum, the network prefix, witness version 0 and the 20-byte
///         program, then burns with exactly that program.
///
///         The burner also names the highest fee rate (sat/vB) it accepts for its payout. The miner charge of a
///         release is `fee rate x chargeVbytes`, taken from the payout; the signers do not pay the burn in a Bitcoin
///         transaction above the rate named here (the burn waits while the market is above it), so the charge is
///         bounded by `maxFeeRate x chargeVbytes`, known before the burn. A burn whose payout would be dust at the
///         rate it names is refused.
///
///         A burn made directly on the token is NEVER paid to the 20 bytes it names. It is paid only after the
///         account that burned calls `claimDirectBurn` here, naming a checked Bitcoin address and a fee ceiling. There
///         is no timeout: until that call the coins stay in the vault (tools/signatario-btc/btc_signer.py).
///         No owner, no setter, no upgrade, holds no balance between calls. The token is not changed.
/// STATUS: PROTOTYPE, UNAUDITED. Not for deployment.
contract BitcoinBurnRouter {
    IBridgedBitcoin public immutable token;
    /// The human-readable part of this network's segwit addresses ("bc" on mainnet), at most 31 bytes.
    bytes32 private immutable HRP;
    uint256 private immutable HRP_LENGTH;

    /// The vault policy's numbers a payout is computed from (tools/signatario-btc/btc_policy.py `release_payout`);
    /// `btc_deploy.py router` derives them from the vault config and refuses a router that states others.
    uint256 public immutable unitSats; // sats per token unit (100)
    uint256 public immutable releaseFeeBps; // bridge fee on a release
    uint256 public immutable chargeVbytes; // vbytes a released burn is charged for (402 for 5 of 7)
    uint256 public immutable dustSats; // the smallest payout the vault makes
    uint16 public immutable feeRateCeiling; // the policy's `maxFeerate`: no vault transaction pays more

    bytes private constant CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

    struct DirectClaim {
        bytes20 keyHash;
        uint16 maxFeeRate;
    }

    /// Highest fee rate (sat/vB) the burner of a router burn accepts; 0 for a burn id this router did not make.
    mapping(bytes32 burnId => uint16 maxFeeRate) public maxFeeRateOf;
    /// The claim of `burner` for the burn with nonce `burnNonce` made directly on the token; set once.
    mapping(address burner => mapping(uint64 burnNonce => DirectClaim)) public claimOf;

    event BitcoinExit(
        bytes32 indexed burnId, address indexed from, uint64 amount, bytes20 keyHash, string bitcoinAddress, uint16 maxFeeRate
    );
    event DirectBurnClaimed(
        address indexed burner, uint64 indexed burnNonce, bytes20 keyHash, string bitcoinAddress, uint16 maxFeeRate
    );

    error BadConfig();
    error NotAP2wpkhAddress();
    error TransferFailed();
    error BadFeeRate();
    error PayoutBelowDustAtFeeRate();
    error AlreadyClaimed();

    constructor(
        address token_,
        string memory hrp_,
        uint256 unitSats_,
        uint256 releaseFeeBps_,
        uint256 chargeVbytes_,
        uint256 dustSats_,
        uint16 feeRateCeiling_
    ) {
        bytes memory h = bytes(hrp_);
        if (token_ == address(0) || h.length == 0 || h.length > 31) revert BadConfig();
        for (uint256 i; i < h.length; ++i) {
            if (uint8(h[i]) < 33 || uint8(h[i]) > 126 || (uint8(h[i]) >= 65 && uint8(h[i]) <= 90)) revert BadConfig();
        }
        if (
            unitSats_ == 0 || unitSats_ > 1e8 || releaseFeeBps_ >= 10_000 || chargeVbytes_ == 0 || chargeVbytes_ > 100_000
                || dustSats_ == 0 || dustSats_ > 1e8 || feeRateCeiling_ == 0
        ) revert BadConfig();
        token = IBridgedBitcoin(token_);
        HRP = bytes32(h);
        HRP_LENGTH = h.length;
        unitSats = unitSats_;
        releaseFeeBps = releaseFeeBps_;
        chargeVbytes = chargeVbytes_;
        dustSats = dustSats_;
        feeRateCeiling = feeRateCeiling_;
    }

    function hrp() external view returns (string memory) {
        bytes memory out = new bytes(HRP_LENGTH);
        for (uint256 i; i < HRP_LENGTH; ++i) out[i] = HRP[i];
        return string(out);
    }

    /// @notice The key hash of a lowercase P2WPKH address of this network (BIP173); reverts on anything else:
    ///         another prefix, a bad checksum, taproot or script addresses, legacy addresses, hex strings, upper case.
    function keyHashOf(string calldata bitcoinAddress) public view returns (bytes20) {
        bytes calldata a = bytes(bitcoinAddress);
        uint256 n = HRP_LENGTH;
        // prefix, separator "1", 1 version + 32 program + 6 checksum characters
        if (a.length != n + 40) revert NotAP2wpkhAddress();
        uint256 chk = 1;
        for (uint256 i; i < n; ++i) {
            if (a[i] != HRP[i]) revert NotAP2wpkhAddress();
            chk = _step(chk, uint8(a[i]) >> 5);
        }
        if (a[n] != "1") revert NotAP2wpkhAddress();
        chk = _step(chk, 0);
        for (uint256 i; i < n; ++i) chk = _step(chk, uint8(a[i]) & 31);
        uint256 program;
        for (uint256 i = n + 1; i < a.length; ++i) {
            uint256 v = _value(a[i]);
            chk = _step(chk, v);
            uint256 k = i - n - 1;
            if (k == 0) {
                if (v != 0) revert NotAP2wpkhAddress(); // witness version 0 only
            } else if (k <= 32) {
                program = (program << 5) | v; // 32 characters x 5 bits = the 160-bit program, no padding
            }
        }
        if (chk != 1 || program == 0) revert NotAP2wpkhAddress(); // bech32 (not bech32m) constant
        return bytes20(uint160(program));
    }

    /// @notice What a burn of `amount` units pays on Bitcoin when its transaction is charged `feeRate` sat/vB, the
    ///         vault's rule exactly: (sats paid out, bridge fee, miner charge). `payoutSats` is 0 when the charge and
    ///         the fee exceed the amount.
    function quote(uint64 amount, uint16 feeRate)
        public
        view
        returns (uint256 payoutSats, uint256 bridgeFeeSats, uint256 minerChargeSats)
    {
        uint256 gross = uint256(amount) * unitSats;
        bridgeFeeSats = gross * releaseFeeBps / 10_000;
        minerChargeSats = uint256(feeRate) * chargeVbytes;
        payoutSats = gross > bridgeFeeSats + minerChargeSats ? gross - bridgeFeeSats - minerChargeSats : 0;
    }

    /// @notice Burn `amount` of the caller's bBTC (after `approve`) for a payout to `bitcoinAddress`, in a Bitcoin
    ///         transaction charged at most `maxFeeRate` sat/vB. The payout is at least `quote(amount, maxFeeRate)`;
    ///         while the fee market is above `maxFeeRate` the burn waits. Reverts if that payout would be dust.
    function burnTo(uint64 amount, string calldata bitcoinAddress, uint16 maxFeeRate) external returns (bytes32 burnId) {
        bytes20 keyHash = keyHashOf(bitcoinAddress);
        if (maxFeeRate == 0 || maxFeeRate > feeRateCeiling) revert BadFeeRate();
        (uint256 payout,,) = quote(amount, maxFeeRate);
        if (payout < dustSats) revert PayoutBelowDustAtFeeRate();
        if (!token.transferFrom(msg.sender, address(this), amount)) revert TransferFailed();
        burnId = token.burn(amount, address(keyHash));
        maxFeeRateOf[burnId] = maxFeeRate;
        emit BitcoinExit(burnId, msg.sender, amount, keyHash, bitcoinAddress, maxFeeRate);
    }

    /// @notice Name where a burn the caller made DIRECTLY on the token (not through `burnTo`) is paid, and the highest
    ///         fee rate accepted. Only the account that burned can make a claim the signers honour (they compare
    ///         `msg.sender` here with the `from` of the token's `Burned` log); a claim by anyone else, or for a burn
    ///         made through this router, is ignored. Set once per (caller, burn nonce). Without this call a direct
    ///         burn is never paid.
    function claimDirectBurn(uint64 burnNonce, string calldata bitcoinAddress, uint16 maxFeeRate) external {
        bytes20 keyHash = keyHashOf(bitcoinAddress);
        if (maxFeeRate == 0 || maxFeeRate > feeRateCeiling) revert BadFeeRate();
        if (burnNonce == 0) revert BadConfig();
        DirectClaim storage claim = claimOf[msg.sender][burnNonce];
        if (claim.maxFeeRate != 0) revert AlreadyClaimed();
        claim.keyHash = keyHash;
        claim.maxFeeRate = maxFeeRate;
        emit DirectBurnClaimed(msg.sender, burnNonce, keyHash, bitcoinAddress, maxFeeRate);
    }

    function _value(bytes1 ch) private pure returns (uint256) {
        for (uint256 v; v < 32; ++v) {
            if (CHARSET[v] == ch) return v;
        }
        revert NotAP2wpkhAddress();
    }

    function _step(uint256 chk, uint256 v) private pure returns (uint256) {
        uint256 b = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ v;
        if (b & 1 != 0) chk ^= 0x3b6a57b2;
        if (b & 2 != 0) chk ^= 0x26508e6d;
        if (b & 4 != 0) chk ^= 0x1ea119fa;
        if (b & 8 != 0) chk ^= 0x3d4233dd;
        if (b & 16 != 0) chk ^= 0x2a1462b3;
        return chk;
    }
}
