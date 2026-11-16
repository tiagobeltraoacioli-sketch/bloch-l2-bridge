// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IBridgedBitcoin {
    function transferFrom(address from, address to, uint256 value) external returns (bool);
    function burn(uint64 amount, address recipient) external returns (bytes32 burnId);
}

/// @title BitcoinBurnRouter — the exit door of bBTC: a burn that names a checked Bitcoin address
/// @notice `BridgedStablecoinV3.burn(uint64, address)` takes any 20 bytes as the recipient. For bBTC those bytes are a
///         Bitcoin P2WPKH key hash, and a caller who passes an Ethereum address there (as on bUSDC) would be paid to a
///         key nobody holds. This router is the only burner the Bitcoin signers pay without a further claim: it takes the
///         destination as a bech32 string, verifies the checksum, the network prefix, witness version 0 and the 20-byte
///         program, then burns with exactly that program. A burn made directly on the token is not paid blind: its
///         burner must sign a claim naming a Bitcoin address (tools/signatario-btc/btc_signer.py).
///         No owner, no setter, no upgrade, holds no balance between calls. The token is not changed.
/// STATUS: PROTOTYPE, UNAUDITED. Not for deployment.
contract BitcoinBurnRouter {
    IBridgedBitcoin public immutable token;
    /// The human-readable part of this network's segwit addresses ("bc" on mainnet), at most 31 bytes.
    bytes32 private immutable HRP;
    uint256 private immutable HRP_LENGTH;

    bytes private constant CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

    event BitcoinExit(bytes32 indexed burnId, address indexed from, uint64 amount, bytes20 keyHash, string bitcoinAddress);

    error BadConfig();
    error NotAP2wpkhAddress();
    error TransferFailed();

    constructor(address token_, string memory hrp_) {
        bytes memory h = bytes(hrp_);
        if (token_ == address(0) || h.length == 0 || h.length > 31) revert BadConfig();
        for (uint256 i; i < h.length; ++i) {
            if (uint8(h[i]) < 33 || uint8(h[i]) > 126 || (uint8(h[i]) >= 65 && uint8(h[i]) <= 90)) revert BadConfig();
        }
        token = IBridgedBitcoin(token_);
        HRP = bytes32(h);
        HRP_LENGTH = h.length;
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

    /// @notice Burn `amount` of the caller's bBTC (after `approve`) for a payout to `bitcoinAddress`.
    function burnTo(uint64 amount, string calldata bitcoinAddress) external returns (bytes32 burnId) {
        bytes20 keyHash = keyHashOf(bitcoinAddress);
        if (!token.transferFrom(msg.sender, address(this), amount)) revert TransferFailed();
        burnId = token.burn(amount, address(keyHash));
        emit BitcoinExit(burnId, msg.sender, amount, keyHash, bitcoinAddress);
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
