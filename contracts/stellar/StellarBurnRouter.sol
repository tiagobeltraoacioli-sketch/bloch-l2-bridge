// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity 0.8.24;

interface IStellarBridgedToken {
    function burn(uint64 amount, address ethRecipient) external returns (bytes32 burnId);
    function transferFrom(address from, address to, uint256 value) external returns (bool);
}

/// @title StellarBurnRouter: burns `bUSDC.xlm` on the Bloch L2 for a Stellar recipient
/// @notice `BridgedStablecoinV3.burn` names a 20-byte recipient. A Stellar address has 32 bytes of key, so a burn
///         for Stellar names a commitment instead: the low 20 bytes of
///         keccak256(bytes32("BLOCH-XLM-RECIPIENT-v1") ‖ strkey), where `strkey` is the 56-character address
///         (`G...` account or `C...` contract). The vault on Stellar pays a release only to an address with that
///         commitment (`recipient_commitment` in stellar/vault).
///         This contract is a convenience and holds no power: it checks that the address is a well-formed strkey (so
///         a typo cannot burn funds towards nothing), burns through the token, and publishes the address in a log
///         for the relayers. A holder may also call `token.burn(amount, commitment)` directly and hand the address
///         to a relayer by any channel; the commitment is what binds it.
///         It never holds tokens between calls, has no owner and no state.
/// STATUS: PROTOTYPE, UNAUDITED. Not for deployment.
contract StellarBurnRouter {
    IStellarBridgedToken public immutable token;
    bytes32 public constant RECIPIENT_TAG = bytes32("BLOCH-XLM-RECIPIENT-v1");

    event StellarExit(bytes32 indexed burnId, address indexed from, uint64 amount, address commitment, string recipient);

    error BadStrkey();
    error TransferFailed();

    constructor(IStellarBridgedToken token_) {
        if (address(token_).code.length == 0) revert BadStrkey();
        token = token_;
    }

    /// @notice The 20 bytes an L2 burn must name to be paid to `recipient` on Stellar. Reverts unless `recipient`
    ///         is a valid `G...` (ed25519 account) or `C...` (contract) strkey: base32, 56 characters, version byte,
    ///         CRC16-XMODEM checksum. Muxed (`M...`) addresses and secret seeds (`S...`) are refused.
    function commitment(string calldata recipient) public pure returns (address) {
        bytes calldata s = bytes(recipient);
        if (s.length != 56) revert BadStrkey();
        // 56 base32 characters are 280 bits: 35 bytes (version, 32 bytes of key, 2 bytes of checksum).
        bytes memory raw = new bytes(35);
        uint256 buffer;
        uint256 bits;
        uint256 n;
        for (uint256 i; i < 56; ++i) {
            uint8 c = uint8(s[i]);
            uint256 v;
            if (c >= 0x41 && c <= 0x5a) v = c - 0x41; // A-Z
            else if (c >= 0x32 && c <= 0x37) v = c - 0x32 + 26; // 2-7
            else revert BadStrkey();
            buffer = ((buffer << 5) | v) & 0xfff;
            bits += 5;
            if (bits >= 8) {
                bits -= 8;
                raw[n++] = bytes1(uint8(buffer >> bits));
            }
        }
        uint8 version = uint8(raw[0]);
        if (version != 0x30 && version != 0x10) revert BadStrkey(); // 6 << 3: account; 2 << 3: contract
        uint16 crc;
        for (uint256 i; i < 33; ++i) {
            crc ^= uint16(uint8(raw[i])) << 8;
            for (uint256 k; k < 8; ++k) {
                crc = (crc & 0x8000) != 0 ? (crc << 1) ^ 0x1021 : crc << 1;
            }
        }
        // The checksum is stored little-endian.
        if (uint8(raw[33]) != uint8(crc) || uint8(raw[34]) != uint8(crc >> 8)) revert BadStrkey();
        return address(uint160(uint256(keccak256(abi.encodePacked(RECIPIENT_TAG, s)))));
    }

    /// @notice Burns `amount` of the caller's tokens (approve this contract first) for `recipient` on Stellar.
    function burnTo(uint64 amount, string calldata recipient) external returns (bytes32 burnId) {
        address c = commitment(recipient);
        if (!token.transferFrom(msg.sender, address(this), amount)) revert TransferFailed();
        burnId = token.burn(amount, c);
        emit StellarExit(burnId, msg.sender, amount, c, recipient);
    }
}
