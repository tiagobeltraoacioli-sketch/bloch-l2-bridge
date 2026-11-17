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
///         This contract holds no power: it checks that the address is a well-formed strkey (so a typo cannot burn
///         funds towards nothing), burns through the token, and publishes the address in a log for the relayers.
///         It never holds tokens between calls and has no owner.
///         EXITS GO THROUGH THIS ROUTER. Its interface has the shape of the other routes' routers
///         (`burnTo(uint64 amount, string address)` and an exit event with the burn id, the caller, the amount, the
///         20 bytes the burn names and the address).
///         A burn made DIRECTLY on the token (`token.burn`) is NEVER paid to the 20 bytes it names (they may be an
///         Ethereum address, as on bUSDC). It is paid only after the ACCOUNT THAT BURNED calls `claimDirectBurn`
///         here, naming one checked Stellar address for that burn nonce. The claim is set once and can never be
///         changed, so for every burn there is at most one claim, the same for every reader of the finalized L2:
///         the signers pay it and the guardians judge a release against it (they compare `msg.sender` here with the
///         `from` of the token's `Burned` log; a claim by anyone else, or for a burn made through this router, is
///         ignored). There is no timeout: until that call the asset stays in the vault. A contract that burned
///         can claim (it is `msg.sender`). The only state of this contract is that table of claims.
/// STATUS: PROTOTYPE, UNAUDITED. Not for deployment.
contract StellarBurnRouter {
    IStellarBridgedToken public immutable token;
    bytes32 public constant RECIPIENT_TAG = bytes32("BLOCH-XLM-RECIPIENT-v1");

    event StellarExit(
        bytes32 indexed burnId, address indexed from, uint64 amount, bytes20 commitment, string stellarAddress
    );

    /// The Stellar address `burner` claimed for the burn with nonce `burnNonce` it made directly on the token; the
    /// empty string while it made no claim. Set once.
    mapping(address burner => mapping(uint64 burnNonce => string stellarAddress)) public claimOf;

    event DirectBurnClaimed(address indexed burner, uint64 indexed burnNonce, bytes20 commitment, string stellarAddress);

    error BadStrkey();
    error TransferFailed();
    error BadNonce();
    error AlreadyClaimed();

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

    /// @notice Burns `amount` of the caller's tokens (approve this contract first) for `stellarAddress` on Stellar.
    function burnTo(uint64 amount, string calldata stellarAddress) external returns (bytes32 burnId) {
        address c = commitment(stellarAddress);
        if (!token.transferFrom(msg.sender, address(this), amount)) revert TransferFailed();
        burnId = token.burn(amount, c);
        emit StellarExit(burnId, msg.sender, amount, bytes20(c), stellarAddress);
    }

    /// @notice Name the Stellar address a burn the caller made DIRECTLY on the token (not through `burnTo`) is paid
    ///         to. Only the account that burned can make a claim the signers honour. Set once per (caller, burn
    ///         nonce): a second call reverts, so the claim of a burn never changes. The address must be a valid
    ///         strkey and, for an account, must hold a trustline for the asset before it can be paid. Without this
    ///         call a direct burn is never paid.
    function claimDirectBurn(uint64 burnNonce, string calldata stellarAddress) external {
        address c = commitment(stellarAddress);
        if (burnNonce == 0) revert BadNonce();
        if (bytes(claimOf[msg.sender][burnNonce]).length != 0) revert AlreadyClaimed();
        claimOf[msg.sender][burnNonce] = stellarAddress;
        emit DirectBurnClaimed(msg.sender, burnNonce, bytes20(c), stellarAddress);
    }
}
