// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity 0.8.24;

interface ISolanaBridgedToken {
    function burn(uint64 amount, address ethRecipient) external returns (bytes32 burnId);
    function transferFrom(address from, address to, uint256 value) external returns (bool);
}

/// @title SolanaBurnRouter: burns `bUSDC.sol` on the Bloch L2 for a Solana wallet
/// @notice `BridgedStablecoinV3.burn(uint64 amount, address ethRecipient)` takes any 20 bytes. For the Solana
///         bridge those bytes must be a COMMITMENT to a 32-byte wallet address: the last 20 bytes of
///         keccak256("BLOCH-SVM-ACCOUNT-ID-v1" || wallet). The Solana vault pays a release only to the
///         associated token account of a wallet that hashes to them. A burn that names anything else (an
///         Ethereum address typed by habit, a token account's address) can never be paid, and the frozen token
///         cannot check it. This contract is where the destination is checked: it takes the wallet as the
///         base58 text every Solana wallet shows, refuses what is not a wallet address, computes the commitment
///         itself, burns through the token and publishes the wallet in the same transaction.
///         Exits go through `burnTo`; the signers certify a burn made directly on the token only when a wallet
///         that hashes to its 20 bytes has been published (docs/SOLANA-VAULT.md, "The L2 side").
///
///         Same shape as `StellarBurnRouter` and `BitcoinBurnRouter`: `token()`, a pure check that maps the
///         destination text to the 20 bytes the burn names, `burnTo(uint64 amount, string destination)` after an
///         `approve`, and one log `<Network>Exit(burnId indexed, from indexed, amount, 20 bytes, text)`.
/// @dev What "a wallet address" means here: 32 bytes in canonical base58 that decode to a point on the Ed25519
///      curve, and are not zero. Every associated token account, and every other program-derived address, is
///      OFF the curve by construction, so the most likely mistake (pasting a token account's address) is
///      refused. A wallet that is itself a program-derived address (a multisig vault, for example) is refused
///      too: such a holder exits to a key wallet.
///
///      Review 330 (R330-SOL-1): "on the curve" is not "a wallet". Refused here as well, because this contract
///      can know them without reading Solana: the eight points of small order (the identity point and seven
///      others, in any spelling: no private key can exist for them), the SPL mint this route's vault holds
///      (`solanaMint`, the answer to "what is the USDC address on Solana"), and the program ids the bridge
///      itself names (classic SPL Token, Token-2022, Associated Token Account).
///      What this contract CANNOT know: whether any other on-curve address is a wallet. A mint or a token
///      account created at a keypair address, or a point nobody holds a key for, passes here. The signers read
///      the destination on Solana at `finalized` and HOLD the burn unless it is absent or a plain System
///      account (tools/signatario-solana/sol_recipient.py), and a held burn has no refund path: a page must
///      take the destination from a connected wallet and have it sign a message before it calls `burnTo`
///      (docs/SOLANA-VAULT.md, "Proof of the destination key").
///      No storage, no owner, never holds tokens between calls. UNAUDITED. Not for deployment.
contract SolanaBurnRouter {
    ISolanaBridgedToken public immutable token;
    /// The SPL mint the Solana vault of this route holds (32 bytes): never a destination.
    bytes32 public immutable solanaMint;

    bytes32 private constant TOKEN_PROGRAM = 0x06ddf6e1d765a193d9cbe146ceeb79ac1cb485ed5f5b37913a8cf5857eff00a9;
    bytes32 private constant TOKEN_2022_PROGRAM = 0x06ddf6e1ee758fde18425dbce46ccddab61afc4d83b90d27febdf928d8a18bfc;
    bytes32 private constant ATA_PROGRAM = 0x8c97258f4e2489f1bb3d1029148e0d830b5a1399daff1084048e7bd8dbe9f859;
    /// y coordinates of the two pairs of points of order 8 (the others of small order have y = 0, 1 and P - 1).
    uint256 private constant ORDER8_Y1 = 0x05fc536d880238b13933c6d305acdfd5f098eff289f4c345b027b2c28f95e826;
    uint256 private constant ORDER8_Y2 = 0x7a03ac9277fdc74ec6cc392cfa53202a0f67100d760b3cba4fd84d3d706a17c7;

    /// Domain tag of the commitment; the Solana program and the tools use the same bytes (`ID_ACCOUNT`).
    string public constant ACCOUNT_ID_DOMAIN = "BLOCH-SVM-ACCOUNT-ID-v1";

    uint256 private constant P = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed;
    /// Edwards d = -121665/121666 mod P.
    uint256 private constant D = 0x52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3;

    event SolanaExit(bytes32 indexed burnId, address indexed from, uint64 amount, address commitment, string recipient);

    error BadConfig();
    error NotASolanaWallet();
    error TransferFailed();

    constructor(ISolanaBridgedToken token_, bytes32 solanaMint_) {
        if (address(token_).code.length == 0 || solanaMint_ == bytes32(0)) revert BadConfig();
        token = token_;
        solanaMint = solanaMint_;
    }

    /// @notice The 32-byte wallet behind `recipient`. Reverts unless it is the canonical base58 text of 32 bytes
    ///         that are a point of the Ed25519 curve, not of small order, and none of the addresses this
    ///         contract knows not to be wallets (the route's mint, the token programs).
    function walletOf(string calldata recipient) public view returns (bytes32) {
        bytes calldata s = bytes(recipient);
        uint256 n = s.length;
        if (n < 32 || n > 44) revert NotASolanaWallet();
        uint256 zeros;
        while (zeros < n && s[zeros] == 0x31) ++zeros; // '1' is the digit zero
        uint256 acc;
        for (uint256 i = zeros; i < n; ++i) {
            uint256 d = _digit(uint8(s[i]));
            if (acc > (type(uint256).max - d) / 58) revert NotASolanaWallet();
            acc = acc * 58 + d;
        }
        // Canonical: as many leading '1' as leading zero bytes, and 32 bytes in all.
        uint256 length;
        for (uint256 v = acc; v != 0; v >>= 8) ++length;
        if (acc == 0 || zeros + length != 32) revert NotASolanaWallet();
        bytes32 key = bytes32(acc);
        if (key == solanaMint || key == TOKEN_PROGRAM || key == TOKEN_2022_PROGRAM || key == ATA_PROGRAM) {
            revert NotASolanaWallet();
        }
        if (!_keyPoint(key)) revert NotASolanaWallet();
        return key;
    }

    /// @notice The 20 bytes an L2 burn must name to be paid to `recipient` on Solana.
    function commitment(string calldata recipient) public view returns (address) {
        return address(uint160(uint256(keccak256(abi.encodePacked(ACCOUNT_ID_DOMAIN, walletOf(recipient))))));
    }

    /// @notice Burns `amount` of the caller's tokens (approve this contract first) for the wallet `recipient`.
    function burnTo(uint64 amount, string calldata recipient) external returns (bytes32 burnId) {
        address c = commitment(recipient);
        if (!token.transferFrom(msg.sender, address(this), amount)) revert TransferFailed();
        burnId = token.burn(amount, c);
        emit SolanaExit(burnId, msg.sender, amount, c, recipient);
    }

    function _digit(uint8 c) private pure returns (uint256) {
        // 123456789 ABCDEFGH JKLMN PQRSTUVWXYZ abcdefghijk mnopqrstuvwxyz (no 0, O, I, l)
        if (c >= 0x31 && c <= 0x39) return c - 0x31;
        if (c >= 0x41 && c <= 0x48) return c - 0x41 + 9;
        if (c >= 0x4a && c <= 0x4e) return c - 0x4a + 17;
        if (c >= 0x50 && c <= 0x5a) return c - 0x50 + 22;
        if (c >= 0x61 && c <= 0x6b) return c - 0x61 + 33;
        if (c >= 0x6d && c <= 0x7a) return c - 0x6d + 44;
        revert NotASolanaWallet();
    }

    /// Whether the 32 bytes decompress to an Ed25519 point, as the Solana runtime decides it for program-derived
    /// addresses: y is the little-endian value without its top bit, and x^2 = (y^2 - 1) / (d y^2 + 1) must have
    /// a root, that is (y^2 - 1)(d y^2 + 1) is zero or a quadratic residue; and the point is not one of the
    /// eight of small order (y = 0, 1, P - 1 or one of the two order-8 values, reduced, whatever the sign bit),
    /// for which no private key exists. y = 1 and y = P - 1 are exactly the points where y^2 - 1 is zero.
    function _keyPoint(bytes32 key) private pure returns (bool) {
        uint256 le;
        uint256 be = uint256(key);
        for (uint256 i; i < 32; ++i) {
            le = (le << 8) | (be & 0xff);
            be >>= 8;
        }
        uint256 y = (le & ((1 << 255) - 1)) % P;
        if (y == 0 || y == ORDER8_Y1 || y == ORDER8_Y2) return false;
        uint256 yy = mulmod(y, y, P);
        uint256 u = addmod(yy, P - 1, P);
        uint256 v = addmod(mulmod(D, yy, P), 1, P);
        uint256 w = mulmod(u, v, P);
        if (w == 0) return false; // u == 0: y = 1 or P - 1 (small order); v == 0 cannot happen (-1/d is no square)
        // Euler's criterion: w^((P - 1) / 2), with (P - 1) / 2 = 2^254 - 10.
        uint256 e = (P - 1) / 2;
        uint256 r = 1;
        for (uint256 bit = 1 << 254; bit != 0; bit >>= 1) {
            r = mulmod(r, r, P);
            if (e & bit != 0) r = mulmod(r, w, P);
        }
        return r == 1;
    }
}
