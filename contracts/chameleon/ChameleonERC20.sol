// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity 0.8.24;

import {ERC20} from "../vendor/openzeppelin-v5.0.2/contracts/token/ERC20/ERC20.sol";
import {ChameleonWire} from "./ChameleonWire.sol";

/// @notice Export authentication interface. A production implementation must
/// authenticate native consensus and the COMPLETE Chameleon state commitment.
/// A proof against an arbitrary submitted root is not export authentication.
interface IChameleonExportVerifier {
    function verifyExport(bytes32 exportId, bytes calldata proof) external view returns (bool);
}

/// @title ChameleonERC20 — unrestricted Ustav representation on an EVM chain
/// @notice Reference adapter, not deployed. Standard accounts are classical.
/// Native PQ authorization and backing live in Bloch; minting trusts the exact
/// configured verifier, whose runtime hash is checked on every mint. No owner,
/// admin mint, upgrade or verifier replacement entry point exists.
/// @dev Uses origin atomic units directly: no fees, rebasing or decimal rounding.
contract ChameleonERC20 is ERC20 {
    bytes32 public immutable originDomain;
    bytes32 public immutable originAsset;
    uint64 public immutable destinationChainId;
    uint64 public immutable originCap;
    uint8 private immutable _originDecimals;
    IChameleonExportVerifier public immutable exportVerifier;
    bytes32 public immutable verifierCodeHash;
    mapping(uint64 => bool) public mintedExportNonce;
    uint64 public burnCount;
    uint128 public totalMintedAtoms;
    uint128 public totalBurnedAtoms;
    bytes32[32] private _burnBranch;

    error InvalidConfiguration();
    error WrongChain();
    error InvalidExport();
    error ExportAlreadyMinted();
    error InvalidProof();
    error SupplyCapExceeded();
    error InvalidBurn();
    error BurnTreeFull();

    event ExportMinted(bytes32 indexed exportId, uint64 indexed nonce, address indexed recipient, uint64 amount);
    event ReturnInitiated(
        bytes32 indexed burnId, uint64 indexed nonce, address indexed sender, uint64 amount, bytes32 pqRecipientHash
    );

    constructor(
        string memory name_,
        string memory symbol_,
        bytes32 origin_,
        bytes32 asset_,
        uint8 decimals_,
        uint64 cap_,
        address verifier_,
        bytes32 verifierCodeHash_
    ) ERC20(name_, symbol_) {
        if (
            origin_ == bytes32(0) || asset_ == bytes32(0) || decimals_ > 18 || cap_ == 0 || block.chainid == 0
                || block.chainid > type(uint64).max || bytes(name_).length == 0 || bytes(name_).length > 256
                || bytes(symbol_).length == 0 || bytes(symbol_).length > 32 || verifier_.code.length == 0
                || verifier_.codehash != verifierCodeHash_
        ) revert InvalidConfiguration();
        originDomain = origin_;
        originAsset = asset_;
        _originDecimals = decimals_;
        originCap = cap_;
        destinationChainId = uint64(block.chainid);
        exportVerifier = IChameleonExportVerifier(verifier_);
        verifierCodeHash = verifierCodeHash_;
    }

    function decimals() public view override returns (uint8) {
        return _originDecimals;
    }

    function routeId() public view returns (bytes32) {
        return ChameleonWire.routeId(
            originDomain, originAsset, destinationChainId, address(this), _originDecimals, originCap
        );
    }

    /// @notice Permissionless relay of an authenticated export; minted funds go
    /// exclusively to the recipient committed by the native owner's PQ signature.
    function mintExport(ChameleonWire.Export calldata item, bytes calldata proof) external {
        if (block.chainid != destinationChainId) revert WrongChain();
        if (
            item.route != routeId() || item.amount == 0 || item.recipient == address(0)
                || item.recipient == address(this) || proof.length > 4096
        ) revert InvalidExport();
        if (mintedExportNonce[item.nonce]) revert ExportAlreadyMinted();
        bytes32 id = ChameleonWire.exportId(item);
        if (address(exportVerifier).codehash != verifierCodeHash || !exportVerifier.verifyExport(id, proof)) {
            revert InvalidProof();
        }
        if (totalSupply() + item.amount > originCap) revert SupplyCapExceeded();
        mintedExportNonce[item.nonce] = true;
        totalMintedAtoms += item.amount;
        _mint(item.recipient, item.amount);
        emit ExportMinted(id, item.nonce, item.recipient, item.amount);
    }

    /// @notice Burn the caller's representation and bind the future native
    /// recipient by SHA-256 of their full PQ public key. No native payout occurs
    /// here; Bloch must authenticate this burn and the claimant's PQ signature.
    function returnToBloch(uint64 amount, bytes32 pqRecipientHash) external returns (bytes32 id) {
        if (block.chainid != destinationChainId) revert WrongChain();
        if (amount == 0 || pqRecipientHash == bytes32(0)) revert InvalidBurn();
        uint64 nonce = burnCount;
        if (nonce >= ChameleonWire.MAX_LEAVES) revert BurnTreeFull();
        _burn(msg.sender, amount);
        totalBurnedAtoms += amount;
        id = ChameleonWire.burnId(routeId(), nonce, msg.sender, amount, pqRecipientHash);
        _appendBurn(id, nonce);
        emit ReturnInitiated(id, nonce, msg.sender, amount, pqRecipientHash);
    }

    function _appendBurn(bytes32 id, uint64 nonce) private {
        uint256 size = uint256(nonce) + 1;
        burnCount = nonce + 1;
        bytes32 node = ChameleonWire.leaf(id);
        for (uint256 i; i < 32; ++i) {
            if ((size & 1) == 1) {
                _burnBranch[i] = node;
                return;
            }
            node = ChameleonWire.parent(_burnBranch[i], node);
            size >>= 1;
        }
        revert BurnTreeFull();
    }

    function burnRoot() external view returns (bytes32) {
        bytes32 zero = ChameleonWire.emptyLeaf();
        bytes32 node = zero;
        uint256 size = burnCount;
        for (uint256 i; i < 32; ++i) {
            node = (size & 1) == 1 ? ChameleonWire.parent(_burnBranch[i], node) : ChameleonWire.parent(node, zero);
            zero = ChameleonWire.parent(zero, zero);
            size >>= 1;
        }
        return node;
    }
}
