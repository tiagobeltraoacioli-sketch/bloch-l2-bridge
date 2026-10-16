// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity 0.8.24;

import {ChameleonERC20, IChameleonExportVerifier} from "../contracts/chameleon/ChameleonERC20.sol";
import {ChameleonWire} from "../contracts/chameleon/ChameleonWire.sol";
import {FrozenExportRootVerifier} from "../contracts/chameleon/FrozenExportRootVerifier.sol";

interface ChameleonVm {
    function prank(address sender) external;
    function startPrank(address sender) external;
    function stopPrank() external;
    function setNonce(address account, uint64 nonce) external;
    function expectRevert() external;
    function expectRevert(bytes4 selector) external;
    function chainId(uint256 id) external;
    function etch(address account, bytes calldata code) external;
}

/// Intentionally unauthenticated test double, NEVER a deployable trust model.
contract AcceptingTestVerifier is IChameleonExportVerifier {
    function verifyExport(bytes32, bytes calldata) external pure returns (bool) {
        return true;
    }
}

contract ChameleonSecurityTest {
    ChameleonVm private constant vm = ChameleonVm(address(uint160(uint256(keccak256("hevm cheat code")))));
    address private constant ALICE = address(0xa11ce);
    address private constant BOB = address(0xb0b);
    address private constant DEPLOYER = address(0xd00d);
    bytes32 private constant ORIGIN = bytes32(uint256(42));
    bytes32 private constant ASSET = bytes32(uint256(43));
    bytes32 private constant PQ_HASH = bytes32(uint256(44));

    function zeroBranch() private pure returns (bytes32[32] memory branch) {
        bytes32 zero = ChameleonWire.emptyLeaf();
        for (uint256 i; i < 32; ++i) {
            branch[i] = zero;
            zero = ChameleonWire.parent(zero, zero);
        }
    }

    function singleRoot(bytes32 id) private pure returns (bytes32 root) {
        root = ChameleonWire.leaf(id);
        bytes32[32] memory branch = zeroBranch();
        for (uint256 i; i < 32; ++i) {
            root = ChameleonWire.parent(root, branch[i]);
        }
    }

    function denseRoot(bytes32[] memory ids) private pure returns (bytes32) {
        uint256 size = ids.length;
        bytes32 zero = ChameleonWire.emptyLeaf();
        for (uint256 i; i < size; ++i) {
            ids[i] = ChameleonWire.leaf(ids[i]);
        }
        for (uint256 height; height < 32; ++height) {
            for (uint256 i; i < size; i += 2) {
                ids[i / 2] = ChameleonWire.parent(ids[i], i + 1 < size ? ids[i + 1] : zero);
            }
            size = (size + 1) / 2;
            zero = ChameleonWire.parent(zero, zero);
        }
        return ids.length == 0 ? zero : ids[0];
    }

    function frozen(uint64 amount)
        private
        returns (ChameleonERC20 token, ChameleonWire.Export memory item, bytes memory proof)
    {
        vm.chainId(31337);
        vm.setNonce(DEPLOYER, 0);
        address predicted = address(uint160(uint256(keccak256(abi.encodePacked(hex"d694", DEPLOYER, hex"01")))));
        bytes32 route = ChameleonWire.routeId(ORIGIN, ASSET, 31337, predicted, 8, 1000);
        item = ChameleonWire.Export(route, 0, ALICE, amount, bytes32(uint256(55)));
        bytes32 root = singleRoot(ChameleonWire.exportId(item));
        vm.startPrank(DEPLOYER);
        FrozenExportRootVerifier verifier = new FrozenExportRootVerifier(root, 1);
        token = new ChameleonERC20(
            "Chameleon Ustav", "cUSTV", ORIGIN, ASSET, 8, 1000, address(verifier), address(verifier).codehash
        );
        vm.stopPrank();
        require(address(token) == predicted && token.routeId() == route, "deployment prediction");
        proof = abi.encode(uint64(0), zeroBranch());
    }

    function unrestricted() private returns (ChameleonERC20 token) {
        AcceptingTestVerifier verifier = new AcceptingTestVerifier();
        token = new ChameleonERC20(
            "Test verifier only", "TEST", ORIGIN, ASSET, 8, 1000, address(verifier), address(verifier).codehash
        );
    }

    function testFrozenExportAuthenticationAndPermissionlessRelay() public {
        (ChameleonERC20 token, ChameleonWire.Export memory item, bytes memory proof) = frozen(100);
        vm.prank(BOB);
        token.mintExport(item, proof);
        require(token.balanceOf(ALICE) == 100 && token.balanceOf(BOB) == 0 && token.totalSupply() == 100);
        require(token.mintedExportNonce(0) && token.totalMintedAtoms() == 100);
        vm.expectRevert(ChameleonERC20.ExportAlreadyMinted.selector);
        token.mintExport(item, proof);
        require(token.totalSupply() == 100);
    }

    function testTamperedExportAndMalformedProofCannotMint() public {
        (ChameleonERC20 token, ChameleonWire.Export memory item, bytes memory proof) = frozen(100);
        item.recipient = BOB;
        vm.expectRevert(ChameleonERC20.InvalidProof.selector);
        token.mintExport(item, proof);
        item.recipient = ALICE;
        item.amount = 101;
        vm.expectRevert(ChameleonERC20.InvalidProof.selector);
        token.mintExport(item, proof);
        item.amount = 100;
        item.nativeTransaction = bytes32(0);
        vm.expectRevert(ChameleonERC20.InvalidExport.selector);
        token.mintExport(item, proof);
        item.nativeTransaction = bytes32(uint256(55));
        item.route = bytes32(0);
        vm.expectRevert(ChameleonERC20.InvalidExport.selector);
        token.mintExport(item, proof);
        item.route = token.routeId();
        bytes memory badIndexProof = abi.encode(uint64(1), zeroBranch());
        vm.expectRevert(ChameleonERC20.InvalidProof.selector);
        token.mintExport(item, badIndexProof);
        vm.expectRevert(ChameleonERC20.InvalidProof.selector);
        token.mintExport(item, bytes.concat(proof, hex"00"));
        vm.expectRevert(ChameleonERC20.InvalidExport.selector);
        token.mintExport(item, new bytes(4097));
        proof[32] = bytes1(uint8(proof[32]) ^ 1);
        vm.expectRevert(ChameleonERC20.InvalidProof.selector);
        token.mintExport(item, proof);
        require(token.totalSupply() == 0 && !token.mintedExportNonce(0));
    }

    function testAbiNarrowIntegerPaddingIsRejected() public {
        (ChameleonERC20 token, ChameleonWire.Export memory item, bytes memory proof) = frozen(100);
        proof[0] = hex"01";
        vm.expectRevert();
        token.mintExport(item, proof);
        require(token.totalSupply() == 0);
    }

    function testVerifierRuntimeIdentityIsCheckedOnEveryMint() public {
        (ChameleonERC20 token, ChameleonWire.Export memory item, bytes memory proof) = frozen(100);
        vm.etch(address(token.exportVerifier()), hex"00");
        vm.expectRevert(ChameleonERC20.InvalidProof.selector);
        token.mintExport(item, proof);
        require(token.totalSupply() == 0 && !token.mintedExportNonce(0));
    }

    function testCapStillAppliesWhenConfiguredVerifierIsUntrustworthy() public {
        ChameleonERC20 token = unrestricted();
        ChameleonWire.Export memory item = ChameleonWire.Export(token.routeId(), 0, ALICE, 900, bytes32(0));
        vm.expectRevert(ChameleonERC20.InvalidExport.selector);
        token.mintExport(item, "");
        item.nativeTransaction = bytes32(uint256(55));
        token.mintExport(item, "");
        item.nonce = 1;
        item.amount = 101;
        vm.expectRevert(ChameleonERC20.SupplyCapExceeded.selector);
        token.mintExport(item, "");
        require(token.totalSupply() == 900 && !token.mintedExportNonce(1));
    }

    function testStandardWalletAllowanceAndTransferFlow() public {
        (ChameleonERC20 token, ChameleonWire.Export memory item, bytes memory proof) = frozen(100);
        token.mintExport(item, proof);
        require(keccak256(bytes(token.name())) == keccak256("Chameleon Ustav"));
        require(keccak256(bytes(token.symbol())) == keccak256("cUSTV") && token.decimals() == 8);
        vm.prank(ALICE);
        require(token.approve(address(this), 40));
        require(token.transferFrom(ALICE, BOB, 30) && token.allowance(ALICE, address(this)) == 10);
        require(token.transferFrom(ALICE, BOB, 0));
        vm.expectRevert();
        token.transferFrom(ALICE, BOB, 11);
        vm.prank(ALICE);
        require(token.approve(address(this), type(uint256).max));
        require(token.transferFrom(ALICE, BOB, 5) && token.allowance(ALICE, address(this)) == type(uint256).max);
        vm.prank(BOB);
        require(token.transfer(ALICE, 5));
        require(token.balanceOf(ALICE) == 70 && token.balanceOf(BOB) == 30 && token.totalSupply() == 100);
    }

    function testOnlyHolderCanBurnAndRecipientCommitmentIsMandatory() public {
        (ChameleonERC20 token, ChameleonWire.Export memory item, bytes memory proof) = frozen(100);
        token.mintExport(item, proof);
        vm.expectRevert();
        token.returnToBloch(1, PQ_HASH);
        vm.prank(ALICE);
        vm.expectRevert(ChameleonERC20.InvalidBurn.selector);
        token.returnToBloch(0, PQ_HASH);
        vm.prank(ALICE);
        vm.expectRevert(ChameleonERC20.InvalidBurn.selector);
        token.returnToBloch(1, bytes32(0));
        require(token.totalSupply() == 100 && token.burnCount() == 0 && token.totalBurnedAtoms() == 0);
        vm.prank(ALICE);
        bytes32 id = token.returnToBloch(25, PQ_HASH);
        require(id == ChameleonWire.burnId(token.routeId(), 0, ALICE, 25, PQ_HASH));
        require(token.burnRoot() == singleRoot(id) && token.burnCount() == 1);
        require(token.balanceOf(ALICE) == 75 && token.totalSupply() == 75 && token.totalBurnedAtoms() == 25);
    }

    function testChainForkChangesCannotMintOrBurnForRegisteredRoute() public {
        (ChameleonERC20 token, ChameleonWire.Export memory item, bytes memory proof) = frozen(100);
        vm.chainId(31338);
        vm.expectRevert(ChameleonERC20.WrongChain.selector);
        token.mintExport(item, proof);
        vm.expectRevert(ChameleonERC20.WrongChain.selector);
        token.returnToBloch(1, PQ_HASH);
        vm.chainId(31337);
        token.mintExport(item, proof);
    }

    function testNoAdministrativeMintUpgradeOrVerifierReplacementEntryPoints() public {
        ChameleonERC20 token = unrestricted();
        (bool mintOk,) = address(token).call(abi.encodeWithSignature("mint(address,uint256)", ALICE, 1));
        (bool upgradeOk,) = address(token).call(abi.encodeWithSignature("upgradeTo(address)", ALICE));
        (bool replaceOk,) = address(token).call(abi.encodeWithSignature("setVerifier(address)", ALICE));
        require(!mintOk && !upgradeOk && !replaceOk && token.totalSupply() == 0);
    }

    function testInvalidConfigurationsFailClosed() public {
        AcceptingTestVerifier verifier = new AcceptingTestVerifier();
        vm.expectRevert(ChameleonERC20.InvalidConfiguration.selector);
        new ChameleonERC20("Ustav", "U", ORIGIN, ASSET, 19, 1000, address(verifier), address(verifier).codehash);
        vm.expectRevert(ChameleonERC20.InvalidConfiguration.selector);
        new ChameleonERC20("Ustav", "U", ORIGIN, ASSET, 8, 1000, address(verifier), bytes32(0));
        vm.expectRevert(ChameleonERC20.InvalidConfiguration.selector);
        new ChameleonERC20("Ustav", "U", ORIGIN, ASSET, 8, 1000, ALICE, ALICE.codehash);
        vm.expectRevert();
        new FrozenExportRootVerifier(bytes32(uint256(1)), 0);
    }

    function testFuzzSupplyAndSingleBurnProof(uint64 mintedSeed, uint64 burnedSeed) public {
        uint64 amount = 1 + mintedSeed % 1000;
        uint64 burn = 1 + burnedSeed % amount;
        (ChameleonERC20 token, ChameleonWire.Export memory item, bytes memory proof) = frozen(amount);
        token.mintExport(item, proof);
        vm.prank(ALICE);
        bytes32 id = token.returnToBloch(burn, PQ_HASH);
        require(token.totalSupply() + token.totalBurnedAtoms() == token.totalMintedAtoms());
        require(token.totalSupply() == amount - burn && token.burnRoot() == singleRoot(id));
    }

    function testFuzzIncrementalBurnTreeMatchesDenseReference(uint8 countSeed) public {
        uint64 count = 1 + uint64(countSeed) % 33;
        (ChameleonERC20 token, ChameleonWire.Export memory item, bytes memory proof) = frozen(1000);
        token.mintExport(item, proof);
        bytes32[] memory ids = new bytes32[](count);
        for (uint64 i; i < count; ++i) {
            vm.prank(ALICE);
            ids[i] = token.returnToBloch(1, bytes32(uint256(i + 1)));
        }
        require(token.burnCount() == count && token.burnRoot() == denseRoot(ids));
        require(token.totalSupply() + token.totalBurnedAtoms() == 1000);
    }

    function testNonzeroProofIndexIsOrderedAndCountBounded() public {
        bytes32 first = bytes32(uint256(1));
        bytes32 second = bytes32(uint256(2));
        bytes32[32] memory proof = zeroBranch();
        proof[0] = ChameleonWire.leaf(first);
        bytes32 root = ChameleonWire.parent(proof[0], ChameleonWire.leaf(second));
        for (uint256 i = 1; i < 32; ++i) {
            root = ChameleonWire.parent(root, proof[i]);
        }
        FrozenExportRootVerifier verifier = new FrozenExportRootVerifier(root, 2);
        require(verifier.verifyExport(second, abi.encode(uint64(1), proof)));
        require(!verifier.verifyExport(second, abi.encode(uint64(0), proof)));
        require(!verifier.verifyExport(second, abi.encode(uint64(2), proof)));
        require(!verifier.verifyExport(first, abi.encode(uint64(1), proof)));
    }
}
