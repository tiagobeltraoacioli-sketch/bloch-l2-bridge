// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity 0.8.24;

import {ChameleonERC20} from "../contracts/chameleon/ChameleonERC20.sol";
import {ChameleonWire} from "../contracts/chameleon/ChameleonWire.sol";
import {FrozenExportRootVerifier} from "../contracts/chameleon/FrozenExportRootVerifier.sol";

interface FixtureVm {
    function envOr(string calldata name, string calldata fallbackValue) external returns (string memory);
    function readFile(string calldata path) external view returns (string memory);
    function parseJsonBytes32(string calldata json, string calldata key) external pure returns (bytes32);
    function parseJsonBytes32Array(string calldata json, string calldata key)
        external
        pure
        returns (bytes32[] memory);
    function parseJsonUint(string calldata json, string calldata key) external pure returns (uint256);
    function serializeBytes32(string calldata object, string calldata key, bytes32 value)
        external
        returns (string memory);
    function serializeUint(string calldata object, string calldata key, uint256 value)
        external
        returns (string memory);
    function writeJson(string calldata json, string calldata path) external;
    function skip(bool skipTest) external;
    function chainId(uint256 id) external;
    function setNonce(address account, uint64 nonce) external;
    function startPrank(address sender) external;
    function stopPrank() external;
    function prank(address sender) external;
    function expectRevert(bytes4 selector) external;
}

/// Invoked twice by bloch-ustav's executable with fresh, real PQ keys. Stage 0
/// determines constructor-derived code identity; stage 1 runs after native PQ
/// enable/mint/export have succeeded. Both stages use a fresh local EVM only.
contract ChameleonRoundTripTest {
    FixtureVm private constant vm = FixtureVm(address(uint160(uint256(keccak256("hevm cheat code")))));
    address private constant DEPLOYER = address(bytes20(hex"1111111111111111111111111111111111111111"));
    address private constant ALICE = address(bytes20(hex"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
    address private constant BOB = address(bytes20(hex"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"));

    function branch(string memory fixture) private pure returns (bytes32[32] memory proof) {
        bytes32[] memory decoded = vm.parseJsonBytes32Array(fixture, ".export_branch");
        require(decoded.length == 32, "proof depth");
        for (uint256 i; i < 32; ++i) {
            proof[i] = decoded[i];
        }
    }

    function deploy(string memory fixture) private returns (ChameleonERC20 token, ChameleonWire.Export memory item) {
        vm.chainId(31337);
        vm.setNonce(DEPLOYER, 0);
        vm.startPrank(DEPLOYER);
        FrozenExportRootVerifier verifier =
            new FrozenExportRootVerifier(vm.parseJsonBytes32(fixture, ".export_root"), 1);
        token = new ChameleonERC20(
            "Chameleon roundtrip test",
            "cTEST",
            vm.parseJsonBytes32(fixture, ".origin"),
            vm.parseJsonBytes32(fixture, ".asset"),
            8,
            1000,
            address(verifier),
            address(verifier).codehash
        );
        vm.stopPrank();
        item = ChameleonWire.Export(token.routeId(), 0, ALICE, 100, vm.parseJsonBytes32(fixture, ".native_transaction"));
        require(token.routeId() == vm.parseJsonBytes32(fixture, ".route_id"), "Rust/EVM route mismatch");
        require(ChameleonWire.exportId(item) == vm.parseJsonBytes32(fixture, ".export_id"), "Rust/EVM export mismatch");
    }

    function testNativeRoundTripFixture() public {
        string memory input = vm.envOr("CHAMELEON_ROUNDTRIP_INPUT", string(""));
        if (bytes(input).length == 0) {
            vm.skip(true);
            return;
        }
        string memory fixture = vm.readFile(input);
        (ChameleonERC20 token, ChameleonWire.Export memory item) = deploy(fixture);
        vm.serializeBytes32("result", "adapter_code_hash", address(token).codehash);
        if (vm.parseJsonUint(fixture, ".phase") == 1) {
            require(address(token).codehash == vm.parseJsonBytes32(fixture, ".adapter_code_hash"), "deployment changed");
            bytes memory proof = abi.encode(uint64(0), branch(fixture));
            token.mintExport(item, proof);
            vm.expectRevert(ChameleonERC20.ExportAlreadyMinted.selector);
            token.mintExport(item, proof);
            // Standard ERC-20 wallet/spender flow. This is not a claim that an
            // actual Uniswap or PancakeSwap pool has been deployed or tested.
            vm.prank(ALICE);
            require(token.approve(address(this), 50));
            require(token.transferFrom(ALICE, BOB, 40));
            require(token.allowance(ALICE, address(this)) == 10);
            bytes32 pqHash = vm.parseJsonBytes32(fixture, ".pq_recipient_hash");
            vm.prank(BOB);
            bytes32 id = token.returnToBloch(25, pqHash);
            require(token.balanceOf(ALICE) == 60 && token.balanceOf(BOB) == 15 && token.totalSupply() == 75);
            vm.serializeBytes32("result", "burn_id", id);
            vm.serializeBytes32("result", "burn_root", token.burnRoot());
            vm.serializeUint("result", "burn_count", token.burnCount());
            vm.serializeUint("result", "evm_supply", token.totalSupply());
        }
        string memory result = vm.serializeBytes32("result", "route_id", token.routeId());
        vm.writeJson(result, vm.envOr("CHAMELEON_ROUNDTRIP_OUTPUT", string("")));
    }

    function testSolidityMatchesIndependentPythonAndRustVectors() public view {
        string memory fixture = vm.readFile("test-vectors/chameleon-v1.json");
        bytes32 origin = hex"1111111111111111111111111111111111111111111111111111111111111111";
        bytes32 asset = hex"2222222222222222222222222222222222222222222222222222222222222222";
        address adapter = address(bytes20(hex"3333333333333333333333333333333333333333"));
        address recipient = address(bytes20(hex"5555555555555555555555555555555555555555"));
        bytes32 route = ChameleonWire.routeId(origin, asset, 1, adapter, 8, 1000);
        require(route == vm.parseJsonBytes32(fixture, ".route_id"));
        ChameleonWire.Export memory item = ChameleonWire.Export(
            route, 0, recipient, 60, hex"4444444444444444444444444444444444444444444444444444444444444444"
        );
        bytes32 id = ChameleonWire.exportId(item);
        require(id == vm.parseJsonBytes32(fixture, ".export_id"));
        require(ChameleonWire.verify(id, 0, branch(fixture), vm.parseJsonBytes32(fixture, ".export_root"), 1));
        bytes32 pqHash = sha256("non-production-pq-vector");
        require(pqHash == vm.parseJsonBytes32(fixture, ".pq_recipient_hash"));
        require(ChameleonWire.burnId(route, 0, recipient, 1, pqHash) == vm.parseJsonBytes32(fixture, ".burn_id"));
        bytes32 empty = ChameleonWire.emptyLeaf();
        for (uint256 i; i < 32; ++i) {
            empty = ChameleonWire.parent(empty, empty);
        }
        require(empty == vm.parseJsonBytes32(fixture, ".empty_root"));
    }
}
