// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity 0.8.24;

import {IReleaseVerifier} from "../contracts/usdt/ContextBoundSourceVault.sol";
import {SP1ReleaseVerifier, ISP1Verifier as ReleaseSP1Verifier} from "../contracts/usdt/SP1ReleaseVerifier.sol";
import {SP1Verifier as SP1VerifierGroth16} from "../contracts/sp1/v6.1.0/SP1VerifierGroth16.sol";

interface Groth16Vm {
    function readFile(string calldata path) external view returns (string memory);
    function parseJsonBytes(string calldata json, string calldata key) external pure returns (bytes memory);
    function parseJsonBytes32(string calldata json, string calldata key) external pure returns (bytes32);
    function parseJsonAddress(string calldata json, string calldata key) external pure returns (address);
    function parseJsonUint(string calldata json, string calldata key) external pure returns (uint256);
    function chainId(uint256 newChainId) external;
    function expectRevert() external;
    function expectRevert(bytes4 selector) external;
}

/// @notice A REAL SP1 6.8.0 Groth16 proof of the Bloch light-client release program, checked by the
/// SP1 v6.1.0 Groth16 verifier through SP1ReleaseVerifier. The proof (bloch-sis-pow
/// `codex/bloch-lc-20261014`, sp1/script `lc devnet4 ... groth16`) recursively verifies a step proof
/// that finalized devnet4 checkpoint 2616 with the validators' real hybrid KES votes, then walks to the
/// L1 block settling L2 block 256 and derives the releaseId of its 5 bUSDC burn (vault v2 on anvil
/// 11155111). The ANCHOR is synthetic (the roster leaf activates at devnet4 epoch 12288), so this pins
/// the verifier path and the public-values binding, not a production trust anchor.
contract SP1ReleaseVerifierGroth16Test {
    Groth16Vm private constant vm = Groth16Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    string private constant VECTOR = "test-vectors/sp1-release-devnet4/release-groth16.json";

    SP1VerifierGroth16 private sp1;
    SP1ReleaseVerifier private lc;
    bytes private publicValues;
    bytes private proofBytes;
    address private vault;
    bytes32 private releaseId;

    function setUp() public {
        string memory j = vm.readFile(VECTOR);
        vm.chainId(vm.parseJsonUint(j, ".chain_id"));
        publicValues = vm.parseJsonBytes(j, ".public_values");
        proofBytes = vm.parseJsonBytes(j, ".proof");
        vault = vm.parseJsonAddress(j, ".vault");
        releaseId = vm.parseJsonBytes32(j, ".release_id");
        sp1 = new SP1VerifierGroth16();
        lc = new SP1ReleaseVerifier(
            ReleaseSP1Verifier(address(sp1)),
            vm.parseJsonBytes32(j, ".program_vkey"),
            vm.parseJsonBytes32(j, ".trust_anchor"),
            vm.parseJsonUint(j, ".l2_chain_id"),
            vm.parseJsonAddress(j, ".l2_token")
        );
    }

    function testRealProofReleases() public view {
        require(keccak256(lc.expectedPublicValues(vault, releaseId)) == keccak256(publicValues), "public values");
        require(
            lc.verifyRelease(vault, releaseId, abi.encode(publicValues, proofBytes))
                == IReleaseVerifier.verifyRelease.selector,
            "selector"
        );
        require(keccak256(bytes(sp1.VERSION())) == keccak256("v6.1.0"), "circuit version");
    }

    function testOtherReleaseVaultOrChainIsRefusedBeforeTheProof() public {
        vm.expectRevert(SP1ReleaseVerifier.PublicValuesMismatch.selector);
        lc.verifyRelease(vault, bytes32(uint256(releaseId) ^ 1), abi.encode(publicValues, proofBytes));
        vm.expectRevert(SP1ReleaseVerifier.PublicValuesMismatch.selector);
        lc.verifyRelease(address(0xBEEF), releaseId, abi.encode(publicValues, proofBytes));
        vm.chainId(1);
        vm.expectRevert(SP1ReleaseVerifier.PublicValuesMismatch.selector);
        lc.verifyRelease(vault, releaseId, abi.encode(publicValues, proofBytes));
    }

    function testTamperedProofIsRefused() public {
        bytes memory bad = proofBytes;
        bad[bad.length - 7] ^= 0x01;
        vm.expectRevert();
        lc.verifyRelease(vault, releaseId, abi.encode(publicValues, bad));
    }

    function testAnotherProgramKeyIsRefused() public {
        string memory j = vm.readFile(VECTOR);
        SP1ReleaseVerifier other = new SP1ReleaseVerifier(
            ReleaseSP1Verifier(address(sp1)),
            bytes32(uint256(vm.parseJsonBytes32(j, ".program_vkey")) ^ 1),
            vm.parseJsonBytes32(j, ".trust_anchor"),
            vm.parseJsonUint(j, ".l2_chain_id"),
            vm.parseJsonAddress(j, ".l2_token")
        );
        vm.expectRevert();
        other.verifyRelease(vault, releaseId, abi.encode(publicValues, proofBytes));
    }

    function testAnotherTrustAnchorIsRefused() public {
        string memory j = vm.readFile(VECTOR);
        SP1ReleaseVerifier other = new SP1ReleaseVerifier(
            ReleaseSP1Verifier(address(sp1)),
            vm.parseJsonBytes32(j, ".program_vkey"),
            bytes32(uint256(vm.parseJsonBytes32(j, ".trust_anchor")) ^ 1),
            vm.parseJsonUint(j, ".l2_chain_id"),
            vm.parseJsonAddress(j, ".l2_token")
        );
        vm.expectRevert(SP1ReleaseVerifier.PublicValuesMismatch.selector);
        other.verifyRelease(vault, releaseId, abi.encode(publicValues, proofBytes));
    }
}
