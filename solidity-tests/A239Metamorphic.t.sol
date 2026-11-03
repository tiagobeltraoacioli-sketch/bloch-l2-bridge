// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.24;

import {SignerMintedToken} from "../contracts/bridged/SignerMintedToken.sol";
import {BridgedStablecoinV2} from "../contracts/stable/BridgedStablecoinV2.sol";
import {BridgedStablecoinV3} from "../contracts/stable/BridgedStablecoinV3.sol";
import {ProvenanceSourceVault} from "../contracts/usdt/ProvenanceSourceVault.sol";
import {IReleaseVerifier} from "../contracts/usdt/ContextBoundSourceVault.sol";
import {D6Usdc} from "./D6Provenance.t.sol";

interface A239MVm {
    function addr(uint256 privateKey) external pure returns (address);
    function sign(uint256 privateKey, bytes32 digest) external pure returns (uint8 v, bytes32 r, bytes32 s);
    function warp(uint256 timestamp) external;
    function roll(uint256 blockNumber) external;
    function envOr(string calldata name, bool defaultValue) external view returns (bool);
}

/// The reviewed-looking verifier: refuses every release, and anyone may self-destruct it. Its code is what the 6 switch
/// signers reviewed and what the vault pins by code hash.
contract A239RejectAllRetirable is IReleaseVerifier {
    function verifyRelease(address, bytes32, bytes calldata) external pure returns (bytes4) {
        revert("rejects all");
    }

    function retire() external {
        selfdestruct(payable(msg.sender));
    }
}

contract A239AcceptAllCode is IReleaseVerifier {
    function verifyRelease(address, bytes32, bytes calldata) external pure returns (bytes4) {
        return IReleaseVerifier.verifyRelease.selector;
    }
}

interface IA239MetaFactory {
    function impl() external view returns (address);
}

/// Metamorphic init code: constant creation code (so a constant CREATE2 address) that returns whatever runtime the
/// factory currently names.
contract A239MetaInit {
    constructor() {
        address i = IA239MetaFactory(msg.sender).impl();
        assembly {
            let n := extcodesize(i)
            extcodecopy(i, 0, 0, n)
            return(0, n)
        }
    }
}

contract A239MetaFactory is IA239MetaFactory {
    address public impl;
    bytes32 constant SALT = keccak256("A239");

    function deploy(address impl_) public returns (address m) {
        impl = impl_;
        bytes memory init = type(A239MetaInit).creationCode;
        bytes32 salt = SALT;
        assembly {
            m := create2(0, add(init, 32), mload(init), salt)
        }
    }

    /// Read in its own (isolated) transaction, after the previous one's self-destruct took effect.
    function sizeOf(address a) external view returns (uint256) {
        return a.code.length;
    }

    function predicted() external view returns (address) {
        return address(
            uint160(
                uint256(keccak256(abi.encodePacked(bytes1(0xff), address(this), SALT, keccak256(type(A239MetaInit).creationCode))))
            )
        );
    }

    /// Create, use and self-destruct in ONE transaction: after Cancun (EIP-6780) this still deletes the account.
    function createCallRetire(address impl_, address target, bytes calldata data) external returns (address m) {
        m = deploy(impl_);
        require(m != address(0), "create2");
        (bool ok, bytes memory ret) = target.call(data);
        if (!ok) {
            assembly {
                revert(add(ret, 32), mload(ret))
            }
        }
        A239RejectAllRetirable(m).retire();
    }
}

/// Agent 239: a real CREATE2 + SELFDESTRUCT metamorphic verifier against `ProvenanceSourceVault`'s one-way switch. Before
/// the A239 fix the vault re-checked the code hash at activation and never after, and both tests below ended with the
/// vault paying 9,000 through the swapped code (commit 60f6fc1). With the fix the swap still happens, and the vault
/// refuses to call the new code. Run in isolation so every top-level
/// call is its own transaction, under both forks:
///   A239_ISOLATE=true forge test --offline --isolate --evm-version shanghai --match-contract A239Metamorphic
///   A239_ISOLATE=true forge test --offline --isolate --evm-version cancun --match-contract A239Metamorphic
/// Without A239_ISOLATE the tests return at once (the default run is one transaction per test, where no self-destruct
/// takes effect before the test ends).
contract A239MetamorphicTest {
    A239MVm constant vm = A239MVm(address(uint160(uint256(keccak256("hevm cheat code")))));
    uint256 constant U = 1e6;
    uint64 constant BUCKET = uint64(10_000 * U);

    uint256[] ethKeys;
    D6Usdc usdc;
    ProvenanceSourceVault vault;
    BridgedStablecoinV3 token;
    A239MetaFactory factory;
    address honest;
    address evil;
    bool isolated;

    function setUp() public {
        isolated = vm.envOr("A239_ISOLATE", false);
        vm.roll(1000);
        vm.warp(1786656679 + 8000 * 960);
        ethKeys = new uint256[](7);
        for (uint256 i; i < 7; ++i) ethKeys[i] = 0x2000 + i;
        for (uint256 i; i < 7; ++i) {
            for (uint256 j = i + 1; j < 7; ++j) {
                if (vm.addr(ethKeys[j]) < vm.addr(ethKeys[i])) (ethKeys[i], ethKeys[j]) = (ethKeys[j], ethKeys[i]);
            }
        }
        address[] memory signers = new address[](7);
        for (uint256 i; i < 7; ++i) signers[i] = vm.addr(ethKeys[i]);
        usdc = new D6Usdc();
        vault = new ProvenanceSourceVault(
            keccak256("ethereum"), keccak256("bloch-l2"), keccak256("USDC"), address(usdc), uint64(100_000 * U), 0, signers, 5,
            ProvenanceSourceVault.Policy(BUCKET, 1 days, 6, 14 days, uint64(11 * U), uint64(10 * U)),
            ProvenanceSourceVault.Guard(new address[](0), 0, 0),
            ProvenanceSourceVault.Provenance(1, 0, address(0), ProvenanceSourceVault.Fees(address(0), 0, 0))
        );
        uint256 until = block.timestamp + 100;
        vault.setControls(true, true, 0, until, cert(vault.controlDigest(true, true, 0, until), 5));
        usdc.mint(address(this), BUCKET);
        vault.deposit(BUCKET, bytes32(uint256(0xA11CE)));
        factory = new A239MetaFactory();
        honest = address(new A239RejectAllRetirable());
        evil = address(new A239AcceptAllCode());
    }

    function cert(bytes32 h, uint256 n) private view returns (bytes[] memory out) {
        out = new bytes[](n);
        for (uint256 i; i < n; ++i) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(ethKeys[i], h);
            out[i] = abi.encodePacked(r, s, v);
        }
    }

    function proposeCall(address m) private view returns (bytes memory) {
        uint256 until = block.timestamp + 1000;
        bytes32 h = honest.codehash; // the reviewed code; at proposal M carries exactly this code
        return abi.encodeCall(
            ProvenanceSourceVault.proposeVerifier, (m, 0, until, cert(vault.switchDigest(false, m, h, 0, until), 6))
        );
    }

    function theft() private view returns (ProvenanceSourceVault.Release memory) {
        return ProvenanceSourceVault.Release(
            vault.routeId(), 7, address(0xBAD), uint64(9_000 * U), keccak256("no burn"), 1, BUCKET, vault.chainHeadAt(1)
        );
    }

    /// Pre-Cancun semantics (the L2, `evm_version = shanghai`): deploy the reviewed code, propose, activate, then any later
    /// transaction self-destructs it and re-creates other code at the same address. The vault pays a release no burn backs.
    /// Under Cancun the late self-destruct does not delete the code and the re-creation fails; this test then asserts that.
    function test_META_lateSelfdestructSwapsTheVerifier() public {
        if (!isolated) return;
        address m = factory.deploy(honest);
        require(m == factory.predicted() && m.codehash == honest.codehash, "reviewed code at M");
        (bool ok,) = address(vault).call(proposeCall(m));
        require(ok, "proposed");
        vm.warp(block.timestamp + 14 days);
        vault.activateVerifier();
        A239RejectAllRetirable(m).retire();
        if (factory.sizeOf(m) != 0) {
            require(factory.deploy(evil) == address(0), "Cancun: no re-creation over live code");
            (ok,) = address(vault).call(abi.encodeCall(ProvenanceSourceVault.releaseWithProof, (theft(), bytes(""))));
            require(!ok, "Cancun: the reviewed code still refuses");
            return;
        }
        require(factory.deploy(evil) == m, "same address, other code");
        (ok,) = address(vault).call(abi.encodeCall(ProvenanceSourceVault.releaseWithProof, (theft(), bytes(""))));
        require(!ok && usdc.balanceOf(address(0xBAD)) == 0, "pre-Cancun: the swap happens, the vault refuses the new code");
    }

    /// Post-Cancun too: create, propose and self-destruct in ONE transaction; 14 days later create, activate and
    /// self-destruct in ONE transaction (the code hash matches at activation); then create other code at the same address.
    /// The vault pays. Only a verifier with no reachable SELFDESTRUCT (and no DELEGATECALL into one) closes this.
    function test_META_sameTransactionSelfdestructSwapsTheVerifierEvenAfterCancun() public {
        if (!isolated) return;
        address m = factory.predicted();
        factory.createCallRetire(honest, address(vault), proposeCall(m));
        require(vault.proposedVerifier() == m && vault.proposedVerifierCodehash() == honest.codehash, "pinned");
        require(factory.sizeOf(m) == 0, "deleted after its creating transaction");
        vm.warp(block.timestamp + 14 days);
        factory.createCallRetire(honest, address(vault), abi.encodeCall(ProvenanceSourceVault.activateVerifier, ()));
        require(vault.verifier() == m && factory.sizeOf(m) == 0, "activated, then deleted");
        require(factory.deploy(evil) == m, "same address, other code");
        (bool ok,) = address(vault).call(abi.encodeCall(ProvenanceSourceVault.releaseWithProof, (theft(), bytes(""))));
        require(!ok && usdc.balanceOf(address(0xBAD)) == 0, "the swap happens, the vault refuses the new code");
    }
}
