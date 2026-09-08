// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.24;

import {L2BlochBridge} from "../contracts/bridge/L2BlochBridge.sol";
import {WBLCH} from "../contracts/wblch/WBLCH.sol";
import {L1ReleaseVerifier, IL1ReleaseVerifier} from "../contracts/l1/L1ReleaseVerifier.sol";

interface Vm {
    function etch(address target, bytes calldata code) external;
    function deal(address target, uint256 balance) external;
    function prank(address sender) external;
    function expectRevert(bytes calldata data) external;
    function assume(bool condition) external;
}

contract FullBridge is L2BlochBridge {
    function fillForTest() external {
        leafCount = uint64(MAX_LEAVES);
        nextNonce = leafCount;
    }
}

contract ReentrantWrapper {
    L2BlochBridge private immutable bridge;
    bool public nativeReentry;
    bool public wrappedReentry;

    constructor(L2BlochBridge bridge_) { bridge = bridge_; }
    function transferFrom(address, address, uint256) external pure returns (bool) { return true; }
    function withdraw(uint256 wad) external {
        (nativeReentry,) = address(bridge).call{value: wad}(
            abi.encodeCall(bridge.withdraw, (bytes20(uint160(123))))
        );
        (wrappedReentry,) = address(bridge).call(
            abi.encodeCall(bridge.withdrawWBLCH, (wad, bytes20(uint160(123))))
        );
        (bool ok,) = address(bridge).call{value: wad}("");
        require(ok);
    }
}

contract UnderpayingWrapper {
    function transferFrom(address, address, uint256) external pure returns (bool) { return true; }
    function withdraw(uint256 wad) external {
        (bool ok,) = msg.sender.call{value: wad - 1}("");
        require(ok);
    }
}

contract ReentrantHolder {
    WBLCH private immutable wrapper;
    bool public reentered;
    constructor(WBLCH wrapper_) { wrapper = wrapper_; }
    function exercise() external payable {
        wrapper.deposit{value: msg.value}();
        wrapper.withdraw(msg.value);
    }
    receive() external payable {
        (reentered,) = address(wrapper).call(abi.encodeCall(wrapper.withdraw, (msg.value)));
    }
}

contract RejectingHolder {
    WBLCH private immutable wrapper;
    constructor(WBLCH wrapper_) { wrapper = wrapper_; }
    function exercise() external payable {
        wrapper.deposit{value: msg.value}();
        (bool ok,) = address(wrapper).call(abi.encodeCall(wrapper.withdraw, (msg.value)));
        require(!ok, "native rejection must revert unwrap");
    }
    receive() external payable { revert("reject native"); }
}

/// Runs bytecode in a local test EVM, including constructor-free genesis
/// predeploys. No chain connection or production deployment is involved.
contract BridgeSecurityTest {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    uint256 private constant SCALE = 1e10;
    bytes20 private constant RECIPIENT = bytes20(uint160(0xbb));
    address private constant WRAPPER = 0x4200000000000000000000000000000000000006;
    address private constant BRIDGE = 0x4200000000000000000000000000000000000010;
    L2BlochBridge private bridge;
    WBLCH private wrapper;
    L1ReleaseVerifier private verifier;

    function setUp() public {
        vm.etch(WRAPPER, address(new WBLCH()).code);
        vm.etch(BRIDGE, address(new L2BlochBridge()).code);
        bridge = L2BlochBridge(payable(BRIDGE));
        wrapper = WBLCH(payable(WRAPPER));
        verifier = new L1ReleaseVerifier(address(this));
        vm.deal(address(this), 1e40);
    }

    receive() external payable {}

    function expect(string memory reason) private {
        vm.expectRevert(abi.encodeWithSignature("Error(string)", reason));
    }

    function zeroBranch() private pure returns (bytes32[32] memory branch, bytes32 root) {
        bytes32 zero;
        for (uint256 h; h < 32; h++) {
            branch[h] = zero;
            zero = keccak256(abi.encodePacked(zero, zero));
        }
        return (branch, zero);
    }

    function testGenesisStorageAndEmptyRoot() public view {
        (, bytes32 empty) = zeroBranch();
        require(bridge.getWithdrawalRoot() == empty && empty != bytes32(0));
        require(bridge.leafCount() == 0 && bridge.nextNonce() == 0);
        require(bridge.epochNumber() == 0 && bridge.totalBurnedWei() == 0);
        require(wrapper.totalSupply() == 0);
    }

    function testRustGoldenLeafInBothContracts() public view {
        address sender = 0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa;
        bytes20 recipient = hex"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        bytes32 expected = hex"0b0f4ac6fd0554ae9b750f72fa2e028753b3985d4faecd52fc2995dd3e3f789a";
        require(bridge.computeLeaf(7, sender, recipient, 100_000_000, 42) == expected);
        require(verifier.computeLeaf(7, sender, recipient, 100_000_000, 42) == expected);
    }

    function testMultiEpochRootsMatchRustAndIndependentPython() public {
        address sender = address(bytes20(hex"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
        bytes20 recipient = hex"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        address system = bridge.SYSTEM_CALLER();
        vm.deal(sender, 1000 * SCALE);
        for (uint64 nonce; nonce < 17; nonce++) {
            if (nonce > 0 && nonce % 3 == 0) {
                vm.prank(system);
                bridge.setEpochNumber(nonce / 3);
            }
            vm.prank(sender);
            bridge.withdraw{value: uint256(nonce + 1) * SCALE}(recipient);
            if (nonce == 6) {
                require(bridge.getWithdrawalRoot() == hex"2a4786e095abbcdfd22cc0056887d00e211109adc3e9074e52cbabc124a7d961");
            }
        }
        require(bridge.getWithdrawalRoot() == hex"100fec66641dbfe9ea1ca07da955144d82c7794dd4aadecf957a593f8760064f");
    }

    function testFuzzNativeWithdrawalAndProof(uint64 atoms, bytes20 recipient) public {
        vm.assume(atoms > 0 && recipient != bytes20(0));
        uint256 wad = uint256(atoms) * SCALE;
        bridge.withdraw{value: wad}(recipient);
        require(bridge.leafCount() == 1 && bridge.nextNonce() == 1);
        require(bridge.totalBurnedWei() == wad && BRIDGE.balance == wad);
        (bytes32[32] memory branch,) = zeroBranch();
        verifier.postWithdrawalsRoot(0, bridge.getWithdrawalRoot());
        require(verifier.checkWithdrawal(0, address(this), recipient, atoms, 0, 0, branch)
            == IL1ReleaseVerifier.Inclusion.Included);
        require(verifier.checkWithdrawal(0, address(this), recipient, atoms, 0, 1, branch)
            == IL1ReleaseVerifier.Inclusion.NotIncluded);
    }

    function testFuzzDustAlwaysRevertsWithoutBurn(uint64 atoms, uint64 dust) public {
        uint256 wad = uint256(atoms) * SCALE + (uint256(dust) % (SCALE - 1)) + 1;
        expect("L2BlochBridge: not atom-aligned");
        bridge.withdraw{value: wad}(RECIPIENT);
        require(bridge.leafCount() == 0 && bridge.totalBurnedWei() == 0 && BRIDGE.balance == 0);
    }

    function testZeroAndOversizedWithdrawalsRevert() public {
        expect("L2BlochBridge: zero recipient");
        bridge.withdraw{value: SCALE}(bytes20(0));
        expect("L2BlochBridge: zero withdrawal");
        bridge.withdraw(RECIPIENT);
        expect("L2BlochBridge: amount overflow");
        bridge.withdraw{value: (uint256(type(uint64).max) + 1) * SCALE}(RECIPIENT);
        require(bridge.nextNonce() == 0 && BRIDGE.balance == 0);
    }

    function testWrappedWithdrawalBurnsExactlyOnce() public {
        uint256 wad = 7 * SCALE;
        wrapper.deposit{value: wad}();
        wrapper.approve(BRIDGE, wad);
        bridge.withdrawWBLCH(wad, RECIPIENT);
        require(wrapper.balanceOf(address(this)) == 0 && wrapper.balanceOf(BRIDGE) == 0);
        require(wrapper.totalSupply() == 0 && bridge.totalBurnedWei() == wad);
        require(bridge.leafCount() == 1 && BRIDGE.balance == wad);
        bytes32 expected = bridge.computeLeaf(0, address(this), RECIPIENT, 7, 0);
        (bytes32[32] memory branch,) = zeroBranch();
        require(verifier.verifyInclusion(expected, 0, branch, bridge.getWithdrawalRoot())
            == IL1ReleaseVerifier.Inclusion.Included);
    }

    function testWrappedFailureRollsBackTransferAllowanceAndBurn() public {
        uint256 wad = 7 * SCALE;
        wrapper.deposit{value: wad}();
        wrapper.approve(BRIDGE, wad);
        expect("L2BlochBridge: zero recipient");
        bridge.withdrawWBLCH(wad, bytes20(0));
        require(wrapper.balanceOf(address(this)) == wad && wrapper.allowance(address(this), BRIDGE) == wad);
        require(wrapper.totalSupply() == wad && bridge.totalBurnedWei() == 0 && BRIDGE.balance == 0);
        require(bridge.leafCount() == 0 && bridge.nextNonce() == 0);
    }

    function testUnwrapCannotReenterEitherWithdrawalEntryPoint() public {
        vm.etch(WRAPPER, address(new ReentrantWrapper(bridge)).code);
        vm.deal(WRAPPER, SCALE);
        bridge.withdrawWBLCH(SCALE, RECIPIENT);
        require(!ReentrantWrapper(WRAPPER).nativeReentry());
        require(!ReentrantWrapper(WRAPPER).wrappedReentry());
        require(bridge.leafCount() == 1 && bridge.totalBurnedWei() == SCALE);
    }

    function testUnderpayingUnwrapCannotCreateUnbackedWithdrawal() public {
        vm.etch(WRAPPER, address(new UnderpayingWrapper()).code);
        vm.deal(WRAPPER, SCALE);
        expect("L2BlochBridge: unwrap balance mismatch");
        bridge.withdrawWBLCH(SCALE, RECIPIENT);
        require(bridge.leafCount() == 0 && bridge.totalBurnedWei() == 0 && BRIDGE.balance == 0);
    }

    function testWrapperCEIPreventsDoubleWithdrawal() public {
        ReentrantHolder holder = new ReentrantHolder(wrapper);
        holder.exercise{value: SCALE}();
        require(!holder.reentered());
        require(address(holder).balance == SCALE && wrapper.balanceOf(address(holder)) == 0);
        require(WRAPPER.balance == 0);
    }

    function testWrapperNativeFailurePreservesClaim() public {
        RejectingHolder holder = new RejectingHolder(wrapper);
        holder.exercise{value: SCALE}();
        require(wrapper.balanceOf(address(holder)) == SCALE && WRAPPER.balance == SCALE);
    }

    function testOnlySystemCanAdvanceEpochMonotonically() public {
        expect("L2BlochBridge: system only");
        bridge.setEpochNumber(3);
        address system = bridge.SYSTEM_CALLER();
        vm.prank(system);
        bridge.setEpochNumber(3);
        expect("L2BlochBridge: epoch not monotonic");
        vm.prank(system);
        bridge.setEpochNumber(3);
        require(bridge.epochNumber() == 3);
    }

    function testFullTreeRefusalRollsBackBurn() public {
        FullBridge full = new FullBridge();
        full.fillForTest();
        expect("L2BlochBridge: tree full");
        full.withdraw{value: SCALE}(RECIPIENT);
        require(full.nextNonce() == full.MAX_LEAVES() && full.totalBurnedWei() == 0);
        require(address(full).balance == 0);
    }

    function testDirectNativeTransferIsRefused() public {
        (bool ok,) = BRIDGE.call{value: SCALE}("");
        require(!ok && BRIDGE.balance == 0 && bridge.leafCount() == 0);
    }

    function testVerifierOperatorAppendOnlyAndReplayGuards() public {
        bytes32 root = bridge.getWithdrawalRoot();
        expect("L1ReleaseVerifier: operator only");
        vm.prank(address(123));
        verifier.postWithdrawalsRoot(0, root);
        expect("L1ReleaseVerifier: zero root refused");
        verifier.postWithdrawalsRoot(0, bytes32(0));
        verifier.postWithdrawalsRoot(0, root);
        expect("L1ReleaseVerifier: epoch already posted");
        verifier.postWithdrawalsRoot(0, root);
        bytes32 leaf = bridge.computeLeaf(0, address(this), RECIPIENT, 1, 0);
        expect("L1ReleaseVerifier: operator only");
        vm.prank(address(123));
        verifier.markReleased(leaf);
        expect("L1ReleaseVerifier: zero leaf");
        verifier.markReleased(bytes32(0));
        verifier.markReleased(leaf);
        expect("L1ReleaseVerifier: already released");
        verifier.markReleased(leaf);
        require(verifier.released(leaf));
    }

    function testVerifierSentinelAndHighIndexCannotAliasValidProof() public {
        bridge.withdraw{value: SCALE}(RECIPIENT);
        (bytes32[32] memory branch,) = zeroBranch();
        bytes32 leaf = bridge.computeLeaf(0, address(this), RECIPIENT, 1, 0);
        require(verifier.verifyInclusion(leaf, 0, branch, bytes32(0))
            == IL1ReleaseVerifier.Inclusion.UnanchoredRoot);
        require(verifier.verifyInclusion(leaf, uint64(1) << 32, branch, bridge.getWithdrawalRoot())
            == IL1ReleaseVerifier.Inclusion.NotIncluded);
    }
}
