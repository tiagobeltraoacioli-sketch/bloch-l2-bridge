// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.24;

import {ScaledUnitToken} from "../contracts/evmnets/ScaledUnitToken.sol";
import {ProvenanceSourceVault} from "../contracts/usdt/ProvenanceSourceVault.sol";

interface UnitVm {
    function addr(uint256 privateKey) external pure returns (address);
    function sign(uint256 privateKey, bytes32 digest) external pure returns (uint8 v, bytes32 r, bytes32 s);
    function prank(address sender) external;
    function expectRevert(bytes4 revertData) external;
    function expectRevert() external;
    function assume(bool) external pure;
}

/// Peg-token stand-in with configurable decimals. `feeBps` takes a fee on transfer; `seize` models an issuer action.
contract PegAsset {
    uint8 public decimals;
    uint256 public feeBps;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    constructor(uint8 d) {
        decimals = d;
    }

    function mint(address to, uint256 v) external {
        balanceOf[to] += v;
    }

    function setFee(uint256 bps) external {
        feeBps = bps;
    }

    function seize(address from, uint256 v) external {
        balanceOf[from] -= v;
    }

    function approve(address s, uint256 v) external returns (bool) {
        allowance[msg.sender][s] = v;
        return true;
    }

    function transfer(address to, uint256 v) external returns (bool) {
        balanceOf[msg.sender] -= v;
        balanceOf[to] += v - v * feeBps / 10_000;
        return true;
    }

    function transferFrom(address f, address to, uint256 v) external returns (bool) {
        allowance[f][msg.sender] -= v;
        balanceOf[f] -= v;
        balanceOf[to] += v - v * feeBps / 10_000;
        return true;
    }
}

/// Round 16, agent 320: the six-decimal unit token that lets the byte-identical ProvenanceSourceVault hold an
/// 18-decimal asset (BNB Smart Chain), alone and under the real vault at the launch shape (5-of-7, 5 + 5 bps).
contract R320ScaledUnitTokenTest {
    UnitVm constant vm = UnitVm(address(uint160(uint256(keccak256("hevm cheat code")))));
    uint256 constant U = 1e6;
    uint256 constant SCALE = 1e12;
    address constant ALICE = address(0xA11CE);
    address constant BOB = address(0xB0B);
    address constant TREASURY = address(0x7EA5);
    PegAsset asset;
    ScaledUnitToken unit;
    ProvenanceSourceVault vault;
    uint256[] keys;

    function setUp() public {
        asset = new PegAsset(18);
        unit = new ScaledUnitToken(address(asset), "Bloch bridge unit of Binance-Peg USD Coin", "uUSDC");
        address[] memory signers = new address[](7);
        for (uint256 i; i < 7; ++i) keys.push(0xA000 + i);
        for (uint256 i; i < 7; ++i) {
            for (uint256 j = i + 1; j < 7; ++j) {
                if (vm.addr(keys[j]) < vm.addr(keys[i])) (keys[i], keys[j]) = (keys[j], keys[i]);
            }
        }
        for (uint256 i; i < 7; ++i) signers[i] = vm.addr(keys[i]);
        vault = new ProvenanceSourceVault(
            keccak256("bnb-smart-chain"),
            keccak256("bloch-l2-700770"),
            keccak256("USDC"),
            address(unit),
            uint64(100_000 * U),
            0,
            signers,
            5,
            ProvenanceSourceVault.Policy(uint64(10_000 * U), 86400, 6, 14 days, uint64(11 * U), uint64(10 * U)),
            ProvenanceSourceVault.Guard(new address[](0), 0, 0),
            ProvenanceSourceVault.Provenance(1, 0, address(0), ProvenanceSourceVault.Fees(TREASURY, 5, 5))
        );
        uint256 validUntil = block.timestamp + 1;
        bytes32 d = vault.controlDigest(true, true, 0, validUntil);
        bytes[] memory sigs = new bytes[](5);
        for (uint256 i; i < 5; ++i) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(keys[i], d);
            sigs[i] = abi.encodePacked(r, s, v);
        }
        vault.setControls(true, true, 0, validUntil, sigs);
        asset.mint(ALICE, 1_000_000 ether);
        vm.prank(ALICE);
        asset.approve(address(unit), type(uint256).max);
    }

    function test_CONFIG_sixDecimalsAndTheScale() public view {
        require(unit.decimals() == 6 && unit.scale() == SCALE && unit.asset() == address(asset));
        require(vault.token() == address(unit) && vault.decimals() == 6);
    }

    function test_CONFIG_refusesAnAssetThatNeedsNoScaling() public {
        PegAsset six = new PegAsset(6);
        vm.expectRevert(ScaledUnitToken.BadConfig.selector);
        new ScaledUnitToken(address(six), "x", "x");
        vm.expectRevert(ScaledUnitToken.BadConfig.selector);
        new ScaledUnitToken(address(0xdead), "x", "x");
    }

    function test_VAULT_refusesTheRawEighteenDecimalAsset() public {
        // The reason this contract exists: the frozen vault's constructor requires decimals() == 6.
        address[] memory signers = new address[](2);
        signers[0] = address(1);
        signers[1] = address(2);
        vm.expectRevert(ProvenanceSourceVault.InvalidConfiguration.selector);
        new ProvenanceSourceVault(
            keccak256("a"), keccak256("b"), keccak256("c"), address(asset), 1, 0, signers, 2,
            ProvenanceSourceVault.Policy(1, 1, 2, 7 days, 1, 1),
            ProvenanceSourceVault.Guard(new address[](0), 0, 0),
            ProvenanceSourceVault.Provenance(1, 0, address(0), ProvenanceSourceVault.Fees(address(0), 0, 0))
        );
    }

    function test_WRAP_roundTripIsExact() public {
        vm.prank(ALICE);
        unit.wrap(ALICE, 250 * U);
        require(unit.balanceOf(ALICE) == 250 * U && asset.balanceOf(address(unit)) == 250 ether);
        vm.prank(ALICE);
        unit.unwrap(BOB, 100 * U);
        require(asset.balanceOf(BOB) == 100 ether && unit.totalSupply() == 150 * U);
        require(asset.balanceOf(address(unit)) == unit.totalSupply() * SCALE);
    }

    function test_WRAP_aFeeOnTransferAssetIsRefused() public {
        asset.setFee(10);
        vm.prank(ALICE);
        vm.expectRevert(ScaledUnitToken.BadAsset.selector);
        unit.wrap(ALICE, 100 * U);
    }

    function test_UNWRAP_cannotTakeMoreThanHeld() public {
        vm.prank(ALICE);
        unit.wrap(ALICE, 10 * U);
        vm.prank(BOB);
        vm.expectRevert();
        unit.unwrap(BOB, 1);
        vm.prank(ALICE);
        vm.expectRevert();
        unit.unwrap(ALICE, 10 * U + 1);
    }

    function test_DEPOSIT_oneTransactionThroughTheRealVault() public {
        bytes32 recipient = bytes32(uint256(uint160(ALICE)));
        vm.prank(ALICE);
        bytes32 id = unit.wrapAndDeposit(address(vault), uint64(1000 * U), recipient);
        // 5 bps fee stays outside backing; the deposit is its net amount, in units.
        require(vault.totalLocked() == 999_500_000 && vault.feesAccrued() == 500_000);
        require(unit.balanceOf(address(vault)) == 1000 * U && asset.balanceOf(address(unit)) == 1000 ether);
        require(unit.balanceOf(address(unit)) == 0 && unit.allowance(address(unit), address(vault)) == 0);
        require(id == vault.depositId(0, address(unit), 999_500_000, recipient));
        require(asset.balanceOf(ALICE) == 1_000_000 ether - 1000 ether);
    }

    function test_DEPOSIT_aVaultRefusalRevertsEverything() public {
        vm.prank(ALICE);
        vm.expectRevert(ProvenanceSourceVault.InvalidTransfer.selector);
        unit.wrapAndDeposit(address(vault), uint64(10 * U), bytes32(uint256(uint160(ALICE))));
        require(asset.balanceOf(ALICE) == 1_000_000 ether && unit.totalSupply() == 0);
    }

    function test_DEPOSIT_aContractThatTakesNothingIsRefused() public {
        Idle idle = new Idle();
        vm.prank(ALICE);
        vm.expectRevert(ScaledUnitToken.DepositIncomplete.selector);
        unit.wrapAndDeposit(address(idle), uint64(100 * U), bytes32(uint256(1)));
    }

    function test_DEPOSIT_reentryIsRefused() public {
        Reenter bad = new Reenter(unit);
        vm.prank(ALICE);
        vm.expectRevert(ScaledUnitToken.Reentrancy.selector);
        unit.wrapAndDeposit(address(bad), uint64(100 * U), bytes32(uint256(1)));
    }

    function test_FEES_theSweepPaysUnitsTheTreasuryUnwraps() public {
        vm.prank(ALICE);
        unit.wrapAndDeposit(address(vault), uint64(1000 * U), bytes32(uint256(uint160(ALICE))));
        vault.sweepFees();
        require(unit.balanceOf(TREASURY) == 500_000);
        vm.prank(TREASURY);
        unit.unwrap(TREASURY, 500_000);
        require(asset.balanceOf(TREASURY) == 0.5 ether);
        require(unit.balanceOf(address(vault)) == vault.totalLocked());
    }

    function test_ISSUER_aSeizureLeavesTheLastUnwrapUnpaid() public {
        // Known limit: this contract cannot repair an asset balance the issuer reduces.
        vm.prank(ALICE);
        unit.wrap(ALICE, 100 * U);
        asset.seize(address(unit), 40 ether);
        vm.prank(ALICE);
        unit.unwrap(ALICE, 60 * U);
        vm.prank(ALICE);
        vm.expectRevert();
        unit.unwrap(ALICE, 40 * U);
    }

    function testFuzz_backingIsExact(uint64 a, uint64 b, uint64 c) public {
        uint256 x = uint256(a) % (500_000 * U);
        uint256 y = uint256(b) % (x + 1);
        uint256 z = uint256(c) % (x - y + 1);
        vm.prank(ALICE);
        unit.wrap(ALICE, x);
        vm.prank(ALICE);
        unit.transfer(BOB, y);
        vm.prank(BOB);
        unit.unwrap(BOB, y);
        vm.prank(ALICE);
        unit.unwrap(ALICE, z);
        require(unit.totalSupply() == x - y - z);
        require(asset.balanceOf(address(unit)) == unit.totalSupply() * SCALE);
        require(asset.balanceOf(BOB) == y * SCALE);
    }
}

contract Idle {
    function deposit(uint64, bytes32) external pure returns (bytes32) {
        return bytes32(0);
    }
}

contract Reenter {
    ScaledUnitToken immutable unit;

    constructor(ScaledUnitToken u) {
        unit = u;
    }

    function deposit(uint64, bytes32) external returns (bytes32) {
        unit.wrap(address(this), 1);
        return bytes32(0);
    }
}
