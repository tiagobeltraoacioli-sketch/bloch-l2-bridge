// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.24;

import {SignerMintedToken} from "../contracts/bridged/SignerMintedToken.sol";
import {BridgedStablecoinV2} from "../contracts/stable/BridgedStablecoinV2.sol";
import {BridgedStablecoinV3} from "../contracts/stable/BridgedStablecoinV3.sol";
import {ProvenanceSourceVault} from "../contracts/usdt/ProvenanceSourceVault.sol";

interface ComposeVm {
    function addr(uint256 privateKey) external pure returns (address);
    function sign(uint256 privateKey, bytes32 digest) external pure returns (uint8 v, bytes32 r, bytes32 s);
    function warp(uint256 timestamp) external;
    function roll(uint256 blockNumber) external;
    function prank(address sender) external;
    function setBlockhash(uint256 blockNumber, bytes32 hash) external;
}

contract ComposeUsdc {
    uint8 public constant decimals = 6;
    mapping(address => uint256) public balanceOf;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

/// The mint chain (agents/108-d6-design.md, O1) on top of agent 87's C + D + I token at T = 100 bUSDC: 3 guardians
/// (cancel quorum 2), 5-of-7 mint, 6-of-7 unpause, instant cap 1,000 a day, 12 h delay. The forger holds 5 mint keys.
contract D6ComposeTest {
    ComposeVm constant vm = ComposeVm(address(uint160(uint256(keccak256("hevm cheat code")))));
    uint256 constant U = 1e6;
    uint64 constant BUCKET = uint64(10_000 * U);
    uint64 constant T = uint64(100 * U);
    address constant MALLORY = address(0xBAD);
    address constant ALICE = address(0xA11CE);
    address constant BOB = address(0xB0B);

    uint256[] mintKeys;
    uint256[] ethKeys;
    uint256[3] guardKeys = [uint256(0x6a01), 0x6a02, 0x6a03];
    ComposeUsdc usdc;
    ProvenanceSourceVault vault;
    BridgedStablecoinV3 token;

    function setUp() public {
        vm.warp(1_000_000);
        vm.roll(1000);
        mintKeys = sorted(0x1000);
        ethKeys = sorted(0x2000);
        usdc = new ComposeUsdc();
        vault = new ProvenanceSourceVault(
            keccak256("ethereum"), keccak256("bloch-l2"), keccak256("USDC"), address(usdc), uint64(100_000 * U), 0,
            addrs(ethKeys), 5, ProvenanceSourceVault.Policy(BUCKET, 1 days, 6, 14 days, uint64(10 * U), uint64(10 * U)),
            ProvenanceSourceVault.Guard(new address[](0), 0, 0), ProvenanceSourceVault.Provenance(1, 0, address(0))
        );
        uint256 until = block.timestamp + 100;
        vault.setControls(true, true, 0, until, cert(vault.controlDigest(true, true, 0, until), 5));
        address[] memory g = new address[](3);
        for (uint256 i; i < 3; ++i) g[i] = vm.addr(guardKeys[i]);
        token = new BridgedStablecoinV3(
            "Bloch Bridged USDC", "bUSDC", block.chainid, address(vault), vault.routeId(), addrs(mintKeys), 5,
            SignerMintedToken.Limits(uint64(100_000 * U), BUCKET, BUCKET / 1 days, T, 12 hours, uint64(10 * U)),
            SignerMintedToken.Guard(g, 3 days, 3 days), BridgedStablecoinV2.MintSwitch(6, 14 days)
        );
    }

    function sorted(uint256 base) internal view returns (uint256[] memory k) {
        k = new uint256[](7);
        for (uint256 i; i < 7; ++i) k[i] = base + i;
        for (uint256 i; i < 7; ++i) {
            for (uint256 j = i + 1; j < 7; ++j) {
                if (vm.addr(k[j]) < vm.addr(k[i])) (k[i], k[j]) = (k[j], k[i]);
            }
        }
    }

    function addrs(uint256[] memory k) internal view returns (address[] memory a) {
        a = new address[](k.length);
        for (uint256 i; i < k.length; ++i) a[i] = vm.addr(k[i]);
    }

    function cert(bytes32 digest, uint256 n) internal view returns (bytes[] memory out) {
        out = new bytes[](n);
        for (uint256 i; i < n; ++i) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(ethKeys[i], digest);
            out[i] = abi.encodePacked(r, s, v);
        }
    }

    function blob(bytes32 digest, uint256 n) internal view returns (bytes memory out) {
        for (uint256 i; i < n; ++i) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(mintKeys[i], digest);
            out = bytes.concat(out, abi.encodePacked(r, s, v));
        }
    }

    function deposit(uint64 amount, address l2) internal returns (bytes32 id) {
        usdc.mint(address(this), amount);
        id = vault.deposit(amount, bytes32(uint256(uint160(l2))));
    }

    function mint(bytes32 id, uint64 nonce, uint64 amount, address to) internal {
        token.mint(id, nonce, amount, to, blob(token.mintDigest(id, nonce, amount, to), 5));
    }

    function cancel(bytes32 id) internal {
        (address r, uint64 a, uint64 ready) = token.pendingMints(id);
        for (uint256 i; i < 2; ++i) {
            vm.prank(vm.addr(guardKeys[i]));
            token.voteCancelMint(id, r, a, ready);
        }
    }

    function burn(address holder, uint64 amount) internal returns (ProvenanceSourceVault.Release memory) {
        vm.prank(holder);
        bytes32 burnId = token.burn(amount, holder);
        return ProvenanceSourceVault.Release(
            vault.routeId(), token.burnNonce(), holder, amount, burnId, token.mintCount(), token.mintedTotal(), token.mintHead()
        );
    }

    function release(ProvenanceSourceVault.Release memory r) internal returns (bool ok) {
        vm.roll(block.number + 1);
        vm.setBlockhash(block.number - 1, keccak256(abi.encode(block.number)));
        ProvenanceSourceVault.ReleaseContext memory c = ProvenanceSourceVault.ReleaseContext(
            block.timestamp + 100, block.number - 1, keccak256(abi.encode(block.number)), 7, keccak256("l2")
        );
        (ok,) = address(vault).call(abi.encodeCall(ProvenanceSourceVault.release, (r, c, cert(vault.releaseDigest(r, c), 5))));
    }

    /// C does its job: a queued forgery is cancelled before it credits, so it never enters the chain; the real deposit
    /// fills its slot and nothing is held.
    function test_C_cancelledForgeryLeavesNoTraceAndNothingIsHeld() public {
        bytes32 bob = deposit(uint64(1000 * U), BOB);
        mint(fid(keccak256("forged"), 0), 0, uint64(5000 * U), MALLORY); // takes slot 0, queued 12 h
        cancel(fid(keccak256("forged"), 0));
        require(token.slotKey(0) == 0 && token.mintCount() == 0, "slot 0 free again");
        mint(bob, 0, uint64(1000 * U), BOB); // the real deposit 0, queued (above T)
        vm.warp(block.timestamp + 12 hours);
        token.executeMint(bob);
        require(release(burn(BOB, uint64(1000 * U))), "Bob paid: no hold after a cancelled forgery");
        require(usdc.balanceOf(MALLORY) == 0, "nothing for Mallory");
    }

    /// I's instant path: a forged mint under T credits at once and enters the chain. It cannot be paid; later exits hold.
    function test_instantForgeryCannotBePaidAndHoldsLaterBurns() public {
        bytes32 a = deposit(uint64(100 * U), ALICE);
        mint(a, 0, uint64(100 * U), ALICE);
        ProvenanceSourceVault.Release memory early = burn(ALICE, uint64(50 * U));
        deposit(uint64(5000 * U), BOB); // slack: unminted
        mint(fid(keccak256("forged"), 1), 1, uint64(100 * U), MALLORY); // instant
        require(token.balanceOf(MALLORY) == 100 * U, "credited by the instant path");
        require(!release(burn(MALLORY, uint64(100 * U))), "forged burn refused");
        require(release(early), "a burn from before the forgery still pays");
        require(!release(burn(ALICE, uint64(50 * U))), "a later honest burn is held");
        require(usdc.balanceOf(MALLORY) == 0 && vault.totalLocked() == 5050 * U, "drained 0");
    }

    /// Credit order lets C cancel small forgeries too: behind a queued mint they wait, so guardians reach them in time.
    function test_smallForgeriesBehindAQueuedMintAreCancellable() public {
        bytes32 a = deposit(uint64(5000 * U), ALICE);
        mint(a, 0, uint64(5000 * U), ALICE); // queued
        for (uint64 i = 1; i <= 3; ++i) mint(fid(keccak256(abi.encode("small", i)), i), i, uint64(50 * U), MALLORY);
        require(token.balanceOf(MALLORY) == 0, "under T but waiting for slot 0");
        for (uint64 i = 1; i <= 3; ++i) cancel(fid(keccak256(abi.encode("small", i)), i));
        vm.warp(block.timestamp + 12 hours);
        token.executeMint(a);
        require(token.balanceOf(MALLORY) == 0 && token.mintCount() == 1, "the cancelled small mints never credit");
        require(release(burn(ALICE, uint64(5000 * U))), "Alice paid");
    }

    /// A cancelled honest mint comes back by remint to its own slot; later slots drain behind it.
    function test_remintReturnsToItsSlotAndLaterSlotsDrain() public {
        bytes32 a = deposit(uint64(500 * U), ALICE);
        bytes32 b = deposit(uint64(50 * U), BOB);
        mint(a, 0, uint64(500 * U), ALICE);
        mint(b, 1, uint64(50 * U), BOB);
        cancel(a); // bad guardians
        require(token.balanceOf(BOB) == 0, "Bob waits behind the cancelled slot");
        bytes memory sigs = blob(token.remintDigest(a, 0, uint64(500 * U), ALICE, false), 5);
        token.remint(a, 0, uint64(500 * U), ALICE, false, sigs);
        vm.warp(block.timestamp + 12 hours);
        token.executeMint(a);
        require(token.balanceOf(ALICE) == 500 * U && token.balanceOf(BOB) == 50 * U, "both credited, in order");
        require(release(burn(BOB, uint64(50 * U))) && release(burn(ALICE, uint64(500 * U))), "both paid");
    }

    /// A slot is taken once: a second mint for the same nonce, or a remint into another slot, is refused.
    function test_slotsCannotBeDoubledOrMoved() public {
        bytes32 a = deposit(uint64(500 * U), ALICE);
        mint(a, 0, uint64(500 * U), ALICE);
        bytes memory sigs = blob(token.mintDigest(fid(keccak256("x"), 0), 0, uint64(50 * U), MALLORY), 5);
        (bool ok,) = address(token).call(abi.encodeCall(BridgedStablecoinV2.mint, (fid(keccak256("x"), 0), 0, uint64(50 * U), MALLORY, sigs)));
        require(!ok, "slot 0 taken");
        sigs = blob(token.mintDigest(fid(keccak256("y"), 5), 5, uint64(50 * U), MALLORY), 5);
        (ok,) = address(token).call(abi.encodeCall(BridgedStablecoinV2.mint, (fid(keccak256("y"), 5), 5, uint64(50 * U), MALLORY, sigs)));
        require(!ok, "no slot ahead of nextSlot");
        cancel(a);
        mint(fid(keccak256("z"), 1), 1, uint64(50 * U), BOB);
        sigs = blob(token.remintDigest(a, 1, uint64(500 * U), ALICE, false), 5);
        (ok,) = address(token).call(abi.encodeCall(BridgedStablecoinV2.remint, (a, 1, uint64(500 * U), ALICE, false, sigs)));
        require(!ok, "a remint goes back to its own slot");
    }

    /// D still holds with the chain: 5 mint keys cannot end a guardian pause.
    function test_D_unpauseStillNeedsSix() public {
        vm.prank(vm.addr(guardKeys[0]));
        token.pause();
        bytes memory five = blob(token.unpauseDigest(), 5);
        (bool ok,) = address(token).call(abi.encodeCall(SignerMintedToken.unpause, (five)));
        require(!ok, "5 keys cannot unpause");
        token.unpause(blob(token.unpauseDigest(), 6));
    }
}

/// A made-up deposit id that names slot `slot`, as ProvenanceSourceVault ids do (nonce in the top 8 bytes): a forger who wants
/// a slot must name it in the id (agent 111, F1).
function fid(bytes32 salt, uint64 slot) pure returns (bytes32) {
    return bytes32((uint256(slot) << 192) | (uint256(salt) & type(uint192).max));
}
