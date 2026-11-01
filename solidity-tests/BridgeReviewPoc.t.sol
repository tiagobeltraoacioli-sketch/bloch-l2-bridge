// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity 0.8.24;

import {ContextBoundSourceVault, IReleaseVerifier} from "../contracts/usdt/ContextBoundSourceVault.sol";
import {BridgedStablecoinV2} from "../contracts/stable/BridgedStablecoinV2.sol";
import {SignerMintedToken} from "../contracts/bridged/SignerMintedToken.sol";

interface ReviewVm {
    function addr(uint256) external returns (address);
    function sign(uint256, bytes32) external returns (uint8, bytes32, bytes32);
    function warp(uint256) external;
    function roll(uint256) external;
    function chainId(uint256) external;
    function prank(address) external;
    function setBlockhash(uint256, bytes32) external;
}

contract ReviewUsdc {
    uint8 public decimals = 6;
    mapping(address => uint256) public balanceOf;
    mapping(address => bool) public blocked;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function approve(address, uint256) external pure returns (bool) {
        return true;
    }

    function block_(address who) external {
        blocked[who] = true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(!blocked[to], "blacklisted");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

contract AcceptAll is IReleaseVerifier {
    function verifyRelease(address, bytes32, bytes calldata) external pure returns (bytes4) {
        return IReleaseVerifier.verifyRelease.selector;
    }
}

/// A wallet or Multicall-style contract that burns twice in one transaction.
contract BatchBurner {
    function run(BridgedStablecoinV2 token, uint64 a, uint64 b, address to) external {
        token.burn(a, to);
        token.burn(b, to);
    }
}

/// Mainnet-shaped parameters (deployments/mainnet/busdc*.config.json) with a 3-of-3 switch committee.
/// Bridge review (agents/29). C1-C5 and C7 assert the fixes.
/// C6 and C9 document behaviour left to the owner (docs/AUDIT-SCOPE.md section 5).
contract BridgeReviewPoc {
    ReviewVm constant vm = ReviewVm(address(uint160(uint256(keccak256("hevm cheat code")))));
    uint64 constant U = 1e6;
    uint64 constant CAP = 100_000 * U;
    uint64 constant WINDOW = 10_000 * U;
    uint256 constant ETH = 1;
    uint256 constant L2 = 700770;
    address constant ALICE = address(0xA11CE);
    address constant BOB = address(0xB0B);
    address constant GUARD = address(0xBA5E);
    address constant GUARD2 = address(0xBA5F);

    ReviewUsdc usdc;
    ContextBoundSourceVault vault;
    BridgedStablecoinV2 busdc;
    uint256[] keys;
    address[] signers;

    function setUp() public {
        vm.chainId(ETH);
        vm.roll(1000);
        vm.warp(2_000_000_000);
        uint256[3] memory raw = [uint256(21), 22, 23];
        address[3] memory a = [vm.addr(raw[0]), vm.addr(raw[1]), vm.addr(raw[2])];
        for (uint256 i; i < 3; ++i) {
            for (uint256 j = i + 1; j < 3; ++j) {
                if (a[j] < a[i]) {
                    (a[i], a[j]) = (a[j], a[i]);
                    (raw[i], raw[j]) = (raw[j], raw[i]);
                }
            }
        }
        for (uint256 i; i < 3; ++i) {
            keys.push(raw[i]);
            signers.push(a[i]);
        }
        usdc = new ReviewUsdc();
        address[] memory g = new address[](2);
        (g[0], g[1]) = (GUARD, GUARD2);
        vault = new ContextBoundSourceVault(
            keccak256("ethereum-mainnet"), keccak256("bloch-l2-700770"), keccak256("USDC"), address(usdc), CAP, 0,
            signers, 2, ContextBoundSourceVault.Policy(WINDOW, 1 days, 3, 14 days, 10 * U, 10 * U),
            ContextBoundSourceVault.Guard(g, 3 days, 3 days)
        );
        uint256 vu = block.timestamp + 1 hours;
        vault.setControls(true, true, 0, vu, _certs(vault.controlDigest(true, true, 0, vu), 2));
        usdc.mint(ALICE, 200_000 * U);
        vm.chainId(L2);
        SignerMintedToken.Limits memory l = SignerMintedToken.Limits({
            supplyCap: CAP, bucketCapacity: WINDOW, refillPerSecond: 115740, largeMintThreshold: 1_000 * U,
            largeMintDelay: 43200, minBurn: 10 * U
        });
        busdc = new BridgedStablecoinV2("Bloch Bridged USDC", "bUSDC", ETH, address(vault), vault.routeId(), signers, 2,
            l, SignerMintedToken.Guard(new address[](0), 0, 0), BridgedStablecoinV2.MintSwitch(2, 14 days));
        vm.chainId(ETH);
    }

    function _sig(uint256 k, bytes32 d) internal returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(k, d);
        return abi.encodePacked(r, s, v);
    }

    function _certs(bytes32 d, uint256 n) internal returns (bytes[] memory out) {
        out = new bytes[](n);
        for (uint256 i; i < n; ++i) {
            out[i] = _sig(keys[i], d);
        }
    }

    function _pq(address a) internal pure returns (bytes32) {
        return bytes32(uint256(uint160(a)));
    }

    function _mintAll(bytes32 dep, uint64 nonce, uint64 amount, address to) internal returns (bool ok) {
        vm.chainId(L2);
        bytes32 md = busdc.mintDigest(dep, nonce, amount, to);
        bytes memory blob = bytes.concat(_sig(keys[0], md), _sig(keys[1], md));
        (ok,) = address(busdc).call(abi.encodeCall(BridgedStablecoinV2.mint, (dep, nonce, amount, to, blob)));
        vm.chainId(ETH);
    }

    function _release(uint64 nonce, address to, uint64 amount, bytes32 burn) internal returns (bool ok) {
        vm.roll(block.number + 1);
        uint256 anchor = block.number - 1;
        bytes32 h = keccak256(abi.encode("eth", anchor));
        vm.setBlockhash(anchor, h);
        ContextBoundSourceVault.Release memory rel = ContextBoundSourceVault.Release(vault.routeId(), nonce, to, amount, burn);
        ContextBoundSourceVault.ReleaseContext memory ctx =
            ContextBoundSourceVault.ReleaseContext(block.timestamp + 1 hours, anchor, h, 7, keccak256("l2-7"));
        bytes[] memory s = _certs(vault.releaseDigest(rel, ctx), 2);
        (ok,) = address(vault).call(abi.encodeCall(ContextBoundSourceVault.release, (rel, ctx, s)));
    }

    function _deposit(uint64 amount, bytes32 pq) internal returns (bytes32 id) {
        vm.prank(ALICE);
        id = vault.deposit(amount, pq);
    }

    /// C1 (fixed): a deposit above the token bucket could never be minted and has no refund: the vault refuses it.
    /// C8: a direct deposit below the L2 minBurn could not be bridged back alone. It reverts before funds move.
    function testC8_depositBelowMinDepositRefusedBeforeFundsMove() public {
        uint256 aliceBefore = usdc.balanceOf(ALICE);
        vm.prank(ALICE);
        (bool ok,) = address(vault).call(abi.encodeCall(ContextBoundSourceVault.deposit, (10 * U - 1, _pq(ALICE))));
        require(!ok, "a deposit below minDeposit is refused");
        require(usdc.balanceOf(ALICE) == aliceBefore && usdc.balanceOf(address(vault)) == 0, "no funds moved");
        require(vault.depositCount() == 0, "nothing recorded");
    }

    /// C8: the constructor ties minDeposit to the declared L2 minBurn and the window.
    function testC8_constructorRefusesABadMinDeposit() public {
        address[] memory g = new address[](0);
        uint64[3][3] memory bad = [[10 * U - 1, 10 * U, WINDOW], [WINDOW + 1, 10 * U, WINDOW], [10 * U, 0, WINDOW]];
        for (uint256 i; i < bad.length; ++i) {
            try new ContextBoundSourceVault(
                keccak256("a"), keccak256("b"), keccak256("USDC"), address(usdc), CAP, 0, signers, 2,
                ContextBoundSourceVault.Policy(bad[i][2], 1 days, 3, 14 days, bad[i][0], bad[i][1]),
                ContextBoundSourceVault.Guard(g, 0, 0)
            ) {
                revert("a bad minDeposit was accepted");
            } catch {}
        }
        require(vault.minDeposit() == 10 * U && vault.l2MinBurn() == 10 * U, "getters");
        bytes32 dep = _deposit(10 * U, _pq(ALICE));
        require(dep != bytes32(0), "minDeposit itself is accepted");
    }

    function testC1_depositAboveBucketRefused() public {
        vm.prank(ALICE);
        (bool ok,) = address(vault).call(abi.encodeCall(ContextBoundSourceVault.deposit, (WINDOW + 1, _pq(ALICE))));
        require(!ok, "a deposit above windowLimit is refused");
        bytes32 dep = _deposit(WINDOW, _pq(ALICE));
        require(_mintAll(dep, 0, WINDOW, ALICE), "the largest deposit fits a full bucket");
    }

    /// C2 (fixed): a burn above the vault window could never be released: the token refuses it.
    function testC2_burnAboveWindowRefused() public {
        bytes32 d0 = _deposit(WINDOW, _pq(ALICE));
        bytes32 d1 = _deposit(1_000 * U, _pq(ALICE));
        require(_mintAll(d0, 0, WINDOW, ALICE), "m0");
        vm.warp(block.timestamp + 1 days);
        require(_mintAll(d1, 1, 1_000 * U, ALICE), "m1");
        vm.warp(block.timestamp + 1 days);
        vm.chainId(L2);
        busdc.executeMint(d0);
        vm.prank(ALICE);
        (bool ok,) = address(busdc).call(abi.encodeCall(BridgedStablecoinV2.burn, (WINDOW + 1, BOB)));
        require(!ok, "a burn above bucketCapacity is refused");
        vm.prank(ALICE);
        bytes32 burn = busdc.burn(WINDOW, BOB);
        uint64 nonce = busdc.burnNonce();
        vm.chainId(ETH);
        require(_release(nonce, BOB, WINDOW, burn), "the largest burn fits an empty window");
    }

    /// C3 (fixed): a recipient that is not a left-padded address could never be minted: the vault refuses it.
    function testC3_nonAddressRecipientRefused() public {
        vm.prank(ALICE);
        (bool ok,) = address(vault).call(
            abi.encodeCall(ContextBoundSourceVault.deposit, (5 * U, keccak256("a post-quantum recipient hash")))
        );
        require(!ok, "a recipient with non-zero high bytes is refused");
    }

    /// C4 (fixed): no boundary lets twice the limit through. Written against behaviour only, so it also runs on the
    /// tumbling window of 8678454, where the release one second after the window fails this test.
    function testC4_noDoubleWindowAtBoundary() public {
        _deposit(WINDOW, _pq(ALICE));
        _deposit(WINDOW, _pq(ALICE));
        require(_release(1, BOB, 1 * U, keccak256("b1")), "first");
        vm.warp(block.timestamp + 1 days - 1);
        require(_release(2, BOB, WINDOW - 1 * U, keccak256("b2")), "drains");
        vm.warp(block.timestamp + 1);
        require(!_release(3, BOB, WINDOW, keccak256("b3")), "a whole new limit one second later");
        vm.warp(block.timestamp + 1 days);
        require(_release(3, BOB, WINDOW, keccak256("b3")), "the largest release fits after a full refill");
    }

    /// Whatever the timing, releases in any span stay within limit * (1 + span / windowSeconds).
    function testFuzzC4_bucketBound(uint32[6] calldata gaps, uint64[6] calldata amounts) public {
        for (uint256 i; i < 6; ++i) {
            _deposit(WINDOW, _pq(ALICE));
        }
        uint256 start = block.timestamp;
        uint256 paid;
        for (uint256 i; i < 6; ++i) {
            vm.warp(block.timestamp + gaps[i] % 2 days);
            uint64 amount = amounts[i] % WINDOW + 1;
            if (_release(uint64(i + 1), BOB, amount, keccak256(abi.encode("fuzz", i)))) {
                paid += amount;
            }
            require(paid <= uint256(WINDOW) + uint256(WINDOW) * (block.timestamp - start) / 1 days, "above the bound");
        }
    }

    /// C5 (fixed): one guardian key could hold the vault paused forever by renewing at each expiry. Behaviour only, so
    /// it also runs on 8678454, where the second pause goes through and this test fails.
    function testC5_singleGuardianCannotRenewAtOnce() public {
        vm.prank(GUARD);
        vault.guardianPause(); // the fast path: one key, no quorum
        require(vault.paused(), "paused");
        vm.warp(block.timestamp + 3 days);
        vm.prank(GUARD);
        (bool renewed,) = address(vault).call(abi.encodeCall(ContextBoundSourceVault.guardianPause, ()));
        require(!renewed, "the same guardian renews at once");
        require(!vault.paused(), "the vault is open");
        vm.warp(block.timestamp + 3 days);
        vm.prank(GUARD);
        vault.guardianPause(); // a new chain after the cooldown
        require(vault.pauseCount() == 2, "second pause");
    }

    /// A second guardian renews at once: the real-incident path. Every guardian used: the cooldown is open.
    function testC5_otherGuardianRenewsThenTheChainEnds() public {
        vm.prank(GUARD);
        vault.guardianPause();
        vm.warp(block.timestamp + 3 days);
        vm.prank(GUARD2);
        vault.guardianPause();
        require(vault.paused(), "renewed by the other guardian");
        vm.warp(block.timestamp + 3 days);
        require(!vault.guardianCanPause(GUARD) && !vault.guardianCanPause(GUARD2), "chain exhausted");
        vm.warp(block.timestamp + 3 days);
        require(vault.guardianCanPause(GUARD) && vault.guardianCanPause(GUARD2), "new chain after the cooldown");
    }

    /// Whatever two guardians do over a year, the vault is open at least a third of the time.
    function testC5_bothGuardiansBoundedOverAYear() public {
        uint256 start = block.timestamp;
        uint256 paused;
        while (block.timestamp < start + 365 days) {
            address who = vault.guardianCanPause(GUARD) ? GUARD : vault.guardianCanPause(GUARD2) ? GUARD2 : address(0);
            if (who != address(0)) {
                vm.prank(who);
                vault.guardianPause();
                paused += 3 days;
                vm.warp(block.timestamp + 3 days);
            } else {
                vm.warp(block.timestamp + 1 hours);
            }
        }
        require(paused * 3 <= (block.timestamp - start) * 2 + 3 days * 3, "more than two thirds frozen");
    }

    /// C6: after the one-way switch the mint committee still mints; a mint backed by nothing, burned, is a valid
    /// release: the verifier proves only that the burn is final. Other users' USDC leaves; guardians cannot pause.
    function testC6_switchLeavesMintTrust() public {
        _deposit(WINDOW, _pq(ALICE));
        AcceptAll lc = new AcceptAll();
        uint256 vu = block.timestamp + 1 hours;
        vault.proposeVerifier(address(lc), 0, vu, _certs(vault.switchDigest(false, address(lc), address(lc).codehash, 0, vu), 3));
        vm.warp(block.timestamp + 14 days);
        vault.activateVerifier();
        vm.prank(GUARD);
        (bool paused,) = address(vault).call(abi.encodeCall(ContextBoundSourceVault.guardianPause, ()));
        require(!paused, "guardians are powerless after the switch");
        bytes32 forged = keccak256("no such deposit");
        require(_mintAll(forged, 999, 1_000 * U, BOB), "the committee still mints after the switch");
        vm.chainId(L2);
        vm.prank(BOB);
        bytes32 burn = busdc.burn(1_000 * U, BOB);
        uint64 nonce = busdc.burnNonce();
        vm.chainId(ETH);
        vault.releaseWithProof(ContextBoundSourceVault.Release(vault.routeId(), nonce, BOB, 1_000 * U, burn), "");
        require(usdc.balanceOf(BOB) == 1_000 * U, "unbacked mint paid with Alice's USDC");
    }

    /// C7 (fixed): a proposal could be activated by anyone years later. Behaviour only, so it also runs on 8678454,
    /// where the late activation succeeds and this test fails.
    function testC7_proposalExpires() public {
        AcceptAll lc = new AcceptAll();
        uint256 vu = block.timestamp + 1 hours;
        vault.proposeVerifier(address(lc), 0, vu, _certs(vault.switchDigest(false, address(lc), address(lc).codehash, 0, vu), 3));
        vm.warp(block.timestamp + 3650 days);
        (bool ok,) = address(vault).call(abi.encodeCall(ContextBoundSourceVault.activateVerifier, ()));
        require(!ok, "activated ten years later by anyone");
        require(vault.verifier() == address(0), "still the committee");
    }

    /// Activation works up to the last second of the window. After it, the quorum may propose again, with a full delay.
    function testC7_windowAndReplacement() public {
        AcceptAll lc = new AcceptAll();
        uint256 vu = block.timestamp + 1 hours;
        vault.proposeVerifier(address(lc), 0, vu, _certs(vault.switchDigest(false, address(lc), address(lc).codehash, 0, vu), 3));
        vu = block.timestamp + 1 hours;
        bytes[] memory twice = _certs(vault.switchDigest(false, address(lc), address(lc).codehash, 1, vu), 3);
        (bool ok,) = address(vault).call(abi.encodeCall(ContextBoundSourceVault.proposeVerifier, (address(lc), 1, vu, twice)));
        require(!ok, "one live proposal at a time");
        uint256 last = uint256(vault.verifierActivatesAt()) + vault.VERIFIER_ACTIVATION_WINDOW();
        vm.warp(last + 1);
        require(!vault.verifierProposalLive(), "expired");
        vu = block.timestamp + 1 hours;
        vault.proposeVerifier(address(lc), 1, vu, _certs(vault.switchDigest(false, address(lc), address(lc).codehash, 1, vu), 3));
        (ok,) = address(vault).call(abi.encodeCall(ContextBoundSourceVault.activateVerifier, ()));
        require(!ok, "a replacement waits the full delay");
        vm.warp(uint256(vault.verifierActivatesAt()) + vault.VERIFIER_ACTIVATION_WINDOW());
        vault.activateVerifier();
        require(vault.verifier() == address(lc), "the last second of the window still activates");
    }

    /// C9: one blacklisted recipient makes its own release revert forever (USDC blacklist); the burn is lost.
    function testC9_blacklistedRecipientBurnIsStuck() public {
        _deposit(100 * U, _pq(ALICE));
        usdc.block_(BOB);
        require(!_release(1, BOB, 20 * U, keccak256("b1")), "reverts in the USDC transfer");
    }
}
