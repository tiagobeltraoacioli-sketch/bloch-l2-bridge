// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.24;

import {SignerMintedToken} from "../contracts/bridged/SignerMintedToken.sol";
import {WrappedGnBV2} from "../contracts/wgnb/WrappedGnBV2.sol";
import {BridgedStablecoinV2} from "../contracts/stable/BridgedStablecoinV2.sol";
import {ContextBoundSourceVault} from "../contracts/usdt/ContextBoundSourceVault.sol";

interface Vm {
    function addr(uint256 privateKey) external pure returns (address);
    function sign(uint256 privateKey, bytes32 digest) external pure returns (uint8 v, bytes32 r, bytes32 s);
    function warp(uint256 timestamp) external;
    function roll(uint256 blockNumber) external;
    function chainId(uint256 newChainId) external;
    function prank(address sender) external;
    function expectRevert(bytes calldata data) external;
}

contract MockStable6 {
    uint8 public constant decimals = 6;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mintTo(address to, uint256 v) external { balanceOf[to] += v; }
    function approve(address s, uint256 v) external returns (bool) { allowance[msg.sender][s] = v; return true; }
    function transfer(address to, uint256 v) external returns (bool) { balanceOf[msg.sender] -= v; balanceOf[to] += v; return true; }
    function transferFrom(address f, address to, uint256 v) external returns (bool) {
        allowance[f][msg.sender] -= v; balanceOf[f] -= v; balanceOf[to] += v; return true;
    }
}

contract BridgeV11Test {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    uint32 private constant GNB = 0x474E0002;
    uint256 private constant L2 = 700771;
    uint256 private constant CAP = 1_000e8; // bucket capacity
    uint256 private constant REFILL = CAP / 1 days; // full refill in 24 h
    uint256 private constant SUPPLY = 10_000e8;
    uint256 private constant LARGE = 100e8; // > 10% of capacity is delayed
    uint256 private constant DELAY = 12 hours;
    uint256 private constant PAUSE = 72 hours;
    uint256 private constant COOLDOWN = 72 hours;

    WrappedGnBV2 private w;
    uint256[3] private keys;
    address private guardian = address(0x6A2D);
    address private alice = address(0xA11CE);
    address private bob = address(0xB0B);

    function setUp() public {
        vm.chainId(L2);
        vm.warp(1_760_000_000);
        uint256[3] memory k = [uint256(0x71), 0x72, 0x73];
        for (uint256 i = 1; i < 3; ++i) {
            for (uint256 j = i; j > 0 && vm.addr(k[j]) < vm.addr(k[j - 1]); --j) (k[j], k[j - 1]) = (k[j - 1], k[j]);
        }
        keys = k;
        w = new WrappedGnBV2(GNB, _signers(), 2, _limits(), _guard());
    }

    // ── helpers ──────────────────────────────────────────────────────────────
    function _signers() private view returns (address[] memory a) {
        a = new address[](3);
        for (uint256 i; i < 3; ++i) a[i] = vm.addr(keys[i]);
    }

    function _limits() private pure returns (SignerMintedToken.Limits memory) {
        return SignerMintedToken.Limits({supplyCap: SUPPLY, bucketCapacity: CAP, refillPerSecond: REFILL,
            largeMintThreshold: LARGE, largeMintDelay: DELAY, minBurn: 100_000});
    }

    function _guard() private view returns (SignerMintedToken.Guard memory g) {
        g.guardians = new address[](1);
        g.guardians[0] = guardian;
        g.pauseDuration = PAUSE;
        g.pauseCooldown = COOLDOWN;
    }

    function _sig(uint256 key, bytes32 d) private pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, d);
        return abi.encodePacked(r, s, v);
    }

    function _two(bytes32 d) private view returns (bytes memory) {
        return bytes.concat(_sig(keys[0], d), _sig(keys[1], d));
    }

    function _mint(bytes32 txid, uint64 amt) private {
        w.mint(txid, 0, amt, alice, _two(w.mintDigest(txid, 0, amt, alice)));
    }

    function _eq(uint256 a, uint256 b, string memory what) private pure { require(a == b, what); }

    function _deployExpectBad(SignerMintedToken.Limits memory l, SignerMintedToken.Guard memory g, address[] memory s) private {
        vm.expectRevert(abi.encodeWithSelector(SignerMintedToken.BadConfig.selector));
        new WrappedGnBV2(GNB, s, 2, l, g);
    }

    // ── config ───────────────────────────────────────────────────────────────
    function testConstructorRejectsBadConfig() public {
        address[] memory s = _signers();
        SignerMintedToken.Limits memory l = _limits();
        l.bucketCapacity = SUPPLY + 1;
        _deployExpectBad(l, _guard(), s);
        l = _limits(); l.refillPerSecond = 0;
        _deployExpectBad(l, _guard(), s);
        l = _limits(); l.refillPerSecond = CAP + 1;
        _deployExpectBad(l, _guard(), s);
        l = _limits(); l.largeMintDelay = 0;
        _deployExpectBad(l, _guard(), s);
        l = _limits(); l.largeMintDelay = 31 days;
        _deployExpectBad(l, _guard(), s);
        SignerMintedToken.Guard memory g = _guard();
        g.guardians[0] = s[0]; // a signer cannot be a guardian
        _deployExpectBad(_limits(), g, s);
        g = _guard(); g.pauseDuration = 0;
        _deployExpectBad(_limits(), g, s);
        g = _guard(); g.pauseDuration = 15 days; g.pauseCooldown = 15 days;
        _deployExpectBad(_limits(), g, s);
        g = _guard(); g.pauseCooldown = PAUSE - 1;
        _deployExpectBad(_limits(), g, s);
        address[] memory eight = new address[](8);
        for (uint256 i; i < 8; ++i) eight[i] = address(uint160(0x1000 + i));
        _deployExpectBad(_limits(), _guard(), eight); // GnB-SMH policy limit is 7
        // no delay at all is expressed as threshold = max (delay may then be zero)
        l = _limits(); l.largeMintThreshold = type(uint256).max; l.largeMintDelay = 0;
        new WrappedGnBV2(GNB, s, 2, l, _guard());
        // no guardians at all is allowed (no pause)
        SignerMintedToken.Guard memory none;
        new WrappedGnBV2(GNB, s, 2, _limits(), none);
    }

    // ── GSMH mainnet pilot (wGSMH on devnet4, 2026-10-16) ──────────────────────
    function testGsmhMainnetPilotConfig() public {
        SignerMintedToken.Limits memory l = SignerMintedToken.Limits({supplyCap: 30e8, bucketCapacity: 10e8,
            refillPerSecond: uint256(10e8) / 1 days, largeMintThreshold: 5e8, largeMintDelay: 1 hours, minBurn: 100_000});
        SignerMintedToken.Guard memory none;
        WrappedGnBV2 p = new WrappedGnBV2(0x474E0001, _signers(), 2, l, none);
        require(keccak256(bytes(p.symbol())) == keccak256("wGSMH"), "symbol");
        require(keccak256(bytes(p.name())) == keccak256("Wrapped GnB-SMH"), "name");
        _eq(p.decimals(), 8, "decimals");
        _eq(p.gnbChainId(), 0x474E0001, "GnB-SMH mainnet");
        _eq(p.bucketCapacity(), 10e8, "bucket = 10 GSMH, so the DEX cap is bucket/10 = 1 wGSMH");
        _eq(p.availableToMint(), 10e8, "starts full");
        bytes32 t = keccak256("pilot-lock");
        p.mint(t, 0, 3e8, alice, _two(p.mintDigest(t, 0, 3e8, alice)));
        _eq(p.balanceOf(alice), 3e8, "3 wGSMH minted at once (below the large-mint threshold)");
        _eq(p.availableToMint(), 7e8, "bucket debited");
        vm.warp(block.timestamp + 1 days);
        _eq(p.availableToMint(), 10e8, "refilled in 24 h");
    }

    // ── token bucket ─────────────────────────────────────────────────────────
    function testBucketHasNoWindowBoundary() public {
        _eq(w.availableToMint(), CAP, "starts full");
        for (uint256 i; i < 10; ++i) _mint(keccak256(abi.encode("b", i)), uint64(LARGE)); // 10 x 100 = capacity
        _eq(w.availableToMint(), 0, "empty");
        bytes32 t = keccak256("next");
        bytes memory sigs = _two(w.mintDigest(t, 0, 1e8, alice));
        vm.expectRevert(abi.encodeWithSelector(SignerMintedToken.RateLimited.selector));
        w.mint(t, 0, 1e8, alice, sigs);
        // one second later only one second of refill is available: no calendar reset
        vm.warp(block.timestamp + 1);
        _eq(w.availableToMint(), REFILL, "one second of refill");
        vm.warp(block.timestamp + 6 hours - 1);
        _eq(w.availableToMint(), REFILL * 6 hours, "six hours of refill");
        w.mint(t, 0, 1e8, alice, sigs);
        vm.warp(block.timestamp + 10 days);
        _eq(w.availableToMint(), CAP, "refill stops at capacity");
    }

    function testSupplyCapCountsQueuedMints() public {
        SignerMintedToken.Limits memory l = _limits();
        l.supplyCap = 150e8;
        l.bucketCapacity = 150e8; // the bucket may not exceed the supply cap
        l.refillPerSecond = uint256(150e8) / 1 days;
        WrappedGnBV2 small = new WrappedGnBV2(GNB, _signers(), 2, l, _guard());
        bytes32 a = keccak256("a");
        small.mint(a, 0, 120e8, alice, _two(small.mintDigest(a, 0, 120e8, alice))); // queued (large)
        _eq(small.pendingSupply(), 120e8, "pending");
        vm.warp(block.timestamp + 1 days); // bucket full again; the queued 120 still count against the cap
        bytes32 b = keccak256("b");
        bytes memory sigs = _two(small.mintDigest(b, 0, 31e8, alice));
        vm.expectRevert(abi.encodeWithSelector(SignerMintedToken.SupplyCapExceeded.selector));
        small.mint(b, 0, 31e8, alice, sigs);
        small.mint(b, 0, 30e8, alice, _two(small.mintDigest(b, 0, 30e8, alice)));
        _eq(small.totalSupply() + small.pendingSupply(), 150e8, "at the cap");
    }

    // ── large-mint delay ─────────────────────────────────────────────────────
    function testLargeMintIsQueuedThenExecutable() public {
        bytes32 t = keccak256("large");
        bytes memory sigs = _two(w.mintDigest(t, 0, uint64(LARGE + 1), alice));
        w.mint(t, 0, uint64(LARGE + 1), alice, sigs);
        bytes32 id = w.lockId(t, 0);
        _eq(w.balanceOf(alice), 0, "not credited yet");
        _eq(w.pendingSupply(), LARGE + 1, "pending");
        require(w.minted(id), "replay key used at queue time");
        vm.expectRevert(abi.encodeWithSelector(SignerMintedToken.AlreadyMinted.selector));
        w.mint(t, 0, uint64(LARGE + 1), alice, sigs);
        vm.expectRevert(abi.encodeWithSelector(SignerMintedToken.NotReady.selector));
        w.executeMint(id);
        vm.warp(block.timestamp + DELAY);
        vm.prank(bob); // anyone may execute
        w.executeMint(id);
        _eq(w.balanceOf(alice), LARGE + 1, "credited");
        _eq(w.pendingSupply(), 0, "pending cleared");
        vm.expectRevert(abi.encodeWithSelector(SignerMintedToken.NotPending.selector));
        w.executeMint(id);
        // at the threshold: immediate
        _mint(keccak256("exact"), uint64(LARGE));
        _eq(w.balanceOf(alice), 2 * LARGE + 1, "threshold amount is immediate");
    }

    // ── pause ────────────────────────────────────────────────────────────────
    function testOnlyGuardiansPauseAndPauseExpires() public {
        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(SignerMintedToken.NotGuardian.selector));
        w.pause();
        vm.prank(vm.addr(keys[0])); // a signer is not a guardian
        vm.expectRevert(abi.encodeWithSelector(SignerMintedToken.NotGuardian.selector));
        w.pause();
        _mint(keccak256("before"), 5e8);
        vm.prank(guardian);
        w.pause();
        require(w.paused(), "paused");
        bytes32 t = keccak256("during");
        bytes memory sigs = _two(w.mintDigest(t, 0, 1e8, alice));
        vm.expectRevert(abi.encodeWithSelector(SignerMintedToken.IsPaused.selector));
        w.mint(t, 0, 1e8, alice, sigs);
        // burns and transfers keep working: holders can always exit
        vm.prank(alice);
        w.burn(1e8, abi.encodePacked(bytes20(uint160(7))));
        vm.prank(alice);
        w.transfer(bob, 1e8);
        // expires by itself
        vm.warp(block.timestamp + PAUSE);
        require(!w.paused(), "expired");
        w.mint(t, 0, 1e8, alice, sigs);
    }

    function testPauseCooldownLimitsAMaliciousGuardian() public {
        vm.prank(guardian);
        w.pause();
        vm.warp(block.timestamp + PAUSE);
        vm.prank(guardian);
        vm.expectRevert(abi.encodeWithSelector(SignerMintedToken.PauseCooldown.selector));
        w.pause();
        vm.warp(block.timestamp + COOLDOWN - 1);
        vm.prank(guardian);
        vm.expectRevert(abi.encodeWithSelector(SignerMintedToken.PauseCooldown.selector));
        w.pause();
        vm.warp(block.timestamp + 1);
        vm.prank(guardian);
        w.pause();
        _eq(w.pauseCount(), 2, "second pause after the cooldown");
    }

    function testSignersEndAPauseEarlyAndCannotReplayIt() public {
        vm.prank(guardian);
        w.pause();
        bytes32 d = w.unpauseDigest();
        vm.expectRevert(abi.encodeWithSelector(SignerMintedToken.BadSignatureCount.selector));
        w.unpause(_sig(keys[0], d)); // one signature is not enough
        bytes memory sigs = _two(d);
        w.unpause(sigs);
        require(!w.paused(), "unpaused");
        _mint(keccak256("after"), 1e8);
        vm.expectRevert(abi.encodeWithSelector(SignerMintedToken.NotPaused.selector));
        w.unpause(sigs);
        // the next pause (after the cooldown) needs new signatures: pauseCount is in the digest
        vm.warp(block.timestamp + COOLDOWN);
        vm.prank(guardian);
        w.pause();
        vm.expectRevert(abi.encodeWithSelector(SignerMintedToken.NotSigner.selector));
        w.unpause(sigs);
    }

    function testQueuedMintWaitsWhilePaused() public {
        bytes32 t = keccak256("q");
        w.mint(t, 0, uint64(LARGE + 1), alice, _two(w.mintDigest(t, 0, uint64(LARGE + 1), alice)));
        vm.prank(guardian);
        w.pause();
        vm.warp(block.timestamp + DELAY);
        bytes32 id = w.lockId(t, 0);
        vm.expectRevert(abi.encodeWithSelector(SignerMintedToken.IsPaused.selector));
        w.executeMint(id);
        vm.warp(block.timestamp + PAUSE);
        w.executeMint(id);
        _eq(w.balanceOf(alice), LARGE + 1, "executed after the pause");
    }

    // ── versions and messages ────────────────────────────────────────────────
    function testV1SignaturesDoNotWorkOnV2() public {
        bytes32 t = keccak256("v1");
        bytes32 domainV1 = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256("Bloch wGnB"), keccak256("1"), L2, address(w)));
        bytes32 st = keccak256(abi.encode(w.MINT_TYPEHASH(), GNB, t, uint32(0), uint64(1e8), alice));
        bytes32 v1 = keccak256(abi.encodePacked("\x19\x01", domainV1, st));
        require(v1 != w.mintDigest(t, 0, 1e8, alice), "domains differ");
        vm.expectRevert(abi.encodeWithSelector(SignerMintedToken.NotSigner.selector));
        w.mint(t, 0, 1e8, alice, _two(v1));
    }

    function testBurnEmitsTheV1Fields() public {
        _mint(keccak256("m"), 3e8);
        vm.prank(alice);
        bytes32 id = w.burn(2e8, abi.encodePacked(bytes20(uint160(9))));
        require(id == keccak256(abi.encode(L2, address(w), uint64(1))), "burnId");
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(WrappedGnBV2.BadScriptPubKey.selector));
        w.burn(1e8, new bytes(21));
    }

    // ── stablecoin v2 against the real vault ─────────────────────────────────
    function testStablecoinV2RoundTripWithVault() public {
        vm.chainId(11155111);
        MockStable6 usdc = new MockStable6();
        ContextBoundSourceVault vault = new ContextBoundSourceVault(
            bytes32("ETHEREUM-SEPOLIA"), bytes32("BLOCH-L2-700771"), bytes32("USDC"), address(usdc), 1_000_000e6, 0,
            _signers(), 2, ContextBoundSourceVault.Policy(50_000e6, 1 days, 2, 7 days, 1, 1), ContextBoundSourceVault.Guard(new address[](0), 0, 0));
        uint256 validUntil = block.timestamp + 1 hours;
        bytes[] memory cs = new bytes[](2);
        bytes32 cd = vault.controlDigest(true, true, 0, validUntil);
        cs[0] = _sig(keys[0], cd);
        cs[1] = _sig(keys[1], cd);
        vault.setControls(true, true, 0, validUntil, cs);
        usdc.mintTo(alice, 20e6);
        vm.prank(alice);
        usdc.approve(address(vault), 20e6);
        vm.prank(alice);
        bytes32 dep = vault.deposit(20e6, bytes32(uint256(uint160(alice))));

        vm.chainId(L2);
        SignerMintedToken.Limits memory l = SignerMintedToken.Limits({supplyCap: 100_000e6, bucketCapacity: 10_000e6,
            refillPerSecond: uint256(10_000e6) / 1 days, largeMintThreshold: 1_000e6, largeMintDelay: DELAY, minBurn: 1e6});
        BridgedStablecoinV2 s = new BridgedStablecoinV2("Bloch Bridged USDC", "bUSDC", 11155111, address(vault),
            vault.routeId(), _signers(), 2, l, _guard(), BridgedStablecoinV2.MintSwitch(2, 14 days));
        bytes32 md = s.mintDigest(dep, 0, 20e6, alice);
        s.mint(dep, 0, 20e6, alice, bytes.concat(_sig(keys[0], md), _sig(keys[2], md)));
        _eq(s.balanceOf(alice), 20e6, "minted");
        vm.prank(alice);
        bytes32 burnId = s.burn(8e6, bob);

        vm.chainId(11155111);
        vm.roll(block.number + 10);
        ContextBoundSourceVault.Release memory rel = ContextBoundSourceVault.Release({
            route: vault.routeId(), nonce: s.burnNonce(), recipient: bob, amount: 8e6, nativeBurn: burnId});
        ContextBoundSourceVault.ReleaseContext memory ctx = ContextBoundSourceVault.ReleaseContext({
            validUntil: block.timestamp + 1 hours, sourceAnchorNumber: block.number - 1,
            sourceAnchorHash: blockhash(block.number - 1), nativeFinalizedNumber: 300,
            nativeFinalizedHash: keccak256("l2-300")});
        bytes32 rd = vault.releaseDigest(rel, ctx);
        bytes[] memory rs = new bytes[](2);
        rs[0] = _sig(keys[1], rd);
        rs[1] = _sig(keys[2], rd);
        vault.release(rel, ctx, rs);
        _eq(usdc.balanceOf(bob), 8e6, "paid on the source chain");
        _eq(vault.totalLocked(), s.totalSupply(), "locked == L2 supply");
    }
}
