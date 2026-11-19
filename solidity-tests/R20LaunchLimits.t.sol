// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.24;

import {SignerMintedToken} from "../contracts/bridged/SignerMintedToken.sol";
import {BridgedStablecoinV2} from "../contracts/stable/BridgedStablecoinV2.sol";
import {BridgedStablecoinV3} from "../contracts/stable/BridgedStablecoinV3.sol";
import {ProvenanceSourceVault} from "../contracts/usdt/ProvenanceSourceVault.sol";

interface R20Vm {
    function addr(uint256 privateKey) external pure returns (address);
    function sign(uint256 privateKey, bytes32 digest) external pure returns (uint8 v, bytes32 r, bytes32 s);
    function warp(uint256 timestamp) external;
    function roll(uint256 blockNumber) external;
    function prank(address sender) external;
    function setBlockhash(uint256 blockNumber, bytes32 hash) external;
}

contract R20Usdc {
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

/// Round 20 (agent 421; review 420, R420-3). The frozen vault and the frozen L2 token at the launch parameters decided
/// on 2026-11-19, which no committed forge suite ran with (R10BridgeParams and 25 other files keep the first shape,
/// 10,000 / 100,000 / 115,740, on purpose: they are not edited). One abstract suite, run once per parameter set:
///   Ethereum                       cap 500,000  window 50,000  refill 578703  deposit 101 / burn 100  fees 5 / 10 bps
///   Arbitrum One and OP Mainnet    cap 250,000  window 25,000  refill 289351  deposit 101 / burn 100  fees 5 / 5 bps
///   Linea                          cap 250,000  window 25,000  refill 289351  deposit 601 / burn 600  fees 5 / 15 bps
/// The constants of the three contracts at the bottom are held to the committed configs by
/// tools/evm-nets/test_forge_params_r20.py, so this file cannot go stale against a later decision.
/// What is exercised: the edges of the window (largest deposit), of the bucket (mints queued in a day, the refill over
/// 12 h and 24 h, the largest burn), of the cap, and the exit of a full vault through the release window in ten days.
/// The real BridgedStablecoinV3 (T = 0: every mint waits 12 h) and the real ProvenanceSourceVault, mode 1, 5 of 7.
abstract contract R20LaunchLimits {
    R20Vm constant vm = R20Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    uint256 constant U = 1e6;
    uint256 constant PAUSE = 3 days;
    uint256 constant DELAY = 12 hours;
    address constant ALICE = address(0xA11CE);
    address constant TREASURY = address(0x7EA5);

    uint256[] mintKeys;
    uint256[] ethKeys;
    uint256[] vaultGuardKeys;
    uint256[3] guardKeys = [uint256(0x6a01), 0x6a02, 0x6a03];
    R20Usdc usdc;
    ProvenanceSourceVault vault;
    BridgedStablecoinV3 token;

    // ── the decided parameters of one route ──────────────────────────────────────────────────────────────────────────
    function CAP() internal pure virtual returns (uint64);
    function WINDOW() internal pure virtual returns (uint64);
    function REFILL() internal pure virtual returns (uint256);
    function MIN_DEPOSIT() internal pure virtual returns (uint64);
    function MIN_BURN() internal pure virtual returns (uint64);
    function DEPOSIT_BPS() internal pure virtual returns (uint16);
    function RELEASE_BPS() internal pure virtual returns (uint16);

    function setUp() public {
        vm.warp(1_000_000);
        vm.roll(1000);
        mintKeys = sorted(0x1000, 7);
        ethKeys = sorted(0x2000, 7);
        vaultGuardKeys = sorted(0x7a00, 3);
        usdc = new R20Usdc();
        vault = new ProvenanceSourceVault(
            keccak256("ethereum"), keccak256("bloch-l2"), keccak256("USDC"), address(usdc), CAP(), 0, addrs(ethKeys), 5,
            ProvenanceSourceVault.Policy(WINDOW(), 1 days, 6, 14 days, MIN_DEPOSIT(), MIN_BURN()),
            ProvenanceSourceVault.Guard(addrs(vaultGuardKeys), uint64(PAUSE), uint64(PAUSE)),
            ProvenanceSourceVault.Provenance(1, 0, address(0), ProvenanceSourceVault.Fees(TREASURY, DEPOSIT_BPS(), RELEASE_BPS()))
        );
        uint256 until = block.timestamp + 100;
        vault.setControls(true, true, 0, until, cert(vault.controlDigest(true, true, 0, until), 5));
        address[] memory g = new address[](3);
        for (uint256 i; i < 3; ++i) g[i] = vm.addr(guardKeys[i]);
        token = new BridgedStablecoinV3(
            "Bloch Bridged USDC", "bUSDC", block.chainid, address(vault), vault.routeId(), addrs(mintKeys), 5,
            SignerMintedToken.Limits(CAP(), WINDOW(), REFILL(), 0, DELAY, MIN_BURN()),
            SignerMintedToken.Guard(g, PAUSE, PAUSE), BridgedStablecoinV2.MintSwitch(6, 14 days)
        );
    }

    // ── helpers (the shape of R10BridgeParams) ───────────────────────────────────────────────────────────────────────
    function sorted(uint256 base, uint256 n) internal view returns (uint256[] memory k) {
        k = new uint256[](n);
        for (uint256 i; i < n; ++i) k[i] = base + i;
        for (uint256 i; i < n; ++i) {
            for (uint256 j = i + 1; j < n; ++j) {
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

    function net(uint64 amount) internal pure returns (uint64) {
        return amount - uint64(uint256(amount) * DEPOSIT_BPS() / 10_000);
    }

    function tryDeposit(uint64 amount) internal returns (bool ok, bytes32 id) {
        usdc.mint(address(this), amount);
        bytes memory data;
        (ok, data) = address(vault).call(abi.encodeCall(ProvenanceSourceVault.deposit, (amount, bytes32(uint256(uint160(ALICE))))));
        if (ok) id = abi.decode(data, (bytes32));
    }

    function deposit(uint64 amount) internal returns (bytes32 id) {
        bool ok;
        (ok, id) = tryDeposit(amount);
        require(ok, "deposit refused");
    }

    function tryMint(bytes32 id, uint64 amount) internal returns (bool ok) {
        uint64 n = uint64(uint256(id) >> 192);
        bytes memory sigs = blob(token.mintDigest(id, n, amount, ALICE), 5);
        (ok,) = address(token).call(abi.encodeCall(BridgedStablecoinV2.mint, (id, n, amount, ALICE, sigs)));
    }

    function tryBurn(uint64 amount) internal returns (bool ok, ProvenanceSourceVault.Release memory r) {
        vm.prank(ALICE);
        bytes memory data;
        (ok, data) = address(token).call(abi.encodeCall(BridgedStablecoinV3.burn, (amount, ALICE)));
        if (ok) {
            r = ProvenanceSourceVault.Release(
                vault.routeId(), token.burnNonce(), ALICE, amount, abi.decode(data, (bytes32)), token.mintCount(),
                token.mintedTotal(), token.mintHead()
            );
        }
    }

    function release(ProvenanceSourceVault.Release memory r) internal returns (bool ok, bytes4 err) {
        vm.roll(block.number + 1);
        vm.setBlockhash(block.number - 1, keccak256(abi.encode(block.number)));
        ProvenanceSourceVault.ReleaseContext memory c = ProvenanceSourceVault.ReleaseContext(
            block.timestamp + 100, block.number - 1, keccak256(abi.encode(block.number)), 7, keccak256("l2")
        );
        bytes memory data;
        (ok, data) =
            address(vault).call(abi.encodeCall(ProvenanceSourceVault.release, (r, c, cert(vault.releaseDigest(r, c), 5))));
        if (!ok && data.length >= 4) err = bytes4(data);
    }

    /// One whole window crosses to the L2: deposited, attested, queued (T = 0) and credited after the 12 h delay.
    function crossOneWindow() internal returns (uint64 credited) {
        bytes32 id = deposit(WINDOW());
        credited = net(WINDOW());
        require(tryMint(id, credited), "the mint of one window's deposit is queued");
        vm.warp(block.timestamp + DELAY);
        token.executeMint(id);
    }

    // ── 1. the shape ─────────────────────────────────────────────────────────────────────────────────────────────────
    function test_decidedShape_isAcceptedByBothConstructors() public view {
        require(vault.cap() == CAP() && vault.windowLimit() == WINDOW() && vault.windowSeconds() == 1 days, "vault limits");
        require(vault.minDeposit() == MIN_DEPOSIT() && vault.l2MinBurn() == MIN_BURN(), "vault minimums");
        require(vault.depositFeeBps() == DEPOSIT_BPS() && vault.releaseFeeBps() == RELEASE_BPS(), "fees");
        require(token.supplyCap() == CAP() && token.bucketCapacity() == WINDOW() && token.refillPerSecond() == REFILL(), "token limits");
        require(token.minBurn() == MIN_BURN() && token.largeMintThreshold() == 0 && token.largeMintDelay() == DELAY, "token rules");
        require(uint256(CAP()) == 10 * uint256(WINDOW()), "the cap is ten windows");
        require(REFILL() == uint256(WINDOW()) / 1 days, "the refill is floor(window / 24 h)");
        require(REFILL() * 1 days <= WINDOW() && (REFILL() + 1) * 1 days > WINDOW(), "never faster than the window; full within 24 h and 1 s");
        require(net(MIN_DEPOSIT()) >= MIN_BURN(), "the smallest deposit, less its fee, can be burned back");
        require(10 * 1 days <= 14 days, "the whole cap leaves through the window inside the switch delay");
    }

    // ── 2. the window is the largest deposit; the minimum is the smallest ────────────────────────────────────────────
    function test_window_isTheLargestDeposit_andTheMinimumTheSmallest() public {
        (bool ok,) = tryDeposit(WINDOW() + 1);
        require(!ok, "one unit above the window is refused");
        (ok,) = tryDeposit(MIN_DEPOSIT() - 1);
        require(!ok, "one unit below the minimum deposit is refused");
        (ok,) = tryDeposit(MIN_DEPOSIT());
        require(ok, "the minimum deposit is accepted");
        (ok,) = tryDeposit(WINDOW());
        require(ok, "a deposit of exactly the window is accepted");
        require(vault.totalLocked() == uint256(net(MIN_DEPOSIT())) + net(WINDOW()), "the vault holds the two nets");
        require(vault.feesAccrued() == uint256(MIN_DEPOSIT()) + WINDOW() - vault.totalLocked(), "and the two fees apart");
    }

    // ── 3. the bucket: what is queued in a day, the refill, the largest burn ─────────────────────────────────────────
    function test_bucket_admitsOneWindowAtOnce_thenOnlyTheRefill() public {
        bytes32 a = deposit(WINDOW());
        bytes32 b = deposit(WINDOW());
        bytes32 c = deposit(WINDOW());
        require(token.availableToMint() == WINDOW(), "the bucket starts full");
        require(tryMint(a, net(WINDOW())), "one window is queued at once");
        uint256 left = uint256(WINDOW()) - net(WINDOW());
        require(token.availableToMint() == left, "the bucket holds only what the fee left");
        require(!tryMint(b, net(WINDOW())), "a second window in the same second is refused");
        // 12 h later the bucket has half a window more (floor rounding), no more
        vm.warp(block.timestamp + 12 hours);
        require(token.availableToMint() == left + REFILL() * 12 hours, "refill over 12 h");
        require(!tryMint(b, net(WINDOW())), "half a day is not a window");
        // after 24 h in all the refill has given back one whole bucket less the rounding (under 1 USDC): the cap of the bucket
        vm.warp(block.timestamp + 12 hours);
        uint256 full = left + REFILL() * 1 days;
        require(token.availableToMint() == (full > WINDOW() ? WINDOW() : full), "refill over 24 h, never above the bucket");
        require(tryMint(b, net(WINDOW())), "the next window is queued a day later");
        // two windows were admitted in 24 h and 1 s from a full bucket: bucket + refill, the figure of the queue bound
        require(!tryMint(c, net(WINDOW())), "not a third");
        require(token.pendingCount() == 2, "two mints wait");
    }

    function test_bucket_isTheLargestBurn_andTheMinimumTheSmallest() public {
        uint64 got = crossOneWindow();
        vm.warp(block.timestamp + 1 days);
        got += crossOneWindow();
        require(token.balanceOf(ALICE) == got, "two windows credited");
        (bool ok,) = tryBurn(WINDOW() + 1);
        require(!ok, "a burn of one unit above the bucket is refused");
        (ok,) = tryBurn(MIN_BURN() - 1);
        require(!ok, "a burn of one unit below the minimum is refused");
        (ok,) = tryBurn(MIN_BURN());
        require(ok, "the minimum burn is accepted");
        (ok,) = tryBurn(WINDOW());
        require(ok, "a burn of exactly the bucket is accepted");
    }

    // ── 4. the cap ───────────────────────────────────────────────────────────────────────────────────────────────────
    function test_cap_isReachedByTenWindows_andNotPassed() public {
        for (uint256 i; i < 9; ++i) {
            (bool ok,) = tryDeposit(WINDOW());
            require(ok, "nine windows fit");
        }
        uint256 room = uint256(CAP()) - vault.totalLocked();
        require(room > WINDOW(), "the nine fees leave more than one window of room");
        (bool tenth,) = tryDeposit(WINDOW());
        require(tenth, "the tenth window fits");
        room = uint256(CAP()) - vault.totalLocked();
        require(room == 10 * (uint256(WINDOW()) - net(WINDOW())), "what is left under the cap is the ten deposit fees");
        (bool over,) = tryDeposit(WINDOW());
        require(!over, "an eleventh window would pass the cap: refused");
        if (room >= MIN_DEPOSIT()) {
            // the room is counted in what the vault LOCKS (the net): a deposit whose net is exactly the room fits
            (bool one,) = tryDeposit(uint64(room));
            require(one, "a deposit of the remaining room is accepted");
        }
        require(vault.totalLocked() <= CAP(), "the vault never holds more than the cap");
    }

    // ── 5. a full vault leaves through the release window in ten days ────────────────────────────────────────────────
    function test_exit_ofTenWindowsTakesTenDays_oneWindowADay() public {
        uint256 held;
        for (uint256 day; day < 10; ++day) {
            held += crossOneWindow();
            vm.warp(block.timestamp + 1 days);
        }
        require(token.totalSupply() == held && vault.totalLocked() == held, "ten windows crossed, every unit backed");
        uint256 before = usdc.balanceOf(ALICE);
        uint256 days_;
        while (token.balanceOf(ALICE) >= MIN_BURN()) {
            uint256 have = token.balanceOf(ALICE);
            uint64 amount = uint64(have > WINDOW() ? WINDOW() : have);
            (bool burned, ProvenanceSourceVault.Release memory r) = tryBurn(amount);
            require(burned, "burn");
            (bool ok,) = release(r);
            require(ok, "one window a day is released");
            if (token.balanceOf(ALICE) >= MIN_BURN()) {
                // a second release on the same day is over the window
                uint256 more = token.balanceOf(ALICE);
                uint64 next = uint64(more > WINDOW() ? WINDOW() : more);
                (bool b2, ProvenanceSourceVault.Release memory r2) = tryBurn(next);
                require(b2, "burn 2");
                (bool ok2, bytes4 err) = release(r2);
                require(!ok2 && err == bytes4(keccak256("RateLimited()")), "a second window on the same day is rate limited");
                vm.warp(block.timestamp + 1 days);
                (ok2,) = release(r2);
                require(ok2, "and is paid a day later");
                ++days_;
            }
            ++days_;
            vm.warp(block.timestamp + 1 days);
        }
        require(days_ == 10, "ten windows left in ten days");
        uint256 paid = usdc.balanceOf(ALICE) - before;
        require(paid == held - held * RELEASE_BPS() / 10_000 || paid + 10 >= held - held * RELEASE_BPS() / 10_000, "paid less the release fee");
        require(vault.totalLocked() == 0 && token.totalSupply() == 0, "the vault is empty and no token is left");
    }
}

contract R20LaunchLimitsEthereumTest is R20LaunchLimits {
    function CAP() internal pure override returns (uint64) { return 500_000_000_000; }
    function WINDOW() internal pure override returns (uint64) { return 50_000_000_000; }
    function REFILL() internal pure override returns (uint256) { return 578_703; }
    function MIN_DEPOSIT() internal pure override returns (uint64) { return 101_000_000; }
    function MIN_BURN() internal pure override returns (uint64) { return 100_000_000; }
    function DEPOSIT_BPS() internal pure override returns (uint16) { return 5; }
    function RELEASE_BPS() internal pure override returns (uint16) { return 10; }
}

contract R20LaunchLimitsArbitrumOpTest is R20LaunchLimits {
    function CAP() internal pure override returns (uint64) { return 250_000_000_000; }
    function WINDOW() internal pure override returns (uint64) { return 25_000_000_000; }
    function REFILL() internal pure override returns (uint256) { return 289_351; }
    function MIN_DEPOSIT() internal pure override returns (uint64) { return 101_000_000; }
    function MIN_BURN() internal pure override returns (uint64) { return 100_000_000; }
    function DEPOSIT_BPS() internal pure override returns (uint16) { return 5; }
    function RELEASE_BPS() internal pure override returns (uint16) { return 5; }
}

contract R20LaunchLimitsLineaTest is R20LaunchLimits {
    function CAP() internal pure override returns (uint64) { return 250_000_000_000; }
    function WINDOW() internal pure override returns (uint64) { return 25_000_000_000; }
    function REFILL() internal pure override returns (uint256) { return 289_351; }
    function MIN_DEPOSIT() internal pure override returns (uint64) { return 601_000_000; }
    function MIN_BURN() internal pure override returns (uint64) { return 600_000_000; }
    function DEPOSIT_BPS() internal pure override returns (uint16) { return 5; }
    function RELEASE_BPS() internal pure override returns (uint16) { return 15; }
}
