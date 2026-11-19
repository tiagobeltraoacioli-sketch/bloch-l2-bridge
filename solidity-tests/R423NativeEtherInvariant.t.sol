// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity 0.8.24;

// Reviewer 423 (round 20): an independent invariant campaign over NativeEtherSourceVault at 17e4231, with its own
// ledger (nothing of the developer's ghost ledger or checkBooks is used; only the signing helpers of the base).
import {NativeEtherSourceVault} from "../contracts/eth/NativeEtherSourceVault.sol";
import {ProvenanceSourceVault} from "../contracts/usdt/ProvenanceSourceVault.sol";
import {NativeEtherVaultBase} from "./NativeEtherVaultBase.sol";

/// A recipient with switchable behaviour that also tries to re-enter with every call it can make, forwarding ether
/// it holds back into the vault as a deposit, and keeping a valid certified release to try from inside.
contract R423Hostile {
    NativeEtherSourceVault public immutable vault;
    uint8 public mode; // 0 accept, 1 revert, 2 burn gas, 3 accept and re-enter, 4 accept only with more than 40k gas
    bytes public stash;
    uint256 public reentrySuccesses;
    uint256 public received;

    constructor(NativeEtherSourceVault v) {
        vault = v;
    }

    function set(uint8 m) external {
        mode = m;
    }

    function keep(bytes calldata releaseCall) external {
        stash = releaseCall;
    }

    function pull(address to) external returns (uint64) {
        return vault.claimTo(to);
    }

    function _try(bytes memory data, uint256 value) private {
        (bool ok,) = address(vault).call{value: value}(data);
        if (ok) ++reentrySuccesses;
    }

    receive() external payable {
        if (mode == 1) revert("no");
        if (mode == 2) {
            while (true) {}
        }
        if (mode == 4) require(gasleft() > 40_000, "hungry");
        if (mode == 3) {
            if (stash.length != 0) _try(stash, 0);
            _try(abi.encodeCall(NativeEtherSourceVault.deposit, (20_000, bytes32(uint256(uint160(address(this)))))), 20_000 * 1e12);
            _try(abi.encodeCall(NativeEtherSourceVault.claimFor, (address(this))), 0);
            _try(abi.encodeCall(NativeEtherSourceVault.claimTo, (address(this))), 0);
            _try(abi.encodeCall(NativeEtherSourceVault.sweepFees, ()), 0);
        }
        received += msg.value;
    }
}

contract R423Bomb {
    constructor(address payable to) payable {
        selfdestruct(to);
    }
}

contract R423Handler is NativeEtherVaultBase {
    R423Hostile[4] public hostile;
    address[] public recips;
    // independent ledger (units unless stated)
    uint256 public depositedWei;
    uint256 public forcedWeiIn;
    uint256 public netSum;
    uint256 public certifiedBurns;
    uint256 public certifiedPaid;
    uint256 public feeSum;
    uint256 public uncertifiedSuccesses;
    uint256 public maxCount;
    mapping(uint64 => bytes32) public headSeen;
    mapping(address => uint256) public entitled; // units a recipient was certified to be paid
    uint256[] public relTime;
    uint256[] public relAmount;
    uint256 public nRelease;
    uint256 public nDeferred;
    uint256 public nClaim;
    uint256 public nDeposit;
    address public treasury = TREASURY;
    NativeEtherSourceVault.Release[] internal spent;

    constructor() {
        baseSetUp();
        for (uint256 i; i < 4; ++i) {
            hostile[i] = new R423Hostile(vault);
            hostile[i].set(uint8(i == 0 ? 3 : i));
            recips.push(address(hostile[i]));
        }
        recips.push(address(0xE0A1));
        recips.push(address(0xE0A2));
        recips.push(address(9)); // a failing precompile
    }

    function theVault() external view returns (NativeEtherSourceVault) {
        return vault;
    }

    function nRecips() external view returns (uint256) {
        return recips.length;
    }

    function stepDeposit(uint256 seed, uint64 amount) external {
        amount = uint64(MIN_DEPOSIT + amount % (BUCKET - MIN_DEPOSIT + 1));
        if (seed % 11 == 0) amount = uint64(amount % MIN_DEPOSIT); // below the minimum
        address who = address(uint160(0xD000 + seed % 5));
        uint256 value = uint256(amount) * UNIT;
        if (seed % 7 == 0) value += 1 + seed % (UNIT - 1); // dust above
        if (seed % 13 == 0 && value > 0) value -= 1; // one wei short
        vm.deal(who, value);
        uint64 lockedBefore = vault.totalLocked();
        vm.prank(who);
        (bool ok,) = address(vault).call{value: value}(abi.encodeCall(NativeEtherSourceVault.deposit, (amount, pad(who))));
        if (ok) {
            require(value == uint256(amount) * UNIT, "R423: a deposit with a value that is not amount x UNIT was taken");
            depositedWei += value;
            uint256 net = vault.totalLocked() - lockedBefore;
            netSum += net;
            feeSum += amount - net;
            require(uint256(amount) * 5 <= (amount - net) * 10_000, "R423: deposit fee below the exact rate");
            uint64 c = vault.depositCount();
            headSeen[c] = vault.depositHead(c);
            ++nDeposit;
        } else {
            vm.deal(who, 0);
        }
    }

    function _item(address to, uint64 amount) internal returns (NativeEtherSourceVault.Release memory r) {
        uint64 count = vault.depositCount();
        r = cleanBurn(to, amount, count);
    }

    function stepRelease(uint256 seed, uint64 amount, uint256 gasSeed) external {
        if (vault.depositCount() == 0) return;
        address to = recips[seed % recips.length];
        uint64 locked = vault.totalLocked();
        if (locked < MIN_BURN) return;
        amount = uint64(MIN_BURN + amount % (locked - MIN_BURN + 1));
        NativeEtherSourceVault.Release memory r = _item(to, amount);
        NativeEtherSourceVault.ReleaseContext memory c = context();
        bytes[] memory s = cert(vault.releaseDigest(r, c), 5 + seed % 3);
        if (seed % 5 == 0) hostile[0].keep(abi.encodeCall(NativeEtherSourceVault.release, (r, c, s)));
        uint256 balBefore = to.balance;
        uint64 claimBefore = vault.claimable(to);
        uint256 gasLimit = gasSeed % 3 == 0 ? 60_000 + gasSeed % 300_000 : 2_000_000;
        (bool ok,) = address(vault).call{gas: gasLimit}(abi.encodeCall(NativeEtherSourceVault.release, (r, c, s)));
        if (!ok) return;
        uint256 fee = (uint256(amount) * 10 + 9_999) / 10_000;
        uint256 paid = amount - fee;
        certifiedBurns += amount;
        certifiedPaid += paid;
        feeSum += fee;
        entitled[to] += paid;
        relTime.push(block.timestamp);
        relAmount.push(amount);
        spent.push(r);
        ++nRelease;
        uint256 pushed = to.balance - balBefore;
        uint256 deferred = vault.claimable(to) - claimBefore;
        require(pushed + deferred * UNIT == paid * UNIT, "R423: a release neither paid nor deferred exactly");
        require(pushed == 0 || deferred == 0, "R423: a release both paid and deferred");
        if (deferred != 0) ++nDeferred;
    }

    /// Everything that is not a fresh certified burn must fail: replay, 4 signatures, changed amount or recipient,
    /// a foreign chain state, a certificate made for the frozen USDC-style vault of the same committee.
    function stepUncertified(uint256 seed) external {
        if (vault.depositCount() == 0 || vault.totalLocked() < 2 * MIN_BURN) return;
        NativeEtherSourceVault.ReleaseContext memory c = context();
        NativeEtherSourceVault.Release memory r;
        bytes[] memory s;
        uint256 kind = seed % 6;
        if (kind == 0 && spent.length != 0) {
            r = spent[seed % spent.length];
            s = cert(vault.releaseDigest(r, c), 5);
        } else if (kind == 1) {
            r = _item(MALLORY, MIN_BURN);
            s = cert(vault.releaseDigest(r, c), 4);
        } else if (kind == 2) {
            r = _item(MALLORY, MIN_BURN);
            s = cert(vault.releaseDigest(r, c), 5);
            r.amount += 1;
        } else if (kind == 3) {
            r = _item(BOB, MIN_BURN);
            s = cert(vault.releaseDigest(r, c), 5);
            r.recipient = MALLORY;
        } else if (kind == 4) {
            r = _item(MALLORY, MIN_BURN);
            r.mintHead = keccak256(abi.encode(r.mintHead));
            s = cert(vault.releaseDigest(r, c), 5);
        } else {
            r = _item(MALLORY, MIN_BURN);
            r.route = keccak256("another vault of the same committee");
            s = cert(vault.releaseDigest(r, c), 5);
        }
        (bool ok,) = address(vault).call(abi.encodeCall(NativeEtherSourceVault.release, (r, c, s)));
        if (ok) ++uncertifiedSuccesses;
    }

    function stepClaim(uint256 seed) external {
        address r = recips[seed % recips.length];
        uint64 owed = vault.claimable(r);
        if (seed % 4 == 0 && seed % recips.length < 4) {
            R423Hostile h = hostile[seed % recips.length];
            address to = address(uint160(0xC1A1 + seed % 3));
            uint256 b = to.balance;
            try h.pull(to) returns (uint64 got) {
                require(got == owed && to.balance - b == uint256(got) * UNIT, "R423: redirected claim not exact");
                entitled[to] += got;
                entitled[r] -= got;
                ++nClaim;
            } catch {}
            return;
        }
        uint256 before = r.balance;
        vm.prank(MALLORY);
        try vault.claimFor(r) returns (uint64 got) {
            require(got == owed && r.balance - before == uint256(got) * UNIT, "R423: claim not exact");
            ++nClaim;
        } catch {}
    }

    function stepMode(uint256 seed) external {
        hostile[seed % 4].set(uint8(seed / 4 % 5));
    }

    function stepSweep() external {
        vm.prank(MALLORY);
        try vault.sweepFees() {} catch {}
    }

    function stepForce(uint256 seed) external {
        uint256 v = 1 + seed % 3 ether;
        if (seed % 2 == 0) {
            vm.deal(address(this), v);
            new R423Bomb{value: v}(payable(address(vault)));
        } else {
            vm.deal(address(vault), address(vault).balance + v);
        }
        forcedWeiIn += v;
    }

    function stepPlain(uint256 seed) external {
        vm.deal(MALLORY, 1 ether);
        vm.prank(MALLORY);
        (bool ok,) = address(vault).call{value: 1 + seed % 1 ether}(seed % 2 == 0 ? bytes("") : abi.encodePacked(bytes4(uint32(seed))));
        if (ok) ++uncertifiedSuccesses;
        vm.deal(MALLORY, 0);
    }

    function stepPause(uint256 seed) external {
        vm.prank(vm.addr(guardKeys[seed % 3]));
        try vault.guardianPause() {} catch {}
    }

    function stepUnpause(uint256 seed) external {
        uint64 n = vault.pauseCount();
        uint256 until = block.timestamp + 100;
        try vault.unpause(n, until, cert(vault.unpauseDigest(n, until), 5 + seed % 2)) {} catch {}
    }

    function stepWarp(uint256 seed) external {
        vm.warp(block.timestamp + 1 + seed % 30_000);
    }

    function check() external {
        NativeEtherSourceVault v = vault;
        // books
        require(v.totalLocked() == netSum - certifiedBurns, "R423 I1: totalLocked != net deposits - certified burns (L2 supply model)");
        require(v.totalLocked() <= v.cap(), "R423: cap");
        uint256 sumClaims;
        uint256 heldByRecipients;
        for (uint256 i; i < recips.length; ++i) {
            sumClaims += v.claimable(recips[i]);
            heldByRecipients += recips[i].balance;
            if (i < 4) {
                // a hostile recipient may have re-deposited? no: every re-entry must have failed
                require(hostile[i].reentrySuccesses() == 0, "R423: a re-entrant call succeeded");
            }
            require(recips[i].balance + uint256(v.claimable(recips[i])) * UNIT == entitled[recips[i]] * UNIT + (recips[i] == address(9) ? 0 : 0),
                "R423 I8: a recipient holds or is owed something other than its certified payouts");
        }
        for (uint160 a = 0xC1A1; a < 0xC1A4; ++a) {
            require(address(a).balance == entitled[address(a)] * UNIT, "R423: redirect target");
            heldByRecipients += address(a).balance;
        }
        require(sumClaims == v.totalClaimable(), "R423 I3: sum of claimable != totalClaimable");
        require(heldByRecipients + sumClaims * UNIT == certifiedPaid * UNIT, "R423: ether out != certified payouts");
        require(treasury.balance + uint256(v.feesAccrued()) * UNIT == feeSum * UNIT, "R423 I2: fees");
        // conservation, to the wei
        require(address(v).balance == depositedWei + forcedWeiIn - heldByRecipients - treasury.balance, "R423: conservation");
        require(address(v).balance == v.owedWei() + forcedWeiIn, "R423 I4: balance != owed + forced");
        require(v.surplusWei() == forcedWeiIn, "R423: surplus");
        require(uncertifiedSuccesses == 0, "R423: ether moved or state changed without a certified burn");
        require(MALLORY.balance == 0, "R423: the stranger holds ether");
        // chain
        uint64 c = v.depositCount();
        require(c >= maxCount, "R423 I7: count fell");
        maxCount = c;
        for (uint64 i = 1; i <= c; ++i) {
            require(v.depositHead(i) == headSeen[i] && headSeen[i] != 0, "R423 I7: a chain head changed");
        }
        // window over every pair of releases
        uint256 n = relTime.length;
        uint256 lim = v.windowLimit();
        for (uint256 i = n > 40 ? n - 40 : 0; i < n; ++i) {
            uint256 sum;
            for (uint256 j = i; j < n; ++j) {
                sum += relAmount[j];
                uint256 t = relTime[j] - relTime[i];
                require(sum * 86_400 <= lim * (86_400 + t) + 86_400, "R423 I6: window");
            }
        }
    }
}

contract R423NativeEtherInvariantTest {
    R423Handler public h;

    struct FuzzSelector {
        address addr;
        bytes4[] selectors;
    }

    event log_named_uint(string key, uint256 val);

    function setUp() public {
        h = new R423Handler();
    }

    function targetSelectors() public view returns (FuzzSelector[] memory out) {
        bytes4[] memory sel = new bytes4[](14);
        sel[0] = R423Handler.stepDeposit.selector;
        sel[1] = R423Handler.stepRelease.selector;
        sel[2] = R423Handler.stepUncertified.selector;
        sel[3] = R423Handler.stepClaim.selector;
        sel[4] = R423Handler.stepMode.selector;
        sel[5] = R423Handler.stepSweep.selector;
        sel[6] = R423Handler.stepForce.selector;
        sel[7] = R423Handler.stepPlain.selector;
        sel[8] = R423Handler.stepPause.selector;
        sel[9] = R423Handler.stepUnpause.selector;
        sel[10] = R423Handler.stepWarp.selector;
        sel[11] = R423Handler.stepDeposit.selector;
        sel[12] = R423Handler.stepRelease.selector;
        sel[13] = R423Handler.stepRelease.selector;
        out = new FuzzSelector[](1);
        out[0] = FuzzSelector(address(h), sel);
    }

    function targetContracts() public view returns (address[] memory a) {
        a = new address[](1);
        a[0] = address(h);
    }

    /// forge-config: default.invariant.runs = 400
    /// forge-config: default.invariant.depth = 120
    /// forge-config: default.invariant.fail-on-revert = true
    function invariant_R423_everything() public {
        h.check();
    }

    function afterInvariant() public {
        emit log_named_uint("deposits", h.nDeposit());
        emit log_named_uint("releases", h.nRelease());
        emit log_named_uint("deferred", h.nDeferred());
        emit log_named_uint("claims", h.nClaim());
    }
}

/// Cross-vault replay: the frozen USDC-style vault and the ether vault under ONE committee, every certificate kind.
contract R423Token {
    mapping(address => uint256) public balanceOf;

    function decimals() external pure returns (uint8) {
        return 6;
    }

    function mint(address to, uint256 a) external {
        balanceOf[to] += a;
    }

    function transfer(address to, uint256 a) external returns (bool) {
        balanceOf[msg.sender] -= a;
        balanceOf[to] += a;
        return true;
    }

    function transferFrom(address f, address to, uint256 a) external returns (bool) {
        balanceOf[f] -= a;
        balanceOf[to] += a;
        return true;
    }
}

contract R423CrossVaultReplayTest is NativeEtherVaultBase {
    ProvenanceSourceVault usdc;
    R423Token tok;

    function setUp() public {
        baseSetUp();
        tok = new R423Token();
        // the SAME labels, cap, committee and guardians as the ether vault: only the token word and the address differ
        usdc = new ProvenanceSourceVault(
            SRC, NAT, ASSET, address(tok), CAP, 0, addrs(keys), 5,
            ProvenanceSourceVault.Policy(BUCKET, WINDOW, 6, 14 days, MIN_DEPOSIT, MIN_BURN),
            ProvenanceSourceVault.Guard(guardians(), 72 hours, 72 hours),
            ProvenanceSourceVault.Provenance(1, 0, address(0), ProvenanceSourceVault.Fees(TREASURY, DEP_BPS, REL_BPS))
        );
        uint256 until = block.timestamp + 100;
        usdc.setControls(true, true, 0, until, cert(usdc.controlDigest(true, true, 0, until), 5));
        depositAs(ALICE, 10_000_000, ALICE);
        tok.mint(ALICE, 10_000_000);
        vm.prank(ALICE);
        usdc.deposit(10_000_000, pad(ALICE));
    }

    function toU(NativeEtherSourceVault.ReleaseContext memory c) internal pure returns (ProvenanceSourceVault.ReleaseContext memory) {
        return ProvenanceSourceVault.ReleaseContext(c.validUntil, c.sourceAnchorNumber, c.sourceAnchorHash, c.nativeFinalizedNumber, c.nativeFinalizedHash);
    }

    function ethTry(NativeEtherSourceVault.Release memory r, NativeEtherSourceVault.ReleaseContext memory c, bytes[] memory s) internal returns (bool ok) {
        (ok,) = address(vault).call(abi.encodeCall(NativeEtherSourceVault.release, (r, c, s)));
    }

    function usdcTry(ProvenanceSourceVault.Release memory r, ProvenanceSourceVault.ReleaseContext memory c, bytes[] memory s) internal returns (bool ok) {
        (ok,) = address(usdc).call(abi.encodeCall(ProvenanceSourceVault.release, (r, c, s)));
    }

    function test_R423_releaseCertificatesDoNotCrossVaults() public {
        require(usdc.routeId() != vault.routeId(), "routes equal");
        require(usdc.mintChainGenesis() != vault.mintChainGenesis(), "genesis equal");
        NativeEtherSourceVault.ReleaseContext memory c = context();
        // (a) a certificate of the USDC vault, item as signed, sent to the ether vault
        ProvenanceSourceVault.Release memory ru = ProvenanceSourceVault.Release(
            usdc.routeId(), 1, BOB, 1_000_000, keccak256("b1"), 1, 0, usdc.chainHeadAt(1)
        );
        bytes[] memory su = cert(usdc.releaseDigest(ru, toU(c)), 7);
        NativeEtherSourceVault.Release memory asEth =
            NativeEtherSourceVault.Release(ru.route, ru.nonce, ru.recipient, ru.amount, ru.nativeBurn, ru.mintCount, ru.mintedTotal, ru.mintHead);
        require(!ethTry(asEth, c, su), "a USDC-vault certificate released ether");
        // (b) the same signatures with the item rewritten to the ether vault's route and head
        asEth.route = vault.routeId();
        asEth.mintHead = vault.chainHeadAt(1);
        require(!ethTry(asEth, c, su), "USDC-vault signatures accepted for a rewritten ether release");
        // control: the USDC certificate works on its own vault
        require(usdcTry(ru, toU(c), su), "control: the USDC certificate is valid where it belongs");
    }

    function test_R423_etherCertificatesDoNotReleaseUsdc() public {
        NativeEtherSourceVault.ReleaseContext memory c = context();
        NativeEtherSourceVault.Release memory re = cleanBurn(BOB, 1_000_000, 1);
        bytes[] memory se = cert(vault.releaseDigest(re, c), 7);
        ProvenanceSourceVault.Release memory asUsdc =
            ProvenanceSourceVault.Release(re.route, re.nonce, re.recipient, re.amount, re.nativeBurn, re.mintCount, re.mintedTotal, re.mintHead);
        require(!usdcTry(asUsdc, toU(c), se), "an ether-vault certificate released USDC");
        asUsdc.route = usdc.routeId();
        asUsdc.mintHead = usdc.chainHeadAt(1);
        require(!usdcTry(asUsdc, toU(c), se), "ether-vault signatures accepted for a rewritten USDC release");
        require(ethTry(re, c, se), "control: the ether certificate is valid where it belongs");
        require(BOB.balance == wei_(1_000_000 - relFee(1_000_000)), "control: the ether release pays");
    }

    function test_R423_controlCertificatesDoNotCrossVaults() public {
        uint256 until = block.timestamp + 100;
        bool ok;
        (ok,) = address(vault).call(
            abi.encodeCall(NativeEtherSourceVault.setControls, (false, false, 1, until, cert(usdc.controlDigest(false, false, 1, until), 7)))
        );
        require(!ok, "a USDC-vault controls certificate moved the ether vault");
        vm.prank(vm.addr(guardKeys[0]));
        vault.guardianPause();
        vm.prank(vm.addr(guardKeys[0]));
        usdc.guardianPause();
        (ok,) = address(vault).call(abi.encodeCall(NativeEtherSourceVault.unpause, (1, until, cert(usdc.unpauseDigest(1, until), 7))));
        require(!ok, "a USDC-vault unpause certificate unpaused the ether vault");
        address ver = address(tok);
        bytes[] memory sw = cert(usdc.switchDigest(false, ver, ver.codehash, 0, until), 7);
        (ok,) = address(vault).call(abi.encodeCall(NativeEtherSourceVault.proposeVerifier, (ver, 0, until, sw)));
        require(!ok, "a USDC-vault switch certificate proposed a verifier on the ether vault");
        vault.unpause(1, until, cert(vault.unpauseDigest(1, until), 6));
        usdc.proposeVerifier(ver, 0, until, sw);
    }
}
