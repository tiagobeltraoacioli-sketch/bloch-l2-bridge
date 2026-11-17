// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity 0.8.24;

import {TronSourceVault} from "../contracts/tron/TronSourceVault.sol";
import {ProvenanceSourceVault} from "../contracts/usdt/ProvenanceSourceVault.sol";
import {TronUSDTLike, TronUSDTUpgraded, TronUSDTFaulty, TronPlainToken} from "./harness/TronUSDTLike.sol";
import {TronVaultBase, TronVaultFormulas} from "./TronVaultBase.sol";

/// TronSourceVault at the launch shape against TronUSDTLike (USDT on TRON as measured): constructor, deposits,
/// certified releases, guardian pause and limits. The issuer-driven cases are in TronVaultIssuer.t.sol, the stateful
/// fuzz in TronVaultStateful.t.sol and the comparison with the Ethereum vault in TronVaultDifferential.t.sol.
/// Every refusal asserts its selector and has its positive control in the same test.
contract TronSourceVaultTest is TronVaultBase {
    event Deposited(
        bytes32 indexed id, bytes32 indexed route, uint64 nonce, address sender, uint64 amount, bytes32 pqRecipientHash
    );
    event Released(
        bytes32 indexed id, bytes32 indexed route, uint64 nonce, address recipient, uint64 amount, bytes32 nativeBurn
    );
    event FeeAccrued(bytes32 indexed id, uint64 fee);
    event FeesSwept(address indexed recipient, uint64 amount);

    function setUp() public {
        baseSetUp(new TronUSDTLike());
    }

    // ================================================================ constructor

    function test_ctor_launchShape() public view {
        require(vault.token() == address(usdt) && vault.cap() == CAP && vault.transferMode() == 1, "token, cap, mode");
        require(vault.threshold() == 5 && vault.signerCount() == 7 && vault.switchThreshold() == 6, "committee");
        require(vault.switchDelay() == 14 days, "switch delay");
        require(vault.guardianCount() == 3 && vault.pauseDuration() == 72 hours && vault.pauseCooldown() == 72 hours, "guard");
        require(vault.windowLimit() == BUCKET && vault.windowSeconds() == 86_400, "window");
        require(vault.minDeposit() == 11 * U && vault.l2MinBurn() == 10 * U, "minimums");
        require(vault.provenanceMode() == 1 && vault.releaseDelay() == 0 && vault.mintVerifier() == address(0), "provenance");
        require(vault.feeRecipient() == TREASURY && vault.depositFeeBps() == 5 && vault.releaseFeeBps() == 5, "fees");
        require(vault.decimals() == 6 && vault.availableToRelease() == BUCKET, "decimals, full bucket");
        (bool known, bool blacklisted, bool replaced) = vault.tokenState();
        require(known && !blacklisted && !replaced, "TRON-5: a healthy token");
        require(
            vault.routeId() == TronVaultFormulas.routeId(address(vault), SRC, NAT, ASSET, address(usdt), CAP), "routeId"
        );
        checkBooks();
    }

    /// TRON-2: only transferMode 1 deploys.
    function test_ctor_transferMode0And2Refused() public {
        (bool ok, bytes4 e,) = tryDeploy(address(usdt), 0);
        require(!ok && e == TronSourceVault.InvalidConfiguration.selector, "mode 0 refused");
        (ok, e,) = tryDeploy(address(usdt), 2);
        require(!ok && e == TronSourceVault.InvalidConfiguration.selector, "mode 2 refused");
        (ok, e,) = tryDeploy(address(usdt), 255);
        require(!ok && e == TronSourceVault.InvalidConfiguration.selector, "mode 255 refused");
        address v;
        (ok,, v) = tryDeploy(address(usdt), 1);
        require(ok && TronSourceVault(v).transferMode() == 1, "control: mode 1 deploys");
    }

    /// TRON-3: a token without the two getters is refused, although the Ethereum vault accepts the very same token with
    /// the very same arguments (so it is TRON-3 that refuses, nothing else).
    function test_ctor_tokenWithoutGettersRefused() public {
        TronPlainToken plain = new TronPlainToken();
        (bool ok, bytes4 e,) = tryDeploy(address(plain), 1);
        require(!ok && e == TronSourceVault.InvalidConfiguration.selector, "no getters: refused");
        ProvenanceSourceVault eth = new ProvenanceSourceVault(
            SRC, NAT, ASSET, address(plain), CAP, 1, addrs(keys), 5,
            ProvenanceSourceVault.Policy(BUCKET, WINDOW, 6, 14 days, MIN_DEPOSIT, MIN_BURN),
            ProvenanceSourceVault.Guard(guardians(), 72 hours, 72 hours),
            ProvenanceSourceVault.Provenance(1, 0, address(0), ProvenanceSourceVault.Fees(TREASURY, DEP_BPS, REL_BPS))
        );
        require(eth.token() == address(plain), "control: the Ethereum vault takes this token with these arguments");
        (ok,,) = tryDeploy(address(usdt), 1);
        require(ok, "control: the same arguments with a USDT-like token deploy");
    }

    /// TRON-3: either getter reverting, returning 0 bytes, 64 bytes, or a set (non-zero) word is refused.
    function test_ctor_malformedGettersRefused() public {
        TronUSDTFaulty f = new TronUSDTFaulty();
        for (uint8 mode = 1; mode <= 4; ++mode) {
            f.setGetterModes(mode, 0);
            (bool ok, bytes4 e,) = tryDeploy(address(f), 1);
            require(!ok && e == TronSourceVault.InvalidConfiguration.selector, "malformed isBlackListed refused");
            f.setGetterModes(0, mode);
            (ok, e,) = tryDeploy(address(f), 1);
            require(!ok && e == TronSourceVault.InvalidConfiguration.selector, "malformed deprecated refused");
        }
        f.setGetterModes(0, 0);
        (bool fine,,) = tryDeploy(address(f), 1);
        require(fine, "control: the same token with well-formed getters deploys");
    }

    /// TRON-3: the issuer already blacklisted the address the vault is about to get.
    function test_ctor_preBlacklistedVaultAddressRefused() public {
        address predicted = vm.computeCreateAddress(address(this), vm.getNonce(address(this)));
        usdt.addBlackList(predicted);
        (bool ok, bytes4 e,) = tryDeploy(address(usdt), 1);
        require(!ok && e == TronSourceVault.InvalidConfiguration.selector, "blacklisted address refused");
        usdt.removeBlackList(predicted);
        address v;
        (ok,, v) = tryDeploy(address(usdt), 1);
        require(ok && v == predicted, "control: the same address deploys once it is not blacklisted");
    }

    /// TRON-3: a token the issuer already deprecated is refused.
    function test_ctor_deprecatedTokenRefused() public {
        TronUSDTLike old = new TronUSDTLike();
        (bool ok,,) = tryDeploy(address(old), 1);
        require(ok, "control: deploys before the deprecation");
        old.deprecate(address(new TronUSDTUpgraded(address(old))));
        bytes4 e;
        (ok, e,) = tryDeploy(address(old), 1);
        require(!ok && e == TronSourceVault.InvalidConfiguration.selector, "deprecated token refused");
    }

    /// Deposits and releases are off until the committee enables them (as on Ethereum).
    function test_ctor_controlsStartOff() public {
        TronSourceVault v = deployRaw(address(usdt), 1);
        usdt.mint(ALICE, 100 * U);
        vm.prank(ALICE);
        usdt.approve(address(v), type(uint256).max);
        vm.expectRevert(TronSourceVault.InvalidTransfer.selector);
        vm.prank(ALICE);
        v.deposit(uint64(100 * U), pad(ALICE));
        enable(v);
        vm.prank(ALICE);
        v.deposit(uint64(100 * U), pad(ALICE));
        require(v.depositCount() == 1, "control: accepted once enabled");
    }

    // ================================================================ deposit

    /// Net/fee accounting, the id, the log and the hash chain, over two deposits.
    function test_deposit_netFeeIdsAndHashChain() public {
        uint64 gross = uint64(1000 * U);
        uint64 net = 999_500_000;
        bytes32 route = vault.routeId();
        bytes32 expectedId = TronVaultFormulas.depositId(route, 0, ALICE, net, pad(BOB));
        prepare(ALICE, gross);
        vm.expectEmit(true, true, false, true, address(vault));
        emit Deposited(expectedId, route, 0, ALICE, net, pad(BOB));
        vm.expectEmit(true, false, false, true, address(vault));
        emit FeeAccrued(expectedId, 500_000);
        vm.prank(ALICE);
        bytes32 id = vault.deposit(gross, pad(BOB));
        recordDeposit(id, gross, BOB);
        require(id == expectedId && id == vault.depositId(0, ALICE, net, pad(BOB)), "id over the NET amount");
        require(uint256(id) >> 192 == 0, "the top 8 bytes are the nonce");
        require(usdt.balanceOf(ALICE) == 0 && usdt.balanceOf(address(vault)) == gross, "the user paid gross");
        require(vault.totalLocked() == net && vault.feesAccrued() == 500_000, "net locked, fee aside");
        bytes32 head1 = TronVaultFormulas.next(
            TronVaultFormulas.genesis(block.chainid, address(vault), route), id, net, BOB
        );
        require(vault.depositHead(1) == head1 && vault.chainHeadAt(1) == head1, "head after one deposit");
        require(vault.provenanceMatches(1, 0, head1), "provenance at count 1");

        bytes32 id2 = depositAs(BOB, uint64(333_333_333), CAROL);
        uint64 net2 = 333_333_333 - 166_666;
        require(id2 == TronVaultFormulas.depositId(route, 1, BOB, net2, pad(CAROL)), "second id");
        require(uint256(id2) >> 192 == 1, "nonce 1 in the top bytes");
        require(vault.depositHead(2) == TronVaultFormulas.next(head1, id2, net2, CAROL), "head after two deposits");
        require(vault.totalLocked() == net + net2 && vault.feesAccrued() == 500_000 + 166_666, "sums");
        checkBooks();
        checkBacked();
    }

    /// Recipient hash rules and the allowance: refused with InvalidTransfer, then the same depositor is accepted.
    function test_deposit_badRecipientOrNoAllowanceRefused() public {
        usdt.mint(ALICE, 100 * U);
        vm.expectRevert(TronSourceVault.InvalidTransfer.selector); // no allowance: the token reverts
        vm.prank(ALICE);
        vault.deposit(uint64(100 * U), pad(ALICE));
        vm.prank(ALICE);
        usdt.approve(address(vault), type(uint256).max);
        vm.expectRevert(TronSourceVault.InvalidTransfer.selector);
        vm.prank(ALICE);
        vault.deposit(uint64(100 * U), bytes32(0));
        vm.expectRevert(TronSourceVault.InvalidTransfer.selector);
        vm.prank(ALICE);
        vault.deposit(uint64(100 * U), bytes32(uint256(1) << 160));
        vm.expectRevert(TronSourceVault.InvalidTransfer.selector); // above the balance: the token reverts
        vm.prank(ALICE);
        vault.deposit(uint64(100 * U + 1), pad(ALICE));
        (bool ok,) = tryDeposit(ALICE, uint64(100 * U), ALICE);
        require(ok, "control");
        checkBooks();
        checkBacked();
    }

    // ================================================================ limits

    function test_limits_minDeposit() public {
        prepare(ALICE, 100 * U);
        (bool ok, bytes4 e) = tryDeposit(ALICE, MIN_DEPOSIT - 1, ALICE);
        require(!ok && e == TronSourceVault.InvalidTransfer.selector, "below 11 USDT refused");
        (ok,) = tryDeposit(ALICE, MIN_DEPOSIT, ALICE);
        require(ok, "11 USDT accepted");
        require(vault.totalLocked() == 11 * U - 5_500 && vault.totalLocked() >= MIN_BURN, "nets at least the L2 minBurn");
        checkBooks();
        checkBacked();
    }

    function test_limits_depositAboveWindowLimitRefused() public {
        prepare(ALICE, 30_000 * U);
        (bool ok, bytes4 e) = tryDeposit(ALICE, BUCKET + 1, ALICE);
        require(!ok && e == TronSourceVault.InvalidTransfer.selector, "10,000.000001 refused");
        (ok,) = tryDeposit(ALICE, BUCKET, ALICE);
        require(ok, "exactly 10,000 accepted");
        checkBooks();
        checkBacked();
    }

    /// The cap counts NET amounts: a deposit whose net lands exactly on the cap passes, any further one is refused.
    function test_limits_cap() public {
        for (uint256 i; i < 10; ++i) depositAs(ALICE, BUCKET, ALICE); // 10 x 9,995 net: 50 USDT of room
        uint64 room = CAP - vault.totalLocked();
        require(room == 50 * U, "room");
        uint64 g = uint64((uint256(room) * 10_000 + 9_994) / 9_995);
        while (g - fee(g, DEP_BPS) > room) --g;
        while (g + 1 - fee(g + 1, DEP_BPS) <= room) ++g;
        prepare(BOB, uint256(g) + 1 + MIN_DEPOSIT);
        (bool ok, bytes4 e) = tryDeposit(BOB, g + 1, BOB);
        require(!ok && e == TronSourceVault.InvalidTransfer.selector, "one unit above the cap refused");
        (ok,) = tryDeposit(BOB, g, BOB);
        require(ok && vault.totalLocked() == CAP, "exactly at the cap");
        (ok, e) = tryDeposit(BOB, MIN_DEPOSIT, BOB);
        require(!ok && e == TronSourceVault.InvalidTransfer.selector, "full: refused");
        // Room opens again only through a release.
        release(cleanBurn(CAROL, uint64(100 * U), 11));
        (ok,) = tryDeposit(BOB, MIN_DEPOSIT, BOB);
        require(ok, "control: accepted after a release made room");
        checkBooks();
        checkBacked();
    }

    /// The release bucket: 10,000 USDT at once, then RateLimited, then a refill of 10,000 per 86,400 s.
    function test_limits_windowBucketAndRefill() public {
        for (uint256 i; i < 3; ++i) depositAs(ALICE, BUCKET, ALICE);
        release(cleanBurn(BOB, uint64(6_000 * U), 3));
        release(cleanBurn(BOB, uint64(4_000 * U), 3));
        require(vault.availableToRelease() == 0, "bucket empty");
        TronSourceVault.Release memory r = cleanBurn(BOB, uint64(5_000 * U), 3);
        (bool ok, bytes4 e) = tryRelease(r);
        require(!ok && e == TronSourceVault.RateLimited.selector && unused(r), "limited, nothing consumed");
        vm.warp(block.timestamp + 43_199);
        require(vault.availableToRelease() == uint256(BUCKET) * 43_199 / 86_400, "linear refill");
        (ok, e) = tryRelease(r);
        require(!ok && e == TronSourceVault.RateLimited.selector, "one second early");
        vm.warp(block.timestamp + 1);
        require(vault.availableToRelease() == 5_000 * U, "half a window: 5,000");
        (ok,) = tryRelease(r);
        require(ok && vault.availableToRelease() == 0, "the same burn is paid after the refill");
        vm.warp(block.timestamp + 10 days);
        require(vault.availableToRelease() == BUCKET, "the bucket never exceeds the limit");
        checkBooks();
        checkBacked();
    }

    // ================================================================ release

    /// A 5-of-7 certificate pays amount less 5 bps although the token answers `false` from the successful transfer.
    function test_release_paysWithFalseReturnAndExactDeltas() public {
        depositAs(ALICE, uint64(2000 * U), ALICE);
        // Control: this token really answers ABI false from a successful transfer.
        usdt.mint(MALLORY, 1);
        vm.prank(MALLORY);
        (bool sent, bytes memory answer) = address(usdt).call(abi.encodeWithSignature("transfer(address,uint256)", MALLORY, 1));
        require(sent && answer.length == 32 && abi.decode(answer, (uint256)) == 0, "transfer returns false");

        uint64 amount = uint64(1234_567_891);
        uint64 f = fee(amount, REL_BPS);
        require(f == 617_283, "5 bps, rounded down");
        TronSourceVault.Release memory r = cleanBurn(BOB, amount, 1);
        TronSourceVault.ReleaseContext memory c = context();
        bytes[] memory s = cert(vault.releaseDigest(r, c), 5);
        require(vault.releaseId(r) == TronVaultFormulas.releaseId(r), "releaseId formula");
        require(
            vault.releaseDigest(r, c) == TronVaultFormulas.releaseDigest(block.chainid, address(vault), r, c),
            "releaseDigest formula"
        );
        Snap memory b = snap();
        vm.expectEmit(true, true, false, true, address(vault));
        emit FeeAccrued(vault.releaseId(r), f);
        vm.expectEmit(true, true, false, true, address(vault));
        emit Released(vault.releaseId(r), r.route, r.nonce, BOB, amount, r.nativeBurn);
        vault.release(r, c, s);
        recordRelease(amount);
        require(usdt.balanceOf(BOB) == amount - f, "the recipient gets the amount less the fee");
        require(usdt.balanceOf(address(vault)) == b.vaultBalance - (amount - f), "the vault loses exactly what was paid");
        require(vault.totalLocked() == b.locked - amount, "the full burned amount is unlocked");
        require(vault.feesAccrued() == b.fees + f, "the release fee accrues");
        require(vault.availableToRelease() == b.available - amount, "the bucket takes the full amount");
        require(vault.releasedNonce(r.nonce) && vault.releasedBurn(r.nativeBurn), "nonce and burn are consumed");
        checkBooks();
        checkBacked();
    }

    /// `sweepFees` also goes through the false-returning transfer: anyone calls, only the treasury is paid.
    function test_sweep_paysWithFalseReturnAndExactDeltas() public {
        depositAs(ALICE, uint64(5000 * U), ALICE);
        release(cleanBurn(BOB, uint64(1000 * U), 1));
        uint64 accrued = vault.feesAccrued();
        require(accrued == 2_500_000 + 500_000, "deposit fee + release fee");
        Snap memory b = snap();
        vm.expectEmit(true, false, false, true, address(vault));
        emit FeesSwept(TREASURY, accrued);
        vm.prank(MALLORY);
        uint64 out = vault.sweepFees();
        feesSwept += out;
        require(out == accrued && usdt.balanceOf(TREASURY) == accrued && usdt.balanceOf(MALLORY) == 0, "to the treasury only");
        require(usdt.balanceOf(address(vault)) == b.vaultBalance - accrued, "the vault loses exactly the fees");
        require(vault.feesAccrued() == 0 && vault.totalLocked() == b.locked, "backing untouched");
        require(sweep() == 0 && usdt.balanceOf(TREASURY) == accrued, "nothing twice");
        release(cleanBurn(BOB, uint64(1000 * U), 1));
        checkBooks();
        checkBacked();
    }

    /// A paid release cannot be paid again: not with its certificate, not by reusing its nonce or its burn.
    function test_release_replayRefused() public {
        depositAs(ALICE, uint64(1000 * U), ALICE);
        TronSourceVault.Release memory r = cleanBurn(BOB, uint64(100 * U), 1);
        TronSourceVault.ReleaseContext memory c = context();
        bytes[] memory s = cert(vault.releaseDigest(r, c), 5);
        (bool ok, bytes4 e) = tryReleaseWith(r, c, s);
        require(ok, "control: paid once");
        Snap memory b = snap();
        (ok, e) = tryReleaseWith(r, c, s);
        require(!ok && e == TronSourceVault.InvalidRelease.selector, "the same certificate again");
        (ok, e) = tryRelease(r);
        require(!ok && e == TronSourceVault.InvalidRelease.selector, "a fresh certificate for the same release");
        TronSourceVault.Release memory sameBurn = cleanBurn(BOB, uint64(100 * U), 1);
        sameBurn.nativeBurn = r.nativeBurn;
        (ok, e) = tryRelease(sameBurn);
        require(!ok && e == TronSourceVault.InvalidRelease.selector, "same burn, other nonce");
        TronSourceVault.Release memory sameNonce = cleanBurn(BOB, uint64(100 * U), 1);
        sameNonce.nonce = r.nonce;
        (ok, e) = tryRelease(sameNonce);
        require(!ok && e == TronSourceVault.InvalidRelease.selector, "same nonce, other burn");
        require(usdt.balanceOf(BOB) == 100 * U - 50_000 && unchanged(b), "paid exactly once");
        checkBooks();
        checkBacked();
    }

    /// A key that is not a signer and whose address sorts above the fourth signer, so that only `isSigner` refuses it.
    function outsiderAbove(address floor) internal pure returns (uint256 k) {
        k = 0x9000;
        while (vm.addr(k) <= floor) ++k;
    }

    /// True when the release with this certificate is refused with exactly InvalidCertificate.
    function badCert(TronSourceVault.Release memory r, TronSourceVault.ReleaseContext memory c, bytes[] memory s)
        internal
        returns (bool)
    {
        (bool ok, bytes4 e) = tryReleaseWith(r, c, s);
        return !ok && e == TronSourceVault.InvalidCertificate.selector;
    }

    /// Forged attestations: each is refused with InvalidCertificate and consumes nothing; the honest certificate for
    /// the same release is then paid.
    function test_release_forgedCertificatesRefused() public {
        depositAs(ALICE, uint64(1000 * U), ALICE);
        TronSourceVault.Release memory r = cleanBurn(BOB, uint64(100 * U), 1);
        TronSourceVault.ReleaseContext memory c = context();
        bytes32 digest = vault.releaseDigest(r, c);
        Snap memory b = snap();

        require(badCert(r, c, cert(digest, 4)), "4 of 7");

        bytes[] memory s = cert(digest, 5);
        s[4] = sig(outsiderAbove(vm.addr(keys[3])), digest);
        require(badCert(r, c, s), "4 valid + 1 non-signer");

        s = cert(digest, 5);
        s[4] = s[3];
        require(badCert(r, c, s), "a duplicated signer");

        s = cert(digest, 5);
        (s[0], s[1]) = (s[1], s[0]);
        require(badCert(r, c, s), "unsorted");

        s = cert(digest, 5);
        s[2] = malleate(s[2]);
        require(badCert(r, c, s), "high s");

        s = cert(digest, 5);
        s[1] = abi.encodePacked(s[1], uint8(0));
        require(badCert(r, c, s), "a 66-byte signature");

        s = cert(digest, 5);
        s[1][64] = bytes1(uint8(s[1][64]) - 27);
        require(badCert(r, c, s), "v of 0 or 1");

        s = new bytes[](8);
        for (uint256 i; i < 8; ++i) s[i] = sig(keys[i % 5], digest);
        require(badCert(r, c, s), "more signatures than signers");

        require(unchanged(b) && unused(r) && usdt.balanceOf(BOB) == 0, "nothing paid, nothing consumed");
        (bool ok,) = tryReleaseWith(r, c, cert(digest, 5));
        require(ok && usdt.balanceOf(BOB) == 100 * U - 50_000, "control: the honest certificate pays");
        checkBooks();
        checkBacked();
    }

    /// Wrong digest: five honest signatures over something else than this release in this context.
    function test_release_certificateForAnotherDigestRefused() public {
        depositAs(ALICE, uint64(1000 * U), ALICE);
        TronSourceVault.Release memory r = cleanBurn(BOB, uint64(100 * U), 1);
        TronSourceVault.ReleaseContext memory c = context();
        Snap memory b = snap();

        r.amount += 1;
        bytes[] memory s = cert(vault.releaseDigest(r, c), 5);
        r.amount -= 1;
        require(badCert(r, c, s), "a certificate for another amount");

        r.recipient = MALLORY;
        s = cert(vault.releaseDigest(r, c), 5);
        r.recipient = BOB;
        require(badCert(r, c, s), "a certificate for another recipient");

        c.nativeFinalizedNumber = 8;
        s = cert(vault.releaseDigest(r, c), 5);
        c.nativeFinalizedNumber = 7;
        require(badCert(r, c, s), "a certificate for another native block");

        c.validUntil += 1;
        s = cert(vault.releaseDigest(r, c), 5);
        c.validUntil -= 1;
        require(badCert(r, c, s), "a certificate with another expiry");

        // A control-plane certificate (same signers, another tag) is not a release certificate.
        require(badCert(r, c, cert(vault.controlDigest(false, true, 1, c.validUntil), 5)), "a controls certificate");

        require(unchanged(b) && unused(r) && usdt.balanceOf(BOB) == 0, "nothing paid, nothing consumed");
        (bool ok,) = tryReleaseWith(r, c, cert(vault.releaseDigest(r, c), 5));
        require(ok && usdt.balanceOf(BOB) == 100 * U - 50_000, "control: the honest certificate pays");
        checkBooks();
        checkBacked();
    }

    /// A certificate signed for another vault (same signers, same token, same arguments) pays nothing here.
    function test_release_wrongVaultRefused() public {
        TronSourceVault other = newVault(address(usdt));
        depositAs(ALICE, uint64(1000 * U), ALICE);
        TronSourceVault.Release memory r = cleanBurn(BOB, uint64(100 * U), 1);
        TronSourceVault.ReleaseContext memory c = context();
        // Same release fields, signed under the other vault's address.
        bytes[] memory foreign = cert(other.releaseDigest(r, c), 5);
        (bool ok, bytes4 e) = tryReleaseWith(r, c, foreign);
        require(!ok && e == TronSourceVault.InvalidCertificate.selector && unused(r), "bound to the vault address");
        // The other vault's own route in the release: refused before the certificate is read.
        TronSourceVault.Release memory theirs = copy(r);
        theirs.route = other.routeId();
        (ok, e) = tryReleaseWith(theirs, c, cert(other.releaseDigest(theirs, c), 5));
        require(!ok && e == TronSourceVault.InvalidRelease.selector, "another route");
        (ok,) = tryReleaseWith(r, c, cert(vault.releaseDigest(r, c), 5));
        require(ok, "control");
        checkBooks();
        checkBacked();
    }

    /// The certificate binds the chain id: on another chain id the same signatures are refused.
    function test_release_wrongChainIdRefused() public {
        depositAs(ALICE, uint64(1000 * U), ALICE);
        TronSourceVault.Release memory r = cleanBurn(BOB, uint64(100 * U), 1);
        TronSourceVault.ReleaseContext memory c = context();
        bytes[] memory s = cert(vault.releaseDigest(r, c), 5);
        uint256 home = block.chainid;
        vm.chainId(home + 1);
        (bool ok, bytes4 e) = tryReleaseWith(r, c, s);
        require(!ok && e == TronSourceVault.InvalidCertificate.selector && unused(r), "another chain id");
        vm.chainId(home);
        (ok,) = tryReleaseWith(r, c, s);
        require(ok, "control: the same certificate pays on its chain");
        checkBooks();
        checkBacked();
    }

    /// The context: a wrong, future or zero anchor, a zero native hash, an anchor older than 256 blocks, an expired
    /// certificate. Each refused with its selector; the honest context is paid.
    function test_release_contextRefusals() public {
        depositAs(ALICE, uint64(1000 * U), ALICE);
        TronSourceVault.Release memory r = cleanBurn(BOB, uint64(100 * U), 1);
        TronSourceVault.ReleaseContext memory c = context();
        bool ok;
        bytes4 e;

        TronSourceVault.ReleaseContext memory x = copy(c);
        x.sourceAnchorHash = keccak256("another fork");
        (ok, e) = tryReleaseWith(r, x, cert(vault.releaseDigest(r, x), 5));
        require(!ok && e == TronSourceVault.InvalidContext.selector, "an anchor hash of another fork");

        x = copy(c);
        x.sourceAnchorNumber = block.number;
        (ok, e) = tryReleaseWith(r, x, cert(vault.releaseDigest(r, x), 5));
        require(!ok && e == TronSourceVault.InvalidContext.selector, "the current block as anchor");

        x = copy(c);
        x.sourceAnchorHash = 0;
        (ok, e) = tryReleaseWith(r, x, cert(vault.releaseDigest(r, x), 5));
        require(!ok && e == TronSourceVault.InvalidContext.selector, "a zero anchor hash");

        x = copy(c);
        x.nativeFinalizedHash = 0;
        (ok, e) = tryReleaseWith(r, x, cert(vault.releaseDigest(r, x), 5));
        require(!ok && e == TronSourceVault.InvalidContext.selector, "a zero native hash");

        bytes[] memory s = cert(vault.releaseDigest(r, c), 5);
        vm.roll(c.sourceAnchorNumber + 257);
        (ok, e) = tryReleaseWith(r, c, s);
        require(!ok && e == TronSourceVault.InvalidContext.selector, "an anchor 257 blocks old");
        vm.roll(c.sourceAnchorNumber + 256);
        uint256 t0 = block.timestamp;
        vm.warp(c.validUntil + 1);
        (ok, e) = tryReleaseWith(r, c, s);
        require(!ok && e == TronSourceVault.InvalidRelease.selector, "expired");
        vm.warp(t0);
        require(unused(r), "nothing consumed");
        (ok,) = tryReleaseWith(r, c, s);
        require(ok, "control: the same certificate pays at exactly 256 blocks, before it expires");
        checkBooks();
        checkBacked();
    }

    /// Provenance (mode 1): the burn must state the vault's own chain head at its mint count.
    function test_release_provenanceMismatchRefused() public {
        depositAs(ALICE, uint64(1000 * U), ALICE);
        depositAs(BOB, uint64(1000 * U), BOB);
        bool ok;
        bytes4 e;
        TronSourceVault.Release memory r = cleanBurn(CAROL, uint64(100 * U), 2);
        r.mintHead = keccak256("a chain with a forged mint");
        (ok, e) = tryRelease(r);
        require(!ok && e == TronSourceVault.ProvenanceMismatch.selector && unused(r), "a foreign head");
        r.mintHead = vault.chainHeadAt(1);
        (ok, e) = tryRelease(r);
        require(!ok && e == TronSourceVault.ProvenanceMismatch.selector, "the head of another count");
        r.mintCount = 0;
        r.mintHead = vault.mintChainGenesis();
        (ok, e) = tryRelease(r);
        require(!ok && e == TronSourceVault.ProvenanceMismatch.selector, "a burn before any mint");
        r.mintCount = 3;
        r.mintHead = vault.chainHeadAt(3);
        (ok, e) = tryRelease(r);
        require(!ok && e == TronSourceVault.ProvenanceMismatch.selector, "more mints than deposits");
        r.mintCount = 2;
        r.mintHead = vault.chainHeadAt(2);
        (ok,) = tryRelease(r);
        require(ok && usdt.balanceOf(CAROL) == 100 * U - 50_000, "control: the vault's own head pays");
        checkBooks();
        checkBacked();
    }

    /// The release's own fields: zero amount, zero or vault recipient, zero burn, above the locked total.
    function test_release_fieldRefusals() public {
        depositAs(ALICE, uint64(1000 * U), ALICE);
        bool ok;
        bytes4 e;
        TronSourceVault.Release memory r = cleanBurn(BOB, uint64(100 * U), 1);
        TronSourceVault.Release memory x = copy(r);
        x.amount = 0;
        (ok, e) = tryRelease(x);
        require(!ok && e == TronSourceVault.InvalidRelease.selector, "zero amount");
        x = copy(r);
        x.recipient = address(0);
        (ok, e) = tryRelease(x);
        require(!ok && e == TronSourceVault.InvalidRelease.selector, "zero recipient");
        x = copy(r);
        x.recipient = address(vault);
        (ok, e) = tryRelease(x);
        require(!ok && e == TronSourceVault.InvalidRelease.selector, "the vault as recipient");
        x = copy(r);
        x.nativeBurn = 0;
        (ok, e) = tryRelease(x);
        require(!ok && e == TronSourceVault.InvalidRelease.selector, "zero burn");
        x = copy(r);
        x.amount = vault.totalLocked() + 1;
        (ok, e) = tryRelease(x);
        require(!ok && e == TronSourceVault.InvalidRelease.selector, "above totalLocked");
        (ok,) = tryRelease(r);
        require(ok, "control");
        checkBooks();
        checkBacked();
    }

    // ================================================================ guardian pause

    /// One guardian key stops deposits and committee releases for 72 h; nothing is consumed and both resume.
    function test_pause_stopsDepositsAndReleasesFor72h() public {
        depositAs(ALICE, uint64(1000 * U), ALICE);
        prepare(BOB, 200 * U);
        TronSourceVault.Release memory r = cleanBurn(CAROL, uint64(100 * U), 1);
        address[] memory g = guardians();
        vm.expectRevert(TronSourceVault.NotGuardian.selector);
        vm.prank(MALLORY);
        vault.guardianPause();
        vm.expectRevert(TronSourceVault.NotGuardian.selector);
        vm.prank(vm.addr(keys[0])); // a signer is not a guardian
        vault.guardianPause();
        vm.prank(g[0]);
        vault.guardianPause();
        require(vault.paused() && vault.pausedUntil() == block.timestamp + 72 hours && vault.pauseCount() == 1, "paused");
        Snap memory b = snap();
        (bool ok, bytes4 e) = tryDeposit(BOB, uint64(100 * U), BOB);
        require(!ok && e == TronSourceVault.Paused.selector, "deposit stopped");
        (ok, e) = tryRelease(r);
        require(!ok && e == TronSourceVault.Paused.selector && unused(r), "release stopped, nothing consumed");
        vm.warp(block.timestamp + 72 hours - 1);
        (ok, e) = tryDeposit(BOB, uint64(100 * U), BOB);
        require(!ok && e == TronSourceVault.Paused.selector, "still stopped one second before the end");
        (ok, e) = tryRelease(r);
        require(!ok && e == TronSourceVault.Paused.selector, "release still stopped");
        require(unchanged(b), "nothing changed during the pause");
        // Fees can still be swept during a pause (sweepFees is not gated; it pays the immutable treasury only).
        require(sweep() == 500_000 && usdt.balanceOf(TREASURY) == 500_000, "sweep works while paused");
        vm.warp(block.timestamp + 1);
        require(!vault.paused(), "over after exactly 72 h");
        (ok,) = tryDeposit(BOB, uint64(100 * U), BOB);
        require(ok, "deposits resume");
        (ok,) = tryRelease(r);
        require(ok && usdt.balanceOf(CAROL) == 100 * U - 50_000, "releases resume");
        checkBooks();
        checkBacked();
    }

    /// One pause per guardian per chain: three guardians hold the vault for at most 3 x 72 h, then it stays open for
    /// the 72 h cooldown, after which a new chain may start.
    function test_pause_onePausePerGuardianPerChain() public {
        address[] memory g = guardians();
        vm.prank(g[0]);
        vault.guardianPause();
        vm.expectRevert(TronSourceVault.InvalidPause.selector);
        vm.prank(g[1]);
        vault.guardianPause(); // not while paused
        vm.warp(block.timestamp + 72 hours);
        require(!vault.guardianCanPause(g[0]) && vault.guardianCanPause(g[1]), "g0 used its pause in this chain");
        vm.expectRevert(TronSourceVault.InvalidPause.selector);
        vm.prank(g[0]);
        vault.guardianPause();
        vm.prank(g[1]);
        vault.guardianPause();
        vm.warp(block.timestamp + 72 hours);
        vm.expectRevert(TronSourceVault.InvalidPause.selector);
        vm.prank(g[1]);
        vault.guardianPause();
        vm.prank(g[2]);
        vault.guardianPause();
        require(vault.pauseCount() == 3 && vault.pauseChain() == 1, "three pauses, one chain");
        vm.warp(block.timestamp + 72 hours);
        for (uint256 i; i < 3; ++i) {
            vm.expectRevert(TronSourceVault.InvalidPause.selector);
            vm.prank(g[i]);
            vault.guardianPause();
        }
        vm.warp(block.timestamp + 72 hours - 1);
        vm.expectRevert(TronSourceVault.InvalidPause.selector);
        vm.prank(g[0]);
        vault.guardianPause();
        require(!vault.paused(), "open during the whole cooldown");
        vm.warp(block.timestamp + 1);
        vm.prank(g[0]);
        vault.guardianPause();
        require(vault.paused() && vault.pauseChain() == 2 && vault.pauseCount() == 4, "a new chain after the cooldown");
    }

    /// Only 6 of 7 signers end a pause early; afterwards guardians wait the 72 h cooldown.
    function test_pause_sixOfSevenUnpauseAndCooldown() public {
        depositAs(ALICE, uint64(1000 * U), ALICE);
        prepare(BOB, 200 * U);
        address[] memory g = guardians();
        vm.prank(g[0]);
        vault.guardianPause();
        uint256 until = block.timestamp + 1 days;
        bytes32 digest = vault.unpauseDigest(1, until);
        vm.expectRevert(TronSourceVault.InvalidCertificate.selector);
        vault.unpause(1, until, cert(digest, 5)); // the release quorum is not enough
        bytes[] memory other = cert(vault.unpauseDigest(2, until), 6);
        vm.expectRevert(TronSourceVault.InvalidPause.selector);
        vault.unpause(2, until, other); // another pause's certificate
        other = cert(vault.unpauseDigest(1, until + 1), 6);
        vm.expectRevert(TronSourceVault.InvalidCertificate.selector);
        vault.unpause(1, until, other); // six signatures over another expiry
        require(vault.paused(), "still paused");
        vault.unpause(1, until, cert(digest, 6));
        require(!vault.paused() && vault.guardianBlockedUntil() == block.timestamp + 72 hours, "unpaused, cooldown set");
        (bool ok,) = tryDeposit(BOB, uint64(100 * U), BOB);
        require(ok, "deposits resume at once");
        (ok,) = tryRelease(cleanBurn(CAROL, uint64(100 * U), 1));
        require(ok, "releases resume at once");
        vm.expectRevert(TronSourceVault.InvalidPause.selector);
        vault.unpause(1, until, cert(digest, 6)); // the certificate cannot be replayed: not paused
        for (uint256 i; i < 3; ++i) {
            vm.expectRevert(TronSourceVault.InvalidPause.selector);
            vm.prank(g[i]);
            vault.guardianPause();
        }
        vm.warp(block.timestamp + 72 hours - 1);
        vm.expectRevert(TronSourceVault.InvalidPause.selector);
        vm.prank(g[1]);
        vault.guardianPause();
        vm.warp(block.timestamp + 1);
        vm.prank(g[1]);
        vault.guardianPause();
        require(vault.paused() && vault.pauseCount() == 2, "a guardian may pause again after the cooldown");
        checkBooks();
        checkBacked();
    }

    // ================================================================ fuzz

    /// Any accepted deposit: fee + net == gross, the id and head follow the formulas, the books balance.
    function testFuzz_depositAccounting(uint64 gross, address l2) public {
        gross = MIN_DEPOSIT + gross % (BUCKET - MIN_DEPOSIT + 1);
        if (l2 == address(0)) l2 = BOB;
        bytes32 id = depositAs(ALICE, gross, l2);
        uint64 f = fee(gross, DEP_BPS);
        require(vault.totalLocked() == gross - f && vault.feesAccrued() == f && gross - f >= MIN_BURN, "net and fee");
        require(id == TronVaultFormulas.depositId(vault.routeId(), 0, ALICE, gross - f, pad(l2)), "id");
        checkBooks();
        checkBacked();
    }

    /// Any release up to the locked amount and the bucket: exact deltas with the false-returning transfer.
    function testFuzz_releaseAccounting(uint64 gross, uint64 amount) public {
        gross = MIN_DEPOSIT + gross % (BUCKET - MIN_DEPOSIT + 1);
        depositAs(ALICE, gross, ALICE);
        amount = 1 + amount % vault.totalLocked();
        uint256 before = usdt.balanceOf(address(vault));
        release(cleanBurn(BOB, amount, 1));
        uint64 f = fee(amount, REL_BPS);
        require(usdt.balanceOf(BOB) == amount - f && usdt.balanceOf(address(vault)) == before - (amount - f), "deltas");
        checkBooks();
        checkBacked();
    }
}
