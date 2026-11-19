// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity 0.8.24;

// Reviewer 423 (round 20): the certificate, context and constructor refusals of the frozen vault's suites
// (A172VaultReview, AuditR7V3, R10BridgeParams), which the native-ether line did not port, asked of
// NativeEtherSourceVault directly. Review branch only.
import {NativeEtherSourceVault} from "../contracts/eth/NativeEtherSourceVault.sol";
import {NativeEtherVaultBase} from "./NativeEtherVaultBase.sol";

contract R423NativeEtherCertificatesTest is NativeEtherVaultBase {
    bytes4 immutable CERT = NativeEtherSourceVault.InvalidCertificate.selector;
    bytes4 immutable CTX = NativeEtherSourceVault.InvalidContext.selector;
    bytes4 immutable REL = NativeEtherSourceVault.InvalidRelease.selector;
    NativeEtherSourceVault.Release r;
    NativeEtherSourceVault.ReleaseContext c;

    function setUp() public {
        baseSetUp();
        depositAs(ALICE, 10_000_000, ALICE);
        r = cleanBurn(BOB, 1_000_000, 1);
        c = context();
    }

    function attempt(bytes[] memory s) internal returns (bytes4 e) {
        Snap memory before = snap();
        (bool ok, bytes memory ret) = address(vault).call(abi.encodeCall(NativeEtherSourceVault.release, (r, c, s)));
        require(!ok, "R423: accepted");
        require(unchanged(before) && unused(r) && BOB.balance == 0, "R423: a refused release changed state");
        e = err(ret);
    }

    function good() internal view returns (bytes[] memory) {
        return cert(vault.releaseDigest(r, c), 5);
    }

    function test_R423_signatureForms() public {
        bytes32 d = vault.releaseDigest(r, c);
        bytes[] memory s = good();
        // high s (the malleable twin of a valid signature)
        (uint8 v, bytes32 rr, bytes32 ss) = vm.sign(keys[0], d);
        s[0] = abi.encodePacked(rr, bytes32(CURVE_N - uint256(ss)), v == 27 ? uint8(28) : uint8(27));
        require(attempt(s) == CERT, "high s");
        // v = 0 / 1
        s = good();
        s[0] = abi.encodePacked(rr, ss, uint8(v - 27));
        require(attempt(s) == CERT, "v 0/1");
        // 64 and 66 bytes
        s = good();
        s[0] = abi.encodePacked(rr, ss);
        require(attempt(s) == CERT, "64 bytes");
        s[0] = abi.encodePacked(rr, ss, v, uint8(0));
        require(attempt(s) == CERT, "66 bytes");
        // order swapped, a duplicate, a stranger, a guardian
        s = good();
        (s[0], s[1]) = (s[1], s[0]);
        require(attempt(s) == CERT, "descending order");
        s = good();
        s[1] = s[0];
        require(attempt(s) == CERT, "duplicate signer");
        s = good();
        s[4] = sig(0xBEEF, d);
        require(attempt(s) == CERT, "stranger");
        s = good();
        s[4] = sig(guardKeys[0], d);
        require(attempt(s) == CERT, "guardian as signer");
        // five copies of one signature; eight signatures; none
        s = new bytes[](5);
        for (uint256 i; i < 5; ++i) s[i] = sig(keys[0], d);
        require(attempt(s) == CERT, "one signer five times");
        s = new bytes[](8);
        for (uint256 i; i < 8; ++i) s[i] = sig(keys[i % 7], d);
        require(attempt(s) == CERT, "eight signatures");
        require(attempt(new bytes[](0)) == CERT, "no signature");
        // signed over another digest kind of the same vault (controls), same signers
        uint256 until = block.timestamp + 100;
        require(attempt(cert(vault.controlDigest(false, false, 1, until), 5)) == CERT, "controls certificate as release");
        require(attempt(cert(vault.unpauseDigest(0, until), 6)) == CERT, "unpause certificate as release");
        // the raw authorization without the EIP-191 prefix
        bytes32 raw = keccak256(
            abi.encode(
                bytes32("BLOCH-USDT-RELEASE-AUTH-v2"), block.chainid, address(vault), vault.releaseId(r), c.validUntil,
                c.sourceAnchorNumber, c.sourceAnchorHash, uint256(c.nativeFinalizedNumber), c.nativeFinalizedHash
            )
        );
        require(keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", raw)) == d, "control: digest formula");
        require(attempt(cert(raw, 5)) == CERT, "unprefixed authorization");
        // control
        vault.release(r, c, good());
        require(BOB.balance == wei_(1_000_000 - relFee(1_000_000)), "control: the good certificate pays");
    }

    function test_R423_contextRefusals() public {
        NativeEtherSourceVault.ReleaseContext memory keep = c;
        // every context field is signed: changing one after signing breaks the certificate
        bytes[] memory s = good();
        c.validUntil += 1;
        require(attempt(s) == CERT, "validUntil not bound");
        c = keep;
        c.nativeFinalizedNumber += 1;
        require(attempt(s) == CERT, "native number not bound");
        c = keep;
        c.nativeFinalizedHash = keccak256("other");
        require(attempt(s) == CERT, "native hash not bound");
        // properly signed but unacceptable contexts
        c = keep;
        c.sourceAnchorHash = keccak256("fork");
        require(attempt(good()) == CTX, "anchor of another fork");
        c = keep;
        c.sourceAnchorNumber = block.number;
        require(attempt(good()) == CTX, "anchor not in the past");
        c = keep;
        c.sourceAnchorHash = 0;
        require(attempt(good()) == CTX, "zero anchor hash");
        c = keep;
        c.nativeFinalizedHash = 0;
        require(attempt(good()) == CTX, "zero native hash");
        c = keep;
        s = good();
        vm.roll(block.number + 257); // the anchor leaves the blockhash window
        require(attempt(s) == CTX, "anchor older than 256 blocks");
        vm.roll(block.number - 257);
        vm.setBlockhash(c.sourceAnchorNumber, c.sourceAnchorHash);
        vm.warp(c.validUntil + 1);
        require(attempt(s) == REL, "expired certificate");
        vm.warp(c.validUntil);
        vault.release(r, c, s);
        require(BOB.balance == wei_(1_000_000 - relFee(1_000_000)), "control: valid at validUntil exactly");
    }

    struct Shape {
        uint8 threshold;
        uint8 sw;
        uint64 delay;
        uint64 window;
        uint64 minDep;
        uint64 minBurn;
        uint16 dep;
        uint16 rel;
        address feeTo;
    }

    function ctor(Shape memory p) external returns (address) {
        NativeEtherSourceVault.Policy memory pol = NativeEtherSourceVault.Policy(p.window, WINDOW, p.sw, p.delay, p.minDep, p.minBurn);
        NativeEtherSourceVault.Provenance memory prov =
            NativeEtherSourceVault.Provenance(1, 0, address(0), NativeEtherSourceVault.Fees(p.feeTo, p.dep, p.rel));
        return address(
            new NativeEtherSourceVault(
                SRC, NAT, ASSET, NATIVE_ETHER, CAP, 0, addrs(keys), p.threshold, pol,
                NativeEtherSourceVault.Guard(guardians(), 72 hours, 72 hours), prov
            )
        );
    }

    function refused(bytes memory call_) internal returns (bool) {
        (bool ok, bytes memory ret) = address(this).call(call_);
        return !ok && err(ret) == NativeEtherSourceVault.InvalidConfiguration.selector;
    }

    function test_R423_constructorRefusals() public {
        require(!refused(abi.encodeCall(this.ctor, (Shape(5, 6, 14 days, BUCKET, MIN_DEPOSIT, MIN_BURN, 5, 10, TREASURY)))), "control");
        require(refused(abi.encodeCall(this.ctor, (Shape(1, 6, 14 days, BUCKET, MIN_DEPOSIT, MIN_BURN, 5, 10, TREASURY)))), "threshold 1");
        require(refused(abi.encodeCall(this.ctor, (Shape(8, 8, 14 days, BUCKET, MIN_DEPOSIT, MIN_BURN, 5, 10, TREASURY)))), "threshold 8 of 7");
        require(refused(abi.encodeCall(this.ctor, (Shape(5, 4, 14 days, BUCKET, MIN_DEPOSIT, MIN_BURN, 5, 10, TREASURY)))), "switch below threshold");
        require(refused(abi.encodeCall(this.ctor, (Shape(5, 6, 7 days - 1, BUCKET, MIN_DEPOSIT, MIN_BURN, 5, 10, TREASURY)))), "switch delay under 7 days");
        require(refused(abi.encodeCall(this.ctor, (Shape(5, 6, 14 days, CAP + 1, MIN_DEPOSIT, MIN_BURN, 5, 10, TREASURY)))), "window above cap");
        require(refused(abi.encodeCall(this.ctor, (Shape(5, 6, 14 days, 0, MIN_DEPOSIT, MIN_BURN, 5, 10, TREASURY)))), "window 0");
        require(refused(abi.encodeCall(this.ctor, (Shape(5, 6, 14 days, BUCKET, BUCKET + 1, MIN_BURN, 5, 10, TREASURY)))), "minDeposit above window");
        require(refused(abi.encodeCall(this.ctor, (Shape(5, 6, 14 days, BUCKET, MIN_DEPOSIT, 0, 5, 10, TREASURY)))), "l2MinBurn 0");
        require(refused(abi.encodeCall(this.ctor, (Shape(5, 6, 14 days, BUCKET, 10_005, 10_000, 5, 10, TREASURY)))), "minDeposit nets below minBurn (fee rounded up)");
        require(!refused(abi.encodeCall(this.ctor, (Shape(5, 6, 14 days, BUCKET, 10_006, 10_000, 5, 10, TREASURY)))), "control: 10,006 nets 10,000");
        require(refused(abi.encodeCall(this.ctor, (Shape(5, 6, 14 days, BUCKET, MIN_DEPOSIT, MIN_BURN, 31, 10, TREASURY)))), "deposit fee above 30 bps");
        require(refused(abi.encodeCall(this.ctor, (Shape(5, 6, 14 days, BUCKET, MIN_DEPOSIT, MIN_BURN, 5, 31, TREASURY)))), "release fee above 30 bps");
        require(refused(abi.encodeCall(this.ctor, (Shape(5, 6, 14 days, BUCKET, MIN_DEPOSIT, MIN_BURN, 5, 10, address(0))))), "fees without a recipient");
        require(refused(abi.encodeCall(this.ctor, (Shape(5, 6, 14 days, BUCKET, MIN_DEPOSIT, MIN_BURN, 0, 0, TREASURY)))), "a recipient without fees");
        // the decided mainnet shape and the shape recommended by this review are both constructible
        require(!refused(abi.encodeCall(this.ctor, (Shape(5, 6, 14 days, BUCKET, 7_004_000, 7_000_000, 5, 10, TREASURY)))), "7.004 / 7");
        require(!refused(abi.encodeCall(this.ctor, (Shape(5, 6, 14 days, BUCKET, 501_000, 500_000, 5, 10, TREASURY)))), "0.501 / 0.5");
        require(refused(abi.encodeCall(this.ctor, (Shape(5, 6, 14 days, BUCKET, 500_250, 500_000, 5, 10, TREASURY)))), "0.50025 nets below 0.5");
        require(!refused(abi.encodeCall(this.ctor, (Shape(5, 6, 14 days, BUCKET, 500_251, 500_000, 5, 10, TREASURY)))), "0.500251 nets 0.5");
    }
}
