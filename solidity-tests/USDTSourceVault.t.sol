// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity 0.8.24;

import {USDTSourceVault} from "../contracts/usdt/USDTSourceVault.sol";

interface UsdtVm {
    function etch(address target, bytes calldata code) external;
    function store(address target, bytes32 slot, bytes32 value) external;
    function addr(uint256) external returns (address);
    function sign(uint256, bytes32) external returns (uint8, bytes32, bytes32);
    function expectRevert() external;
    function expectRevert(bytes4 selector) external;
    function warp(uint256) external;
}

contract MockSourceUSDT {
    uint8 public decimals = 6;
    mapping(address => uint256) public balanceOf;
    uint8 public mode; // 0 normal, 1 no-return, 2 false/no move, 3 taxed, 4 revert, 5 false/success, 6 callback
    address public callback;
    bool public callbackSucceeded;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    // Model reserve destruction by an external token issuer, not a vault method.
    function destroy(address from, uint256 amount) external {
        balanceOf[from] -= amount;
    }

    function configure(uint8 m, address cb) external {
        mode = m;
        callback = cb;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        return move(from, to, amount);
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        return move(msg.sender, to, amount);
    }

    function move(address from, address to, uint256 amount) private returns (bool) {
        require(mode != 4, "blacklisted");
        if (mode == 2) return false;
        balanceOf[from] -= amount;
        balanceOf[to] += mode == 3 ? amount - 1 : amount;
        if (mode == 6) {
            (callbackSucceeded,) =
                callback.call(abi.encodeCall(USDTSourceVault.deposit, (uint64(1), bytes32(uint256(1)))));
        }
        if (mode == 1) {
            assembly {
                return(0, 0)
            }
        }
        return mode != 5;
    }
}

contract USDTSourceVaultTest {
    UsdtVm constant vm = UsdtVm(address(uint160(uint256(keccak256("hevm cheat code")))));
    MockSourceUSDT token;
    USDTSourceVault vault;
    uint256 key0;
    uint256 key1;

    function committee() private returns (address[] memory s) {
        s = new address[](2);
        key0 = 11;
        key1 = 12;
        if (vm.addr(key0) > vm.addr(key1)) (key0, key1) = (key1, key0);
        s[0] = vm.addr(key0);
        s[1] = vm.addr(key1);
    }

    function deployPaused(uint8 mode, bytes32 domain) private returns (USDTSourceVault) {
        return new USDTSourceVault(
            domain, bytes32(uint256(2)), bytes32(uint256(3)), address(token), 1_000_000, mode, committee(), 2
        );
    }

    function controlCert(
        USDTSourceVault subject,
        bool depositsEnabled,
        bool releasesEnabled,
        uint64 nonce,
        uint256 deadline
    ) private returns (bytes[] memory sigs) {
        sigs = new bytes[](2);
        bytes32 h = subject.controlDigest(depositsEnabled, releasesEnabled, nonce, deadline);
        (uint8 v, bytes32 rr, bytes32 ss) = vm.sign(key0, h);
        sigs[0] = abi.encodePacked(rr, ss, v);
        (v, rr, ss) = vm.sign(key1, h);
        sigs[1] = abi.encodePacked(rr, ss, v);
    }

    function controls(USDTSourceVault subject, bool depositsEnabled, bool releasesEnabled, uint64 nonce) private {
        subject.setControls(
            depositsEnabled,
            releasesEnabled,
            nonce,
            100,
            controlCert(subject, depositsEnabled, releasesEnabled, nonce, 100)
        );
    }

    function deploy(uint8 mode, bytes32 domain) private returns (USDTSourceVault subject) {
        subject = deployPaused(mode, domain);
        controls(subject, true, true, 0);
    }

    function setUp() public {
        token = new MockSourceUSDT();
        vault = deploy(0, bytes32(uint256(1)));
        token.mint(address(this), 2_000_000);
    }

    function item() private view returns (USDTSourceVault.Release memory r) {
        r = USDTSourceVault.Release(vault.routeId(), 0, address(123), 40, bytes32(uint256(99)));
    }

    function certFor(USDTSourceVault subject, USDTSourceVault.Release memory r, uint256 deadline)
        private
        returns (bytes[] memory sigs)
    {
        sigs = new bytes[](2);
        bytes32 h = subject.releaseDigest(r, deadline);
        (uint8 v, bytes32 rr, bytes32 ss) = vm.sign(key0, h);
        sigs[0] = abi.encodePacked(rr, ss, v);
        (v, rr, ss) = vm.sign(key1, h);
        sigs[1] = abi.encodePacked(rr, ss, v);
    }

    function cert(USDTSourceVault.Release memory r, uint256 deadline) private returns (bytes[] memory sigs) {
        return certFor(vault, r, deadline);
    }

    function deposit() private {
        vault.deposit(100, bytes32(uint256(8)));
    }

    function testDeploymentStartsPausedAndThresholdControlsAreReplayProtected() public {
        USDTSourceVault subject = deployPaused(0, bytes32(uint256(91)));
        require(!subject.depositsEnabled() && !subject.releasesEnabled() && subject.controlNonce() == 0);
        vm.expectRevert(USDTSourceVault.InvalidTransfer.selector);
        subject.deposit(1, bytes32(uint256(1)));

        bytes[] memory short = new bytes[](1);
        short[0] = controlCert(subject, true, false, 0, 100)[0];
        vm.expectRevert(USDTSourceVault.InvalidCertificate.selector);
        subject.setControls(true, false, 0, 100, short);

        controls(subject, true, false, 0);
        require(subject.depositsEnabled() && !subject.releasesEnabled() && subject.controlNonce() == 1);
        subject.deposit(100, bytes32(uint256(8)));
        USDTSourceVault.Release memory r =
            USDTSourceVault.Release(subject.routeId(), 0, address(123), 40, bytes32(uint256(99)));
        bytes[] memory releaseSignatures = certFor(subject, r, 100);
        vm.expectRevert(USDTSourceVault.InvalidRelease.selector);
        subject.release(r, 100, releaseSignatures);

        bytes[] memory noOpSignatures = controlCert(subject, true, false, 1, 100);
        vm.expectRevert(USDTSourceVault.InvalidControls.selector);
        subject.setControls(true, false, 1, 100, noOpSignatures);

        bytes[] memory replaySignatures = controlCert(subject, true, false, 0, 100);
        vm.expectRevert(USDTSourceVault.InvalidControls.selector);
        subject.setControls(true, false, 0, 100, replaySignatures);

        bytes[] memory wrongFlagsSignatures = controlCert(subject, true, false, 1, 100);
        vm.expectRevert(USDTSourceVault.InvalidCertificate.selector);
        subject.setControls(true, true, 1, 100, wrongFlagsSignatures);

        USDTSourceVault other = deployPaused(0, bytes32(uint256(91)));
        bytes[] memory wrongVaultSignatures = controlCert(subject, true, true, 1, 100);
        vm.expectRevert(USDTSourceVault.InvalidCertificate.selector);
        other.setControls(true, true, 0, 100, wrongVaultSignatures);

        controls(subject, true, true, 1);
        subject.release(r, 100, certFor(subject, r, 100));
        controls(subject, false, false, 2);
        vm.expectRevert(USDTSourceVault.InvalidTransfer.selector);
        subject.deposit(1, bytes32(uint256(1)));
        require(!subject.depositsEnabled() && !subject.releasesEnabled() && subject.controlNonce() == 3);
    }

    function testExpiredControlCertificateIsRejected() public {
        USDTSourceVault subject = deployPaused(0, bytes32(uint256(92)));
        bytes[] memory signatures = controlCert(subject, true, false, 0, 100);
        vm.warp(101);
        vm.expectRevert(USDTSourceVault.InvalidControls.selector);
        subject.setControls(true, false, 0, 100, signatures);
    }

    function testCommitteeReadbackIsCompleteAndStableAcrossDeposit() public {
        require(vault.signerCount() == 2);
        require(vault.threshold() == 2);
        for (uint256 i; i < vault.signerCount(); ++i) {
            require(vault.isSigner(vault.signers(i)));
        }
        uint256 count = vault.signerCount();
        vm.expectRevert();
        vault.signers(count);
        deposit();
        require(vault.signerCount() == 2);
        require(vault.signers(0) == vm.addr(key0) && vault.signers(1) == vm.addr(key1));
    }

    function testNormalNoReturnAndTronFalseSuccess() public {
        for (uint8 i; i < 3; i++) {
            vault = deploy(i == 2 ? 1 : 0, bytes32(uint256(i + 10)));
            token.configure(i == 2 ? 5 : i, address(0));
            deposit();
            USDTSourceVault.Release memory r = item();
            vault.release(r, 100, cert(r, 100));
            require(vault.totalLocked() == 60 && token.balanceOf(address(vault)) == 60);
        }
        require(token.balanceOf(address(123)) == 120);
    }

    function testBadTokenDepositsRollbackBothModes() public {
        for (uint8 policy; policy < 2; policy++) {
            vault = deploy(policy, bytes32(uint256(20 + policy)));
            for (uint8 mode = 2; mode <= 4; mode++) {
                token.configure(mode, address(0));
                uint256 before = token.balanceOf(address(this));
                vm.expectRevert();
                deposit();
                require(
                    vault.totalLocked() == 0 && vault.depositCount() == 0 && token.balanceOf(address(vault)) == 0
                        && token.balanceOf(address(this)) == before
                );
            }
        }
    }

    function testFalseSuccessRejectedByEthereumPolicy() public {
        token.configure(5, address(0));
        vm.expectRevert();
        deposit();
        require(vault.totalLocked() == 0);
    }

    function testPayoutFailuresRollbackNullifiersAndLiabilities() public {
        deposit();
        USDTSourceVault.Release memory r = item();
        bytes[] memory sigs = cert(r, 100);
        for (uint8 mode = 2; mode <= 4; mode++) {
            token.configure(mode, address(0));
            vm.expectRevert();
            vault.release(r, 100, sigs);
            require(vault.totalLocked() == 100 && !vault.releasedNonce(0) && !vault.releasedBurn(r.nativeBurn));
            require(token.balanceOf(address(vault)) == 100 && token.balanceOf(address(123)) == 0);
        }
        token.configure(0, address(0));
        vault.release(r, 100, sigs);
        require(vault.totalLocked() == 60);
    }

    function rejected(USDTSourceVault.Release memory r) private {
        bytes[] memory signatures = cert(r, 100);
        vm.expectRevert();
        vault.release(r, 100, signatures);
    }

    function testReplayNonceBurnAndWrongRouteFail() public {
        deposit();
        USDTSourceVault.Release memory r = item();
        vault.release(r, 100, cert(r, 100));
        rejected(r);
        r.nonce = 1;
        rejected(r);
        r.nonce = 0;
        r.nativeBurn = bytes32(uint256(100));
        rejected(r);
        r.nonce = 2;
        r.route = bytes32(uint256(999));
        rejected(r);
        require(vault.totalLocked() == 60);
    }

    function testCertificateMalformedDuplicateUnsortedWrongMessageAndExpired() public {
        deposit();
        USDTSourceVault.Release memory r = item();
        bytes[] memory sigs = cert(r, 100);
        bytes[] memory bad = new bytes[](2);
        bad[0] = sigs[0];
        bad[1] = sigs[0];
        vm.expectRevert();
        vault.release(r, 100, bad);
        bad[0] = sigs[1];
        bad[1] = sigs[0];
        vm.expectRevert();
        vault.release(r, 100, bad);
        bad[0] = hex"01";
        vm.expectRevert();
        vault.release(r, 100, bad);
        r.amount = 41;
        vm.expectRevert();
        vault.release(r, 100, sigs);
        r.amount = 40;
        vm.expectRevert();
        vault.release(r, 101, sigs);
        vm.warp(101);
        vm.expectRevert();
        vault.release(r, 100, sigs);
        require(vault.totalLocked() == 100);
    }

    function testCapZeroInputsAndDomainSeparation() public {
        vm.expectRevert();
        vault.deposit(0, bytes32(uint256(1)));
        vm.expectRevert();
        vault.deposit(1, bytes32(0));
        vm.expectRevert();
        vault.deposit(1_000_001, bytes32(uint256(1)));
        require(vault.depositCount() == 0);
        USDTSourceVault other = deploy(1, bytes32(uint256(77)));
        require(vault.routeId() != other.routeId());
        require(
            vault.depositId(0, address(this), 1, bytes32(uint256(1)))
                != other.depositId(0, address(this), 1, bytes32(uint256(1)))
        );
    }

    function testTokenCallbackCannotReenter() public {
        token.configure(6, address(vault));
        deposit();
        require(!token.callbackSucceeded());
        USDTSourceVault.Release memory r = item();
        vault.release(r, 100, cert(r, 100));
        require(!token.callbackSucceeded() && vault.totalLocked() == 60);
    }

    function testFuzzExactBackingAcrossDepositAndRelease(uint64 raw, uint64 spent) public {
        uint64 amount = raw % 1_000_000 + 1;
        vault.deposit(amount, bytes32(uint256(8)));
        USDTSourceVault.Release memory r = item();
        r.amount = spent % amount + 1;
        vault.release(r, 100, cert(r, 100));
        require(vault.totalLocked() == amount - r.amount);
        require(token.balanceOf(address(vault)) == vault.totalLocked());
        require(token.balanceOf(address(123)) == r.amount);
    }

    function testHighSInvalidVAndInsufficientQuorum() public {
        deposit();
        USDTSourceVault.Release memory r = item();
        bytes[] memory sigs = cert(r, 100);
        bytes[] memory short = new bytes[](1);
        short[0] = sigs[0];
        vm.expectRevert();
        vault.release(r, 100, short);
        sigs[0][64] = bytes1(uint8(0));
        vm.expectRevert();
        vault.release(r, 100, sigs);
        sigs = cert(r, 100);
        for (uint256 i = 32; i < 64; ++i) {
            sigs[0][i] = 0xff;
        }
        vm.expectRevert();
        vault.release(r, 100, sigs);
        require(vault.totalLocked() == 100);
    }

    function testInvalidCommitteeAndTransferPolicy() public {
        address[] memory s = committee();
        vm.expectRevert();
        new USDTSourceVault(bytes32(uint256(1)), bytes32(uint256(2)), bytes32(uint256(3)), address(token), 100, 0, s, 1);
        vm.expectRevert();
        new USDTSourceVault(bytes32(uint256(1)), bytes32(uint256(2)), bytes32(uint256(3)), address(token), 100, 2, s, 2);
        s[1] = s[0];
        vm.expectRevert();
        new USDTSourceVault(bytes32(uint256(1)), bytes32(uint256(2)), bytes32(uint256(3)), address(token), 100, 0, s, 2);
    }

    function testIndependentPythonAndRustWireVectors() public {
        // Copy runtime to fixed synthetic addresses solely to test address-bound IDs.
        address fixedToken = 0x4444444444444444444444444444444444444444;
        address fixedVault = 0x5555555555555555555555555555555555555555;
        vm.etch(fixedToken, address(token).code);
        vm.store(fixedToken, bytes32(0), bytes32(uint256(6)));
        bytes32[2] memory domains = [
            bytes32(uint256(0x1111111111111111111111111111111111111111111111111111111111111111)),
            bytes32(uint256(0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa))
        ];
        bytes32[2] memory routes = [
            bytes32(0xbedfb1847536bad45596e081fd252de7706dd95a67a451dd590943753a79e365),
            bytes32(0x9b9eab23042ff74bfa60b50e710f7c3851b282568a192118428af5fb0b1c488a)
        ];
        bytes32[2] memory deposits = [
            bytes32(0x9856510a180e52c66e907abc5a4c2294273d4b0854ad93e0910e7d6a628cf89d),
            bytes32(0x27f7a7b64559c4bf0196c3907924e97346292b0ea037a59e409d9b481878d0fd)
        ];
        bytes32[2] memory releases = [
            bytes32(0xb0601056ff581bfd91e0b233f806f477958c68c3fe8fabc9bed9e212917b533a),
            bytes32(0x939cc0db9088b7d8aa7018e423298d0baeaf6f54122c80b5cf864c3145d8f48b)
        ];
        for (uint256 i; i < 2; ++i) {
            USDTSourceVault configured = new USDTSourceVault(
                domains[i],
                0x2222222222222222222222222222222222222222222222222222222222222222,
                0x3333333333333333333333333333333333333333333333333333333333333333,
                fixedToken,
                10_000_000_000,
                uint8(i),
                committee(),
                2
            );
            vm.etch(fixedVault, address(configured).code);
            USDTSourceVault subject = USDTSourceVault(fixedVault);
            require(subject.routeId() == routes[i]);
            require(
                subject.depositId(
                    0x0102030405060708,
                    0x6666666666666666666666666666666666666666,
                    123_456_789,
                    0x8888888888888888888888888888888888888888888888888888888888888888
                ) == deposits[i]
            );
            USDTSourceVault.Release memory r = USDTSourceVault.Release(
                routes[i],
                0x0102030405060708,
                0x7777777777777777777777777777777777777777,
                123_456_789,
                0x9999999999999999999999999999999999999999999999999999999999999999
            );
            require(subject.releaseId(r) == releases[i]);
        }
        require(routes[0] != routes[1] && deposits[0] != deposits[1] && releases[0] != releases[1]);
    }

    function testDonationsCannotCreateDepositCredit() public {
        token.mint(address(vault), 123);
        token.configure(2, address(0));
        vm.expectRevert();
        deposit();
        require(vault.totalLocked() == 0 && vault.depositCount() == 0 && token.balanceOf(address(vault)) == 123);
    }

    function testReserveLossBlocksDepositsAndEvenAffordableReleasesUntilReplenished() public {
        for (uint8 policy; policy < 2; ++policy) {
            vault = deploy(policy, bytes32(uint256(80 + policy)));
            token.configure(policy == 1 ? 5 : 0, address(0));
            deposit();
            token.destroy(address(vault), 1);
            USDTSourceVault.Release memory r = item();
            bytes[] memory sigs = cert(r, 100);
            uint256 senderBefore = token.balanceOf(address(this));
            uint256 recipientBefore = token.balanceOf(r.recipient);
            vm.expectRevert(USDTSourceVault.InsufficientBacking.selector);
            deposit();
            require(token.balanceOf(address(this)) == senderBefore);
            require(vault.depositCount() == 1 && vault.totalLocked() == 100);
            // There are enough tokens for this payout, but not all liabilities.
            vm.expectRevert(USDTSourceVault.InsufficientBacking.selector);
            vault.release(r, 100, sigs);
            require(!vault.releasedNonce(r.nonce) && !vault.releasedBurn(r.nativeBurn));
            require(token.balanceOf(address(vault)) == 99 && vault.totalLocked() == 100);
            require(token.balanceOf(r.recipient) == recipientBefore);
            // External replenishment restores backing without creating claims.
            token.mint(address(vault), 1);
            vault.release(r, 100, sigs);
            require(token.balanceOf(address(vault)) == 60 && vault.totalLocked() == 60);
            deposit();
            require(vault.depositCount() == 2 && vault.totalLocked() == 160);
        }
    }

    function testFuzzDonatedSurplusIsPreserved(uint64 rawSurplus, uint64 rawLoss) public {
        uint256 surplus = uint256(rawSurplus) + 1;
        uint256 loss = uint256(rawLoss) % (surplus + 1);
        deposit();
        token.mint(address(vault), surplus);
        token.destroy(address(vault), loss);
        USDTSourceVault.Release memory r = item();
        vault.release(r, 100, cert(r, 100));
        deposit();
        require(token.balanceOf(address(vault)) == uint256(vault.totalLocked()) + surplus - loss);
        require(vault.totalLocked() == 160 && vault.depositCount() == 2);
    }
}
