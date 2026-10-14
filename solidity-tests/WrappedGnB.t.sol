// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.24;

import {WrappedGnB} from "../contracts/wgnb/WrappedGnB.sol";

interface Vm {
    struct Log {
        bytes32[] topics;
        bytes data;
        address emitter;
    }

    function addr(uint256 privateKey) external pure returns (address);
    function sign(uint256 privateKey, bytes32 digest) external pure returns (uint8 v, bytes32 r, bytes32 s);
    function warp(uint256 timestamp) external;
    function chainId(uint256 newChainId) external;
    function prank(address sender) external;
    function expectRevert(bytes calldata data) external;
    function assume(bool condition) external;
    function recordLogs() external;
    function getRecordedLogs() external returns (Log[] memory);
}

contract WrappedGnBTest {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    uint32 private constant GNB_TESTNET = 0x474E0002;
    uint32 private constant GNB_MAINNET = 0x474E0001;
    uint256 private constant L2_CHAIN = 700771;
    uint256 private constant PERIOD = 1 days;
    uint256 private constant PERIOD_CAP = 1_000e8;
    uint256 private constant SUPPLY_CAP = 10_000e8;
    uint256 private constant MIN_BURN = 100_000;
    uint256 private constant HALF_N = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;
    uint256 private constant N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    WrappedGnB private w;
    uint256[3] private keys; // sorted by address, ascending
    address private alice = address(0xA11CE);
    address private bob = address(0xB0B);
    bytes32 private constant TXID = keccak256("lock-1");

    function setUp() public {
        vm.chainId(L2_CHAIN);
        vm.warp(1_760_000_000);
        uint256[3] memory k = [uint256(0x51), 0x52, 0x53];
        // insertion sort by address so tests can sign "in order"
        for (uint256 i = 1; i < 3; ++i) {
            for (uint256 j = i; j > 0 && vm.addr(k[j]) < vm.addr(k[j - 1]); --j) {
                (k[j], k[j - 1]) = (k[j - 1], k[j]);
            }
        }
        keys = k;
        w = _deploy(GNB_TESTNET, 2);
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    function _signerAddrs() private view returns (address[] memory a) {
        a = new address[](3);
        for (uint256 i; i < 3; ++i) a[i] = vm.addr(keys[i]);
    }

    function _deploy(uint32 gnb, uint256 k) private returns (WrappedGnB) {
        return new WrappedGnB(gnb, _signerAddrs(), k, PERIOD, PERIOD_CAP, SUPPLY_CAP, MIN_BURN);
    }

    function _sig(uint256 key, bytes32 digest) private pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        return abi.encodePacked(r, s, v);
    }

    function _sigs2(WrappedGnB t, uint256 a, uint256 b, bytes32 txid, uint32 vout, uint64 amt, address to)
        private
        view
        returns (bytes memory)
    {
        bytes32 d = t.mintDigest(txid, vout, amt, to);
        return bytes.concat(_sig(a, d), _sig(b, d));
    }

    function _mint(bytes32 txid, uint64 amt, address to) private {
        w.mint(txid, 0, amt, to, _sigs2(w, keys[0], keys[1], txid, 0, amt, to));
    }

    function _eq(uint256 a, uint256 b, string memory what) private pure {
        require(a == b, what);
    }

    // ── constructor ──────────────────────────────────────────────────────────

    function testConstructorStoresConfig() public view {
        _eq(w.gnbChainId(), GNB_TESTNET, "chain");
        _eq(w.threshold(), 2, "k");
        _eq(w.periodLength(), PERIOD, "period");
        _eq(w.periodMintCap(), PERIOD_CAP, "pcap");
        _eq(w.supplyCap(), SUPPLY_CAP, "scap");
        _eq(w.minBurn(), MIN_BURN, "minburn");
        _eq(w.decimals(), 8, "decimals");
        address[] memory s = w.signers();
        _eq(s.length, 3, "n");
        for (uint256 i; i < 3; ++i) require(w.isSigner(s[i]) && s[i] == vm.addr(keys[i]), "signer");
        require(!w.isSigner(address(this)), "not signer");
    }

    function testConstructorRejectsBadConfig() public {
        address[] memory s = _signerAddrs();
        bytes memory bad = abi.encodeWithSelector(WrappedGnB.BadConfig.selector);
        vm.expectRevert(bad);
        new WrappedGnB(0, s, 2, PERIOD, PERIOD_CAP, SUPPLY_CAP, MIN_BURN);
        vm.expectRevert(bad);
        new WrappedGnB(GNB_TESTNET, s, 0, PERIOD, PERIOD_CAP, SUPPLY_CAP, MIN_BURN);
        vm.expectRevert(bad);
        new WrappedGnB(GNB_TESTNET, s, 4, PERIOD, PERIOD_CAP, SUPPLY_CAP, MIN_BURN);
        vm.expectRevert(bad);
        new WrappedGnB(GNB_TESTNET, new address[](0), 1, PERIOD, PERIOD_CAP, SUPPLY_CAP, MIN_BURN);
        vm.expectRevert(bad);
        new WrappedGnB(GNB_TESTNET, s, 2, 0, PERIOD_CAP, SUPPLY_CAP, MIN_BURN);
        vm.expectRevert(bad);
        new WrappedGnB(GNB_TESTNET, s, 2, PERIOD, 0, SUPPLY_CAP, MIN_BURN);
        vm.expectRevert(bad);
        new WrappedGnB(GNB_TESTNET, s, 2, PERIOD, SUPPLY_CAP + 1, SUPPLY_CAP, MIN_BURN);
        vm.expectRevert(bad);
        new WrappedGnB(GNB_TESTNET, s, 2, PERIOD, PERIOD_CAP, uint256(type(uint64).max) + 1, MIN_BURN);
        vm.expectRevert(bad);
        new WrappedGnB(GNB_TESTNET, s, 2, PERIOD, PERIOD_CAP, SUPPLY_CAP, 0);

        address[] memory dup = new address[](2);
        dup[0] = s[0];
        dup[1] = s[0];
        vm.expectRevert(bad);
        new WrappedGnB(GNB_TESTNET, dup, 1, PERIOD, PERIOD_CAP, SUPPLY_CAP, MIN_BURN);

        address[] memory zero = new address[](2);
        zero[0] = s[0];
        vm.expectRevert(bad);
        new WrappedGnB(GNB_TESTNET, zero, 1, PERIOD, PERIOD_CAP, SUPPLY_CAP, MIN_BURN);

        address[] memory eight = new address[](8);
        for (uint256 i; i < 8; ++i) eight[i] = address(uint160(i + 1));
        vm.expectRevert(bad);
        new WrappedGnB(GNB_TESTNET, eight, 5, PERIOD, PERIOD_CAP, SUPPLY_CAP, MIN_BURN);
    }

    function testNoAdminSurface() public {
        string[6] memory fns = ["owner()", "pause()", "setSigners(address[])", "setCaps(uint256,uint256)",
            "upgradeTo(address)", "transferOwnership(address)"];
        for (uint256 i; i < fns.length; ++i) {
            (bool ok,) = address(w).call(abi.encodeWithSignature(fns[i]));
            require(!ok, fns[i]);
        }
    }

    // ── mint: accepted ───────────────────────────────────────────────────────

    function testMintEverySignerPair() public {
        uint256[2][3] memory pairs = [[uint256(0), 1], [uint256(0), 2], [uint256(1), 2]];
        for (uint256 p; p < 3; ++p) {
            bytes32 txid = keccak256(abi.encode("pair", p));
            uint64 amt = uint64(10e8 + p);
            w.mint(txid, 0, amt, alice, _sigs2(w, keys[pairs[p][0]], keys[pairs[p][1]], txid, 0, amt, alice));
            require(w.minted(w.lockId(txid, 0)), "flag");
        }
        _eq(w.balanceOf(alice), 30e8 + 3, "balance");
        _eq(w.totalSupply(), 30e8 + 3, "supply");
        _eq(w.mintedInPeriod(w.currentPeriod()), 30e8 + 3, "period");
    }

    function testMintByAnyRelayerAndEmits() public {
        bytes memory sigs = _sigs2(w, keys[0], keys[2], TXID, 0, 5e8, alice);
        vm.recordLogs();
        vm.prank(bob);
        w.mint(TXID, 0, 5e8, alice, sigs);
        Vm.Log[] memory logs = vm.getRecordedLogs();
        _eq(logs.length, 2, "logs");
        require(logs[1].topics[0] == keccak256("Minted(bytes32,bytes32,uint32,address,uint64)"), "topic");
        require(logs[1].topics[1] == w.lockId(TXID, 0), "lockId");
        require(logs[1].topics[2] == bytes32(uint256(uint160(alice))), "recipient");
        (bytes32 txid, uint32 vout, uint64 amt) = abi.decode(logs[1].data, (bytes32, uint32, uint64));
        require(txid == TXID && vout == 0 && amt == 5e8, "data");
        _eq(w.balanceOf(bob), 0, "relayer gets nothing");
    }

    function testDigestMatchesSpec() public view {
        bytes32 domain = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("Bloch wGnB"),
                keccak256("1"),
                L2_CHAIN,
                address(w)
            )
        );
        require(w.DOMAIN_SEPARATOR() == domain, "domain");
        bytes32 st = keccak256(
            abi.encode(
                keccak256("Mint(uint32 gnbChainId,bytes32 lockTxid,uint32 lockVout,uint64 amount,address recipient)"),
                GNB_TESTNET,
                TXID,
                uint32(0),
                uint64(7),
                alice
            )
        );
        require(w.mintDigest(TXID, 0, 7, alice) == keccak256(abi.encodePacked("\x19\x01", domain, st)), "digest");
    }

    function testSameTxidOtherVoutIsDistinctLock() public {
        _mint(TXID, 1e8, alice);
        w.mint(TXID, 1, 1e8, alice, _sigs2(w, keys[0], keys[1], TXID, 1, 1e8, alice));
        _eq(w.balanceOf(alice), 2e8, "two locks");
    }

    // ── mint: rejected ───────────────────────────────────────────────────────

    function testRejectReplay() public {
        bytes memory sigs = _sigs2(w, keys[0], keys[1], TXID, 0, 1e8, alice);
        w.mint(TXID, 0, 1e8, alice, sigs);
        vm.expectRevert(abi.encodeWithSelector(WrappedGnB.AlreadyMinted.selector));
        w.mint(TXID, 0, 1e8, alice, sigs);
        // other signer pair, same lock: still replay
        bytes memory other = _sigs2(w, keys[1], keys[2], TXID, 0, 1e8, alice);
        vm.expectRevert(abi.encodeWithSelector(WrappedGnB.AlreadyMinted.selector));
        w.mint(TXID, 0, 1e8, alice, other);
    }

    function testRejectBelowThresholdAndExtraSignatures() public {
        bytes32 d = w.mintDigest(TXID, 0, 1e8, alice);
        vm.expectRevert(abi.encodeWithSelector(WrappedGnB.BadSignatureCount.selector));
        w.mint(TXID, 0, 1e8, alice, _sig(keys[0], d));
        bytes memory three = bytes.concat(_sig(keys[0], d), _sig(keys[1], d), _sig(keys[2], d));
        vm.expectRevert(abi.encodeWithSelector(WrappedGnB.BadSignatureCount.selector));
        w.mint(TXID, 0, 1e8, alice, three);
        vm.expectRevert(abi.encodeWithSelector(WrappedGnB.BadSignatureCount.selector));
        w.mint(TXID, 0, 1e8, alice, "");
        bytes memory two = bytes.concat(_sig(keys[0], d), _sig(keys[1], d));
        vm.expectRevert(abi.encodeWithSelector(WrappedGnB.BadSignatureCount.selector));
        w.mint(TXID, 0, 1e8, alice, bytes.concat(two, hex"00"));
    }

    function testRejectDuplicateSigner() public {
        bytes32 d = w.mintDigest(TXID, 0, 1e8, alice);
        vm.expectRevert(abi.encodeWithSelector(WrappedGnB.SignersNotAscending.selector));
        w.mint(TXID, 0, 1e8, alice, bytes.concat(_sig(keys[0], d), _sig(keys[0], d)));
    }

    function testRejectUnsortedSigners() public {
        bytes32 d = w.mintDigest(TXID, 0, 1e8, alice);
        vm.expectRevert(abi.encodeWithSelector(WrappedGnB.SignersNotAscending.selector));
        w.mint(TXID, 0, 1e8, alice, bytes.concat(_sig(keys[1], d), _sig(keys[0], d)));
    }

    function testRejectOutsider() public {
        bytes32 d = w.mintDigest(TXID, 0, 1e8, alice);
        uint256 outsider = 0x99;
        bytes memory sigs = vm.addr(outsider) < vm.addr(keys[0])
            ? bytes.concat(_sig(outsider, d), _sig(keys[0], d))
            : bytes.concat(_sig(keys[0], d), _sig(outsider, d));
        vm.expectRevert(abi.encodeWithSelector(WrappedGnB.NotSigner.selector));
        w.mint(TXID, 0, 1e8, alice, sigs);
    }

    function testRejectAlteredFields() public {
        bytes memory sigs = _sigs2(w, keys[0], keys[1], TXID, 0, 1e8, alice);
        bytes memory notSigner = abi.encodeWithSelector(WrappedGnB.NotSigner.selector);
        vm.expectRevert(notSigner);
        w.mint(TXID, 0, 2e8, alice, sigs); // amount
        vm.expectRevert(notSigner);
        w.mint(TXID, 0, 1e8, bob, sigs); // recipient
        vm.expectRevert(notSigner);
        w.mint(keccak256("other"), 0, 1e8, alice, sigs); // txid
        vm.expectRevert(notSigner);
        w.mint(TXID, 1, 1e8, alice, sigs); // vout
    }

    function testRejectOtherGnbNetwork() public {
        // a signature over the same lock for the mainnet GnB id (same contract, same L2) is rejected
        bytes32 st = keccak256(abi.encode(w.MINT_TYPEHASH(), GNB_MAINNET, TXID, uint32(0), uint64(1e8), alice));
        bytes32 d = keccak256(abi.encodePacked("\x19\x01", w.DOMAIN_SEPARATOR(), st));
        require(d != w.mintDigest(TXID, 0, 1e8, alice), "gnb chain in digest");
        bytes memory sigs = bytes.concat(_sig(keys[0], d), _sig(keys[1], d));
        vm.expectRevert(abi.encodeWithSelector(WrappedGnB.NotSigner.selector));
        w.mint(TXID, 0, 1e8, alice, sigs);
        require(_deploy(GNB_MAINNET, 2).gnbChainId() == GNB_MAINNET, "mainnet id accepted");
    }

    function testRejectOtherContract() public {
        WrappedGnB other = _deploy(GNB_TESTNET, 2);
        bytes memory sigs = _sigs2(other, keys[0], keys[1], TXID, 0, 1e8, alice);
        other.mint(TXID, 0, 1e8, alice, sigs);
        vm.expectRevert(abi.encodeWithSelector(WrappedGnB.NotSigner.selector));
        w.mint(TXID, 0, 1e8, alice, sigs);
    }

    function testRejectOtherL2Chain() public {
        bytes memory sigs = _sigs2(w, keys[0], keys[1], TXID, 0, 1e8, alice);
        vm.chainId(1);
        vm.expectRevert(abi.encodeWithSelector(WrappedGnB.NotSigner.selector));
        w.mint(TXID, 0, 1e8, alice, sigs);
        vm.chainId(L2_CHAIN);
        w.mint(TXID, 0, 1e8, alice, sigs);
    }

    function testRejectHighSMalleation() public {
        bytes32 d = w.mintDigest(TXID, 0, 1e8, alice);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(keys[0], d);
        bytes memory flipped = abi.encodePacked(r, bytes32(N - uint256(s)), v == 27 ? uint8(28) : uint8(27));
        require(N - uint256(s) > HALF_N, "flipped is high-s");
        vm.expectRevert(abi.encodeWithSelector(WrappedGnB.BadSignature.selector));
        w.mint(TXID, 0, 1e8, alice, bytes.concat(flipped, _sig(keys[1], d)));
    }

    function testRejectBadVAndGarbage() public {
        bytes32 d = w.mintDigest(TXID, 0, 1e8, alice);
        (, bytes32 r, bytes32 s) = vm.sign(keys[0], d);
        vm.expectRevert(abi.encodeWithSelector(WrappedGnB.BadSignature.selector));
        w.mint(TXID, 0, 1e8, alice, bytes.concat(abi.encodePacked(r, s, uint8(0)), _sig(keys[1], d)));
        vm.expectRevert(abi.encodeWithSelector(WrappedGnB.BadSignature.selector));
        w.mint(TXID, 0, 1e8, alice, bytes.concat(abi.encodePacked(bytes32(0), bytes32(0), uint8(27)), _sig(keys[1], d)));
    }

    function testRejectZeroAmountAndRecipient() public {
        bytes memory sigs = _sigs2(w, keys[0], keys[1], TXID, 0, 0, alice);
        vm.expectRevert(abi.encodeWithSelector(WrappedGnB.ZeroAmount.selector));
        w.mint(TXID, 0, 0, alice, sigs);
        sigs = _sigs2(w, keys[0], keys[1], TXID, 0, 1e8, address(0));
        vm.expectRevert(abi.encodeWithSelector(WrappedGnB.ZeroRecipient.selector));
        w.mint(TXID, 0, 1e8, address(0), sigs);
    }

    // ── caps ─────────────────────────────────────────────────────────────────

    function testPeriodCap() public {
        _mint(keccak256("a"), uint64(PERIOD_CAP - 1), alice);
        bytes32 t = keccak256("b");
        bytes memory sigs = _sigs2(w, keys[0], keys[1], t, 0, 2, alice);
        vm.expectRevert(abi.encodeWithSelector(WrappedGnB.PeriodCapExceeded.selector));
        w.mint(t, 0, 2, alice, sigs);
        w.mint(t, 0, 1, alice, _sigs2(w, keys[0], keys[1], t, 0, 1, alice)); // exactly at cap
        // burning does not free the period cap
        vm.prank(alice);
        w.burn(uint64(MIN_BURN), abi.encodePacked(bytes20(uint160(1))));
        bytes32 t2 = keccak256("c");
        sigs = _sigs2(w, keys[0], keys[1], t2, 0, 1, alice);
        vm.expectRevert(abi.encodeWithSelector(WrappedGnB.PeriodCapExceeded.selector));
        w.mint(t2, 0, 1, alice, sigs);
        // next period: the same signatures are still valid (no expiry), the cap resets
        vm.warp(block.timestamp + PERIOD);
        w.mint(t2, 0, 1, alice, sigs);
    }

    function testSupplyCapAndBurnFreesRoom() public {
        for (uint256 i; i < 10; ++i) {
            _mint(keccak256(abi.encode("s", i)), uint64(PERIOD_CAP), alice);
            vm.warp(block.timestamp + PERIOD);
        }
        _eq(w.totalSupply(), SUPPLY_CAP, "full");
        bytes32 t = keccak256("over");
        bytes memory sigs = _sigs2(w, keys[0], keys[1], t, 0, 1, alice);
        vm.expectRevert(abi.encodeWithSelector(WrappedGnB.SupplyCapExceeded.selector));
        w.mint(t, 0, 1, alice, sigs);
        vm.prank(alice);
        w.burn(uint64(MIN_BURN), abi.encodePacked(bytes20(uint160(1))));
        w.mint(t, 0, 1, alice, sigs);
        _eq(w.totalSupply(), SUPPLY_CAP - MIN_BURN + 1, "after burn+mint");
    }

    // ── burn ─────────────────────────────────────────────────────────────────

    function testBurnKeyHashAndPolicyDestinations() public {
        _mint(TXID, 10e8, alice);
        bytes memory pkh = abi.encodePacked(bytes20(keccak256("pkh")));
        bytes memory policy = abi.encodePacked(bytes1(0x02), keccak256("policy"));
        vm.recordLogs();
        vm.prank(alice);
        bytes32 id1 = w.burn(1e8, pkh);
        vm.prank(alice);
        bytes32 id2 = w.burn(2e8, policy);
        Vm.Log[] memory logs = vm.getRecordedLogs();
        require(id1 == keccak256(abi.encode(L2_CHAIN, address(w), uint64(1))), "burnId 1");
        require(id2 == w.burnIdOf(2) && id1 != id2, "burnId 2");
        _eq(w.burnNonce(), 2, "nonce");
        _eq(w.balanceOf(alice), 7e8, "balance");
        _eq(w.totalSupply(), 7e8, "supply");
        _eq(logs.length, 4, "logs");
        Vm.Log memory b = logs[3];
        require(b.topics[0] == keccak256("Burned(bytes32,uint64,address,uint64,bytes)"), "topic");
        require(b.topics[1] == id2 && uint256(b.topics[2]) == 2, "id/nonce");
        require(b.topics[3] == bytes32(uint256(uint160(alice))), "from");
        (uint64 amt, bytes memory spk) = abi.decode(b.data, (uint64, bytes));
        require(amt == 2e8 && keccak256(spk) == keccak256(policy), "data");
    }

    function testRejectBurns() public {
        _mint(TXID, 1e8, alice);
        bytes memory pkh = abi.encodePacked(bytes20(uint160(7)));
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(WrappedGnB.BurnTooSmall.selector));
        w.burn(uint64(MIN_BURN - 1), pkh);
        uint256[6] memory lens = [uint256(0), 19, 21, 32, 34, 65];
        for (uint256 i; i < lens.length; ++i) {
            vm.prank(alice);
            vm.expectRevert(abi.encodeWithSelector(WrappedGnB.BadScriptPubKey.selector));
            w.burn(uint64(MIN_BURN), new bytes(lens[i]));
        }
        bytes memory wrongTag = abi.encodePacked(bytes1(0x01), keccak256("x"));
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(WrappedGnB.BadScriptPubKey.selector));
        w.burn(uint64(MIN_BURN), wrongTag);
        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(WrappedGnB.InsufficientBalance.selector));
        w.burn(uint64(MIN_BURN), pkh);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(WrappedGnB.InsufficientBalance.selector));
        w.burn(2e8, pkh);
        _eq(w.burnNonce(), 0, "no burn happened");
    }

    // ── ERC-20 ───────────────────────────────────────────────────────────────

    function testTransfersAndAllowance() public {
        _mint(TXID, 5e8, alice);
        vm.prank(alice);
        w.transfer(bob, 1e8);
        vm.prank(alice);
        w.approve(address(this), 2e8);
        w.transferFrom(alice, bob, 2e8);
        _eq(w.allowance(alice, address(this)), 0, "allowance spent");
        vm.expectRevert(abi.encodeWithSelector(WrappedGnB.InsufficientAllowance.selector));
        w.transferFrom(alice, bob, 1);
        vm.prank(alice);
        w.approve(address(this), type(uint256).max);
        w.transferFrom(alice, bob, 1e8);
        _eq(w.allowance(alice, address(this)), type(uint256).max, "infinite allowance kept");
        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(WrappedGnB.InsufficientBalance.selector));
        w.transfer(alice, 5e8);
        _eq(w.balanceOf(alice), 1e8, "alice");
        _eq(w.balanceOf(bob), 4e8, "bob");
        _eq(w.totalSupply(), 5e8, "supply unchanged");
    }

    // ── fuzz ─────────────────────────────────────────────────────────────────

    function testFuzzMintBurnConservesSupply(uint64 a, uint64 b, uint64 burnAmt) public {
        vm.assume(a > 0 && b > 0 && uint256(a) + b <= PERIOD_CAP);
        _mint(keccak256("fa"), a, alice);
        _mint(keccak256("fb"), b, bob);
        uint256 burnable = a < MIN_BURN ? 0 : a;
        if (burnable > 0) {
            burnAmt = uint64(MIN_BURN + uint256(burnAmt) % (burnable - MIN_BURN + 1));
            vm.prank(alice);
            w.burn(burnAmt, abi.encodePacked(bytes20(uint160(9))));
        } else {
            burnAmt = 0;
        }
        _eq(w.totalSupply(), uint256(a) + b - burnAmt, "supply");
        _eq(w.balanceOf(alice) + w.balanceOf(bob), w.totalSupply(), "sum of balances");
    }

    function testFuzzRandomSignatureRejected(bytes32 r, bytes32 s, uint8 v) public {
        bytes32 d = w.mintDigest(TXID, 0, 1e8, alice);
        bytes memory sigs = bytes.concat(abi.encodePacked(r, s, v), _sig(keys[1], d));
        (bool ok,) = address(w).call(abi.encodeCall(w.mint, (TXID, 0, 1e8, alice, sigs)));
        require(!ok, "random signature accepted");
    }
}
