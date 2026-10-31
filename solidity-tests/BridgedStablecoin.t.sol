// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.24;

import {BridgedStablecoin} from "../contracts/stable/BridgedStablecoin.sol";
import {ContextBoundSourceVault} from "../contracts/usdt/ContextBoundSourceVault.sol";

interface Vm {
    struct Log {
        bytes32[] topics;
        bytes data;
        address emitter;
    }

    function addr(uint256 privateKey) external pure returns (address);
    function sign(uint256 privateKey, bytes32 digest) external pure returns (uint8 v, bytes32 r, bytes32 s);
    function warp(uint256 timestamp) external;
    function roll(uint256 blockNumber) external;
    function chainId(uint256 newChainId) external;
    function prank(address sender) external;
    function expectRevert(bytes calldata data) external;
    function recordLogs() external;
    function getRecordedLogs() external returns (Log[] memory);
}

/// Six-decimal ERC-20 standing in for USDC/USDT on the source chain.
contract MockStable {
    uint8 public constant decimals = 6;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mintTo(address to, uint256 v) external {
        balanceOf[to] += v;
    }

    function approve(address s, uint256 v) external returns (bool) {
        allowance[msg.sender][s] = v;
        return true;
    }

    function transfer(address to, uint256 v) external returns (bool) {
        balanceOf[msg.sender] -= v;
        balanceOf[to] += v;
        return true;
    }

    function transferFrom(address f, address to, uint256 v) external returns (bool) {
        allowance[f][msg.sender] -= v;
        balanceOf[f] -= v;
        balanceOf[to] += v;
        return true;
    }
}

contract BridgedStablecoinTest {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    uint256 private constant L2_CHAIN = 700771;
    uint256 private constant ETH_CHAIN = 11155111;
    uint256 private constant PERIOD = 1 days;
    uint256 private constant PERIOD_CAP = 100_000e6;
    uint256 private constant SUPPLY_CAP = 1_000_000e6;
    uint256 private constant MIN_BURN = 1e6;
    bytes32 private constant ROUTE = keccak256("route");
    address private constant VAULT = address(0x7a017);
    bytes32 private constant DEP = keccak256("deposit-0");

    BridgedStablecoin private t;
    uint256[3] private keys; // ascending by address
    address private alice = address(0xA11CE);
    address private bob = address(0xB0B);

    function setUp() public {
        vm.chainId(L2_CHAIN);
        vm.warp(1_760_000_000);
        uint256[3] memory k = [uint256(0x61), 0x62, 0x63];
        for (uint256 i = 1; i < 3; ++i) {
            for (uint256 j = i; j > 0 && vm.addr(k[j]) < vm.addr(k[j - 1]); --j) {
                (k[j], k[j - 1]) = (k[j - 1], k[j]);
            }
        }
        keys = k;
        t = _deploy(ETH_CHAIN, VAULT, ROUTE);
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    function _addrs() private view returns (address[] memory a) {
        a = new address[](3);
        for (uint256 i; i < 3; ++i) a[i] = vm.addr(keys[i]);
    }

    function _deploy(uint256 chain, address vault, bytes32 route) private returns (BridgedStablecoin) {
        return new BridgedStablecoin(
            "Bloch Bridged USDC", "bUSDC", chain, vault, route, _addrs(), 2, PERIOD, PERIOD_CAP, SUPPLY_CAP, MIN_BURN
        );
    }

    function _sig(uint256 key, bytes32 digest) private pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        return abi.encodePacked(r, s, v);
    }

    function _sigs(BridgedStablecoin c, uint256 a, uint256 b, bytes32 id, uint64 n, uint64 amt, address to)
        private
        view
        returns (bytes memory)
    {
        bytes32 d = c.mintDigest(id, n, amt, to);
        return bytes.concat(_sig(a, d), _sig(b, d));
    }

    function _mint(bytes32 id, uint64 n, uint64 amt, address to) private {
        t.mint(id, n, amt, to, _sigs(t, keys[0], keys[1], id, n, amt, to));
    }

    function _eq(uint256 a, uint256 b, string memory what) private pure {
        require(a == b, what);
    }

    // ── config ───────────────────────────────────────────────────────────────

    function testConfig() public view {
        _eq(t.decimals(), 6, "decimals");
        require(keccak256(bytes(t.symbol())) == keccak256("bUSDC"), "symbol");
        _eq(t.sourceChainId(), ETH_CHAIN, "chain");
        require(t.sourceVault() == VAULT && t.sourceRoute() == ROUTE, "source");
        _eq(t.threshold(), 2, "k");
        _eq(t.signers().length, 3, "n");
    }

    function testConstructorRejectsBadConfig() public {
        address[] memory s = _addrs();
        bytes memory bad = abi.encodeWithSelector(BridgedStablecoin.BadConfig.selector);
        vm.expectRevert(bad);
        new BridgedStablecoin("n", "s", 0, VAULT, ROUTE, s, 2, PERIOD, PERIOD_CAP, SUPPLY_CAP, MIN_BURN);
        vm.expectRevert(bad);
        new BridgedStablecoin("n", "s", ETH_CHAIN, address(0), ROUTE, s, 2, PERIOD, PERIOD_CAP, SUPPLY_CAP, MIN_BURN);
        vm.expectRevert(bad);
        new BridgedStablecoin("n", "s", ETH_CHAIN, VAULT, 0, s, 2, PERIOD, PERIOD_CAP, SUPPLY_CAP, MIN_BURN);
        vm.expectRevert(bad);
        new BridgedStablecoin("n", "s", ETH_CHAIN, VAULT, ROUTE, s, 0, PERIOD, PERIOD_CAP, SUPPLY_CAP, MIN_BURN);
        vm.expectRevert(bad);
        new BridgedStablecoin("n", "s", ETH_CHAIN, VAULT, ROUTE, s, 4, PERIOD, PERIOD_CAP, SUPPLY_CAP, MIN_BURN);
        vm.expectRevert(bad);
        new BridgedStablecoin("n", "s", ETH_CHAIN, VAULT, ROUTE, s, 2, 0, PERIOD_CAP, SUPPLY_CAP, MIN_BURN);
        vm.expectRevert(bad);
        new BridgedStablecoin("n", "s", ETH_CHAIN, VAULT, ROUTE, s, 2, PERIOD, SUPPLY_CAP + 1, SUPPLY_CAP, MIN_BURN);
        vm.expectRevert(bad);
        new BridgedStablecoin("n", "s", ETH_CHAIN, VAULT, ROUTE, s, 2, PERIOD, PERIOD_CAP, SUPPLY_CAP, 0);
        vm.expectRevert(bad);
        new BridgedStablecoin("", "s", ETH_CHAIN, VAULT, ROUTE, s, 2, PERIOD, PERIOD_CAP, SUPPLY_CAP, MIN_BURN);
        address[] memory dup = new address[](2);
        dup[0] = s[0];
        dup[1] = s[0];
        vm.expectRevert(bad);
        new BridgedStablecoin("n", "s", ETH_CHAIN, VAULT, ROUTE, dup, 1, PERIOD, PERIOD_CAP, SUPPLY_CAP, MIN_BURN);
    }

    function testNoAdminSurface() public {
        string[5] memory fns = ["owner()", "pause()", "setSigners(address[])", "upgradeTo(address)", "setCaps(uint256,uint256)"];
        for (uint256 i; i < fns.length; ++i) {
            (bool ok,) = address(t).call(abi.encodeWithSignature(fns[i]));
            require(!ok, fns[i]);
        }
    }

    // ── mint ─────────────────────────────────────────────────────────────────

    function testDigestMatchesSpec() public view {
        bytes32 domain = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("Bloch Bridged Stablecoin"),
                keccak256("1"),
                L2_CHAIN,
                address(t)
            )
        );
        bytes32 st = keccak256(
            abi.encode(
                keccak256(
                    "Mint(uint256 sourceChainId,address sourceVault,bytes32 sourceRoute,bytes32 depositId,uint64 depositNonce,uint64 amount,address recipient)"
                ),
                ETH_CHAIN,
                VAULT,
                ROUTE,
                DEP,
                uint64(0),
                uint64(5e6),
                alice
            )
        );
        require(t.mintDigest(DEP, 0, 5e6, alice) == keccak256(abi.encodePacked("\x19\x01", domain, st)), "digest");
    }

    function testMintAndReplay() public {
        bytes memory sigs = _sigs(t, keys[1], keys[2], DEP, 0, 5e6, alice);
        vm.prank(bob);
        t.mint(DEP, 0, 5e6, alice, sigs);
        _eq(t.balanceOf(alice), 5e6, "balance");
        require(t.minted(DEP), "flag");
        vm.expectRevert(abi.encodeWithSelector(BridgedStablecoin.AlreadyMinted.selector));
        t.mint(DEP, 0, 5e6, alice, sigs);
    }

    function testRejectBadSignatures() public {
        bytes32 d = t.mintDigest(DEP, 0, 5e6, alice);
        vm.expectRevert(abi.encodeWithSelector(BridgedStablecoin.BadSignatureCount.selector));
        t.mint(DEP, 0, 5e6, alice, _sig(keys[0], d));
        vm.expectRevert(abi.encodeWithSelector(BridgedStablecoin.SignersNotAscending.selector));
        t.mint(DEP, 0, 5e6, alice, bytes.concat(_sig(keys[0], d), _sig(keys[0], d)));
        vm.expectRevert(abi.encodeWithSelector(BridgedStablecoin.SignersNotAscending.selector));
        t.mint(DEP, 0, 5e6, alice, bytes.concat(_sig(keys[1], d), _sig(keys[0], d)));
        bytes memory sigs = bytes.concat(_sig(keys[0], d), _sig(keys[1], d));
        vm.expectRevert(abi.encodeWithSelector(BridgedStablecoin.NotSigner.selector));
        t.mint(DEP, 0, 6e6, alice, sigs); // amount
        vm.expectRevert(abi.encodeWithSelector(BridgedStablecoin.NotSigner.selector));
        t.mint(DEP, 1, 5e6, alice, sigs); // deposit nonce
        vm.expectRevert(abi.encodeWithSelector(BridgedStablecoin.NotSigner.selector));
        t.mint(DEP, 0, 5e6, bob, sigs); // recipient
    }

    function testRejectOtherSourceVaultRouteOrChain() public {
        BridgedStablecoin[3] memory others =
            [_deploy(1, VAULT, ROUTE), _deploy(ETH_CHAIN, address(0xBEEF), ROUTE), _deploy(ETH_CHAIN, VAULT, keccak256("x"))];
        for (uint256 i; i < 3; ++i) {
            bytes32 st = keccak256(
                abi.encode(
                    t.MINT_TYPEHASH(),
                    others[i].sourceChainId(),
                    others[i].sourceVault(),
                    others[i].sourceRoute(),
                    DEP,
                    uint64(0),
                    uint64(5e6),
                    alice
                )
            );
            bytes32 d = keccak256(abi.encodePacked("\x19\x01", t.DOMAIN_SEPARATOR(), st));
            vm.expectRevert(abi.encodeWithSelector(BridgedStablecoin.NotSigner.selector));
            t.mint(DEP, 0, 5e6, alice, bytes.concat(_sig(keys[0], d), _sig(keys[1], d)));
        }
        bytes memory forOther = _sigs(others[0], keys[0], keys[1], DEP, 0, 5e6, alice);
        vm.expectRevert(abi.encodeWithSelector(BridgedStablecoin.NotSigner.selector));
        t.mint(DEP, 0, 5e6, alice, forOther);
        bytes memory ok = _sigs(t, keys[0], keys[1], DEP, 0, 5e6, alice);
        vm.chainId(1);
        vm.expectRevert(abi.encodeWithSelector(BridgedStablecoin.NotSigner.selector));
        t.mint(DEP, 0, 5e6, alice, ok);
    }

    function testRejectHighS() public {
        bytes32 d = t.mintDigest(DEP, 0, 5e6, alice);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(keys[0], d);
        uint256 n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
        bytes memory flipped = abi.encodePacked(r, bytes32(n - uint256(s)), v == 27 ? uint8(28) : uint8(27));
        vm.expectRevert(abi.encodeWithSelector(BridgedStablecoin.BadSignature.selector));
        t.mint(DEP, 0, 5e6, alice, bytes.concat(flipped, _sig(keys[1], d)));
    }

    function testZeroAmountAndRecipient() public {
        vm.expectRevert(abi.encodeWithSelector(BridgedStablecoin.ZeroAmount.selector));
        t.mint(DEP, 0, 0, alice, "");
        vm.expectRevert(abi.encodeWithSelector(BridgedStablecoin.ZeroRecipient.selector));
        t.mint(DEP, 0, 1, address(0), "");
    }

    function testCaps() public {
        _mint(keccak256("a"), 1, uint64(PERIOD_CAP), alice);
        bytes32 id = keccak256("b");
        bytes memory sigs = _sigs(t, keys[0], keys[1], id, 2, 1, alice);
        vm.expectRevert(abi.encodeWithSelector(BridgedStablecoin.PeriodCapExceeded.selector));
        t.mint(id, 2, 1, alice, sigs);
        vm.warp(block.timestamp + PERIOD);
        t.mint(id, 2, 1, alice, sigs);
        for (uint256 i; i < 8; ++i) {
            vm.warp(block.timestamp + PERIOD);
            _mint(keccak256(abi.encode("c", i)), uint64(10 + i), uint64(PERIOD_CAP), alice);
        }
        _eq(t.totalSupply(), SUPPLY_CAP - PERIOD_CAP + 1, "nine full periods + 1");
        vm.warp(block.timestamp + PERIOD);
        bytes32 over = keccak256("over");
        sigs = _sigs(t, keys[0], keys[1], over, 99, uint64(PERIOD_CAP), alice);
        vm.expectRevert(abi.encodeWithSelector(BridgedStablecoin.SupplyCapExceeded.selector));
        t.mint(over, 99, uint64(PERIOD_CAP), alice, sigs);
        _mint(over, 99, uint64(PERIOD_CAP - 1), alice);
        _eq(t.totalSupply(), SUPPLY_CAP, "exactly at the supply cap");
    }

    // ── burn ─────────────────────────────────────────────────────────────────

    function testBurn() public {
        _mint(DEP, 0, 10e6, alice);
        vm.recordLogs();
        vm.prank(alice);
        bytes32 id = t.burn(3e6, bob);
        Vm.Log[] memory logs = vm.getRecordedLogs();
        require(id == keccak256(abi.encode(L2_CHAIN, address(t), uint64(1))) && id == t.burnIdOf(1), "burnId");
        Vm.Log memory b = logs[1];
        require(b.topics[0] == keccak256("Burned(bytes32,uint64,address,uint64,address)"), "topic");
        require(b.topics[1] == id && uint256(b.topics[2]) == 1, "id/nonce");
        (uint64 amt, address to) = abi.decode(b.data, (uint64, address));
        require(amt == 3e6 && to == bob, "data");
        _eq(t.totalSupply(), 7e6, "supply");
    }

    function testRejectBurns() public {
        _mint(DEP, 0, 10e6, alice);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(BridgedStablecoin.BurnTooSmall.selector));
        t.burn(uint64(MIN_BURN - 1), bob);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(BridgedStablecoin.BadEthRecipient.selector));
        t.burn(uint64(MIN_BURN), address(0));
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(BridgedStablecoin.BadEthRecipient.selector));
        t.burn(uint64(MIN_BURN), VAULT);
        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(BridgedStablecoin.InsufficientBalance.selector));
        t.burn(uint64(MIN_BURN), bob);
        _eq(t.burnNonce(), 0, "no burn");
    }

    // ── round trip with the real ContextBoundSourceVault (same EVM, two chain ids) ──

    function testRoundTripWithContextBoundSourceVault() public {
        // "Ethereum": the vault with the same three signers (the vault requires ascending order)
        vm.chainId(ETH_CHAIN);
        MockStable usdc = new MockStable();
        ContextBoundSourceVault vault = new ContextBoundSourceVault(
            bytes32("ETHEREUM-SEPOLIA"), bytes32("BLOCH-L2-700771"), bytes32("USDC"), address(usdc), 1_000_000e6, 0,
            _addrs(), 2, ContextBoundSourceVault.Policy(50_000e6, 1 days, 2, 7 days, 1, 1), ContextBoundSourceVault.Guard(new address[](0), 0, 0)
        );
        uint256 validUntil = block.timestamp + 1 hours;
        bytes32 cd = vault.controlDigest(true, true, 0, validUntil);
        bytes[] memory cs = new bytes[](2);
        cs[0] = _sig(keys[0], cd);
        cs[1] = _sig(keys[1], cd);
        vault.setControls(true, true, 0, validUntil, cs);

        // deposit: the L2 recipient goes in pqRecipientHash as a left-padded address (interface S2)
        usdc.mintTo(alice, 20e6);
        vm.prank(alice);
        usdc.approve(address(vault), 20e6);
        vm.prank(alice);
        bytes32 depId = vault.deposit(20e6, bytes32(uint256(uint160(alice))));

        // "L2": token bound to that vault and route; signers mint after seeing the deposit
        vm.chainId(L2_CHAIN);
        BridgedStablecoin l2 = _deploy(ETH_CHAIN, address(vault), vault.routeId());
        l2.mint(depId, 0, 20e6, alice, _sigs(l2, keys[0], keys[2], depId, 0, 20e6, alice));
        vm.prank(alice);
        bytes32 burnId = l2.burn(8e6, bob);

        // back on "Ethereum": release (nonce = burnNonce, nativeBurn = burnId) with a context certificate
        vm.chainId(ETH_CHAIN);
        vm.roll(block.number + 10);
        ContextBoundSourceVault.Release memory rel = ContextBoundSourceVault.Release({
            route: vault.routeId(), nonce: l2.burnNonce(), recipient: bob, amount: 8e6, nativeBurn: burnId
        });
        ContextBoundSourceVault.ReleaseContext memory ctx = ContextBoundSourceVault.ReleaseContext({
            validUntil: block.timestamp + 1 hours,
            sourceAnchorNumber: block.number - 1,
            sourceAnchorHash: blockhash(block.number - 1),
            nativeFinalizedNumber: 231,
            nativeFinalizedHash: keccak256("l2-finalized-231")
        });
        require(ctx.sourceAnchorHash != 0, "anchor");
        bytes32 rd = vault.releaseDigest(rel, ctx);
        bytes[] memory rs = new bytes[](2);
        rs[0] = _sig(keys[1], rd);
        rs[1] = _sig(keys[2], rd);
        vault.release(rel, ctx, rs);
        _eq(usdc.balanceOf(bob), 8e6, "bob paid on the source chain");
        _eq(vault.totalLocked(), 12e6, "locked = L2 supply");
        vm.chainId(L2_CHAIN);
        _eq(l2.totalSupply(), vault.totalLocked(), "supply matches backing");
        // the same burn cannot be released twice
        vm.chainId(ETH_CHAIN);
        vm.expectRevert(abi.encodeWithSelector(ContextBoundSourceVault.InvalidRelease.selector));
        vault.release(rel, ctx, rs);
    }
}
