// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.24;

import {SignerMintedToken} from "../contracts/bridged/SignerMintedToken.sol";
import {BridgedStablecoinV2} from "../contracts/stable/BridgedStablecoinV2.sol";
import {BridgedStablecoinV3} from "../contracts/stable/BridgedStablecoinV3.sol";
import {StellarBurnRouter, IStellarBridgedToken} from "../contracts/stellar/StellarBurnRouter.sol";

interface R324Vm {
    function addr(uint256 privateKey) external pure returns (address);
    function sign(uint256 privateKey, bytes32 digest) external pure returns (uint8 v, bytes32 r, bytes32 s);
    function warp(uint256 timestamp) external;
    function prank(address sender) external;
    function expectRevert(bytes4 revertData) external;
    function recordLogs() external;
    function getRecordedLogs() external returns (Log[] memory);

    struct Log {
        bytes32[] topics;
        bytes data;
        address emitter;
    }
}

/// Agent 324 (round 16): the Stellar exit router over the unchanged BridgedStablecoinV3, deployed the way
/// `bUSDC.xlm` would be: `sourceChainId` is the Stellar network id (sha256 of the passphrase) as a uint256 and
/// `sourceVault` the low 20 bytes of the vault's contract id.
contract R324StellarBurnRouterTest {
    R324Vm constant vm = R324Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    uint256 constant U = 1e6;
    address constant ALICE = address(0xA11CE);
    // Public strkeys: the owner's fee address on Stellar, and the USDC asset contract on the public network.
    string constant G_ADDR = "GAF2DTU23X5CFOPOUCUBTFJ5PKTSOV4GLZAJB5VMJW2JUA5KKYF5OLNA";
    string constant C_ADDR = "CCW67TSZV3SSS2HXMBQ5JFGCKJNXKZM7UQUWUZPUTHXSTZLEO7SJMI75";

    uint256[] keys;
    BridgedStablecoinV3 token;
    StellarBurnRouter router;
    uint256 sourceChainId = uint256(sha256(bytes("Public Global Stellar Network ; September 2015")));
    address sourceVault = address(0x432B05ed3B5F18cF1E40e76d346474c545965D8A);
    bytes32 route = keccak256("route");

    function setUp() public {
        vm.warp(1_000_000);
        for (uint256 i; i < 7; ++i) keys.push(0x3240 + i);
        for (uint256 i; i < 7; ++i) {
            for (uint256 j = i + 1; j < 7; ++j) {
                if (vm.addr(keys[j]) < vm.addr(keys[i])) (keys[i], keys[j]) = (keys[j], keys[i]);
            }
        }
        address[] memory signers = new address[](7);
        for (uint256 i; i < 7; ++i) signers[i] = vm.addr(keys[i]);
        address[] memory guardians = new address[](3);
        for (uint256 i; i < 3; ++i) guardians[i] = vm.addr(0x6a10 + i);
        for (uint256 i; i < 3; ++i) {
            for (uint256 j = i + 1; j < 3; ++j) {
                if (guardians[j] < guardians[i]) (guardians[i], guardians[j]) = (guardians[j], guardians[i]);
            }
        }
        token = new BridgedStablecoinV3(
            "Bloch Bridged USDC (Stellar)", "bUSDC.xlm", sourceChainId, sourceVault, route, signers, 5,
            SignerMintedToken.Limits(100_000 * U, 10_000 * U, 10_000 * U / 1 days, 0, 12 hours, 10 * U),
            SignerMintedToken.Guard(guardians, 3 days, 3 days), BridgedStablecoinV2.MintSwitch(6, 14 days)
        );
        router = new StellarBurnRouter(IStellarBridgedToken(address(token)));
        // One real mint: slot 0, 12 h in the queue, then credited.
        bytes32 id = bytes32(uint256(0xabc));
        bytes32 digest = token.mintDigest(id, 0, uint64(500 * U), ALICE);
        bytes memory blob;
        for (uint256 i; i < 5; ++i) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(keys[i], digest);
            blob = abi.encodePacked(blob, r, s, v);
        }
        token.mint(id, 0, uint64(500 * U), ALICE, blob);
        vm.warp(block.timestamp + 12 hours);
        token.executeMint(id);
        require(token.balanceOf(ALICE) == 500 * U, "setup mint");
    }

    function test_tokenTakesAStellarSource() public view {
        require(token.sourceChainId() == sourceChainId && token.sourceChainId() > type(uint64).max, "256-bit network id");
        require(token.sourceVault() == sourceVault, "vault20");
        require(token.decimals() == 6, "decimals");
        // The chain the Stellar vault keeps: its genesis over (network id, vault20, route), then one link per credit.
        bytes32 genesis = keccak256(abi.encode(bytes32("BLOCH-USDT-MINT-CHAIN-v1"), sourceChainId, sourceVault, route));
        require(
            token.mintHead() == keccak256(abi.encode(genesis, bytes32(uint256(0xabc)), uint256(500 * U), ALICE)), "chain"
        );
    }

    function test_commitmentIsTheTaggedHashOfTheStrkey() public view {
        address g = router.commitment(G_ADDR);
        require(g == address(uint160(uint256(keccak256(abi.encodePacked(bytes32("BLOCH-XLM-RECIPIENT-v1"), G_ADDR))))), "g");
        address c = router.commitment(C_ADDR);
        require(c != g && c != address(0), "c");
    }

    function test_badStrkeysAreRefused() public {
        // one character changed (checksum fails)
        _refused("GAF2DTU23X5CFOPOUCUBTFJ5PKTSOV4GLZAJB5VMJW2JUA5KKYF5OLNB");
        // two characters swapped
        _refused("GAF2DTU23X5CFOPOUCUBTFJ5PKTSOV4GLZAJB5VMJW2JUA5KKYF5ONLA");
        // too short, too long, empty
        _refused("GAF2DTU23X5CFOPOUCUBTFJ5PKTSOV4GLZAJB5VMJW2JUA5KKYF5OLN");
        _refused("GAF2DTU23X5CFOPOUCUBTFJ5PKTSOV4GLZAJB5VMJW2JUA5KKYF5OLNAA");
        _refused("");
        // lower case and a character outside base32
        _refused("gaf2dtu23x5cfopoucubtfj5pktsov4glzajb5vmjw2jua5kkyf5olna");
        _refused("GAF2DTU23X5CFOPOUCUBTFJ5PKTSOV4GLZAJB5VMJW2JUA5KKYF5OL1A");
        // a muxed address (69 characters) and an Ethereum address
        _refused("MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVAAAAAAAAAAAAAJLK");
        _refused("0x775a993F09Bd80aeCF8F8c2ADe0C84158E3a0544");
    }

    function test_aSecretSeedIsRefused() public {
        // A well-formed strkey of another version (S..., a seed): version byte 18 << 3 over the bytes 1..32, valid checksum.
        _refused("SAAQEAYEAUDAOCAJBIFQYDIOB4IBCEQTCQKRMFYYDENBWHA5DYPSBF5K");
    }

    function test_burnToBurnsTowardsTheCommitmentAndPublishesTheAddress() public {
        vm.prank(ALICE);
        token.approve(address(router), 200 * U);
        vm.recordLogs();
        vm.prank(ALICE);
        bytes32 burnId = router.burnTo(uint64(200 * U), G_ADDR);
        require(token.balanceOf(ALICE) == 300 * U && token.balanceOf(address(router)) == 0, "balances");
        require(token.totalSupply() == 300 * U, "supply");
        require(burnId == token.burnIdOf(1), "burn id");
        R324Vm.Log[] memory logs = vm.getRecordedLogs();
        bool burned;
        bool exit;
        address want = router.commitment(G_ADDR);
        for (uint256 i; i < logs.length; ++i) {
            if (logs[i].topics[0] == keccak256("Burned(bytes32,uint64,address,uint64,address,uint64,uint64,bytes32)")) {
                (uint64 amount, address recipient, uint64 mintCount,,) =
                    abi.decode(logs[i].data, (uint64, address, uint64, uint64, bytes32));
                require(logs[i].topics[1] == burnId && amount == 200 * U && recipient == want && mintCount == 1, "Burned");
                burned = true;
            }
            if (logs[i].topics[0] == keccak256("StellarExit(bytes32,address,uint64,bytes20,string)")) {
                (uint64 amount, bytes20 c, string memory recipient) = abi.decode(logs[i].data, (uint64, bytes20, string));
                require(logs[i].topics[1] == burnId && address(uint160(uint256(logs[i].topics[2]))) == ALICE, "topics");
                require(amount == 200 * U && c == bytes20(want) && keccak256(bytes(recipient)) == keccak256(bytes(G_ADDR)), "StellarExit");
                exit = true;
            }
        }
        require(burned && exit, "logs");
    }

    function test_burnToWithoutAllowanceReverts() public {
        vm.prank(ALICE);
        (bool ok,) = address(router).call(abi.encodeCall(router.burnTo, (uint64(200 * U), G_ADDR)));
        require(!ok && token.balanceOf(ALICE) == 500 * U, "no allowance");
    }

    function test_burnToBelowMinBurnReverts() public {
        vm.prank(ALICE);
        token.approve(address(router), 200 * U);
        vm.prank(ALICE);
        (bool ok,) = address(router).call(abi.encodeCall(router.burnTo, (uint64(9 * U), G_ADDR)));
        require(!ok && token.balanceOf(ALICE) == 500 * U, "below minBurn");
    }

    function test_aBadAddressBurnsNothing() public {
        vm.prank(ALICE);
        token.approve(address(router), 200 * U);
        vm.prank(ALICE);
        (bool ok,) = address(router).call(
            abi.encodeCall(router.burnTo, (uint64(200 * U), "GAF2DTU23X5CFOPOUCUBTFJ5PKTSOV4GLZAJB5VMJW2JUA5KKYF5OLNB"))
        );
        require(!ok && token.balanceOf(ALICE) == 500 * U && token.burnNonce() == 0, "nothing burned");
    }

    // ── round 17 (review 331, R331-XLM-3P-1): the claim of a direct burn is on the L2 ──────────────────────────
    // Round 18 (brief 373): it is no longer set once. Every claim is kept in order and the latest is `claimOf`;
    // the signers certify the latest claim final before the vault records a release. The properties of the set-once
    // test are kept: one log per claim with the same topics and data, a claim by another account is ignored, the
    // address must be valid; restated: a second claim for another address is now RECORDED (it was: reverts), a
    // second claim for the same address still reverts (SameAddress), and the history is bounded.
    function test_aDirectBurnIsClaimedByItsBurnerAndTheLatestClaimCounts() public {
        vm.prank(ALICE);
        token.burn(uint64(50 * U), ALICE); // a direct burn towards 20 bytes that are no commitment
        require(bytes(router.claimOf(ALICE, 1)).length == 0 && router.claimCount(ALICE, 1) == 0, "no claim yet");
        vm.recordLogs();
        vm.prank(ALICE);
        router.claimDirectBurn(1, G_ADDR);
        require(keccak256(bytes(router.claimOf(ALICE, 1))) == keccak256(bytes(G_ADDR)), "claim stored");
        R324Vm.Log[] memory logs = vm.getRecordedLogs();
        require(logs.length == 1 && logs[0].emitter == address(router), "one log");
        require(logs[0].topics[0] == keccak256("DirectBurnClaimed(address,uint64,bytes20,string)"), "topic");
        require(address(uint160(uint256(logs[0].topics[1]))) == ALICE && uint256(logs[0].topics[2]) == 1, "indexed");
        (bytes20 c, string memory to) = abi.decode(logs[0].data, (bytes20, string));
        require(c == bytes20(router.commitment(G_ADDR)) && keccak256(bytes(to)) == keccak256(bytes(G_ADDR)), "data");
        // the same address twice in a row reverts and changes nothing
        vm.prank(ALICE);
        (bool ok, bytes memory why) = address(router).call(abi.encodeCall(router.claimDirectBurn, (1, G_ADDR)));
        require(!ok && bytes4(why) == StellarBurnRouter.SameAddress.selector, "same claim again");
        require(router.claimCount(ALICE, 1) == 1, "unchanged");
        // another address: recorded, and it is the latest
        vm.prank(ALICE);
        router.claimDirectBurn(1, C_ADDR);
        require(keccak256(bytes(router.claimOf(ALICE, 1))) == keccak256(bytes(C_ADDR)), "latest claim");
        require(router.claimCount(ALICE, 1) == 2, "two claims");
        require(keccak256(bytes(router.claimAt(ALICE, 1, 0))) == keccak256(bytes(G_ADDR)), "history 0");
        require(keccak256(bytes(router.claimAt(ALICE, 1, 1))) == keccak256(bytes(C_ADDR)), "history 1");
        // and back again: allowed (not the same as the latest)
        vm.prank(ALICE);
        router.claimDirectBurn(1, G_ADDR);
        require(keccak256(bytes(router.claimOf(ALICE, 1))) == keccak256(bytes(G_ADDR)) && router.claimCount(ALICE, 1) == 3, "back");
    }

    function test_theClaimHistoryIsBounded() public {
        vm.prank(ALICE);
        token.burn(uint64(50 * U), ALICE);
        uint256 max = router.MAX_NAMINGS();
        for (uint256 i; i < max; ++i) {
            vm.prank(ALICE);
            router.claimDirectBurn(1, i % 2 == 0 ? G_ADDR : C_ADDR);
        }
        vm.prank(ALICE);
        (bool ok, bytes memory why) = address(router).call(abi.encodeCall(router.claimDirectBurn, (1, C_ADDR)));
        require(!ok && bytes4(why) == StellarBurnRouter.TooManyNamings.selector && router.claimCount(ALICE, 1) == max, "bounded");
    }

    // ── round 18 (brief 373): a held router exit is redirected by its own burner, on the L2 ───────────────────
    function test_aRouterExitRecordsItsBurnerAndOnlyItRedirects() public {
        vm.prank(ALICE);
        token.approve(address(router), 200 * U);
        vm.prank(ALICE);
        router.burnTo(uint64(200 * U), G_ADDR);
        require(router.exitBurnerOf(1) == ALICE, "exit burner");
        require(bytes(router.redirectOf(1)).length == 0 && router.redirectCount(1) == 0, "no redirect");
        address mallory = address(0xBAD);
        vm.prank(mallory);
        (bool ok, bytes memory why) = address(router).call(abi.encodeCall(router.redirectHeldBurn, (1, C_ADDR)));
        require(!ok && bytes4(why) == StellarBurnRouter.NotTheBurner.selector, "stranger");
        vm.prank(ALICE);
        (ok, why) = address(router).call(abi.encodeCall(router.redirectHeldBurn, (2, C_ADDR)));
        require(!ok && bytes4(why) == StellarBurnRouter.NotTheBurner.selector, "no such exit");
        vm.prank(ALICE);
        (ok, why) = address(router).call(abi.encodeCall(router.redirectHeldBurn, (0, C_ADDR)));
        require(!ok && bytes4(why) == StellarBurnRouter.BadNonce.selector, "nonce 0");
        vm.prank(ALICE);
        (ok, why) = address(router).call(
            abi.encodeCall(router.redirectHeldBurn, (1, "GAF2DTU23X5CFOPOUCUBTFJ5PKTSOV4GLZAJB5VMJW2JUA5KKYF5OLNB"))
        );
        require(!ok && bytes4(why) == StellarBurnRouter.BadStrkey.selector, "bad strkey");
        vm.recordLogs();
        vm.prank(ALICE);
        router.redirectHeldBurn(1, C_ADDR);
        R324Vm.Log[] memory logs = vm.getRecordedLogs();
        require(logs.length == 1 && logs[0].emitter == address(router), "one log");
        require(logs[0].topics[0] == keccak256("HeldBurnRedirected(address,uint64,uint256,bytes20,string)"), "topic");
        require(address(uint160(uint256(logs[0].topics[1]))) == ALICE && uint256(logs[0].topics[2]) == 1, "indexed");
        (uint256 version, bytes20 c, string memory to) = abi.decode(logs[0].data, (uint256, bytes20, string));
        require(version == 1 && c == bytes20(router.commitment(C_ADDR)) && keccak256(bytes(to)) == keccak256(bytes(C_ADDR)), "data");
        require(keccak256(bytes(router.redirectOf(1))) == keccak256(bytes(C_ADDR)) && router.redirectCount(1) == 1, "stored");
        vm.prank(ALICE);
        (ok, why) = address(router).call(abi.encodeCall(router.redirectHeldBurn, (1, C_ADDR)));
        require(!ok && bytes4(why) == StellarBurnRouter.SameAddress.selector, "same again");
        vm.prank(ALICE);
        router.redirectHeldBurn(1, G_ADDR);
        require(keccak256(bytes(router.redirectAt(1, 0))) == keccak256(bytes(C_ADDR)), "history");
        require(keccak256(bytes(router.redirectOf(1))) == keccak256(bytes(G_ADDR)) && router.redirectCount(1) == 2, "latest");
    }

    function test_aDirectBurnCannotBeRedirectedAndARouterBurnCannotBeClaimed() public {
        vm.prank(ALICE);
        token.burn(uint64(50 * U), ALICE); // nonce 1, direct
        vm.prank(ALICE);
        (bool ok, bytes memory why) = address(router).call(abi.encodeCall(router.redirectHeldBurn, (1, C_ADDR)));
        require(!ok && bytes4(why) == StellarBurnRouter.NotTheBurner.selector && router.exitBurnerOf(1) == address(0), "direct");
        vm.prank(ALICE);
        token.approve(address(router), 100 * U);
        vm.prank(ALICE);
        router.burnTo(uint64(100 * U), G_ADDR); // nonce 2, through the router
        vm.prank(ALICE);
        router.claimDirectBurn(2, C_ADDR); // recorded under ALICE, but the burn's `from` is the router: ignored by readers
        require(bytes(router.claimOf(address(router), 2)).length == 0, "the router never claims");
    }

    function test_aClaimBelongsToItsCallerOnly() public {
        vm.prank(ALICE);
        token.burn(uint64(50 * U), ALICE);
        address mallory = address(0xBAD);
        vm.prank(mallory);
        router.claimDirectBurn(1, C_ADDR); // a stranger's claim for the same nonce sits under the stranger's key
        require(bytes(router.claimOf(ALICE, 1)).length == 0, "the burner's slot is untouched");
        require(keccak256(bytes(router.claimOf(mallory, 1))) == keccak256(bytes(C_ADDR)), "stranger's own slot");
        vm.prank(ALICE);
        router.claimDirectBurn(1, G_ADDR); // and does not stop the burner
        require(keccak256(bytes(router.claimOf(ALICE, 1))) == keccak256(bytes(G_ADDR)), "burner's claim");
    }

    function test_aClaimNeedsAValidAddressAndANonce() public {
        vm.prank(ALICE);
        (bool ok, bytes memory why) = address(router).call(
            abi.encodeCall(router.claimDirectBurn, (1, "GAF2DTU23X5CFOPOUCUBTFJ5PKTSOV4GLZAJB5VMJW2JUA5KKYF5OLNB"))
        );
        require(!ok && bytes4(why) == StellarBurnRouter.BadStrkey.selector, "bad strkey");
        vm.prank(ALICE);
        (ok, why) = address(router).call(abi.encodeCall(router.claimDirectBurn, (0, G_ADDR)));
        require(!ok && bytes4(why) == StellarBurnRouter.BadNonce.selector, "nonce 0");
        vm.prank(ALICE);
        (ok,) = address(router).call(abi.encodeCall(router.claimDirectBurn, (1, "")));
        require(!ok && bytes(router.claimOf(ALICE, 1)).length == 0, "empty address");
    }

    function test_aRouterBurnHasNoClaimSlotOfTheUser() public {
        vm.prank(ALICE);
        token.approve(address(router), 200 * U);
        vm.prank(ALICE);
        router.burnTo(uint64(200 * U), G_ADDR);
        // the burner of a router burn is the router, and the router never claims
        require(bytes(router.claimOf(address(router), 1)).length == 0, "router has no claim");
    }

    function testFuzz_randomStringsAreRefused(bytes32 a, bytes24 b) public {
        // 56 random bytes are a valid strkey with negligible probability.
        string memory s = string(abi.encodePacked(a, b));
        (bool ok,) = address(router).staticcall(abi.encodeCall(router.commitment, (s)));
        require(!ok, "random string accepted");
    }

    function _refused(string memory s) private {
        vm.expectRevert(StellarBurnRouter.BadStrkey.selector);
        router.commitment(s);
    }
}
