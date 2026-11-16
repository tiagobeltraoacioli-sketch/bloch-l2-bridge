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
