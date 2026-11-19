// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity 0.8.24;

// Reviewer 423 (round 20): NativeEtherSourceVault paired with the real frozen BridgedStablecoinV3 ("bETH", six
// decimals): units against wei, the cap edge, the mint chain end to end, and mint-certificate replay between two
// tokens of one committee. Review branch only. (One EVM stands for both chains: the token only needs sourceChainId.)
import {NativeEtherSourceVault} from "../contracts/eth/NativeEtherSourceVault.sol";
import {BridgedStablecoinV3} from "../contracts/stable/BridgedStablecoinV3.sol";
import {BridgedStablecoinV2} from "../contracts/stable/BridgedStablecoinV2.sol";
import {SignerMintedToken} from "../contracts/bridged/SignerMintedToken.sol";
import {NativeEtherVaultBase} from "./NativeEtherVaultBase.sol";

interface R423LogVm {
    struct Log {
        bytes32[] topics;
        bytes data;
        address emitter;
    }

    function recordLogs() external;
    function getRecordedLogs() external returns (Log[] memory);
}

contract R423NativeEtherTokenPairTest is NativeEtherVaultBase {
    R423LogVm constant lvm = R423LogVm(address(uint160(uint256(keccak256("hevm cheat code")))));
    BridgedStablecoinV3 beth;
    BridgedStablecoinV3 busdc;
    uint64 nextSlot;

    function token(string memory name, string memory symbol, address v, bytes32 route) internal returns (BridgedStablecoinV3) {
        return new BridgedStablecoinV3(
            name, symbol, block.chainid, v, route, addrs(keys), 5,
            SignerMintedToken.Limits(CAP, BUCKET, BUCKET / uint256(WINDOW), 0, 12 hours, MIN_BURN),
            SignerMintedToken.Guard(guardians(), 3 days, 3 days), BridgedStablecoinV2.MintSwitch(6, 14 days)
        );
    }

    function setUp() public {
        baseSetUp();
        beth = token("Bloch Bridged Ether", "bETH", address(vault), vault.routeId());
        // a second token of the SAME committee, source chain and (hypothetically) the same vault address and route
        busdc = token("Bloch Bridged USDC", "bUSDC", address(vault), vault.routeId());
    }

    function blob(bytes32 digest, uint256 n) internal view returns (bytes memory b) {
        for (uint256 i; i < n; ++i) b = abi.encodePacked(b, sig(keys[i], digest));
    }

    function mintNow(bytes32 id, uint64 slot, uint64 net, address who) internal {
        bytes memory sigs = blob(beth.mintDigest(id, slot, net, who), 5);
        beth.mint(id, slot, net, who, sigs);
        vm.warp(block.timestamp + 12 hours + 1);
        beth.executeMint(id);
    }

    /// Deposit `gross` units of ether and credit the L2 mint of its net amount (12 h queue).
    function bridgeIn(address who, uint64 gross) internal returns (bytes32 id, uint64 net) {
        id = depositAs(who, gross, who);
        net = gross - depFee(gross);
        mintNow(id, nextSlot++, net, who);
    }

    function test_R423_unitsDecimalsAndBackingEndToEnd() public {
        require(beth.decimals() == 6 && vault.decimals() == 6 && vault.UNIT() == 1e12, "decimals");
        require(beth.mintHead() == vault.mintChainGenesis(), "the token starts at the vault's genesis");
        (, uint64 net) = bridgeIn(ALICE, 10_000_001); // 10.000001 ETH: fee ceil(5000.0005) = 5001
        require(net == 10_000_001 - 5_001 && beth.balanceOf(ALICE) == net, "net minted");
        require(beth.totalSupply() == vault.totalLocked(), "supply == totalLocked (units)");
        require(address(vault).balance == uint256(vault.totalLocked() + vault.feesAccrued()) * 1e12, "wei == units x 1e12");
        require(beth.mintHead() == vault.chainHeadAt(1) && beth.mintCount() == 1, "one chain on both sides");
        // burn 3.000001 bETH back to a fresh Ethereum address; the certificate carries the burn's own chain state
        lvm.recordLogs();
        vm.prank(ALICE);
        bytes32 burnId = beth.burn(3_000_001, BOB);
        R423LogVm.Log[] memory logs = lvm.getRecordedLogs();
        (uint64 amount, address to, uint64 mc, uint64 mt, bytes32 mh) = (0, address(0), 0, 0, bytes32(0));
        for (uint256 i; i < logs.length; ++i) {
            if (logs[i].topics[0] == keccak256("Burned(bytes32,uint64,address,uint64,address,uint64,uint64,bytes32)")) {
                (amount, to, mc, mt, mh) = abi.decode(logs[i].data, (uint64, address, uint64, uint64, bytes32));
            }
        }
        require(amount == 3_000_001 && to == BOB && mc == 1 && mh == vault.chainHeadAt(1), "the Burned log");
        NativeEtherSourceVault.Release memory r = NativeEtherSourceVault.Release(vault.routeId(), 0, to, amount, burnId, mc, mt, mh);
        NativeEtherSourceVault.ReleaseContext memory c = context();
        vault.release(r, c, cert(vault.releaseDigest(r, c), 5));
        uint64 fee = relFee(3_000_001); // ceil(3000.001) = 3001
        require(fee == 3_001 && BOB.balance == uint256(3_000_001 - fee) * 1e12, "paid in wei, fee rounded up");
        require(beth.totalSupply() == vault.totalLocked(), "supply == totalLocked after the exit");
        require(address(vault).balance == vault.owedWei() && vault.surplusWei() == 0, "nothing unaccounted");
    }

    /// The cap in units is one number on both sides: the vault fills to exactly `cap` net, the token mints exactly
    /// `supplyCap`, and one unit more is refused by the VAULT (so no deposit can exist that the token cannot mint).
    function test_R423_capEdgeMatchesSupplyCap() public {
        require(beth.supplyCap() == vault.cap() && beth.bucketCapacity() == vault.windowLimit(), "limits pair");
        // ten deposits of the window size net 27.986 ETH each; then top up to the cap exactly
        uint256 guard;
        while (vault.cap() - vault.totalLocked() >= BUCKET && guard++ < 20) {
            bridgeIn(ALICE, BUCKET);
            vm.warp(block.timestamp + 1 days);
        }
        uint64 room = vault.cap() - vault.totalLocked();
        // the gross amount whose net is exactly `room`: gross - ceil(gross * 5 / 10000) == room
        uint64 gross = room + uint64((uint256(room) * 5 + 9_994) / 9_995);
        while (gross - depFee(gross) > room) --gross;
        while (gross - depFee(gross) < room) ++gross;
        require(gross - depFee(gross) == room, "control: a gross amount netting the room exactly");
        (bool ok,) = tryDeposit(BOB, gross + 1, BOB);
        if (gross + 1 - depFee(gross + 1) > room) require(!ok, "the vault took a deposit above its cap");
        bridgeIn(BOB, gross);
        require(vault.totalLocked() == vault.cap() && beth.totalSupply() == beth.supplyCap(), "both full, to the unit");
        (ok,) = tryDeposit(CAROL, MIN_DEPOSIT, CAROL);
        require(!ok, "a deposit above the cap");
        require(address(vault).balance == vault.owedWei(), "books");
    }

    function mintTry(BridgedStablecoinV3 t, bytes32 id, uint64 amount, address to, bytes memory sigs) internal returns (bool ok) {
        (ok,) = address(t).call(abi.encodeCall(BridgedStablecoinV2.mint, (id, 0, amount, to, sigs)));
    }

    function releaseBlob() internal returns (bytes memory) {
        NativeEtherSourceVault.Release memory r = cleanBurn(ALICE, 1_000, 1);
        NativeEtherSourceVault.ReleaseContext memory c = context();
        return blob(vault.releaseDigest(r, c), 5);
    }

    /// A mint certificate of one token is refused by another token of the same committee, same source vault and route
    /// (the EIP-712 domain binds the token address), and a certificate over other fields is refused.
    function test_R423_mintCertificatesDoNotCrossTokens() public {
        bytes32 id = depositAs(ALICE, 1_000_000, ALICE);
        uint64 net = 1_000_000 - depFee(1_000_000);
        require(beth.mintDigest(id, 0, net, ALICE) != busdc.mintDigest(id, 0, net, ALICE), "digests equal");
        bytes memory forUsdc = blob(busdc.mintDigest(id, 0, net, ALICE), 5);
        bytes memory forEth = blob(beth.mintDigest(id, 0, net, ALICE), 5);
        require(!mintTry(beth, id, net, ALICE, forUsdc), "a bUSDC mint certificate minted bETH");
        require(!mintTry(busdc, id, net, ALICE, forEth), "a bETH mint certificate minted bUSDC");
        require(!mintTry(beth, id, net + 1, ALICE, forEth), "amount not bound");
        require(!mintTry(beth, id, net, MALLORY, forEth), "recipient not bound");
        require(!mintTry(beth, id, net, ALICE, releaseBlob()), "a release certificate minted");
        require(beth.pendingSupply() == 0 && beth.totalSupply() == 0, "nothing queued by a refused mint");
        require(mintTry(beth, id, net, ALICE, forEth), "control: the right certificate is accepted");
        require(beth.pendingSupply() == net, "control: the mint is queued (12 h)");
    }
}
