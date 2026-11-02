// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.24;

import {SignerMintedToken} from "../contracts/bridged/SignerMintedToken.sol";
import {BridgedStablecoinV2} from "../contracts/stable/BridgedStablecoinV2.sol";
import {BridgedStablecoinV3} from "../contracts/stable/BridgedStablecoinV3.sol";
import {ContextBoundSourceVault} from "../contracts/usdt/ContextBoundSourceVault.sol";
import {ProvenanceSourceVault} from "../contracts/usdt/ProvenanceSourceVault.sol";

interface D6Vm {
    function addr(uint256 privateKey) external pure returns (address);
    function sign(uint256 privateKey, bytes32 digest) external pure returns (uint8 v, bytes32 r, bytes32 s);
    function warp(uint256 timestamp) external;
    function roll(uint256 blockNumber) external;
    function prank(address sender) external;
    function setBlockhash(uint256 blockNumber, bytes32 hash) external;
    function expectRevert(bytes4 selector) external;
}

contract D6Usdc {
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

/// Stands for SP1ReleaseVerifier with the option-4 guest: it accepts a proof only for the release id the guest commits,
/// and the guest computes that id from the real `Burned` log, mint-chain fields included. `commit` is the test's way of
/// saying "a valid proof of this burn log exists".
contract D6ReleaseVerifier {
    mapping(bytes32 => bool) public committed;

    function commit(bytes32 id) external {
        committed[id] = true;
    }

    function verifyRelease(address, bytes32 id, bytes calldata) external view returns (bytes4) {
        return committed[id] ? this.verifyRelease.selector : bytes4(0);
    }
}

/// Stands for an SP1 mint-inclusion verifier (option 2 after the switch): a proof exists only for a real `Minted` log.
contract D6MintVerifier {
    mapping(bytes32 => bool) public committed;

    function commit(bytes32 id) external {
        committed[id] = true;
    }

    function verifyMint(address, bytes32 id, bytes calldata) external view returns (bytes4) {
        return committed[id] ? this.verifyMint.selector : bytes4(0);
    }
}

/// D6 (agents/101-bridge-audit.md): forged bUSDC, minted by the L2 mint quorum alone, is burned; honest Ethereum keys
/// (or a light-client proof) certify the real burn, and the vault pays it out of other users' deposits.
/// Mainnet parameters (busdc-mainnet.config.json): 5-of-7 on both sides, switch 6-of-7, bucket 10,000/day,
/// large-mint threshold 1,000 and delay 12 h, minBurn 10. The mint keys and the Ethereum keys are distinct sets;
/// the forger holds 5 mint keys and no Ethereum key.
/// `test_control_*` reproduce the attack where it still works. `test_O1_*` (mint chain), `test_O2_*` (delay and
/// challenge), `test_O3_*` (cumulative supply) and `test_O4_*` (light-client path of O1) are the options of
/// agents/108-d6-design.md. `*_limit_*` and `*_cost_*` tests assert the known weakness or price of an option.
contract D6ProvenanceTest {
    D6Vm constant vm = D6Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    uint256 constant U = 1e6;
    uint64 constant CAP = uint64(100_000 * U);
    uint64 constant BUCKET = uint64(10_000 * U);
    uint64 constant LARGE = uint64(1_000 * U);
    uint64 constant MIN_BURN = uint64(10 * U);
    uint64 constant DELAY = 1 days;
    address constant MALLORY = address(0xBAD);
    address constant ALICE = address(0xA11CE);
    address constant BOB = address(0xB0B);
    address constant CAROL = address(0xCA201);

    uint256[] mintKeys;
    uint256[] ethKeys;
    D6Usdc usdc;

    event Gas(string what, uint256 gas);

    function setUp() public {
        vm.warp(1_000_000);
        vm.roll(1000);
        mintKeys = sortedKeys(0x1000);
        ethKeys = sortedKeys(0x2000);
        usdc = new D6Usdc();
    }

    function sortedKeys(uint256 base) internal view returns (uint256[] memory k) {
        k = new uint256[](7);
        for (uint256 i; i < 7; ++i) k[i] = base + i;
        for (uint256 i; i < 7; ++i) {
            for (uint256 j = i + 1; j < 7; ++j) {
                if (vm.addr(k[j]) < vm.addr(k[i])) (k[i], k[j]) = (k[j], k[i]);
            }
        }
    }

    function addrs(uint256[] memory k) internal view returns (address[] memory a) {
        a = new address[](k.length);
        for (uint256 i; i < k.length; ++i) a[i] = vm.addr(k[i]);
    }

    function limits() internal pure returns (SignerMintedToken.Limits memory) {
        return SignerMintedToken.Limits(CAP, BUCKET, BUCKET / 1 days, LARGE, 12 hours, MIN_BURN);
    }

    function noGuard() internal pure returns (SignerMintedToken.Guard memory) {
        return SignerMintedToken.Guard(new address[](0), 0, 0);
    }

    function cert(bytes32 digest, uint256 n) internal view returns (bytes[] memory out) {
        out = new bytes[](n);
        for (uint256 i; i < n; ++i) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(ethKeys[i], digest);
            out[i] = abi.encodePacked(r, s, v);
        }
    }

    function mintBlob(bytes32 digest) internal view returns (bytes memory out) {
        for (uint256 i; i < 5; ++i) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(mintKeys[i], digest);
            out = bytes.concat(out, abi.encodePacked(r, s, v));
        }
    }

    function pad(address a) internal pure returns (bytes32) {
        return bytes32(uint256(uint160(a)));
    }

    // ── prototype pair: ProvenanceSourceVault + BridgedStablecoinV3 ──────────────────────────────────────────────────
    struct Pair {
        ProvenanceSourceVault vault;
        BridgedStablecoinV3 token;
    }

    function pair(uint8 mode, uint64 delay, address mintVerifier) internal returns (Pair memory p) {
        p.vault = new ProvenanceSourceVault(
            keccak256("ethereum"), keccak256("bloch-l2"), keccak256("USDC"), address(usdc), CAP, 0, addrs(ethKeys), 5,
            ProvenanceSourceVault.Policy(BUCKET, 1 days, 6, 14 days, MIN_BURN, MIN_BURN),
            ProvenanceSourceVault.Guard(new address[](0), 0, 0),
            ProvenanceSourceVault.Provenance(mode, delay, mintVerifier)
        );
        uint256 until = block.timestamp + 100;
        p.vault.setControls(true, true, 0, until, cert(p.vault.controlDigest(true, true, 0, until), 5));
        p.token = new BridgedStablecoinV3(
            "Bloch Bridged USDC", "bUSDC", block.chainid, address(p.vault), p.vault.routeId(), addrs(mintKeys), 5,
            limits(), noGuard(), BridgedStablecoinV2.MintSwitch(6, 14 days)
        );
        require(p.token.mintHead() == p.vault.mintChainGenesis(), "same genesis on both sides");
    }

    function deposit(Pair memory p, uint64 amount, address l2) internal returns (bytes32 id, uint64 nonce) {
        usdc.mint(address(this), amount);
        nonce = p.vault.depositCount();
        id = p.vault.deposit(amount, pad(l2));
    }

    /// The mint quorum signs; honest when the fields are a real deposit's, forged otherwise.
    function mint(Pair memory p, bytes32 id, uint64 nonce, uint64 amount, address to) internal {
        p.token.mint(id, nonce, amount, to, mintBlob(p.token.mintDigest(id, nonce, amount, to)));
    }

    /// A holder burns; returns the release item exactly as its `Burned` log states it.
    function burn(Pair memory p, address holder, uint64 amount)
        internal
        returns (ProvenanceSourceVault.Release memory r)
    {
        vm.prank(holder);
        bytes32 burnId = p.token.burn(amount, holder);
        r = ProvenanceSourceVault.Release(
            p.vault.routeId(), p.token.burnNonce(), holder, amount, burnId, p.token.mintCount(), p.token.mintedTotal(),
            p.token.mintHead()
        );
    }

    function context() internal returns (ProvenanceSourceVault.ReleaseContext memory) {
        vm.roll(block.number + 1);
        vm.setBlockhash(block.number - 1, keccak256(abi.encode("anchor", block.number)));
        return ProvenanceSourceVault.ReleaseContext(
            block.timestamp + 100, block.number - 1, keccak256(abi.encode("anchor", block.number)), 7, keccak256("l2")
        );
    }

    /// Honest Ethereum signers certify a real, final burn (they cannot see where the tokens came from).
    function certify(Pair memory p, ProvenanceSourceVault.Release memory r)
        internal
        returns (ProvenanceSourceVault.ReleaseContext memory c, bytes[] memory sigs)
    {
        c = context();
        sigs = cert(p.vault.releaseDigest(r, c), 5);
    }

    function tryRelease(Pair memory p, ProvenanceSourceVault.Release memory r) internal returns (bool ok, bytes4 err) {
        (ProvenanceSourceVault.ReleaseContext memory c, bytes[] memory sigs) = certify(p, r);
        bytes memory ret;
        (ok, ret) = address(p.vault).call(abi.encodeCall(ProvenanceSourceVault.release, (r, c, sigs)));
        if (!ok && ret.length >= 4) err = bytes4(ret);
    }

    function forgeD6(Pair memory p) internal returns (ProvenanceSourceVault.Release memory r) {
        // 101's D6: Alice's 1,000 deposit is final and not yet minted; the quorum mints 500 to Mallory, who burns.
        deposit(p, 1000 * uint64(U), ALICE);
        mint(p, keccak256("forged"), p.token.nextSlot(), 500 * uint64(U), MALLORY);
        r = burn(p, MALLORY, 500 * uint64(U));
    }

    // ── controls: the attack where it still works ────────────────────────────────────────────────────────────────────
    /// RC 12287a0 contracts: the forged burn is certified and paid out of Alice's deposit.
    function test_control_RC_forgedBurnIsPaid() public {
        ContextBoundSourceVault v = new ContextBoundSourceVault(
            keccak256("ethereum"), keccak256("bloch-l2"), keccak256("USDC"), address(usdc), CAP, 0, addrs(ethKeys), 5,
            ContextBoundSourceVault.Policy(BUCKET, 1 days, 6, 14 days, MIN_BURN, MIN_BURN),
            ContextBoundSourceVault.Guard(new address[](0), 0, 0)
        );
        uint256 until = block.timestamp + 100;
        v.setControls(true, true, 0, until, cert(v.controlDigest(true, true, 0, until), 5));
        BridgedStablecoinV2 t = new BridgedStablecoinV2(
            "Bloch Bridged USDC", "bUSDC", block.chainid, address(v), v.routeId(), addrs(mintKeys), 5, limits(), noGuard(), BridgedStablecoinV2.MintSwitch(6, 14 days)
        );
        usdc.mint(address(this), 1000 * U);
        v.deposit(uint64(1000 * U), pad(ALICE));
        bytes32 forged = keccak256("forged");
        t.mint(forged, 0, uint64(500 * U), MALLORY, mintBlob(t.mintDigest(forged, 0, uint64(500 * U), MALLORY)));
        vm.prank(MALLORY);
        bytes32 burnId = t.burn(uint64(500 * U), MALLORY);
        ContextBoundSourceVault.Release memory r =
            ContextBoundSourceVault.Release(v.routeId(), t.burnNonce(), MALLORY, uint64(500 * U), burnId);
        vm.roll(block.number + 1);
        vm.setBlockhash(block.number - 1, keccak256("a"));
        ContextBoundSourceVault.ReleaseContext memory c =
            ContextBoundSourceVault.ReleaseContext(block.timestamp + 100, block.number - 1, keccak256("a"), 7, keccak256("l2"));
        v.release(r, c, cert(v.releaseDigest(r, c), 5));
        require(usdc.balanceOf(MALLORY) == 500 * U && v.totalLocked() == 500 * U, "RC pays the forged burn");
    }

    /// Prototype with every option off: same result as the RC.
    function test_control_mode0_forgedBurnIsPaid() public {
        Pair memory p = pair(0, 0, address(0));
        (bool ok,) = tryRelease(p, forgeD6(p));
        require(ok && usdc.balanceOf(MALLORY) == 500 * U, "mode 0 pays the forged burn");
    }

    // ── O1: mint chain ───────────────────────────────────────────────────────────────────────────────────────────────
    function test_O1_D6_forgedBurnIsRefused() public {
        Pair memory p = pair(1, 0, address(0));
        ProvenanceSourceVault.Release memory r = forgeD6(p);
        require(!p.vault.provenanceMatches(r.mintCount, r.mintedTotal, r.mintHead), "the chain does not match");
        (bool ok, bytes4 err) = tryRelease(p, r);
        require(!ok && err == ProvenanceSourceVault.ProvenanceMismatch.selector, "refused: provenance");
        require(usdc.balanceOf(MALLORY) == 0 && p.vault.totalLocked() == 1000 * U, "Alice's deposit intact");
    }

    function test_O1_forgedMintAheadOfDepositsIsRefused() public {
        Pair memory p = pair(1, 0, address(0));
        (bytes32 a,) = deposit(p, 1000 * uint64(U), ALICE);
        mint(p, a, 0, 1000 * uint64(U), ALICE);
        mint(p, keccak256("ahead"), 1, 500 * uint64(U), MALLORY); // no deposit 1 exists
        ProvenanceSourceVault.Release memory r = burn(p, MALLORY, 500 * uint64(U));
        (bool ok, bytes4 err) = tryRelease(p, r);
        require(!ok && err == ProvenanceSourceVault.ProvenanceMismatch.selector, "count above depositCount");
        deposit(p, 500 * uint64(U), BOB); // a real deposit 1 arrives later: still not Mallory's
        (ok, err) = tryRelease(p, r);
        require(!ok && err == ProvenanceSourceVault.ProvenanceMismatch.selector, "a later real deposit does not back it");
    }

    function test_O1_inflatedRealDepositIsRefused() public {
        Pair memory p = pair(1, 0, address(0));
        (bytes32 a,) = deposit(p, 100 * uint64(U), MALLORY);
        mint(p, a, 0, 600 * uint64(U), MALLORY); // the real id and recipient, a larger amount
        deposit(p, 1000 * uint64(U), ALICE);
        (bool ok, bytes4 err) = tryRelease(p, burn(p, MALLORY, 600 * uint64(U)));
        require(!ok && err == ProvenanceSourceVault.ProvenanceMismatch.selector, "amount is bound");
    }

    function test_O1_redirectedRealDepositIsRefused() public {
        Pair memory p = pair(1, 0, address(0));
        (bytes32 a,) = deposit(p, 1000 * uint64(U), ALICE);
        mint(p, a, 0, 1000 * uint64(U), MALLORY); // the real id and amount, minted to Mallory
        (bool ok, bytes4 err) = tryRelease(p, burn(p, MALLORY, 1000 * uint64(U)));
        require(!ok && err == ProvenanceSourceVault.ProvenanceMismatch.selector, "recipient is bound");
    }

    function test_O1_outOfOrderMintIsRefused() public {
        Pair memory p = pair(1, 0, address(0));
        deposit(p, 100 * uint64(U), ALICE);
        (bytes32 b,) = deposit(p, 100 * uint64(U), BOB);
        bytes memory sigs = mintBlob(p.token.mintDigest(b, 1, 100 * uint64(U), BOB));
        (bool ok, bytes memory ret) =
            address(p.token).call(abi.encodeCall(BridgedStablecoinV2.mint, (b, 1, 100 * uint64(U), BOB, sigs)));
        require(!ok && bytes4(ret) == BridgedStablecoinV3.MintOutOfOrder.selector, "deposit order");
    }

    /// Honest flows pass, including burns made under an older head after later deposits.
    function test_O1_honestFlowsPay() public {
        Pair memory p = pair(1, 0, address(0));
        (bytes32 a,) = deposit(p, 1000 * uint64(U), ALICE);
        (bytes32 b,) = deposit(p, 800 * uint64(U), BOB);
        mint(p, a, 0, 1000 * uint64(U), ALICE);
        mint(p, b, 1, 800 * uint64(U), BOB);
        ProvenanceSourceVault.Release memory ra = burn(p, ALICE, 400 * uint64(U));
        ProvenanceSourceVault.Release memory rb = burn(p, BOB, 800 * uint64(U));
        (bytes32 c,) = deposit(p, 300 * uint64(U), CAROL); // later deposit, not yet minted
        (bool ok,) = tryRelease(p, ra);
        require(ok, "Alice paid");
        mint(p, c, 2, 300 * uint64(U), CAROL);
        (ok,) = tryRelease(p, rb);
        require(ok, "Bob paid with a head two deposits old");
        vm.prank(ALICE);
        p.token.transfer(CAROL, 600 * uint64(U));
        (ok,) = tryRelease(p, burn(p, CAROL, 900 * uint64(U)));
        require(ok, "Carol paid, tokens mixed from two deposits");
        require(usdc.balanceOf(ALICE) == 400 * U && usdc.balanceOf(BOB) == 800 * U && usdc.balanceOf(CAROL) == 900 * U, "amounts");
        require(p.vault.totalLocked() == 0 && p.token.totalSupply() == 0, "fully unwound");
    }

    /// Mints credit in slot order: a small mint behind a queued large one waits, then credits with it.
    function test_O1_creditOrderSmallMintWaitsForTheLargeOneAhead() public {
        Pair memory p = pair(1, 0, address(0));
        (bytes32 a,) = deposit(p, 5000 * uint64(U), ALICE);
        (bytes32 b,) = deposit(p, 200 * uint64(U), BOB);
        mint(p, a, 0, 5000 * uint64(U), ALICE); // queued 12 h
        mint(p, b, 1, 200 * uint64(U), BOB); // due now, but slot 0 waits
        require(p.token.balanceOf(BOB) == 0 && p.token.mintCount() == 0, "Bob waits for slot 0");
        (bool ok,) = address(p.token).call(abi.encodeCall(SignerMintedToken.executeMint, (b)));
        require(!ok, "not out of order");
        vm.warp(block.timestamp + 12 hours);
        p.token.executeMint(a);
        require(p.token.balanceOf(BOB) == 200 * U && p.token.mintCount() == 2, "Bob credited with Alice's execution");
        (ok,) = tryRelease(p, burn(p, BOB, 200 * uint64(U)));
        require(ok, "Bob paid");
        (ok,) = tryRelease(p, burn(p, ALICE, 5000 * uint64(U)));
        require(ok, "Alice paid");
    }

    /// Burns made before a forged mint keep paying after it: the chain holds them by count.
    function test_O1_burnBeforeTheForgeryStillPays() public {
        Pair memory p = pair(1, 0, address(0));
        (bytes32 a,) = deposit(p, 1000 * uint64(U), ALICE);
        mint(p, a, 0, 1000 * uint64(U), ALICE);
        ProvenanceSourceVault.Release memory early = burn(p, ALICE, 400 * uint64(U));
        mint(p, keccak256("forged"), 1, 500 * uint64(U), MALLORY);
        (bool ok,) = tryRelease(p, early);
        require(ok && usdc.balanceOf(ALICE) == 400 * U, "pre-forgery burn paid");
        (bool forgedOk,) = tryRelease(p, burn(p, MALLORY, 500 * uint64(U)));
        require(!forgedOk, "forged burn refused");
    }

    /// Price of O1: after an unbacked mint, honest burns made later are held too (liveness, not funds).
    function test_O1_cost_burnsAfterTheForgeryAreHeld() public {
        Pair memory p = pair(1, 0, address(0));
        (bytes32 a,) = deposit(p, 1000 * uint64(U), ALICE);
        mint(p, a, 0, 1000 * uint64(U), ALICE);
        mint(p, keccak256("forged"), 1, 500 * uint64(U), MALLORY);
        (bool ok, bytes4 err) = tryRelease(p, burn(p, ALICE, 1000 * uint64(U)));
        require(!ok && err == ProvenanceSourceVault.ProvenanceMismatch.selector, "held");
        require(p.vault.totalLocked() == 1000 * U, "nothing left the vault");
    }

    /// Griefing without the mint quorum: interleaved third-party deposits (dust at minDeposit) and burns never move an
    /// honest burn's match; a release with an invented head needs an Ethereum quorum certificate.
    function test_O1_griefing_withoutTheMintQuorumNothingMoves() public {
        Pair memory p = pair(1, 0, address(0));
        (bytes32 a,) = deposit(p, 1000 * uint64(U), ALICE);
        mint(p, a, 0, 1000 * uint64(U), ALICE);
        ProvenanceSourceVault.Release memory r = burn(p, ALICE, 1000 * uint64(U));
        for (uint256 i; i < 20; ++i) deposit(p, MIN_BURN, MALLORY);
        require(p.vault.provenanceMatches(r.mintCount, r.mintedTotal, r.mintHead), "old head still matches");
        (bool ok,) = tryRelease(p, r);
        require(ok, "paid after 20 dust deposits");
    }

    // ── O4: O1 on the light-client path (guest commits the burn's mint-chain fields in the v2 release id) ───────────────
    function switchTo(Pair memory p, address lc) internal {
        uint256 until = block.timestamp + 100;
        p.vault.proposeVerifier(lc, 0, until, cert(p.vault.switchDigest(false, lc, lc.codehash, 0, until), 6));
        vm.warp(block.timestamp + 14 days);
        p.vault.activateVerifier();
    }

    function test_O4_LC_forgedBurnWithAValidProofIsRefused() public {
        Pair memory p = pair(1, 0, address(0));
        D6ReleaseVerifier lc = new D6ReleaseVerifier();
        switchTo(p, address(lc));
        ProvenanceSourceVault.Release memory r = forgeD6(p);
        lc.commit(p.vault.releaseId(r)); // the guest proves the real burn log, forged chain included
        (bool ok, bytes memory ret) = address(p.vault).call(abi.encodeCall(ProvenanceSourceVault.releaseWithProof, (r, "")));
        require(!ok && bytes4(ret) == ProvenanceSourceVault.ProvenanceMismatch.selector, "valid proof, unbacked chain");
        // lying about the chain (the vault's real head) changes the release id, which no proof commits
        r.mintHead = p.vault.chainHeadAt(r.mintCount);
        (ok, ret) = address(p.vault).call(abi.encodeCall(ProvenanceSourceVault.releaseWithProof, (r, "")));
        require(!ok && bytes4(ret) == ProvenanceSourceVault.InvalidProof.selector, "the guest commits the log's head");
        require(usdc.balanceOf(MALLORY) == 0, "nothing paid");
    }

    function test_O4_LC_honestBurnPays() public {
        Pair memory p = pair(1, 0, address(0));
        D6ReleaseVerifier lc = new D6ReleaseVerifier();
        switchTo(p, address(lc));
        (bytes32 a,) = deposit(p, 1000 * uint64(U), ALICE);
        mint(p, a, 0, 1000 * uint64(U), ALICE);
        ProvenanceSourceVault.Release memory r = burn(p, ALICE, 1000 * uint64(U));
        lc.commit(p.vault.releaseId(r));
        p.vault.releaseWithProof(r, "");
        require(usdc.balanceOf(ALICE) == 1000 * U, "paid by proof");
    }

    /// Control for O4: with provenance off, the light-client path pays the forged burn (103's test of the same name).
    function test_control_LC_mode0_forgedBurnIsPaid() public {
        Pair memory p = pair(0, 0, address(0));
        D6ReleaseVerifier lc = new D6ReleaseVerifier();
        switchTo(p, address(lc));
        ProvenanceSourceVault.Release memory r = forgeD6(p);
        lc.commit(p.vault.releaseId(r));
        p.vault.releaseWithProof(r, "");
        require(usdc.balanceOf(MALLORY) == 500 * U, "paid; no guardian or signer can stop it after the switch");
    }

    // ── O2: release delay with a challenge by evidence of a forged mint ──────────────────────────────────────────────
    function claimOf(bytes32 id, uint64 nonce, uint64 amount, address to)
        internal
        pure
        returns (ProvenanceSourceVault.MintClaim memory)
    {
        return ProvenanceSourceVault.MintClaim(id, nonce, amount, to);
    }

    function test_O2_D6_challengeFreezesTheForgedRelease() public {
        Pair memory p = pair(0, DELAY, address(0));
        ProvenanceSourceVault.Release memory r = forgeD6(p);
        (bool ok,) = tryRelease(p, r);
        require(ok, "certified and queued");
        ProvenanceSourceVault.MintClaim memory m = claimOf(keccak256("forged"), 0, 500 * uint64(U), MALLORY);
        // the Ethereum committee attests the final `Minted` log; anyone submits
        p.vault.proveForgedMint(m, cert(p.vault.mintClaimDigest(m), 5), "");
        vm.warp(block.timestamp + DELAY);
        bytes32 id = p.vault.releaseId(r);
        (ok,) = address(p.vault).call(abi.encodeCall(ProvenanceSourceVault.executeRelease, (id)));
        require(!ok && usdc.balanceOf(MALLORY) == 0 && p.vault.totalLocked() == 1000 * U, "frozen, nothing paid");
    }

    function test_O2_aRealMintIsNotEvidence() public {
        Pair memory p = pair(0, DELAY, address(0));
        (bytes32 a,) = deposit(p, 1000 * uint64(U), ALICE);
        mint(p, a, 0, 1000 * uint64(U), ALICE);
        ProvenanceSourceVault.MintClaim memory m = claimOf(a, 0, 1000 * uint64(U), ALICE);
        bytes[] memory sigs = cert(p.vault.mintClaimDigest(m), 5);
        (bool ok, bytes memory ret) =
            address(p.vault).call(abi.encodeCall(ProvenanceSourceVault.proveForgedMint, (m, sigs, bytes(""))));
        require(!ok && bytes4(ret) == ProvenanceSourceVault.NotForged.selector, "a real mint cannot freeze");
        ProvenanceSourceVault.MintClaim memory fake = claimOf(keccak256("x"), 0, 1, MALLORY);
        bytes[] memory few = cert(p.vault.mintClaimDigest(fake), 4);
        (ok, ret) = address(p.vault).call(abi.encodeCall(ProvenanceSourceVault.proveForgedMint, (fake, few, bytes(""))));
        require(!ok && bytes4(ret) == ProvenanceSourceVault.InvalidCertificate.selector, "evidence needs the quorum");
        require(p.vault.forgeryProvenAt() == 0, "not frozen");
    }

    function test_O2_honestReleaseWaitsExactlyTheDelay() public {
        Pair memory p = pair(0, DELAY, address(0));
        (bytes32 a,) = deposit(p, 1000 * uint64(U), ALICE);
        mint(p, a, 0, 1000 * uint64(U), ALICE);
        ProvenanceSourceVault.Release memory r = burn(p, ALICE, 1000 * uint64(U));
        (bool ok,) = tryRelease(p, r);
        require(ok, "queued");
        bytes32 id = p.vault.releaseId(r);
        vm.warp(block.timestamp + DELAY - 1);
        (ok,) = address(p.vault).call(abi.encodeCall(ProvenanceSourceVault.executeRelease, (id)));
        require(!ok, "not before the delay");
        vm.warp(block.timestamp + 1);
        p.vault.executeRelease(id);
        require(usdc.balanceOf(ALICE) == 1000 * U, "paid at the delay");
        (ok,) = tryRelease(p, r);
        require(!ok, "no second queue of the same burn");
    }

    /// Limit of O2: with no watcher inside the delay, the forged release is paid (window bound as at the RC).
    function test_O2_limit_noChallengeInTimeIsPaid() public {
        Pair memory p = pair(0, DELAY, address(0));
        ProvenanceSourceVault.Release memory r = forgeD6(p);
        (bool ok,) = tryRelease(p, r);
        require(ok, "queued");
        vm.warp(block.timestamp + DELAY);
        p.vault.executeRelease(p.vault.releaseId(r));
        require(usdc.balanceOf(MALLORY) == 500 * U, "paid without a challenge");
    }

    /// Price of O2: a proven forgery freezes every queued release, honest ones included (the forger can trigger it).
    function test_O2_cost_aProvenForgeryFreezesHonestReleases() public {
        Pair memory p = pair(0, DELAY, address(0));
        (bytes32 a,) = deposit(p, 1000 * uint64(U), ALICE);
        mint(p, a, 0, 1000 * uint64(U), ALICE);
        ProvenanceSourceVault.Release memory r = burn(p, ALICE, 1000 * uint64(U));
        (bool ok,) = tryRelease(p, r);
        require(ok, "queued");
        mint(p, keccak256("forged"), 1, 10 * uint64(U), MALLORY);
        ProvenanceSourceVault.MintClaim memory m = claimOf(keccak256("forged"), 1, 10 * uint64(U), MALLORY);
        p.vault.proveForgedMint(m, cert(p.vault.mintClaimDigest(m), 5), "");
        vm.warp(block.timestamp + DELAY);
        (ok,) = address(p.vault).call(abi.encodeCall(ProvenanceSourceVault.executeRelease, (p.vault.releaseId(r))));
        require(!ok && p.vault.totalLocked() == 1000 * U, "Alice's release is frozen with it");
    }

    function test_O2_LC_challengeByMintProof() public {
        D6MintVerifier mv = new D6MintVerifier();
        Pair memory p = pair(0, DELAY, address(mv));
        D6ReleaseVerifier lc = new D6ReleaseVerifier();
        switchTo(p, address(lc));
        ProvenanceSourceVault.Release memory r = forgeD6(p);
        lc.commit(p.vault.releaseId(r));
        p.vault.releaseWithProof(r, "");
        ProvenanceSourceVault.MintClaim memory m = claimOf(keccak256("forged"), 0, 500 * uint64(U), MALLORY);
        bytes[] memory none = new bytes[](0);
        (bool ok,) = address(p.vault).call(abi.encodeCall(ProvenanceSourceVault.proveForgedMint, (m, none, bytes(""))));
        require(!ok, "no proof of that Minted log yet");
        mv.commit(p.vault.mintClaimId(m));
        p.vault.proveForgedMint(m, none, "");
        vm.warp(block.timestamp + DELAY);
        (ok,) = address(p.vault).call(abi.encodeCall(ProvenanceSourceVault.executeRelease, (p.vault.releaseId(r))));
        require(!ok && usdc.balanceOf(MALLORY) == 0, "frozen after the switch, with no committee");
    }

    // ── O3: cumulative supply proof against the deposits ────────────────────────────────────────────────────────────
    function test_O3_D6_inflationIsRefused() public {
        Pair memory p = pair(2, 0, address(0));
        (bool ok, bytes4 err) = tryRelease(p, forgeD6(p));
        require(!ok && err == ProvenanceSourceVault.ProvenanceMismatch.selector, "500 minted against 1,000 deposited");
    }

    function test_O3_honestFlowPays() public {
        Pair memory p = pair(2, 0, address(0));
        (bytes32 a,) = deposit(p, 1000 * uint64(U), ALICE);
        mint(p, a, 0, 1000 * uint64(U), ALICE);
        (bool ok,) = tryRelease(p, burn(p, ALICE, 1000 * uint64(U)));
        require(ok, "paid");
    }

    /// Limit of O3: a forged mint that copies a real deposit's amount to another recipient passes the amount check.
    function test_O3_limit_redirectedDepositIsPaid() public {
        Pair memory p = pair(2, 0, address(0));
        deposit(p, 1000 * uint64(U), ALICE);
        mint(p, keccak256("redirect"), 0, 1000 * uint64(U), MALLORY);
        (bool ok,) = tryRelease(p, burn(p, MALLORY, 1000 * uint64(U)));
        require(ok && usdc.balanceOf(MALLORY) == 1000 * U, "redirected deposit paid");
    }

    /// Limit of the naive supply check (101's second layer: refuse while supply + pending + this burn > totalLocked):
    /// in D6 it holds, because Alice's unminted deposit is slack. Shown on the RC-shaped numbers.
    function test_O3_limit_naiveSupplyCheckMissesD6() public {
        Pair memory p = pair(0, 0, address(0));
        ProvenanceSourceVault.Release memory r = forgeD6(p);
        uint256 supplyAfterBurn = p.token.totalSupply() + p.token.pendingSupply();
        require(supplyAfterBurn + r.amount <= p.vault.totalLocked(), "the naive check would let it through");
        (bool ok,) = tryRelease(p, r);
        require(ok && usdc.balanceOf(MALLORY) == 500 * U, "and it is paid");
    }

    // ── gas: one honest round trip per mode (read with --gas-report or -vvvv) ───────────────────────────────────────
    function roundTrip(uint8 mode, uint64 delay) internal {
        Pair memory p = pair(mode, delay, address(0));
        deposit(p, 1000 * uint64(U), BOB); // warm the chain and the bucket slots
        mint(p, p.vault.depositId(0, address(this), 1000 * uint64(U), pad(BOB)), 0, 1000 * uint64(U), BOB);
        usdc.mint(address(this), 1000 * U);
        uint256 g = gasleft();
        bytes32 a = p.vault.deposit(1000 * uint64(U), pad(ALICE));
        emit Gas("deposit", g - gasleft());
        bytes memory sigs = mintBlob(p.token.mintDigest(a, 1, 1000 * uint64(U), ALICE));
        g = gasleft();
        p.token.mint(a, 1, 1000 * uint64(U), ALICE, sigs);
        emit Gas("mint", g - gasleft());
        vm.prank(ALICE);
        g = gasleft();
        bytes32 burnId = p.token.burn(1000 * uint64(U), ALICE);
        emit Gas("burn", g - gasleft());
        ProvenanceSourceVault.Release memory r = ProvenanceSourceVault.Release(
            p.vault.routeId(), p.token.burnNonce(), ALICE, 1000 * uint64(U), burnId, p.token.mintCount(),
            p.token.mintedTotal(), p.token.mintHead()
        );
        (ProvenanceSourceVault.ReleaseContext memory c, bytes[] memory rs) = certify(p, r);
        g = gasleft();
        p.vault.release(r, c, rs);
        emit Gas("release", g - gasleft());
        if (delay != 0) {
            vm.warp(block.timestamp + delay);
            bytes32 id = p.vault.releaseId(r);
            g = gasleft();
            p.vault.executeRelease(id);
            emit Gas("executeRelease", g - gasleft());
        }
        require(usdc.balanceOf(ALICE) == 1000 * U, "round trip");
    }

    function test_gas_mode0() public {
        roundTrip(0, 0);
    }

    function test_gas_O1() public {
        roundTrip(1, 0);
    }

    function test_gas_O2() public {
        roundTrip(0, DELAY);
    }

    function test_gas_O3() public {
        roundTrip(2, 0);
    }

    function test_gas_O2_challenge() public {
        Pair memory p = pair(0, DELAY, address(0));
        forgeD6(p);
        ProvenanceSourceVault.MintClaim memory m = claimOf(keccak256("forged"), 0, 500 * uint64(U), MALLORY);
        bytes[] memory sigs = cert(p.vault.mintClaimDigest(m), 5);
        uint256 g = gasleft();
        p.vault.proveForgedMint(m, sigs, "");
        emit Gas("proveForgedMint", g - gasleft());
    }

    /// The same round trip on the RC contracts, for the baseline.
    function test_gas_RC() public {
        ContextBoundSourceVault v = new ContextBoundSourceVault(
            keccak256("ethereum"), keccak256("bloch-l2"), keccak256("USDC"), address(usdc), CAP, 0, addrs(ethKeys), 5,
            ContextBoundSourceVault.Policy(BUCKET, 1 days, 6, 14 days, MIN_BURN, MIN_BURN),
            ContextBoundSourceVault.Guard(new address[](0), 0, 0)
        );
        uint256 until = block.timestamp + 100;
        v.setControls(true, true, 0, until, cert(v.controlDigest(true, true, 0, until), 5));
        BridgedStablecoinV2 t = new BridgedStablecoinV2(
            "Bloch Bridged USDC", "bUSDC", block.chainid, address(v), v.routeId(), addrs(mintKeys), 5, limits(), noGuard(), BridgedStablecoinV2.MintSwitch(6, 14 days)
        );
        usdc.mint(address(this), 2000 * U);
        bytes32 w = v.deposit(uint64(1000 * U), pad(BOB));
        t.mint(w, 0, uint64(1000 * U), BOB, mintBlob(t.mintDigest(w, 0, uint64(1000 * U), BOB)));
        uint256 g = gasleft();
        bytes32 a = v.deposit(uint64(1000 * U), pad(ALICE));
        emit Gas("deposit", g - gasleft());
        bytes memory sigs = mintBlob(t.mintDigest(a, 1, uint64(1000 * U), ALICE));
        g = gasleft();
        t.mint(a, 1, uint64(1000 * U), ALICE, sigs);
        emit Gas("mint", g - gasleft());
        vm.prank(ALICE);
        g = gasleft();
        bytes32 burnId = t.burn(uint64(1000 * U), ALICE);
        emit Gas("burn", g - gasleft());
        ContextBoundSourceVault.Release memory r =
            ContextBoundSourceVault.Release(v.routeId(), t.burnNonce(), ALICE, uint64(1000 * U), burnId);
        vm.roll(block.number + 1);
        vm.setBlockhash(block.number - 1, keccak256("a"));
        ContextBoundSourceVault.ReleaseContext memory c =
            ContextBoundSourceVault.ReleaseContext(block.timestamp + 100, block.number - 1, keccak256("a"), 7, keccak256("l2"));
        bytes[] memory rs = cert(v.releaseDigest(r, c), 5);
        g = gasleft();
        v.release(r, c, rs);
        emit Gas("release", g - gasleft());
    }
}
