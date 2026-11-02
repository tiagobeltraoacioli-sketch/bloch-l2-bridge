// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.24;

import {SignerMintedToken} from "../contracts/bridged/SignerMintedToken.sol";
import {BridgedStablecoinV2, IMintVerifier} from "../contracts/stable/BridgedStablecoinV2.sol";
import {ContextBoundSourceVault} from "../contracts/usdt/ContextBoundSourceVault.sol";

interface SwitchTestVm {
    function addr(uint256 privateKey) external pure returns (address);
    function sign(uint256 privateKey, bytes32 digest) external pure returns (uint8 v, bytes32 r, bytes32 s);
    function warp(uint256 timestamp) external;
    function chainId(uint256 newChainId) external;
    function prank(address sender) external;
    function etch(address target, bytes calldata code) external;
    function expectRevert(bytes4 selector) external;
    function roll(uint256 blockNumber) external;
    function setBlockhash(uint256 blockNumber, bytes32 hash) external;
}

/// A "proof" is valid iff it equals keccak256(token, mintHash), standing in for an SP1 proof of the deposit.
contract HashMintVerifier is IMintVerifier {
    function verifyMint(address token, bytes32 mintHash, bytes calldata proof) external pure returns (bytes4) {
        require(keccak256(proof) == keccak256(abi.encode(keccak256(abi.encode(token, mintHash)))), "bad proof");
        return IMintVerifier.verifyMint.selector;
    }
}

contract OtherMintVerifier is IMintVerifier {
    function verifyMint(address, bytes32, bytes calldata) external pure returns (bytes4) {
        return IMintVerifier.verifyMint.selector;
    }
}

contract WrongMagicMintVerifier is IMintVerifier {
    function verifyMint(address, bytes32, bytes calldata) external pure returns (bytes4) {
        return 0xdeadbeef;
    }
}

contract RevertingMintVerifier {
    fallback() external {
        bytes4 magic = IMintVerifier.verifyMint.selector;
        assembly {
            mstore(0, magic)
            revert(0, 32)
        }
    }
}

contract ShortReturnMintVerifier {
    fallback() external {
        assembly {
            mstore(0, 0xfeed)
            return(0, 4)
        }
    }
}

/// Tries to change state inside the proof check; the staticcall must refuse it.
contract StatefulMintVerifier {
    uint256 public calls;

    fallback() external {
        ++calls;
        bytes4 magic = IMintVerifier.verifyMint.selector;
        assembly {
            mstore(0, magic)
            return(0, 32)
        }
    }
}

contract SwitchUsdc {
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

contract MintSwitchTest {
    SwitchTestVm constant vm = SwitchTestVm(address(uint160(uint256(keccak256("hevm cheat code")))));
    uint256 constant L2 = 700770;
    uint256 constant U = 1e6;
    uint256 constant CAP = 100_000 * U;
    uint256 constant BUCKET = 10_000 * U;
    uint256 constant REFILL = BUCKET / 1 days;
    uint256 constant LARGE = 1_000 * U;
    uint256 constant LARGE_DELAY = 12 hours;
    uint64 constant PAUSE = 3 days;
    uint64 constant DELAY = 14 days;
    uint256 constant K = 5;
    uint256 constant SWITCH_K = 6;
    address constant VAULT = address(0x5A17);
    bytes32 constant ROUTE = keccak256("route");
    address constant ALICE = address(0xA11CE);
    address constant BOB = address(0xB0B);

    uint256[] keys; // sorted by address
    uint256 constant G1_KEY = 0x6a01;
    uint256 constant G2_KEY = 0x6a02;
    BridgedStablecoinV2 token;
    HashMintVerifier good;
    uint64 nextNonce;

    function setUp() public {
        vm.chainId(L2);
        vm.warp(1_000_000);
        keys = new uint256[](7);
        for (uint256 i; i < 7; ++i) keys[i] = 0x1000 + i;
        for (uint256 i; i < 7; ++i) {
            for (uint256 j = i + 1; j < 7; ++j) {
                if (vm.addr(keys[j]) < vm.addr(keys[i])) (keys[i], keys[j]) = (keys[j], keys[i]);
            }
        }
        token = make(SWITCH_K, DELAY);
        good = new HashMintVerifier();
    }

    function signerAddrs() internal view returns (address[] memory s) {
        s = new address[](7);
        for (uint256 i; i < 7; ++i) s[i] = vm.addr(keys[i]);
    }

    function guardCfg() internal pure returns (SignerMintedToken.Guard memory g) {
        g.guardians = new address[](2);
        g.guardians[0] = vm.addr(G1_KEY);
        g.guardians[1] = vm.addr(G2_KEY);
        g.pauseDuration = PAUSE;
        g.pauseCooldown = PAUSE;
    }

    function limits() internal pure returns (SignerMintedToken.Limits memory) {
        return SignerMintedToken.Limits({
            supplyCap: CAP,
            bucketCapacity: BUCKET,
            refillPerSecond: REFILL,
            largeMintThreshold: LARGE,
            largeMintDelay: LARGE_DELAY,
            minBurn: 10 * U
        });
    }

    function make(uint256 switchK, uint64 delay) internal returns (BridgedStablecoinV2) {
        return new BridgedStablecoinV2(
            "Bloch Bridged USDC", "bUSDC", 1, VAULT, ROUTE, signerAddrs(), K, limits(), guardCfg(),
            BridgedStablecoinV2.MintSwitch(switchK, delay)
        );
    }

    function sigs(bytes32 digest, uint256 n) internal view returns (bytes memory blob) {
        for (uint256 i; i < n; ++i) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(keys[i], digest);
            blob = bytes.concat(blob, abi.encodePacked(r, s, v));
        }
    }

    function propose(address v) internal {
        uint64 nonce = token.switchNonce();
        uint256 until = block.timestamp + 100;
        token.proposeVerifier(v, nonce, until, sigs(token.mintSwitchDigest(false, v, v.codehash, nonce, until), SWITCH_K));
    }

    function activate(address v) internal {
        propose(v);
        vm.warp(block.timestamp + DELAY);
        token.activateVerifier();
    }

    function proofOf(BridgedStablecoinV2 t, bytes32 id, uint64 nonce, uint64 amount, address to)
        internal
        view
        returns (bytes memory)
    {
        bytes32 structHash = keccak256(abi.encode(t.MINT_TYPEHASH(), uint256(1), VAULT, ROUTE, id, nonce, amount, to));
        return abi.encode(keccak256(abi.encode(address(t), structHash)));
    }

    function dep(uint256 n) internal pure returns (bytes32) {
        return keccak256(abi.encode("deposit", n));
    }

    function committeeMint(bytes32 d, uint64 amount, address to) internal {
        uint64 nonce = nextNonce++;
        token.mint(d, nonce, amount, to, sigs(token.mintDigest(d, nonce, amount, to), K));
    }

    function proofMint(bytes32 d, uint64 amount, address to) internal {
        uint64 nonce = nextNonce++;
        token.mintWithProof(d, nonce, amount, to, proofOf(token, d, nonce, amount, to));
    }

    function eq(uint256 a, uint256 b, string memory what) internal pure {
        require(a == b, what);
    }

    function no(bytes memory call, bytes4 err) internal {
        (bool ok, bytes memory ret) = address(token).call(call);
        require(!ok, "call should revert");
        bytes4 got;
        assembly {
            got := mload(add(ret, 32))
        }
        require(got == err, "wrong revert reason");
    }

    function noPropose(address v, uint64 nonce, uint256 until, bytes memory blob, bytes4 err) internal {
        no(abi.encodeCall(BridgedStablecoinV2.proposeVerifier, (v, nonce, until, blob)), err);
    }

    function goodBlob(address v, uint64 nonce, uint256 until) internal view returns (bytes memory) {
        return sigs(token.mintSwitchDigest(false, v, v.codehash, nonce, until), SWITCH_K);
    }

    // ── constructor misuse ───────────────────────────────────────────────────
    function testCtorRefusesBadSwitchConfig() public {
        SignerMintedToken.Limits memory l = limits();
        uint256[4] memory ks = [K - 1, 8, SWITCH_K, SWITCH_K];
        uint64[4] memory ds = [DELAY, DELAY, uint64(7 days - 1), uint64(0)];
        for (uint256 i; i < 4; ++i) {
            vm.expectRevert(SignerMintedToken.BadConfig.selector);
            new BridgedStablecoinV2("B", "b", 1, VAULT, ROUTE, signerAddrs(), K, l, guardCfg(),
                BridgedStablecoinV2.MintSwitch(ks[i], ds[i]));
        }
        // the delay must exceed the large-mint delay even when that is above the minimum
        l.largeMintDelay = 8 days;
        vm.expectRevert(SignerMintedToken.BadConfig.selector);
        new BridgedStablecoinV2("B", "b", 1, VAULT, ROUTE, signerAddrs(), K, l, guardCfg(),
            BridgedStablecoinV2.MintSwitch(SWITCH_K, 8 days));
    }

    function testFreshTokenHasNoVerifierAndCommitteeMints() public {
        eq(uint160(token.verifier()), 0, "no verifier");
        eq(token.switchThreshold(), SWITCH_K, "k");
        eq(token.switchDelay(), DELAY, "delay");
        committeeMint(dep(1), uint64(100 * U), ALICE);
        eq(token.balanceOf(ALICE), 100 * U, "minted");
    }

    // ── propose misuse ───────────────────────────────────────────────────────
    function testProposeRefusals() public {
        address v = address(good);
        uint256 until = block.timestamp + 100;
        bytes4 sw = BridgedStablecoinV2.InvalidSwitch.selector;
        noPropose(address(0), 0, until, goodBlob(address(0), 0, until), sw);
        noPropose(address(token), 0, until, goodBlob(address(token), 0, until), sw);
        noPropose(ALICE, 0, until, goodBlob(ALICE, 0, until), sw); // no code
        noPropose(v, 1, until, goodBlob(v, 1, until), sw); // wrong nonce
        noPropose(v, 0, block.timestamp - 1, goodBlob(v, 0, block.timestamp - 1), sw); // expired certificate
    }

    function testProposeNeedsSwitchQuorumNotMintQuorum() public {
        address v = address(good);
        uint256 until = block.timestamp + 100;
        bytes32 d = token.mintSwitchDigest(false, v, v.codehash, 0, until);
        noPropose(v, 0, until, sigs(d, K), SignerMintedToken.BadSignatureCount.selector);
        noPropose(v, 0, until, sigs(d, 7), SignerMintedToken.BadSignatureCount.selector);
        noPropose(v, 0, until, "", SignerMintedToken.BadSignatureCount.selector);
    }

    function testProposeRefusesBadSigners() public {
        address v = address(good);
        uint256 until = block.timestamp + 100;
        bytes32 d = token.mintSwitchDigest(false, v, v.codehash, 0, until);
        // a guardian is not a signer, even with five real signers
        (uint8 gv, bytes32 gr, bytes32 gs) = vm.sign(G1_KEY, d);
        noPropose(v, 0, until, bytes.concat(abi.encodePacked(gr, gs, gv), sigs(d, 5)), SignerMintedToken.NotSigner.selector);
        // the same signer twice
        (uint8 v0, bytes32 r0, bytes32 s0) = vm.sign(keys[0], d);
        bytes memory one = abi.encodePacked(r0, s0, v0);
        noPropose(v, 0, until, bytes.concat(one, one, one, one, one, one), SignerMintedToken.SignersNotAscending.selector);
    }

    function testProposeBoundToVerifierCodeNonceTokenAndChain() public {
        address v = address(good);
        uint256 until = block.timestamp + 100;
        // signed for another verifier
        OtherMintVerifier other = new OtherMintVerifier();
        noPropose(v, 0, until, goodBlob(address(other), 0, until), SignerMintedToken.NotSigner.selector);
        // a cancel certificate is not a proposal
        noPropose(v, 0, until, sigs(token.mintSwitchDigest(true, v, v.codehash, 0, until), SWITCH_K),
            SignerMintedToken.NotSigner.selector);
        // a mint certificate is not a proposal
        noPropose(v, 0, until, sigs(token.mintDigest(dep(9), 0, 1, ALICE), SWITCH_K), SignerMintedToken.NotSigner.selector);
        // signed for another token at the same parameters
        BridgedStablecoinV2 second = make(SWITCH_K, DELAY);
        noPropose(v, 0, until, sigs(second.mintSwitchDigest(false, v, v.codehash, 0, until), SWITCH_K),
            SignerMintedToken.NotSigner.selector);
        // signed on another chain
        vm.chainId(1);
        bytes memory otherChain = goodBlob(v, 0, until);
        vm.chainId(L2);
        noPropose(v, 0, until, otherChain, SignerMintedToken.NotSigner.selector);
    }

    function testOneLiveProposalAtATimeAndSignatureNotReplayable() public {
        address v = address(good);
        uint256 until = block.timestamp + 100;
        bytes memory blob = goodBlob(v, 0, until);
        token.proposeVerifier(v, 0, until, blob);
        eq(token.verifierActivatesAt(), block.timestamp + DELAY, "activates");
        // no second proposal over a live one
        noPropose(v, 1, until, goodBlob(v, 1, until), BridgedStablecoinV2.InvalidSwitch.selector);
        // cancel, then the old proposal certificate is dead
        token.cancelVerifier(1, until, sigs(token.mintSwitchDigest(true, v, v.codehash, 1, until), SWITCH_K));
        noPropose(v, 0, until, blob, BridgedStablecoinV2.InvalidSwitch.selector);
        eq(token.switchNonce(), 2, "nonce");
    }

    // ── cancel ───────────────────────────────────────────────────────────────
    function testCancelRefusalsAndEffect() public {
        address v = address(good);
        uint256 until = block.timestamp + 100;
        no(abi.encodeCall(BridgedStablecoinV2.cancelVerifier, (0, until, "")), BridgedStablecoinV2.InvalidSwitch.selector);
        propose(v);
        bytes32 d = token.mintSwitchDigest(true, v, v.codehash, 1, until);
        no(abi.encodeCall(BridgedStablecoinV2.cancelVerifier, (1, until, sigs(d, K))),
            SignerMintedToken.BadSignatureCount.selector);
        no(abi.encodeCall(BridgedStablecoinV2.cancelVerifier, (0, until, sigs(d, SWITCH_K))),
            BridgedStablecoinV2.InvalidSwitch.selector);
        token.cancelVerifier(1, until, sigs(d, SWITCH_K));
        eq(uint160(token.proposedVerifier()), 0, "cleared");
        vm.warp(block.timestamp + DELAY);
        no(abi.encodeCall(BridgedStablecoinV2.activateVerifier, ()), BridgedStablecoinV2.InvalidSwitch.selector);
        eq(uint160(token.verifier()), 0, "still committee");
    }

    // ── activate ─────────────────────────────────────────────────────────────
    function testActivationTimingAndPermissionless() public {
        propose(address(good));
        uint256 t = token.verifierActivatesAt();
        vm.warp(t - 1);
        no(abi.encodeCall(BridgedStablecoinV2.activateVerifier, ()), BridgedStablecoinV2.InvalidSwitch.selector);
        vm.warp(t);
        vm.prank(address(0xD00D)); // holds no role
        token.activateVerifier();
        eq(uint160(token.verifier()), uint160(address(good)), "active");
        no(abi.encodeCall(BridgedStablecoinV2.activateVerifier, ()), BridgedStablecoinV2.InvalidSwitch.selector);
    }

    function testProposalExpiresAndCanBeReplacedWithFullDelay() public {
        propose(address(good));
        uint256 t = token.verifierActivatesAt();
        vm.warp(t + token.VERIFIER_ACTIVATION_WINDOW() + 1);
        no(abi.encodeCall(BridgedStablecoinV2.activateVerifier, ()), BridgedStablecoinV2.InvalidSwitch.selector);
        require(!token.verifierProposalLive(), "expired");
        OtherMintVerifier other = new OtherMintVerifier();
        propose(address(other));
        eq(token.verifierActivatesAt(), block.timestamp + DELAY, "full new delay");
        no(abi.encodeCall(BridgedStablecoinV2.activateVerifier, ()), BridgedStablecoinV2.InvalidSwitch.selector);
    }

    function testActivationAtTheLastSecondOfTheWindow() public {
        propose(address(good));
        vm.warp(uint256(token.verifierActivatesAt()) + token.VERIFIER_ACTIVATION_WINDOW());
        token.activateVerifier();
        eq(uint160(token.verifier()), uint160(address(good)), "active");
    }

    function testActivationRefusesChangedVerifierCode() public {
        propose(address(good));
        vm.etch(address(good), address(new OtherMintVerifier()).code);
        vm.warp(block.timestamp + DELAY);
        no(abi.encodeCall(BridgedStablecoinV2.activateVerifier, ()), BridgedStablecoinV2.InvalidSwitch.selector);
    }

    // ── the irreversible path ────────────────────────────────────────────────
    function testBeforeActivationProofsAreRefusedAndCommitteeStillMints() public {
        no(abi.encodeCall(BridgedStablecoinV2.mintWithProof, (dep(1), 0, uint64(U), ALICE, proofOf(token, dep(1), 0, uint64(U), ALICE))),
            BridgedStablecoinV2.InvalidProof.selector);
        propose(address(good));
        no(abi.encodeCall(BridgedStablecoinV2.mintWithProof, (dep(1), 0, uint64(U), ALICE, proofOf(token, dep(1), 0, uint64(U), ALICE))),
            BridgedStablecoinV2.InvalidProof.selector);
        vm.warp(block.timestamp + DELAY - 1);
        committeeMint(dep(2), uint64(U), ALICE); // the last second of committee mode
        eq(token.balanceOf(ALICE), U, "committee minted during the delay");
    }

    function testAfterActivationCommitteeHasNoPathBack() public {
        // a certificate gathered in time, and every power the signers ever had, all with all seven keys available
        bytes32 d = dep(1);
        bytes memory late = sigs(token.mintDigest(d, 0, uint64(U), ALICE), K);
        activate(address(good));
        bytes4 retired = BridgedStablecoinV2.CommitteeRetired.selector;
        no(abi.encodeCall(BridgedStablecoinV2.mint, (d, 0, uint64(U), ALICE, late)), retired);
        // a wrong signature gets the same answer: the path is closed before signatures are read
        no(abi.encodeCall(BridgedStablecoinV2.mint, (dep(2), 1, uint64(U), ALICE, "")), retired);
        no(abi.encodeCall(SignerMintedToken.unpause, (sigs(token.unpauseDigest(), K))), retired);
        uint256 until = block.timestamp + 100;
        OtherMintVerifier other = new OtherMintVerifier();
        noPropose(address(other), 1, until, goodBlob(address(other), 1, until), BridgedStablecoinV2.InvalidSwitch.selector);
        no(abi.encodeCall(BridgedStablecoinV2.cancelVerifier, (1, until, sigs(token.mintSwitchDigest(true, address(good), address(good).codehash, 1, until), SWITCH_K))),
            BridgedStablecoinV2.InvalidSwitch.selector);
        // ten years on, nothing has changed
        vm.warp(block.timestamp + 3650 days);
        eq(uint160(token.verifier()), uint160(address(good)), "same verifier");
        no(abi.encodeCall(BridgedStablecoinV2.mint, (d, 0, uint64(U), ALICE, late)), retired);
        noPropose(address(other), 1, block.timestamp + 1, goodBlob(address(other), 1, block.timestamp + 1), BridgedStablecoinV2.InvalidSwitch.selector);
    }

    // ── signer set across the switch ─────────────────────────────────────────
    function testSignerSetIsUnchangedAndPowerless() public {
        activate(address(good));
        address[] memory s = token.signers();
        eq(s.length, 7, "set kept");
        for (uint256 i; i < 7; ++i) require(token.isSigner(vm.addr(keys[i])), "still listed");
        // listed signers do not gain anything from being listed: a proof mint does not read them
        proofMint(dep(1), uint64(U), ALICE);
        eq(token.balanceOf(ALICE), U, "minted without any signer");
    }

    function testLostKeysBelowSwitchQuorumMeanNoSwitchEver() public {
        // two of seven lost: five mint, nobody can reach six, and nothing else can change that
        address v = address(good);
        uint256 until = block.timestamp + 100;
        bytes32 d = token.mintSwitchDigest(false, v, v.codehash, 0, until);
        noPropose(v, 0, until, sigs(d, 5), SignerMintedToken.BadSignatureCount.selector);
        committeeMint(dep(1), uint64(U), ALICE);
    }

    function testLostKeysAfterProposalDoNotStopActivation() public {
        // Activation needs no key, and no signer can be replaced in between.
        propose(address(good));
        delete keys;
        vm.warp(block.timestamp + DELAY);
        vm.prank(ALICE);
        token.activateVerifier();
        proofMint(dep(1), uint64(U), ALICE);
    }

    function testMinorityCannotCancelAgainstTheSwitchQuorum() public {
        propose(address(good));
        uint256 until = block.timestamp + 100;
        bytes32 d = token.mintSwitchDigest(true, address(good), address(good).codehash, 1, until);
        // five of seven, even though five can mint
        no(abi.encodeCall(BridgedStablecoinV2.cancelVerifier, (1, until, sigs(d, 5))),
            SignerMintedToken.BadSignatureCount.selector);
    }

    // ── proof path: binding and refusals ─────────────────────────────────────
    function testProofBindsEveryField() public {
        activate(address(good));
        uint64 a = uint64(100 * U);
        bytes memory p = proofOf(token, dep(1), 7, a, ALICE);
        bytes4 bad = BridgedStablecoinV2.InvalidProof.selector;
        no(abi.encodeCall(BridgedStablecoinV2.mintWithProof, (dep(2), 7, a, ALICE, p)), bad);
        no(abi.encodeCall(BridgedStablecoinV2.mintWithProof, (dep(1), 8, a, ALICE, p)), bad);
        no(abi.encodeCall(BridgedStablecoinV2.mintWithProof, (dep(1), 7, a + 1, ALICE, p)), bad);
        no(abi.encodeCall(BridgedStablecoinV2.mintWithProof, (dep(1), 7, a, BOB, p)), bad);
        no(abi.encodeCall(BridgedStablecoinV2.mintWithProof, (dep(1), 7, a, ALICE, "")), bad);
        // a proof made for another token
        BridgedStablecoinV2 second = make(SWITCH_K, DELAY);
        no(abi.encodeCall(BridgedStablecoinV2.mintWithProof, (dep(1), 7, a, ALICE, proofOf(second, dep(1), 7, a, ALICE))), bad);
        token.mintWithProof(dep(1), 7, a, ALICE, p);
        eq(token.balanceOf(ALICE), a, "paid to the proven recipient");
    }

    function testAnyoneSubmitsAndTheRecipientIsFixed() public {
        activate(address(good));
        vm.prank(address(0xBAD));
        proofMint(dep(1), uint64(U), ALICE);
        eq(token.balanceOf(ALICE), U, "recipient");
        eq(token.balanceOf(address(0xBAD)), 0, "submitter gets nothing");
    }

    function testNoDoubleMintAcrossPaths() public {
        committeeMint(dep(1), uint64(U), ALICE);
        activate(address(good));
        bytes memory p = proofOf(token, dep(1), 0, uint64(U), ALICE);
        no(abi.encodeCall(BridgedStablecoinV2.mintWithProof, (dep(1), 0, uint64(U), ALICE, p)), SignerMintedToken.AlreadyMinted.selector);
        // same deposit id with other fields: the replay key alone refuses it, before the verifier is asked
        no(abi.encodeCall(BridgedStablecoinV2.mintWithProof, (dep(1), 0, uint64(2 * U), ALICE, "")), SignerMintedToken.AlreadyMinted.selector);
        bytes memory q = proofOf(token, dep(2), 1, uint64(U), ALICE);
        token.mintWithProof(dep(2), 1, uint64(U), ALICE, q);
        no(abi.encodeCall(BridgedStablecoinV2.mintWithProof, (dep(2), 1, uint64(U), ALICE, q)), SignerMintedToken.AlreadyMinted.selector);
        eq(token.totalSupply(), 2 * U, "two deposits, two mints");
    }

    function testZeroAmountAndZeroRecipient() public {
        activate(address(good));
        no(abi.encodeCall(BridgedStablecoinV2.mintWithProof, (dep(1), 0, 0, ALICE, "")), SignerMintedToken.ZeroAmount.selector);
        no(abi.encodeCall(BridgedStablecoinV2.mintWithProof, (dep(1), 0, 1, address(0), "")), SignerMintedToken.ZeroRecipient.selector);
    }

    function _noBadVerifier(address v) internal {
        activate(v);
        no(abi.encodeCall(BridgedStablecoinV2.mintWithProof, (dep(1), 0, uint64(U), ALICE, "")), BridgedStablecoinV2.InvalidProof.selector);
        eq(token.totalSupply(), 0, "nothing minted");
    }

    function testWrongMagicIsARefusal() public {
        _noBadVerifier(address(new WrongMagicMintVerifier()));
    }

    function testVerifierRevertIsARefusal() public {
        _noBadVerifier(address(new RevertingMintVerifier()));
    }

    function testShortReturnIsARefusal() public {
        _noBadVerifier(address(new ShortReturnMintVerifier()));
    }

    function testVerifierCannotWriteState() public {
        _noBadVerifier(address(new StatefulMintVerifier()));
    }

    function testVerifierWithCodeRemovedFailsClosed() public {
        activate(address(good));
        vm.etch(address(good), "");
        bytes memory p = proofOf(token, dep(1), 0, uint64(U), ALICE);
        no(abi.encodeCall(BridgedStablecoinV2.mintWithProof, (dep(1), 0, uint64(U), ALICE, p)), BridgedStablecoinV2.InvalidProof.selector);
    }

    function testBrokenVerifierNeverStopsBurns() public {
        committeeMint(dep(1), uint64(100 * U), ALICE);
        activate(address(new WrongMagicMintVerifier()));
        vm.prank(ALICE);
        token.burn(uint64(100 * U), BOB);
        eq(token.totalSupply(), 0, "exit stays open with a broken mint verifier");
    }

    // ── token bucket and supply cap ──────────────────────────────────────────
    function testBucketIsNotResetByTheSwitch() public {
        for (uint256 i; i < 10; ++i) committeeMint(dep(i), uint64(LARGE), ALICE);
        eq(token.availableToMint(), 0, "committee emptied the bucket");
        propose(address(good));
        // The refill during the delay is what is available, not a fresh bucket beyond it.
        vm.warp(block.timestamp + DELAY);
        eq(token.availableToMint(), BUCKET, "full after the delay, never more");
        token.activateVerifier();
        eq(token.availableToMint(), BUCKET, "activation does not touch the bucket");
        for (uint256 i = 10; i < 20; ++i) proofMint(dep(i), uint64(LARGE), ALICE);
        eq(token.availableToMint(), 0, "the proof path spends the same bucket");
    }

    function testProofMintAboveBucketRevertsAndTheSameProofLaterSucceeds() public {
        activate(address(good));
        for (uint256 i; i < 9; ++i) proofMint(dep(i), uint64(LARGE), ALICE);
        proofMint(dep(100), uint64(LARGE - U), ALICE);
        eq(token.availableToMint(), U, "1 USDC left");
        bytes memory p = proofOf(token, dep(200), 500, uint64(100 * U), BOB);
        no(abi.encodeCall(BridgedStablecoinV2.mintWithProof, (dep(200), 500, uint64(100 * U), BOB, p)), SignerMintedToken.RateLimited.selector);
        require(!token.minted(dep(200)), "a refused mint does not burn the deposit id");
        vm.warp(block.timestamp + 1 days);
        token.mintWithProof(dep(200), 500, uint64(100 * U), BOB, p);
        eq(token.balanceOf(BOB), 100 * U, "the same proof is good later");
    }

    function testFuzzProofPathBucketBound(uint32[6] memory gaps, uint32[6] memory amounts) public {
        activate(address(good));
        uint256 start = block.timestamp;
        uint256 total;
        for (uint256 i; i < 6; ++i) {
            vm.warp(block.timestamp + gaps[i] % 2 days);
            uint256 a = uint256(amounts[i]) % (LARGE + 1);
            if (a == 0 || a > token.availableToMint()) continue;
            proofMint(dep(i), uint64(a), ALICE);
            total += a;
        }
        require(total <= BUCKET + (block.timestamp - start) * REFILL, "bucket bound");
    }

    function testSupplyCapHoldsOnTheProofPath() public {
        activate(address(good));
        uint256 n;
        while (token.totalSupply() + LARGE <= CAP) {
            vm.warp(block.timestamp + 2 days); // the integer refill rate takes slightly over a day to fill the bucket
            for (uint256 i; i < 10 && token.totalSupply() + LARGE <= CAP; ++i) proofMint(dep(n++), uint64(LARGE), ALICE);
        }
        eq(token.totalSupply(), CAP, "at cap");
        vm.warp(block.timestamp + 1 days);
        bytes memory p = proofOf(token, dep(n), uint64(n), 1, ALICE);
        no(abi.encodeCall(BridgedStablecoinV2.mintWithProof, (dep(n), uint64(n), 1, ALICE, p)), SignerMintedToken.SupplyCapExceeded.selector);
    }

    function testLargeProofMintIsDelayedAndExecutableByAnyone() public {
        activate(address(good));
        uint64 a = uint64(LARGE + 1);
        proofMint(dep(1), a, ALICE);
        eq(token.balanceOf(ALICE), 0, "queued");
        eq(token.pendingSupply(), a, "pending counts");
        no(abi.encodeCall(SignerMintedToken.executeMint, (dep(1))), SignerMintedToken.NotReady.selector);
        vm.warp(block.timestamp + LARGE_DELAY);
        vm.prank(address(0xD00D));
        token.executeMint(dep(1));
        eq(token.balanceOf(ALICE), a, "paid");
        eq(token.pendingSupply(), 0, "drained");
    }

    // ── guardian pause ───────────────────────────────────────────────────────
    function guardianPause(uint256 key) internal {
        vm.prank(vm.addr(key));
        token.pause();
    }

    function testPauseDoesNotBlockTheSwitch() public {
        guardianPause(G1_KEY);
        propose(address(good)); // while paused
        vm.warp(token.verifierActivatesAt());
        token.activateVerifier();
        eq(uint160(token.verifier()), uint160(address(good)), "active");
    }

    function testActivationDuringAPause() public {
        propose(address(good));
        vm.warp(block.timestamp + DELAY);
        guardianPause(G1_KEY);
        require(token.paused(), "paused");
        token.activateVerifier();
        eq(uint160(token.verifier()), uint160(address(good)), "activated under a pause");
    }

    function testPauseStopsProofMintsAndOnlyTimeEndsItAfterTheSwitch() public {
        activate(address(good));
        guardianPause(G1_KEY);
        bytes memory p = proofOf(token, dep(1), 0, uint64(U), ALICE);
        no(abi.encodeCall(BridgedStablecoinV2.mintWithProof, (dep(1), 0, uint64(U), ALICE, p)), SignerMintedToken.IsPaused.selector);
        // pre-switch the committee could end this; now it cannot, with any number of signatures
        bytes memory all = sigs(token.unpauseDigest(), K);
        no(abi.encodeCall(SignerMintedToken.unpause, (all)), BridgedStablecoinV2.CommitteeRetired.selector);
        vm.warp(token.pausedUntil());
        token.mintWithProof(dep(1), 0, uint64(U), ALICE, p);
        eq(token.balanceOf(ALICE), U, "the proof still works after the pause");
    }

    function testGuardiansCannotHoldProofMintsBeyondTheirChainAfterTheSwitch() public {
        activate(address(good));
        uint256 start = block.timestamp;
        for (uint256 i; i < 3; ++i) {
            guardianPause(G1_KEY);
            vm.warp(token.pausedUntil());
            guardianPause(G2_KEY);
            vm.warp(token.pausedUntil());
            vm.prank(vm.addr(G2_KEY));
            vm.expectRevert(SignerMintedToken.PauseCooldown.selector);
            token.pause();
            proofMint(dep(i), uint64(U), ALICE); // open in the gap
            vm.warp(token.pausedUntil() + PAUSE);
        }
        eq(block.timestamp - start, 3 * 3 * PAUSE, "two guardians close at most two thirds of the time");
    }

    function testPauseReservesBurnsAfterTheSwitch() public {
        committeeMint(dep(1), uint64(100 * U), ALICE);
        activate(address(good));
        guardianPause(G1_KEY);
        vm.prank(ALICE);
        token.burn(uint64(100 * U), BOB);
        eq(token.burnNonce(), 1, "burns are never paused");
    }

    function testCommitteeUnpausesBeforeTheSwitchAsBefore() public {
        propose(address(good)); // a pending proposal changes nothing
        guardianPause(G1_KEY);
        token.unpause(sigs(token.unpauseDigest(), token.switchThreshold()));
        require(!token.paused(), "unpaused");
    }

    // ── queued mints across the switch ───────────────────────────────────────
    function testMintQueuedBeforeTheSwitchSurvivesIt() public {
        propose(address(good));
        vm.warp(token.verifierActivatesAt() - 1);
        uint64 a = uint64(LARGE + 1);
        committeeMint(dep(1), a, ALICE); // queued one second before activation
        vm.warp(block.timestamp + 1);
        token.activateVerifier();
        no(abi.encodeCall(SignerMintedToken.executeMint, (dep(1))), SignerMintedToken.NotReady.selector);
        vm.warp(block.timestamp + LARGE_DELAY);
        // its deposit is locked, so it stays payable; a guardian can still hold it, and the committee cannot lift that
        guardianPause(G1_KEY);
        no(abi.encodeCall(SignerMintedToken.executeMint, (dep(1))), SignerMintedToken.IsPaused.selector);
        no(abi.encodeCall(SignerMintedToken.unpause, (sigs(token.unpauseDigest(), K))), BridgedStablecoinV2.CommitteeRetired.selector);
        vm.warp(token.pausedUntil());
        token.executeMint(dep(1));
        eq(token.balanceOf(ALICE), a, "paid after the switch");
        eq(token.pendingSupply(), 0, "queue empty");
    }

    function testQueuedMintCannotBeProvenASecondTime() public {
        propose(address(good));
        vm.warp(token.verifierActivatesAt());
        uint64 a = uint64(LARGE + 1);
        uint64 nonce = nextNonce;
        committeeMint(dep(1), a, ALICE);
        token.activateVerifier();
        bytes memory p = proofOf(token, dep(1), nonce, a, ALICE);
        no(abi.encodeCall(BridgedStablecoinV2.mintWithProof, (dep(1), nonce, a, ALICE, p)), SignerMintedToken.AlreadyMinted.selector);
    }

    // ── burns ────────────────────────────────────────────────────────────────
    function testBurnNonceAndSupplyContinueAcrossTheSwitch() public {
        committeeMint(dep(1), uint64(500 * U), ALICE);
        vm.prank(ALICE);
        token.burn(uint64(100 * U), BOB);
        activate(address(good));
        proofMint(dep(2), uint64(50 * U), ALICE);
        vm.prank(ALICE);
        token.burn(uint64(100 * U), BOB);
        eq(token.burnNonce(), 2, "nonce continues");
        eq(token.totalSupply(), 350 * U, "supply continues");
    }

    // ── what omission means: a replacement token cannot share the vault ──────
    function testReplacementTokenCollidesOnTheVaultNonce() public {
        ContextBoundSourceVault vault = _vault();
        BridgedStablecoinV2 second = make(SWITCH_K, DELAY);
        bytes32 anchor = keccak256("eth block 99");
        ContextBoundSourceVault.ReleaseContext memory c = ContextBoundSourceVault.ReleaseContext(
            block.timestamp + 100, 99, anchor, 1, bytes32(uint256(1)));
        vault.release(_release(vault, token), c, _sign(vault.releaseDigest(_release(vault, token), c)));
        ContextBoundSourceVault.Release memory next = _release(vault, second);
        require(next.nativeBurn != _release(vault, token).nativeBurn, "another burn id");
        bytes[] memory blob = _sign(vault.releaseDigest(next, c));
        vm.expectRevert(ContextBoundSourceVault.InvalidRelease.selector);
        vault.release(next, c, blob);
    }

    function _release(ContextBoundSourceVault vault, BridgedStablecoinV2 t)
        private
        view
        returns (ContextBoundSourceVault.Release memory)
    {
        return ContextBoundSourceVault.Release(vault.routeId(), 1, BOB, uint64(100 * U), t.burnIdOf(1));
    }

    function _vault() private returns (ContextBoundSourceVault vault) {
        vm.roll(100);
        vm.setBlockhash(99, keccak256("eth block 99"));
        SwitchUsdc usdc = new SwitchUsdc();
        address[] memory s = signerAddrs();
        ContextBoundSourceVault.Guard memory g;
        vault = new ContextBoundSourceVault(bytes32(uint256(1)), bytes32(uint256(2)), bytes32(uint256(3)), address(usdc),
            uint64(CAP), 0, s, 5, ContextBoundSourceVault.Policy(uint64(BUCKET), 1 days, 6, DELAY, uint64(10 * U), uint64(10 * U)), g);
        uint256 until = block.timestamp + 100;
        vault.setControls(true, true, 0, until, _sign(vault.controlDigest(true, true, 0, until)));
        usdc.mint(address(this), 1_000 * U);
        vault.deposit(uint64(500 * U), bytes32(uint256(8)));
    }

    function _sign(bytes32 digest) private view returns (bytes[] memory blob) {
        blob = new bytes[](K);
        for (uint256 i; i < K; ++i) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(keys[i], digest);
            blob[i] = abi.encodePacked(r, s, v);
        }
    }
}
