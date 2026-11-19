// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity 0.8.24;

// Reviewer 423 (round 20): independent adversarial tests of NativeEtherSourceVault at 17e4231. Review branch only.
import {NativeEtherSourceVault} from "../contracts/eth/NativeEtherSourceVault.sol";
import {NativeEtherVaultBase} from "./NativeEtherVaultBase.sol";
import {EthGasBurner, EthReverter} from "./harness/EthRecipients.sol";

interface R423Vm {
    function cool(address target) external;
    function etch(address target, bytes calldata code) external;
    function deal(address who, uint256 newBalance) external;
}

contract R423NativeEtherReviewTest is NativeEtherVaultBase {
    R423Vm constant cvm = R423Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    uint64 constant ONE = 1_000_000;

    function setUp() public {
        baseSetUp();
        depositAs(ALICE, 20 * ONE, ALICE);
        depositAs(BOB, 5 * ONE, BOB);
    }

    /// Execution gas of one release as a transaction would pay it: the vault's slots and the recipient are made cold.
    function coldReleaseGas(address recipient) internal returns (uint256 used, bool deferred) {
        NativeEtherSourceVault.Release memory r = cleanBurn(recipient, ONE, 2);
        NativeEtherSourceVault.ReleaseContext memory c = context();
        bytes[] memory s = cert(vault.releaseDigest(r, c), 5);
        uint64 before = vault.claimable(recipient);
        cvm.cool(address(vault));
        if (uint160(recipient) > 0x1ff) cvm.cool(recipient); // precompiles are always warm (EIP-2929)
        uint256 g = gasleft();
        vault.release(r, c, s);
        used = g - gasleft();
        deferred = vault.claimable(recipient) != before;
        recordRelease(r.amount, deferred);
    }

    /// R423-1: the "worst case" of the relayer (a gas burner with a new claim slot) is not the worst case. An EMPTY
    /// precompile that fails on empty input (BLAKE2F 0x09, and on mainnet rules 0x0a..0x11) charges the caller the
    /// 25,000 new-account gas, then burns the whole push allowance, then the payment is deferred into a new slot.
    function test_R423_1_emptyFailingPrecompileCostsMoreThanTheRecordedWorstCase() public {
        coldReleaseGas(address(0xE0A)); // first-use costs out of the way
        (uint256 burner, bool d1) = coldReleaseGas(address(new EthGasBurner()));
        require(d1, "control: burner deferred");
        address blake2f = address(9);
        require(blake2f.balance == 0 && blake2f.code.length == 0, "control: the precompile account is empty");
        (uint256 pre, bool d2) = coldReleaseGas(blake2f);
        require(d2, "control: the failing precompile deferred");
        emitUint("burner worst case (execution gas)", burner);
        emitUint("empty failing precompile (execution gas)", pre);
        require(pre > burner + 20_000, "R423-1 not reproduced");
        // repeatable: the failed call creates nothing, so the next burn to it costs the same again (minus the claim slot)
        (uint256 again, bool d3) = coldReleaseGas(blake2f);
        require(d3 && blake2f.balance == 0, "still empty");
        emitUint("the same precompile again (claim slot now used)", again);
        // the operator's cheap mitigation: one wei makes the account exist
        cvm.deal(blake2f, 1);
        (uint256 funded,) = coldReleaseGas(address(0x0a09)); // unrelated new account as control for ordering
        funded;
        checkBooks();
    }

    /// R423-1b (run with --evm-version prague): a recipient that is an EIP-7702 delegated account costs the CALLER a
    /// second cold access (the delegate), outside PUSH_GAS; its code then burns the allowance.
    function test_R423_1b_delegatedAccountAddsAColdAccessForTheCaller() public {
        coldReleaseGas(address(0xE0A));
        EthGasBurner impl = new EthGasBurner();
        (uint256 burner,) = coldReleaseGas(address(impl));
        address eoa = address(0x7702AAAA);
        cvm.etch(eoa, abi.encodePacked(hex"ef0100", address(impl)));
        cvm.cool(address(impl));
        (uint256 delegated, bool d) = coldReleaseGas(eoa);
        emitUint("burner", burner);
        emitUint("7702-delegated burner", delegated);
        emitUint("deferred", d ? 1 : 0);
    }

    /// The submitter cannot force a deferral by call depth: at the deepest frame gas allows, the release still pays.
    function test_R423_depthCannotForceADeferral() public {
        NativeEtherSourceVault.Release memory r = cleanBurn(CAROL, ONE, 2);
        NativeEtherSourceVault.ReleaseContext memory c = context();
        bytes[] memory s = cert(vault.releaseDigest(r, c), 5);
        bytes memory data = abi.encodeCall(NativeEtherSourceVault.release, (r, c, s));
        R423Deep deep = new R423Deep();
        uint256 depth = deep.dive{gas: 29_000_000}(address(vault), data, 0);
        emitUint("deepest frame at which the release ran", depth);
        require(depth < 1000, "a 30M-gas transaction reached the depth limit");
        require(vault.claimable(CAROL) == 0 && CAROL.balance == wei_(ONE - relFee(ONE)), "paid by the push");
    }

    /// R423-4: the four `InsufficientBacking` checks (ETH-6) are reached by no test and no mutant of the line. A vault
    /// that holds less than its books (which no call can bring about; a cheat code does it here) must refuse every
    /// path that takes or pays ether, and work again when the ether is back.
    function test_R423_4_everyPathRefusesAVaultShortOfItsBooks() public {
        firstClaimant = address(new EthReverter());
        release(cleanBurn(firstClaimant, ONE, 2)); // one claim outstanding
        uint256 full = address(vault).balance;
        require(full == vault.owedWei() && vault.feesAccrued() != 0 && vault.totalClaimable() != 0, "control");
        cvm.deal(address(vault), full - 1); // one wei short
        bytes4 want = NativeEtherSourceVault.InsufficientBacking.selector;
        (bool ok, bytes4 e) = tryDeposit(ALICE, ONE, ALICE);
        require(!ok && e == want, "deposit into a short vault");
        (ok, e) = tryRelease(cleanBurn(CAROL, ONE, 2));
        require(!ok && e == want, "release from a short vault");
        bytes memory ret;
        (ok, ret) = address(vault).call(abi.encodeCall(NativeEtherSourceVault.sweepFees, ()));
        require(!ok && err(ret) == want, "sweep from a short vault");
        // the outstanding claim belongs to a reverting contract: claimFor reaches the backing check before the payment
        address first = firstClaimant;
        (ok, ret) = address(vault).call(abi.encodeCall(NativeEtherSourceVault.claimFor, (first)));
        require(!ok && err(ret) == want, "claim from a short vault");
        cvm.deal(address(vault), full);
        depositAs(ALICE, ONE, ALICE);
        release(cleanBurn(CAROL, ONE, 2));
        checkBooks();
    }

    address firstClaimant;

    event log_named_uint(string key, uint256 val);

    function emitUint(string memory what, uint256 v) internal {
        emit log_named_uint(what, v);
    }
}

/// Recurses as deep as gas allows, then tries the call at every level on the way back until one succeeds.
contract R423Deep {
    bool public done;

    function dive(address target, bytes calldata data, uint256 level) external returns (uint256 at) {
        if (gasleft() > 400_000) {
            try this.dive(target, data, level + 1) returns (uint256 inner) {
                if (done) return inner;
            } catch {}
        }
        if (!done) {
            (bool ok,) = target.call(data);
            if (ok) {
                done = true;
                return level + 2; // this frame is at depth level+1; the vault at level+2
            }
        }
        return 0;
    }
}
