#!/usr/bin/env python3
"""Shows each ether-specific defence of contracts/eth/NativeEtherSourceVault.sol being load-bearing: for every row of
the hazard table (docs/ETH-VAULT-DIFF.md section 3) it removes ONE defence from a copy of the vault and requires the
test that pins the hazard to FAIL on that copy (and the whole hazard suite to pass on the unchanged vault).

  python3 scripts/eth/mutants.py WORKDIR [--only M3,M7] [--forge PATH]

WORKDIR receives a copy of the tree (tracked files, plus `out/` and `cache/` when present, so that only the mutated
contract is recompiled). Nothing in the repository is changed. Exit 1 if a mutant survives (its test passes), if a
mutant does not compile, if a mutation's anchor text is not found exactly once, or if the control run fails.
Standard library only. `forge` is taken from --forge, else $FOUNDRY_BIN/forge, else PATH.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
VAULT = 'contracts/eth/NativeEtherSourceVault.sol'
SUITE = 'solidity-tests/NativeEtherVault.t.sol'

# id, hazard, (old, new) replacements of the vault source, tests that must fail on the mutant.
MUTANTS = [
    ('M1', 'reentrancy: the guard removed',
     [('        if (entered) revert Reentrancy();\n', '')],
     ['test_release_reentrancyFromThePushIsRefused', 'test_release_reentrancyFromAClaimIsRefused',
      'test_release_reentrancyFromTheSweepIsRefused']),
    ('M2', 'a release that cannot be paid reverts (naive push): one recipient blocks its release for good',
     [('''        if (!_send(recipient, uint256(paid) * UNIT, PUSH_GAS)) {
            claimable[recipient] += paid;
            totalClaimable += paid;
            emit ReleaseDeferred(id, recipient, paid);
        }''', '''        if (!_send(recipient, uint256(paid) * UNIT, PUSH_GAS)) revert PaymentFailed();''')],
     ['test_release_revertingRecipientDoesNotBlockTheQueue', 'test_release_delayedPathDefersToo']),
    ('M3', 'the push forwards all gas: a recipient makes the relayer pay for everything it burns',
     [('if (!_send(recipient, uint256(paid) * UNIT, PUSH_GAS)) {', 'if (!_send(recipient, uint256(paid) * UNIT, gasleft())) {')],
     ['test_release_gasBurningRecipientIsBounded', 'test_release_recipientGetsThePushGas']),
    ('M4', 'return data is copied (a Solidity low-level call): a return bomb costs the relayer',
     [('''        assembly ("memory-safe") {
            ok := call(gasLimit, to, value, 0, 0, 0, 0)
        }''', '''        bytes memory data;
        (ok, data) = to.call{value: value, gas: gasLimit}("");''')],
     ['test_release_returnDataIsNeverCopied']),
    ('M5', 'no gas check before the push: a relayer starves it (EIP-150) and books a payable release as a claim',
     [('        if (gasleft() < PUSH_GAS * 64 / 63 + PUSH_CALL_RESERVE) revert InsufficientGas();\n', '')],
     ['test_release_relayerCannotStarveThePush']),
    ('M6', 'backing measured, not counted (the token vault\'s exact-balance rule): forced ether stops deposits',
     [('        if (address(this).balance - msg.value < owedWei()) revert InsufficientBacking();',
       '        if (address(this).balance - msg.value != owedWei()) revert InsufficientBacking();')],
     ['test_forced_selfdestructBreaksNothing', 'test_forced_prefundedAddress', 'test_forced_blockRewardStandIn']),
    ('M7', 'plain transfers accepted (an empty receive)',
     [('''    receive() external payable {
        revert DirectTransferRefused();
    }''', '''    receive() external payable {}''')],
     ['test_deposit_plainTransfersAreRefused']),
    ('M8', 'fees rounded down (the token vault\'s rule): a rounding gain for the user',
     [('        return uint64((uint256(amount) * bps + BPS - 1) / BPS);', '        return uint64(uint256(amount) * bps / BPS);')],
     ['testFuzz_fee_depositRoundsUpNeverInTheUsersFavour', 'testFuzz_fee_releaseRoundsUpAndPaysExactWei',
      'test_fee_knownValues']),
    ('M9', 'the value sent is not compared with the stated amount (only a lower bound)',
     [('        if (msg.value != uint256(amount) * UNIT) revert ValueMismatch(); // ETH-4',
       '        if (msg.value < uint256(amount) * UNIT) revert ValueMismatch(); // ETH-4')],
     ['test_deposit_valueMustBeExactlyTheStatedAmount']),
    ('M10', 'the L2 recipient defaults to the sender',
     [('        address l2Recipient = address(uint160(uint256(pqRecipientHash)));', '        address l2Recipient = msg.sender;')],
     ['test_deposit_fromAContractCreditsTheStatedRecipient']),
    ('M11', 'the cap counts the balance instead of the books: forced ether fills it',
     [('|| uint256(pqRecipientHash) >> 160 != 0 || uint256(totalLocked) + net > cap',
       '|| uint256(pqRecipientHash) >> 160 != 0 || (address(this).balance - msg.value) / UNIT + net > cap')],
     ['test_forced_capIsNotFilledByForcedEther']),
    ('M12', 'a failed push books no claim: the burn loses its payment',
     [('''            claimable[recipient] += paid;
            totalClaimable += paid;
''', '')],
     ['test_release_revertingRecipientDoesNotBlockTheQueue', 'test_claim_paths']),
    ('M13', 'the sweep pays the balance above the backing instead of the accrued fees: forced ether leaves',
     [('        if (!_send(feeRecipient, uint256(amount) * UNIT, gasleft())) revert PaymentFailed(); // ETH-9',
       '        if (!_send(feeRecipient, address(this).balance - (uint256(totalLocked) + totalClaimable) * UNIT, gasleft())) revert PaymentFailed(); // ETH-9')],
     ['test_forced_selfdestructBreaksNothing', 'test_forced_surplusIsNeverPaidOut']),
    ('M14', 'a claim can be taken by anyone to any address',
     [('''    function claim(address to) external nonReentrant returns (uint64 amount) {
        return _claim(msg.sender, to);''', '''    function claim(address to) external nonReentrant returns (uint64 amount) {
        return _claim(to, msg.sender);''')],
     ['test_claim_paths', 'test_claim_recipientRedirects']),
    ('M15', 'a failed claim is swallowed (the claim is cleared without payment)',
     [('        if (!_send(to, uint256(amount) * UNIT, gasleft())) revert PaymentFailed();\n        emit Claimed',
       '        _send(to, uint256(amount) * UNIT, gasleft());\n        emit Claimed')],
     ['test_claim_paths']),
    ('M16', 'the constructor accepts any token address',
     [('token_ != NATIVE_ETHER /* ETH-2 */', 'token_ == address(1) /* ETH-2 */')],
     ['test_ctor_onlyTheNativeEtherMarkerIsAToken']),
    ('M17', 'a release not above its fee is accepted',
     [('                || item.amount <= _fee(item.amount, releaseFeeBps) // ETH-5\n', ''),
      ('        if (fee >= amount) revert InvalidRelease(); // ETH-5: `_checkRelease` already refused it\n', '')],
     ['test_fee_releaseNotAboveItsFeeRefused']),
    ('M18', 'a deferred payment does not charge the release window',
     [('''        if (!_send(recipient, uint256(paid) * UNIT, PUSH_GAS)) {
            claimable[recipient] += paid;''', '''        if (!_send(recipient, uint256(paid) * UNIT, PUSH_GAS)) {
            releaseBucket += amount;
            claimable[recipient] += paid;''')],
     ['test_release_revertingRecipientDoesNotBlockTheQueue', 'test_claim_notHeldByPauseControlsOrWindow']),
]


def forge_bin(argv):
    if '--forge' in argv:
        return argv[argv.index('--forge') + 1]
    fb = os.environ.get('FOUNDRY_BIN')
    return str(Path(fb) / 'forge') if fb else 'forge'


def run(forge, work, tests=None):
    cmd = [forge, 'test', '--offline', '--root', str(work), '--match-path', SUITE]
    if tests:
        cmd += ['--match-test', '^(' + '|'.join(tests) + r')\(']
    done = subprocess.run(cmd, capture_output=True, text=True)
    text = done.stdout + done.stderr
    compiled = 'Suite result' in text
    failed = sorted({line.split('] ', 1)[1].split('(')[0] for line in text.splitlines() if line.startswith('[FAIL')})
    passed = sorted({line.split('] ', 1)[1].split('(')[0] for line in text.splitlines() if line.startswith('[PASS]')})
    return done.returncode, compiled, passed, failed, text


def main(argv):
    if not argv or argv[0].startswith('-'):
        raise SystemExit(__doc__)
    work = Path(argv[0]).resolve()
    only = set(argv[argv.index('--only') + 1].split(',')) if '--only' in argv else None
    forge = forge_bin(argv)
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)
    files = subprocess.run(['git', '-C', str(ROOT), 'ls-files', '-co', '--exclude-standard', 'contracts', 'solidity-tests',
                            'foundry.toml', 'test-vectors'], capture_output=True, text=True, check=True).stdout.split('\n')
    for rel in filter(None, files):
        (work / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / rel, work / rel)
    for d in ('out', 'cache'):
        if (ROOT / d).is_dir():
            shutil.copytree(ROOT / d, work / d)
    original = (work / VAULT).read_text()
    rows, bad = [], 0
    code, compiled, passed, failed, text = run(forge, work)
    control = code == 0 and compiled and not failed
    rows.append({'id': 'control', 'what': 'the unchanged vault', 'passed': len(passed), 'failed': failed, 'ok': control})
    print(f'control: {len(passed)} passed, {len(failed)} failed -> {"OK" if control else "BROKEN"}', flush=True)
    if not control:
        print(text[-3000:])
        bad += 1
    for mid, what, edits, tests in MUTANTS:
        if only and mid not in only:
            continue
        source, missing = original, None
        for old, new in edits:
            if source.count(old) != 1:
                missing = old
                break
            source = source.replace(old, new)
        if missing is not None:
            rows.append({'id': mid, 'what': what, 'ok': False, 'why': 'anchor text not found exactly once'})
            print(f'{mid}: ANCHOR NOT FOUND: {missing[:70]!r}', flush=True)
            bad += 1
            continue
        (work / VAULT).write_text(source)
        code, compiled, passed, failed, text = run(forge, work, tests)
        killed = compiled and sorted(failed) == sorted(tests)
        rows.append({'id': mid, 'what': what, 'tests': tests, 'compiled': compiled, 'failedOnMutant': failed,
                     'passedOnMutant': passed, 'ok': killed})
        state = 'killed' if killed else ('DOES NOT COMPILE' if not compiled else f'SURVIVED in {passed}')
        print(f'{mid}: {state}: {what}', flush=True)
        if not killed:
            bad += 1
            print(text[-1500:])
    (work / VAULT).write_text(original)
    print(json.dumps({'mutants': len(rows) - 1, 'notKilled': bad, 'rows': rows}, indent=1))
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
