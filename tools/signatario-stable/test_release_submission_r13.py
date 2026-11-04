"""Lost broadcast replies cannot create a second release at a fresh nonce."""
import json
from pathlib import Path
import unittest

from test_relayer_review import Base, GWEI
from test_relayer_r11 import BURN


class ReleaseSubmission(Base):
    def ready(self):
        daemon = self.vigia()
        directory = self.d / 'shared' / 'release' / BURN[2:]
        round_path = directory / 'r-2000-2-bb'
        round_path.mkdir(parents=True, exist_ok=True)
        daemon.burn_done = lambda *args: None
        daemon.quorum_release = lambda *args: (round_path, ['release()'])
        daemon.backup_due = lambda *args: True
        return daemon, directory, round_path

    def pending(self):
        return next((self.d / '.relayer-submissions').glob('*/pending.json'))

    def reserved(self):
        daemon, directory, _ = self.ready()
        original = daemon.rpc

        def lost(url, method, params):
            result = original(url, method, params)
            if method == 'eth_sendRawTransaction':
                raise OSError('lost accepted reply')
            return result

        daemon.rpc = lost
        with self.assertRaises(OSError):
            daemon.relay_release(directory)
        daemon.rpc = original
        signer = next(iter(self.sent_transactions.values()))['from']
        journal = daemon.release_journal(signer, '0x12345678')
        return daemon, journal, journal.read(journal.pending)

    def receipt(self, journal, item, status=1):
        receipt = {'transactionHash': item[0]['hash'], 'from': journal.context['signer'],
                   'to': journal.context['vault'], 'blockHash': '0x' + 'a1' * 32,
                   'blockNumber': '0xa', 'status': hex(status)}
        self.answers['eth_getTransactionReceipt'] = receipt
        self.answers['eth_getBlockByNumber'] = {'hash': receipt['blockHash'], 'number': '0xa'}
        return receipt

    def test_lost_reply_recovers_the_original_hash_instead_of_a_new_nonce(self):
        daemon, directory, round_path = self.ready()
        original = daemon.rpc
        lose_reply = True

        def rpc(url, method, params):
            result = original(url, method, params)
            if method == 'eth_sendRawTransaction' and lose_reply:
                raise OSError('connection closed after the node accepted the release')
            return result

        daemon.rpc = rpc
        with self.assertRaises(OSError):
            daemon.relay_release(directory)
        self.assertFalse(daemon.nonce_path.exists())
        self.assertFalse((round_path / 'sent').exists())
        lose_reply = False
        self.answers['eth_getTransactionCount'] = lambda url, args: '0x1' if args[1] == 'pending' else '0x0'
        daemon.relay_release(directory)
        self.assertEqual(len(self.sent), 1, 'a lost reply must not send the same release again at nonce 1')
        self.assertEqual(len(self.mktx_args()), 1)
        self.assertEqual((round_path / 'sent').read_text().strip(), next(iter(self.sent_transactions)))

    def test_restart_recovers_a_signed_reservation_and_ignores_deleted_shared_marker(self):
        daemon, directory, marker = self.ready()
        original = daemon.rpc

        def lost(url, method, params):
            result = original(url, method, params)
            if method == 'eth_sendRawTransaction':
                raise OSError('lost accepted reply')
            return result

        daemon.rpc = lost
        with self.assertRaises(OSError):
            daemon.relay_release(directory)
        daemon, directory, marker = self.ready()  # a different process, no trusted memory survives
        daemon.relay_release(directory)
        (marker / 'sent').unlink()
        daemon, directory, _ = self.ready()
        daemon.relay_release(directory)
        self.assertEqual(len(self.sent), 1)
        self.assertEqual(len(self.mktx_args()), 1)

    def test_unknown_transport_or_generic_rpc_error_only_repeats_identical_signed_bytes(self):
        for error in (OSError('timeout'), RuntimeError('nonce too low'), RuntimeError('already known')):
            with self.subTest(error=type(error).__name__, message=str(error)):
                daemon, directory, round_path = self.ready()
                # Give each case a separate private reservation directory.
                daemon.cfg['relayer_submission_dir'] = str(self.d / ('journal-' + str(len(list(self.d.glob('journal-*'))))))
                original, submitted, refused = daemon.rpc, [], True

                def rpc(url, method, params):
                    if method == 'eth_sendRawTransaction':
                        submitted.append(params[0])
                        if refused:
                            raise error
                    return original(url, method, params)

                daemon.rpc = rpc
                (round_path / 'sent').unlink(missing_ok=True)
                with self.assertRaises(type(error)):
                    daemon.relay_release(directory)
                before = len(self.mktx_args())
                refused = False
                daemon.relay_release(directory)
                self.assertEqual(len(self.mktx_args()), before)
                self.assertEqual(submitted[0], submitted[1])

    def test_wrong_response_hash_is_uncertain_not_an_acknowledgement(self):
        daemon, directory, round_path = self.ready()
        original = daemon.rpc

        def wrong_hash(url, method, params):
            result = original(url, method, params)
            return '0x' + 'fe' * 32 if method == 'eth_sendRawTransaction' else result

        daemon.rpc = wrong_hash
        with self.assertRaisesRegex(RuntimeError, 'outcome remains unknown'):
            daemon.relay_release(directory)
        self.assertTrue(self.pending().exists())
        self.assertFalse(daemon.nonce_path.exists())
        self.assertFalse((round_path / 'sent').exists())
        daemon.rpc = original
        daemon.relay_release(directory)
        self.assertEqual(len(self.sent), 1)

    def test_tampered_record_cannot_select_a_nonce_hash_or_other_burn(self):
        for field, value in (('hash', '0x' + '11' * 32), ('burn', '0x' + '22' * 32), ('raw', '0xdeadbeef')):
            with self.subTest(field=field):
                daemon, directory, round_path = self.ready()
                daemon.cfg['relayer_submission_dir'] = str(self.d / ('tamper-' + field))
                original = daemon.rpc
                daemon.rpc = lambda url, method, params: (_ for _ in ()).throw(OSError('offline')) if method == 'eth_sendRawTransaction' else original(url, method, params)
                (round_path / 'sent').unlink(missing_ok=True)
                with self.assertRaises(OSError):
                    daemon.relay_release(directory)
                path = next(Path(daemon.cfg['relayer_submission_dir']).glob('*/pending.json'))
                record = json.loads(path.read_bytes())
                record[field] = value
                path.write_text(json.dumps(record))
                before = len(self.mktx_args())
                with self.assertRaises((RuntimeError, ValueError)):
                    daemon.relay_release(directory)
                self.assertEqual(len(self.mktx_args()), before)

    def test_a_lower_current_ceiling_does_not_reprice_an_uncertain_release(self):
        daemon, directory, _ = self.ready()
        original = daemon.rpc
        daemon.rpc = lambda url, method, args: (_ for _ in ()).throw(OSError('timeout')) if method == 'eth_sendRawTransaction' else original(url, method, args)
        with self.assertRaises(OSError):
            daemon.relay_release(directory)
        daemon.rpc = original
        daemon.max_price['eth'] = GWEI
        with self.assertRaisesRegex(RuntimeError, 'current gas ceiling'):
            daemon.relay_release(directory)
        self.assertEqual(self.sent, [])
        self.assertEqual(len(self.mktx_args()), 1)

    def test_route_or_vault_change_cannot_hide_the_same_accounts_pending_nonce(self):
        daemon, journal, _ = self.reserved()
        daemon.vault = '0x' + '44' * 20
        daemon.route = '0x' + '55' * 32
        changed = daemon.release_journal(journal.context['signer'], '0x12345678')
        self.assertEqual(changed.pending, journal.pending)
        with self.assertRaisesRegex(RuntimeError, 'another signer, chain, vault or route'):
            changed.resume(BURN)
        self.assertTrue(journal.pending.exists())
        self.assertEqual(len(self.mktx_args()), 1)

    def test_a_reverted_receipt_releases_the_attempt_only_after_finality(self):
        daemon, journal, item = self.reserved()
        receipt = self.receipt(journal, item, status=0)
        final = {'hash': '0x' + 'b2' * 32, 'number': '0x9'}
        self.answers['eth_getBlockByNumber'] = lambda url, params: final if params[0] == 'finalized' else {
            'hash': receipt['blockHash'], 'number': receipt['blockNumber']}
        self.assertEqual(journal.resume(BURN), item[0]['hash'])
        self.assertTrue(journal.accepted(BURN).exists())
        self.assertEqual(len(self.sent), 1)
        final['number'] = '0xa'
        final['hash'] = receipt['blockHash']
        self.assertIsNone(journal.resume(BURN))
        self.assertFalse(journal.accepted(BURN).exists())

    def test_an_orphan_receipt_can_only_rebroadcast_the_original_bytes(self):
        _, journal, item = self.reserved()
        self.receipt(journal, item, status=0)
        self.answers['eth_getBlockByNumber'] = {'hash': '0x' + 'b2' * 32, 'number': '0xa'}
        self.assertEqual(journal.observe(item), 'unknown')
        self.assertEqual(journal.resume(BURN), item[0]['hash'])
        self.assertEqual(len(self.mktx_args()), 1)
        self.assertEqual(len(self.sent_transactions), 1)
        self.assertEqual(len(self.sent), 2)

    def test_inconsistent_finalized_hash_cannot_free_a_reverted_attempt(self):
        _, journal, item = self.reserved()
        receipt = self.receipt(journal, item, status=0)
        self.answers['eth_getBlockByNumber'] = lambda url, params: {
            'number': '0xa', 'hash': '0x' + 'bb' * 32 if params[0] == 'finalized' else receipt['blockHash']}
        self.assertEqual(journal.observe(item), 'unknown')
        self.assertTrue(journal.pending.exists())

    def test_mismatched_receipts_do_not_acknowledge_or_free_an_attempt(self):
        daemon, journal, item = self.reserved()
        receipt = self.receipt(journal, item)
        for field, value in (('transactionHash', '0x' + '11' * 32), ('from', '0x' + '22' * 20),
                             ('to', '0x' + '33' * 20), ('status', '0x2'), ('blockHash', '0x0')):
            original = receipt[field]
            with self.subTest(field=field):
                receipt[field] = value
                with self.assertRaises(RuntimeError):
                    journal.resume(BURN)
                self.assertTrue(journal.pending.exists())
                self.assertFalse(daemon.nonce_path.exists())
            receipt[field] = original

    def test_archive_name_cannot_substitute_another_burn(self):
        _, journal, item = self.reserved()
        journal.accept(item)
        other = '0x' + 'ee' * 32
        journal.write(journal.accepted(other), item[0])
        with self.assertRaisesRegex(RuntimeError, 'filename'):
            journal.resume(other)
        self.assertEqual(len(self.sent), 1)

    def test_nonprivate_files_and_symlinks_are_refused(self):
        _, journal, item = self.reserved()
        journal.pending.chmod(0o644)
        with self.assertRaisesRegex(RuntimeError, 'private regular file'):
            journal.resume(BURN)
        journal.pending.chmod(0o600)
        target = journal.account / 'target.json'
        journal.pending.rename(target)
        journal.pending.symlink_to(target)
        with self.assertRaises(OSError):
            journal.resume(BURN)
        self.assertEqual(len(self.sent), 1)

    def test_unknown_replacement_can_resolve_to_the_older_canonical_transaction(self):
        _, journal, older = self.reserved()
        journal.accept(older)
        fake = json.loads(bytes.fromhex(older[0]['raw'][2:]))
        fake['gasPrice'] = hex(int(fake['gasPrice'], 16) * 2)
        raw = '0x' + json.dumps(fake).encode().hex()
        replacement = journal.make(raw, BURN, older[1]['input'])
        journal.write(journal.pending, replacement[0])
        receipt = self.receipt(journal, older)
        self.answers['eth_getTransactionReceipt'] = lambda url, params: receipt if params[0] == older[0]['hash'] else None
        self.assertEqual(journal.resume(BURN), older[0]['hash'])
        self.assertFalse(journal.pending.exists())
        self.assertEqual(len(self.sent), 1)

    def test_private_account_lock_prevents_overlapping_nonce_state_configurations(self):
        daemon, journal, _ = self.reserved()
        daemon.nonce_path = self.d / 'other-nonce-state.json'
        with journal.lock():
            with self.assertRaisesRegex(RuntimeError, 'another relayer holds'):
                daemon.send('eth', daemon.vault, ['release()'], release_id=BURN)
        self.assertTrue(journal.pending.exists())
        self.assertFalse(daemon.nonce_path.exists())
        self.assertEqual(len(self.sent), 1)

    def test_reorg_nonce_rewind_cannot_assign_an_older_releases_nonce_to_a_later_burn(self):
        daemon, journal, original = self.reserved()
        journal.accept(original)
        # A reorg removed the release; pending/latest both rewind while its
        # advisory SHARED marker is still within the ordinary lost-reply grace.
        self.sent_transactions.clear()
        with self.assertRaisesRegex(RuntimeError, 'reserved for another signed release'):
            daemon.send('eth', daemon.vault, ['release()'], release_id='0x' + 'ee' * 32)
        self.assertEqual(len(self.mktx_args()), 1)
        self.assertEqual(len(self.sent), 1)
        self.assertEqual(daemon.send('eth', daemon.vault, ['release()'], release_id=BURN), original[0]['hash'])
        self.assertEqual(len(self.sent), 2)
        self.assertEqual(len(self.mktx_args()), 1)

    def test_legacy_archives_rebuild_the_nonce_index_before_permitting_another_burn(self):
        daemon, journal, original = self.reserved()
        journal.accept(original)
        journal.nonce_path(0).unlink()
        (journal.account / 'nonce-index.json').unlink()
        self.sent_transactions.clear()
        with self.assertRaisesRegex(RuntimeError, 'reserved for another signed release'):
            daemon.send('eth', daemon.vault, ['release()'], release_id='0x' + 'ee' * 32)
        self.assertEqual(journal.read(journal.nonce_path(0))[0], original[0])
        self.assertEqual(len(self.mktx_args()), 1)

    def interrupted_write(self, phase):
        daemon, directory, _ = self.ready()
        signer = daemon.cast_out('wallet', 'address', *daemon.relayer_wallet('eth'))
        journal = daemon.release_journal(signer, '0x12345678')
        daemon.release_journal = lambda *args: journal
        target = journal.nonce_path(0) if phase == 'before' else journal.accepted(BURN)
        original = journal.write

        def fail(path, record):
            if path == target:
                raise OSError('injected durable-write failure')
            original(path, record)

        journal.write = fail
        with self.assertRaises(OSError):
            daemon.relay_release(directory)
        self.assertTrue(journal.pending.exists())
        self.assertFalse(daemon.nonce_path.exists())
        self.assertEqual(len(self.sent), 0 if phase == 'before' else 1)
        reserved = journal.read(journal.pending)[0]
        journal.write = original
        daemon.relay_release(directory)
        self.assertEqual(len(self.sent), 1)
        self.assertEqual(len(self.mktx_args()), 1)
        self.assertEqual(journal.read_accepted(BURN)[0], reserved)

    def test_index_write_failure_before_rpc_preserves_the_original_reservation(self):
        self.interrupted_write('before')

    def test_archive_write_failure_after_rpc_recovers_without_another_submission(self):
        self.interrupted_write('after')


if __name__ == '__main__':
    unittest.main()
