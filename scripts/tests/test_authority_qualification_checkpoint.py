"""Adversarial tests for the observation-only durable checkpoint journal."""
import concurrent.futures
import copy
import hashlib
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
TESTS = SCRIPTS / "tests"
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(TESTS))

import authority_qualification_checkpoint as journal  # noqa: E402
from bridge_authority_qualification import (  # noqa: E402
    verify_bridge_authority_qualification,
)
from custody_deployment_manifest import canonical_sha256  # noqa: E402
from test_bridge_authority_ceremony import package as ceremony_package  # noqa: E402
from test_bridge_authority_qualification import (  # noqa: E402
    policy, qualification, qualification_checkpoint,
)
from test_custody_deployment_manifest import pin  # noqa: E402


class QualificationCheckpointJournalTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "state"
        self.root.mkdir(mode=0o700)
        self.ceremony = ceremony_package()
        self.policy, self.private_keys = policy(self.temporary.name)
        self.checkpoint = qualification_checkpoint(self.ceremony, self.policy)
        self.package = qualification(
            self.ceremony, self.policy, self.private_keys,
            checkpoint_value=self.checkpoint,
        )
        executable = shutil.which("ssh-keygen")
        if executable is None:
            self.fail("ssh-keygen is required")
        executable = str(Path(executable).resolve())
        executable_digest = "0x" + hashlib.sha256(
            Path(executable).read_bytes()
        ).hexdigest()
        self.observation = verify_bridge_authority_qualification(
            self.ceremony, self.package, self.policy,
            canonical_sha256(self.policy), checkpoint=self.checkpoint,
            trusted_checkpoint_sha256=canonical_sha256(self.checkpoint),
            ssh_keygen=executable,
            trusted_ssh_keygen_sha256=executable_digest,
        )
        self.checkpoint_digest = journal._digest(self.checkpoint)
        self.observation_digest = journal._digest(self.observation)
        journal.provision_checkpoint(self.root, self.checkpoint)

    def tearDown(self):
        self.temporary.cleanup()

    def advance(self):
        return journal.advance_checkpoint(
            self.root, self.observation, self.checkpoint_digest,
            self.observation_digest,
        )

    def test_exact_successor_is_durable_and_observation_only(self):
        report = self.advance()
        self.assertTrue(report["observationOnly"])
        self.assertFalse(report["externalRecordsAuthenticated"])
        self.assertFalse(report["activationAuthorized"])
        self.assertFalse(report["recovered"])
        checkpoint = journal._parse_canonical(
            journal._read(self.root / "checkpoint.json", "checkpoint"),
            "checkpoint",
        )
        self.assertEqual(checkpoint["lastQualificationSequence"], "1")
        self.assertEqual(
            checkpoint["lastQualificationSha256"],
            self.observation["qualificationPackageCanonicalSha256"],
        )
        records, tip, pending = journal._journal(
            journal._read(self.root / "checkpoint.journal", "journal")
        )
        self.assertEqual(len(records), 2)
        self.assertEqual(tip, report["checkpointSha256"])
        self.assertIsNone(pending)

    def test_concurrent_same_sequence_has_one_cas_winner(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(self.advance) for _ in range(2)]
        successes = [future.result() for future in futures if future.exception() is None]
        failures = [future.exception() for future in futures if future.exception() is not None]
        self.assertEqual(len(successes), 1)
        self.assertEqual(len(failures), 1)
        self.assertIn("CAS mismatch", str(failures[0]))

    def test_rollback_corruption_and_context_substitution_fail_closed(self):
        self.advance()
        (self.root / "checkpoint.json").write_bytes(journal._canonical(self.checkpoint))
        with self.assertRaisesRegex(ValueError, "journal tip mismatch"):
            self.advance()

        # Restore a fresh state, then corrupt a complete journal record.
        other = Path(self.temporary.name) / "other"
        other.mkdir(mode=0o700)
        journal.provision_checkpoint(other, self.checkpoint)
        (other / "checkpoint.journal").write_bytes(b"{not-json}\n")
        with self.assertRaisesRegex(ValueError, "invalid checkpoint journal"):
            journal.advance_checkpoint(
                other, self.observation, self.checkpoint_digest,
                self.observation_digest,
            )

        context_root = Path(self.temporary.name) / "context"
        context_root.mkdir(mode=0o700)
        journal.provision_checkpoint(context_root, self.checkpoint)
        changed = copy.deepcopy(self.observation)
        changed["reviewPolicySha256"] = pin("another-review-policy")
        with self.assertRaisesRegex(ValueError, "context does not match"):
            journal.advance_checkpoint(
                context_root, changed, self.checkpoint_digest,
                journal._digest(changed),
            )

    def test_crash_after_state_rename_recovers_exact_pending_transition(self):
        original = journal._append_journal
        calls = 0

        def crash_on_commit(path, value):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("injected crash before commit record")
            return original(path, value)

        with patch.object(journal, "_append_journal", side_effect=crash_on_commit):
            with self.assertRaisesRegex(OSError, "injected crash"):
                self.advance()
        report = self.advance()
        self.assertTrue(report["recovered"])
        records, tip, pending = journal._journal(
            journal._read(self.root / "checkpoint.journal", "journal")
        )
        self.assertEqual(len(records), 2)
        self.assertEqual(tip, report["checkpointSha256"])
        self.assertIsNone(pending)

    def test_crash_before_state_rename_recovers_exact_pending_transition(self):
        original = journal._atomic_checkpoint
        calls = 0

        def crash_before_rename(root, value):
            nonlocal calls
            calls += 1
            if calls == 1:
                raise OSError("injected crash before state rename")
            return original(root, value)

        with patch.object(journal, "_atomic_checkpoint", side_effect=crash_before_rename):
            with self.assertRaisesRegex(OSError, "injected crash"):
                self.advance()
        report = self.advance()
        self.assertTrue(report["recovered"])
        checkpoint = journal._parse_canonical(
            journal._read(self.root / "checkpoint.json", "checkpoint"),
            "checkpoint",
        )
        self.assertEqual(checkpoint["lastQualificationSequence"], "1")


if __name__ == "__main__":
    unittest.main()
