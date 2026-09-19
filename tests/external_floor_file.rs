// SPDX-License-Identifier: MIT OR Apache-2.0
#![cfg(unix)]

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{symlink, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use bloch_l2_bridge::{
    DurableExternalFloorReplayGuard, ExternalFloorDurableReplayError,
    ExternalFloorReplayCasOutcome, ExternalFloorReplayCheckpoint, ExternalFloorReplayStore,
    UnixExternalFloorReplayStore, EXTERNAL_FLOOR_REPLAY_RECORD_LEN,
};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct TemporaryDirectory(PathBuf);

impl TemporaryDirectory {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "bloch-external-floor-{label}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }

    fn store(&self) -> PathBuf {
        self.0.join("store")
    }
}

impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn checkpoint(revision: u64, sequence: u64) -> ExternalFloorReplayCheckpoint {
    ExternalFloorReplayCheckpoint::new(revision, [0x5a; 32], sequence).unwrap()
}

fn provision(label: &str, initial: ExternalFloorReplayCheckpoint) -> TemporaryDirectory {
    let temporary = TemporaryDirectory::new(label);
    UnixExternalFloorReplayStore::provision(&temporary.store(), initial).unwrap();
    temporary
}

fn state(path: &Path) -> PathBuf {
    path.join(".external-floor-replay")
}

#[test]
fn durable_cas_survives_restart_and_requires_exact_external_checkpoint() {
    let initial = checkpoint(7, 11);
    let replacement = checkpoint(8, 12);
    let temporary = provision("restart", initial);
    let store = UnixExternalFloorReplayStore::open(&temporary.store(), initial).unwrap();
    assert_eq!(
        store.compare_and_swap(initial, replacement).unwrap(),
        ExternalFloorReplayCasOutcome::Committed
    );
    assert_eq!(store.load().unwrap(), replacement);
    drop(store);

    assert!(UnixExternalFloorReplayStore::open(&temporary.store(), initial).is_err());
    let restarted = UnixExternalFloorReplayStore::open(&temporary.store(), replacement).unwrap();
    assert_eq!(restarted.load().unwrap(), replacement);
}

#[test]
fn complete_checkpoint_is_compared_and_conflict_reports_current() {
    let initial = checkpoint(7, 11);
    let temporary = provision("conflict", initial);
    let store = UnixExternalFloorReplayStore::open(&temporary.store(), initial).unwrap();
    let stale = checkpoint(6, 11);
    assert_eq!(
        store.compare_and_swap(stale, checkpoint(8, 12)).unwrap(),
        ExternalFloorReplayCasOutcome::Conflict(initial)
    );
    assert_eq!(store.load().unwrap(), initial);

    for invalid in [
        ExternalFloorReplayCheckpoint {
            revision: initial.revision + 2,
            session_nonce: initial.session_nonce,
            next_sequence: initial.next_sequence + 1,
        },
        ExternalFloorReplayCheckpoint {
            revision: initial.revision + 1,
            session_nonce: [0x6b; 32],
            next_sequence: initial.next_sequence + 1,
        },
        ExternalFloorReplayCheckpoint {
            revision: initial.revision + 1,
            session_nonce: initial.session_nonce,
            next_sequence: initial.next_sequence + 2,
        },
    ] {
        assert!(store.compare_and_swap(initial, invalid).is_err());
        assert_eq!(store.load().unwrap(), initial);
    }
}

#[test]
fn record_is_fixed_length_and_rejects_corruption_truncation_and_trailing_bytes() {
    for (label, mutate) in [("corrupt", 0_u8), ("truncate", 1_u8), ("trailing", 2_u8)] {
        let initial = checkpoint(1, 2);
        let temporary = provision(label, initial);
        let path = state(&temporary.store());
        let mut bytes = Vec::new();
        fs::File::open(&path)
            .unwrap()
            .read_to_end(&mut bytes)
            .unwrap();
        assert_eq!(bytes.len(), EXTERNAL_FLOOR_REPLAY_RECORD_LEN);
        match mutate {
            0 => bytes[16] ^= 1,
            1 => {
                bytes.pop();
            }
            _ => bytes.push(0),
        }
        let mut file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(path)
            .unwrap();
        file.write_all(&bytes).unwrap();
        file.sync_all().unwrap();
        assert!(UnixExternalFloorReplayStore::open(&temporary.store(), initial).is_err());
    }
}

#[test]
fn rejects_group_permissions_symlinks_and_hardlinks() {
    let initial = checkpoint(1, 0);

    let permissions = provision("permissions", initial);
    fs::set_permissions(permissions.store(), fs::Permissions::from_mode(0o750)).unwrap();
    assert!(UnixExternalFloorReplayStore::open(&permissions.store(), initial).is_err());

    let symlink_case = provision("symlink", initial);
    let alias = symlink_case.0.join("alias");
    symlink(symlink_case.store(), &alias).unwrap();
    assert!(UnixExternalFloorReplayStore::open(&alias, initial).is_err());

    let hardlink = provision("hardlink", initial);
    fs::hard_link(
        state(&hardlink.store()),
        hardlink.0.join("attacker-state-alias"),
    )
    .unwrap();
    assert!(UnixExternalFloorReplayStore::open(&hardlink.store(), initial).is_err());
}

#[test]
fn lock_is_exclusive_persistent_and_unsafe_lock_is_rejected() {
    let initial = checkpoint(1, 0);
    let temporary = provision("lock", initial);
    let first = UnixExternalFloorReplayStore::open(&temporary.store(), initial).unwrap();
    assert!(UnixExternalFloorReplayStore::open(&temporary.store(), initial).is_err());
    drop(first);
    assert!(temporary
        .store()
        .join(".external-floor-replay.lock")
        .exists());

    fs::hard_link(
        temporary.store().join(".external-floor-replay.lock"),
        temporary.0.join("attacker-lock-alias"),
    )
    .unwrap();
    assert!(UnixExternalFloorReplayStore::open(&temporary.store(), initial).is_err());
}

#[test]
fn stale_temporary_file_is_not_removed_or_adopted() {
    let initial = checkpoint(2, 3);
    let temporary = provision("orphan", initial);
    let store = UnixExternalFloorReplayStore::open(&temporary.store(), initial).unwrap();
    let orphan = temporary.store().join(".external-floor-replay.tmp");
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&orphan)
        .unwrap();
    file.sync_all().unwrap();
    assert!(store.load().is_err());
    assert!(store.compare_and_swap(initial, checkpoint(3, 4)).is_err());
    assert!(orphan.exists());
    drop(store);

    // Restart is fail-closed before accepting the independently retained
    // checkpoint, and the backend leaves reconciliation to the operator.
    assert!(UnixExternalFloorReplayStore::open(&temporary.store(), initial).is_err());
    assert!(orphan.exists());
    fs::remove_file(orphan).unwrap();
    let reconciled = UnixExternalFloorReplayStore::open(&temporary.store(), initial).unwrap();
    assert_eq!(reconciled.load().unwrap(), initial);
}

#[test]
fn sequence_and_revision_exhaustion_never_modify_the_file() {
    for (label, initial, sequence) in [
        ("sequence-exhausted", checkpoint(9, u64::MAX), u64::MAX),
        ("revision-exhausted", checkpoint(u64::MAX, 4), 4),
    ] {
        let temporary = provision(label, initial);
        let store = UnixExternalFloorReplayStore::open(&temporary.store(), initial).unwrap();
        let mut guard = DurableExternalFloorReplayGuard::open(store, initial).unwrap();
        let error = guard.reserve(initial.session_nonce, sequence).unwrap_err();
        assert!(matches!(
            error,
            ExternalFloorDurableReplayError::SequenceExhausted
                | ExternalFloorDurableReplayError::RevisionExhausted
        ));
        assert_eq!(guard.checkpoint(), initial);
    }
}
