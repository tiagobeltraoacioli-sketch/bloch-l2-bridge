// SPDX-License-Identifier: MIT OR Apache-2.0
#![cfg(unix)]

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{symlink, OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use bloch_l2_bridge::{
    ExternalFloorCustodianAnchorCasOutcome, ExternalFloorCustodianAnchorStore,
    ExternalFloorCustodianClientAnchor, UnixExternalFloorCustodianAnchorStore,
    EXTERNAL_FLOOR_CUSTODIAN_ANCHOR_RECORD_LEN,
};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct Temp {
    root: PathBuf,
    store: PathBuf,
}

impl Temp {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "bloch-bxrc-anchor-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        Self {
            store: root.join("external"),
            root,
        }
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}

fn anchor(revision: u64, byte: u8) -> ExternalFloorCustodianClientAnchor {
    ExternalFloorCustodianClientAnchor {
        revision,
        commitment: [byte; 32],
    }
}

#[test]
fn create_once_exact_cas_is_durable_and_conflicts_are_non_mutating() {
    let temp = Temp::new();
    let initial = anchor(0, 0x11);
    let next = anchor(1, 0x22);
    let store = UnixExternalFloorCustodianAnchorStore::provision(&temp.store, initial).unwrap();
    assert_eq!(store.load().unwrap(), initial);
    assert_eq!(
        store.compare_and_swap(anchor(0, 0x99), next).unwrap(),
        ExternalFloorCustodianAnchorCasOutcome::Conflict(initial)
    );
    assert_eq!(store.load().unwrap(), initial);
    assert!(store.compare_and_swap(initial, initial).is_err());
    assert!(store.compare_and_swap(initial, anchor(3, 0x33)).is_err());
    assert!(store
        .compare_and_swap(
            initial,
            ExternalFloorCustodianClientAnchor {
                revision: 1,
                commitment: initial.commitment,
            },
        )
        .is_err());
    assert_eq!(
        store.compare_and_swap(initial, next).unwrap(),
        ExternalFloorCustodianAnchorCasOutcome::Committed
    );
    assert_eq!(store.load().unwrap(), next);
    let reconciled_descendant = anchor(3, 0x33);
    assert_eq!(
        store.compare_and_swap(next, reconciled_descendant).unwrap(),
        ExternalFloorCustodianAnchorCasOutcome::Committed
    );
    assert!(UnixExternalFloorCustodianAnchorStore::open(&temp.store).is_err());
    drop(store);

    let reopened = UnixExternalFloorCustodianAnchorStore::open(&temp.store).unwrap();
    assert_eq!(reopened.load().unwrap(), reconciled_descendant);
    assert!(UnixExternalFloorCustodianAnchorStore::provision(&temp.store, initial).is_err());

    let bytes = fs::read(temp.store.join(".bxrc-external-anchor")).unwrap();
    assert_eq!(bytes.len(), EXTERNAL_FLOOR_CUSTODIAN_ANCHOR_RECORD_LEN);
}

#[test]
fn zero_commitments_relative_paths_and_relaxed_permissions_fail_closed() {
    let temp = Temp::new();
    assert!(UnixExternalFloorCustodianAnchorStore::provision(
        PathBuf::from("relative-anchor").as_path(),
        anchor(0, 1),
    )
    .is_err());
    assert!(UnixExternalFloorCustodianAnchorStore::provision(
        &temp.store,
        ExternalFloorCustodianClientAnchor {
            revision: 0,
            commitment: [0; 32],
        },
    )
    .is_err());

    let store =
        UnixExternalFloorCustodianAnchorStore::provision(&temp.store, anchor(0, 1)).unwrap();
    assert!(store
        .compare_and_swap(
            anchor(0, 1),
            ExternalFloorCustodianClientAnchor {
                revision: 1,
                commitment: [0; 32],
            },
        )
        .is_err());
    drop(store);
    fs::set_permissions(&temp.store, fs::Permissions::from_mode(0o750)).unwrap();
    assert!(UnixExternalFloorCustodianAnchorStore::open(&temp.store).is_err());
}

#[test]
fn corruption_hardlinks_symlinks_and_orphan_temporary_files_are_rejected() {
    let temp = Temp::new();
    let store =
        UnixExternalFloorCustodianAnchorStore::provision(&temp.store, anchor(0, 1)).unwrap();
    drop(store);
    let state = temp.store.join(".bxrc-external-anchor");
    let original = fs::read(&state).unwrap();

    let mut corrupted = original.clone();
    corrupted[20] ^= 1;
    fs::write(&state, &corrupted).unwrap();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(UnixExternalFloorCustodianAnchorStore::open(&temp.store).is_err());
    fs::write(&state, &original).unwrap();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o600)).unwrap();

    let alias = temp.root.join("hardlink");
    fs::hard_link(&state, &alias).unwrap();
    assert!(UnixExternalFloorCustodianAnchorStore::open(&temp.store).is_err());
    fs::remove_file(alias).unwrap();

    let temporary = temp.store.join(".bxrc-external-anchor.tmp");
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .unwrap()
        .write_all(b"orphan")
        .unwrap();
    assert!(UnixExternalFloorCustodianAnchorStore::open(&temp.store).is_err());
    fs::remove_file(temporary).unwrap();

    let moved = temp.root.join("moved-anchor");
    fs::rename(&state, &moved).unwrap();
    symlink(&moved, &state).unwrap();
    assert!(UnixExternalFloorCustodianAnchorStore::open(&temp.store).is_err());
}

#[test]
fn directory_symlink_and_unsafe_lock_are_rejected() {
    let temp = Temp::new();
    let store =
        UnixExternalFloorCustodianAnchorStore::provision(&temp.store, anchor(0, 1)).unwrap();
    drop(store);

    let alias = temp.root.join("external-link");
    symlink(&temp.store, &alias).unwrap();
    assert!(UnixExternalFloorCustodianAnchorStore::open(&alias).is_err());

    let lock = temp.store.join(".bxrc-external-anchor.lock");
    fs::set_permissions(&lock, fs::Permissions::from_mode(0o640)).unwrap();
    assert!(UnixExternalFloorCustodianAnchorStore::open(&temp.store).is_err());
}
