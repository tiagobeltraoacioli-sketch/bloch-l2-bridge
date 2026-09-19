// SPDX-License-Identifier: MIT OR Apache-2.0
#![cfg(unix)]

use std::cell::Cell;
use std::fs;
use std::io;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use bloch_l2_bridge::watcher::MemorySource;
use bloch_l2_bridge::{
    persist_versioned_source, restore_versioned_source, L1Block, SourceGenerationFloor,
    SourceStoreError, VersionedMemorySource, VersionedSourceRestoreError,
};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "bloch-source-store-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }

    fn snapshot(&self) -> PathBuf {
        self.0.join("source.json")
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[derive(Default)]
struct TestFloor {
    generation: Cell<u64>,
    fail_after_advance: Cell<bool>,
    overshoot: Cell<bool>,
}

impl SourceGenerationFloor for TestFloor {
    fn current_generation(&self) -> io::Result<u64> {
        Ok(self.generation.get())
    }

    fn advance_generation(&self, generation: u64) -> io::Result<()> {
        self.generation.set(self.generation.get().max(generation));
        if self.overshoot.get() {
            self.generation.set(generation.checked_add(1).unwrap());
        }
        if self.fail_after_advance.get() {
            return Err(io::Error::other("simulated failure after durable advance"));
        }
        Ok(())
    }
}

fn source(blocks: u64) -> MemorySource {
    let mut source = MemorySource::new();
    let mut parent = [0; 32];
    for height in 0..blocks {
        let hash = [(height + 1) as u8; 32];
        source
            .push(L1Block {
                height,
                hash,
                parent_hash: parent,
                txs: Vec::new(),
            })
            .unwrap();
        parent = hash;
    }
    source
}

fn temporary_path(path: &Path) -> PathBuf {
    PathBuf::from(format!("{}.tmp", path.display()))
}

#[test]
fn snapshot_and_seal_round_trip_with_an_independent_floor() {
    let directory = TestDirectory::new();
    let path = directory.snapshot();
    let staged = source(3);
    let adapter = VersionedMemorySource::new(staged.clone());
    adapter.install(staged).unwrap();
    let floor = TestFloor::default();

    persist_versioned_source(&path, &adapter, &floor, 16 * 1024).unwrap();

    assert_eq!(floor.generation.get(), 1);
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let restored = restore_versioned_source(&path, &floor, 16 * 1024).unwrap();
    assert_eq!(restored.seal().unwrap(), adapter.seal().unwrap());
}

#[test]
fn floor_first_order_turns_an_interrupted_update_into_safe_refusal() {
    let directory = TestDirectory::new();
    let path = directory.snapshot();
    let staged = source(2);
    let adapter = VersionedMemorySource::new(staged.clone());
    let floor = TestFloor::default();
    persist_versioned_source(&path, &adapter, &floor, 16 * 1024).unwrap();
    let old_bytes = fs::read(&path).unwrap();

    adapter.install(staged).unwrap();
    floor.fail_after_advance.set(true);
    assert!(matches!(
        persist_versioned_source(&path, &adapter, &floor, 16 * 1024),
        Err(SourceStoreError::Io(_))
    ));
    assert_eq!(floor.generation.get(), 1);
    assert_eq!(fs::read(&path).unwrap(), old_bytes);
    assert!(matches!(
        restore_versioned_source(&path, &floor, 16 * 1024),
        Err(SourceStoreError::Seal(
            VersionedSourceRestoreError::Rollback {
                minimum: 1,
                found: 0
            }
        ))
    ));
}

#[test]
fn stale_temporary_file_and_concurrent_floor_change_are_fail_closed() {
    let directory = TestDirectory::new();
    let path = directory.snapshot();
    let temporary = temporary_path(&path);
    fs::write(&temporary, b"crash evidence").unwrap();
    let adapter = VersionedMemorySource::new(source(1));
    let floor = TestFloor::default();

    assert!(matches!(
        persist_versioned_source(&path, &adapter, &floor, 16 * 1024),
        Err(SourceStoreError::UnsafePath("stale temporary snapshot"))
    ));
    assert_eq!(floor.generation.get(), 0);
    fs::remove_file(&temporary).unwrap();

    floor.overshoot.set(true);
    assert!(matches!(
        persist_versioned_source(&path, &adapter, &floor, 16 * 1024),
        Err(SourceStoreError::FloorChanged {
            expected: 0,
            actual: 1
        })
    ));
    assert!(!path.exists());
}

#[test]
fn serialization_limit_is_enforced_before_floor_or_file_changes() {
    let directory = TestDirectory::new();
    let path = directory.snapshot();
    let adapter = VersionedMemorySource::new(source(2));
    let floor = TestFloor::default();

    assert!(matches!(
        persist_versioned_source(&path, &adapter, &floor, 1),
        Err(SourceStoreError::TooLarge { limit: 1 })
    ));
    assert_eq!(floor.generation.get(), 0);
    assert!(!path.exists());
    assert!(!temporary_path(&path).exists());
}

#[test]
fn restore_rejects_truncation_oversize_symlinks_and_public_directories() {
    let directory = TestDirectory::new();
    let path = directory.snapshot();
    let adapter = VersionedMemorySource::new(source(2));
    let floor = TestFloor::default();
    persist_versioned_source(&path, &adapter, &floor, 16 * 1024).unwrap();

    assert!(matches!(
        restore_versioned_source(&path, &floor, 1),
        Err(SourceStoreError::TooLarge { limit: 1 })
    ));
    fs::write(&path, b"{").unwrap();
    assert!(matches!(
        restore_versioned_source(&path, &floor, 16 * 1024),
        Err(SourceStoreError::Json(_))
    ));

    fs::remove_file(&path).unwrap();
    let target = directory.0.join("target");
    fs::write(&target, b"{}").unwrap();
    symlink(&target, &path).unwrap();
    assert!(matches!(
        restore_versioned_source(&path, &floor, 16 * 1024),
        Err(SourceStoreError::UnsafePath(_))
    ));

    fs::remove_file(&path).unwrap();
    fs::set_permissions(&directory.0, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(
        persist_versioned_source(&path, &adapter, &floor, 16 * 1024),
        Err(SourceStoreError::UnsafePath(_))
    ));
    fs::set_permissions(&directory.0, fs::Permissions::from_mode(0o700)).unwrap();
}
