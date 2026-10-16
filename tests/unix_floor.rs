// SPDX-License-Identifier: MIT OR Apache-2.0
#![cfg(unix)]

use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{symlink, OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use bloch_l2_bridge::watcher::MemorySource;
use bloch_l2_bridge::{
    persist_versioned_source, restore_versioned_source, L1Block, SourceFloorState,
    SourceGenerationFloor, UnixFloorAuthentication, UnixGenerationFloor, VersionedMemorySource,
};

const FLOOR_FILE: &str = ".source-generation-floor";
const TEMPORARY_FILE: &str = ".source-generation-floor.tmp";
const LOCK_FILE: &str = ".source-generation-floor.lock";
const LOCK_EXCLUSIVE: i32 = 2;
const LOCK_NONBLOCKING: i32 = 4;
const LOCK_RELEASE: i32 = 8;
const AUTHENTICATION_KEY: [u8; 32] = [0x42; 32];
const AUTHENTICATION_DOMAIN: [u8; 32] = [0x24; 32];

unsafe extern "C" {
    fn flock(file_descriptor: i32, operation: i32) -> i32;
}

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct TestDomain {
    root: PathBuf,
    floor: PathBuf,
    snapshot: PathBuf,
}

impl TestDomain {
    fn new() -> Self {
        let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "bloch-unix-floor-{}-{sequence}",
            std::process::id()
        ));
        let floor = root.join("floor-domain");
        let snapshot = root.join("snapshot-domain");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&floor).unwrap();
        fs::create_dir(&snapshot).unwrap();
        for path in [&root, &floor, &snapshot] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        Self {
            root,
            floor,
            snapshot,
        }
    }

    fn snapshot_path(&self) -> PathBuf {
        self.snapshot.join("source.json")
    }

    fn backend(&self) -> UnixGenerationFloor {
        UnixGenerationFloor::open_authenticated_separate(
            &self.floor,
            &self.snapshot_path(),
            UnixFloorAuthentication::new(AUTHENTICATION_KEY, AUTHENTICATION_DOMAIN).unwrap(),
        )
        .unwrap()
    }
}

impl Drop for TestDomain {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}

fn private_write(path: &PathBuf, value: &[u8]) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(value).unwrap();
    file.sync_all().unwrap();
}

fn source() -> MemorySource {
    let mut source = MemorySource::new();
    source
        .push(L1Block {
            height: 0,
            hash: [1; 32],
            parent_hash: [0; 32],
            txs: Vec::new(),
        })
        .unwrap();
    source
}

fn bound(generation: u64) -> SourceFloorState {
    SourceFloorState {
        generation,
        snapshot_commitment: Some([generation as u8 + 1; 32]),
    }
}

#[test]
fn durable_floor_is_monotonic_across_reopen_and_integrates_with_snapshot_store() {
    let domain = TestDomain::new();
    let floor = domain.backend();
    assert_eq!(floor.current().unwrap().generation, 0);
    floor.advance(bound(3)).unwrap();
    assert_eq!(floor.current().unwrap(), bound(3));
    assert_eq!(
        floor.advance(bound(2)).unwrap_err().kind(),
        ErrorKind::InvalidInput
    );
    drop(floor);
    assert_eq!(domain.backend().current().unwrap(), bound(3));

    let adapter = VersionedMemorySource::new(source());
    adapter.install(source()).unwrap();
    let fresh_domain = TestDomain::new();
    let fresh_floor = fresh_domain.backend();
    let snapshot_path = fresh_domain.snapshot_path();
    persist_versioned_source(&snapshot_path, &adapter, &fresh_floor, 16 * 1024).unwrap();
    let restored = restore_versioned_source(&snapshot_path, &fresh_floor, 16 * 1024).unwrap();
    assert_eq!(restored.seal().unwrap(), adapter.seal().unwrap());
}

#[test]
fn records_are_authenticated_and_bound_to_the_configured_domain() {
    let domain = TestDomain::new();
    let floor = domain.backend();
    floor.advance(bound(9)).unwrap();
    drop(floor);

    let wrong_key = UnixGenerationFloor::open_authenticated_separate(
        &domain.floor,
        &domain.snapshot_path(),
        UnixFloorAuthentication::new([0x43; 32], AUTHENTICATION_DOMAIN).unwrap(),
    )
    .unwrap();
    assert_eq!(
        wrong_key.current().unwrap_err().kind(),
        ErrorKind::InvalidData
    );

    let wrong_domain = UnixGenerationFloor::open_authenticated_separate(
        &domain.floor,
        &domain.snapshot_path(),
        UnixFloorAuthentication::new(AUTHENTICATION_KEY, [0x25; 32]).unwrap(),
    )
    .unwrap();
    assert_eq!(
        wrong_domain.current().unwrap_err().kind(),
        ErrorKind::InvalidData
    );

    assert_eq!(domain.backend().current().unwrap(), bound(9));

    let floor_path = domain.floor.join(FLOOR_FILE);
    let mut legacy = fs::read(&floor_path).unwrap();
    let version = legacy
        .windows(2)
        .position(|window| window == b"v3")
        .expect("record contains its version marker");
    legacy[version + 1] = b'2';
    fs::write(floor_path, legacy).unwrap();
    assert_eq!(
        domain.backend().current().unwrap_err().kind(),
        ErrorKind::InvalidData,
        "legacy generation-only v2 records must require explicit migration"
    );
}

#[test]
fn current_generation_binding_is_immutable_and_unbound_advances_are_refused() {
    let domain = TestDomain::new();
    let floor = domain.backend();
    floor.advance(bound(3)).unwrap();

    let conflicting = SourceFloorState {
        generation: 3,
        snapshot_commitment: Some([0x99; 32]),
    };
    assert_eq!(
        floor.advance(conflicting).unwrap_err().kind(),
        ErrorKind::AlreadyExists
    );
    assert_eq!(floor.current().unwrap(), bound(3));
    assert_eq!(
        floor
            .advance(SourceFloorState {
                generation: 4,
                snapshot_commitment: None,
            })
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidInput
    );
    assert_eq!(floor.current().unwrap(), bound(3));
}

#[test]
fn credentials_reject_null_configuration_and_redact_the_key() {
    assert_eq!(
        UnixFloorAuthentication::new([0; 32], AUTHENTICATION_DOMAIN)
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidInput
    );
    assert_eq!(
        UnixFloorAuthentication::new(AUTHENTICATION_KEY, [0; 32])
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidInput
    );
    let debug = format!(
        "{:?}",
        UnixFloorAuthentication::new(AUTHENTICATION_KEY, AUTHENTICATION_DOMAIN).unwrap()
    );
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains("66, 66"));
}

#[test]
fn valid_pending_record_is_recovered_but_regressive_or_torn_record_is_refused() {
    let domain = TestDomain::new();
    let floor = domain.backend();
    floor.advance(bound(3)).unwrap();
    let old_record = fs::read(domain.floor.join(FLOOR_FILE)).unwrap();
    floor.advance(bound(4)).unwrap();
    let new_record = fs::read(domain.floor.join(FLOOR_FILE)).unwrap();

    fs::write(domain.floor.join(FLOOR_FILE), &old_record).unwrap();
    private_write(&domain.floor.join(TEMPORARY_FILE), &new_record);
    assert_eq!(floor.current().unwrap(), bound(4));
    assert!(!domain.floor.join(TEMPORARY_FILE).exists());

    private_write(&domain.floor.join(TEMPORARY_FILE), &old_record);
    assert_eq!(floor.current().unwrap_err().kind(), ErrorKind::InvalidData);
    fs::remove_file(domain.floor.join(TEMPORARY_FILE)).unwrap();
    private_write(&domain.floor.join(TEMPORARY_FILE), b"torn");
    assert_eq!(floor.current().unwrap_err().kind(), ErrorKind::InvalidData);
}

#[test]
fn pending_record_cannot_rebind_the_current_generation() {
    let domain = TestDomain::new();
    let floor = domain.backend();
    floor.advance(bound(3)).unwrap();
    let trusted_record = fs::read(domain.floor.join(FLOOR_FILE)).unwrap();

    let conflicting_domain = TestDomain::new();
    let conflicting_floor = conflicting_domain.backend();
    conflicting_floor
        .advance(SourceFloorState {
            generation: 3,
            snapshot_commitment: Some([0x99; 32]),
        })
        .unwrap();
    let conflicting_record = fs::read(conflicting_domain.floor.join(FLOOR_FILE)).unwrap();
    private_write(&domain.floor.join(TEMPORARY_FILE), &conflicting_record);

    assert_eq!(floor.current().unwrap_err().kind(), ErrorKind::InvalidData);
    assert_eq!(
        fs::read(domain.floor.join(FLOOR_FILE)).unwrap(),
        trusted_record
    );
    assert!(domain.floor.join(TEMPORARY_FILE).exists());
}

#[test]
fn corrupt_symlinked_or_public_floor_state_is_refused() {
    let domain = TestDomain::new();
    let floor = domain.backend();
    floor.advance(bound(7)).unwrap();
    let floor_path = domain.floor.join(FLOOR_FILE);
    let mut corrupt = fs::read(&floor_path).unwrap();
    let last = corrupt.len() - 1;
    corrupt[last] ^= 1;
    fs::write(&floor_path, corrupt).unwrap();
    assert_eq!(floor.current().unwrap_err().kind(), ErrorKind::InvalidData);

    fs::remove_file(&floor_path).unwrap();
    let target = domain.root.join("attacker-floor");
    fs::write(&target, b"not a floor").unwrap();
    symlink(&target, &floor_path).unwrap();
    assert_eq!(
        floor.current().unwrap_err().kind(),
        ErrorKind::PermissionDenied
    );

    fs::remove_file(&floor_path).unwrap();
    assert_eq!(floor.current().unwrap().generation, 0);
    fs::set_permissions(&floor_path, fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(
        floor.current().unwrap_err().kind(),
        ErrorKind::PermissionDenied
    );
    fs::set_permissions(&floor_path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::set_permissions(&domain.floor, fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(
        floor.current().unwrap_err().kind(),
        ErrorKind::PermissionDenied
    );
    fs::set_permissions(&domain.floor, fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn symlinked_or_public_lock_file_is_refused() {
    let domain = TestDomain::new();
    let floor = domain.backend();
    let target = domain.root.join("attacker-lock");
    fs::write(&target, b"").unwrap();
    let lock_path = domain.floor.join(LOCK_FILE);
    symlink(&target, &lock_path).unwrap();
    assert_eq!(
        floor.current().unwrap_err().kind(),
        ErrorKind::PermissionDenied
    );
    fs::remove_file(&lock_path).unwrap();
    assert_eq!(floor.current().unwrap().generation, 0);
    fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(
        floor.current().unwrap_err().kind(),
        ErrorKind::PermissionDenied
    );
}

#[test]
fn constructor_refuses_shared_nested_symlinked_and_public_domains() {
    let domain = TestDomain::new();
    let snapshot_path = domain.snapshot_path();
    assert_eq!(
        UnixGenerationFloor::open_authenticated_separate(
            &domain.snapshot,
            &snapshot_path,
            UnixFloorAuthentication::new(AUTHENTICATION_KEY, AUTHENTICATION_DOMAIN).unwrap(),
        )
        .unwrap_err()
        .kind(),
        ErrorKind::InvalidInput
    );
    let nested = domain.snapshot.join("nested-floor");
    fs::create_dir(&nested).unwrap();
    fs::set_permissions(&nested, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(
        UnixGenerationFloor::open_authenticated_separate(
            &nested,
            &snapshot_path,
            UnixFloorAuthentication::new(AUTHENTICATION_KEY, AUTHENTICATION_DOMAIN).unwrap(),
        )
        .unwrap_err()
        .kind(),
        ErrorKind::InvalidInput
    );
    let link = domain.root.join("floor-link");
    symlink(&domain.floor, &link).unwrap();
    assert_eq!(
        UnixGenerationFloor::open_authenticated_separate(
            &link,
            &snapshot_path,
            UnixFloorAuthentication::new(AUTHENTICATION_KEY, AUTHENTICATION_DOMAIN).unwrap(),
        )
        .unwrap_err()
        .kind(),
        ErrorKind::PermissionDenied
    );
    fs::set_permissions(&domain.floor, fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(
        UnixGenerationFloor::open_authenticated_separate(
            &domain.floor,
            &snapshot_path,
            UnixFloorAuthentication::new(AUTHENTICATION_KEY, AUTHENTICATION_DOMAIN).unwrap(),
        )
        .unwrap_err()
        .kind(),
        ErrorKind::PermissionDenied
    );
    fs::set_permissions(&domain.floor, fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn concurrent_operation_is_refused_without_racing_the_counter() {
    let domain = TestDomain::new();
    let floor = domain.backend();
    assert_eq!(floor.current().unwrap().generation, 0);
    let lock = File::open(domain.floor.join(LOCK_FILE)).unwrap();
    // SAFETY: `lock` remains live until after the matching unlock below.
    assert_eq!(
        unsafe { flock(lock.as_raw_fd(), LOCK_EXCLUSIVE | LOCK_NONBLOCKING) },
        0
    );
    assert_eq!(
        floor.advance(bound(1)).unwrap_err().kind(),
        ErrorKind::WouldBlock
    );
    // SAFETY: this releases the lock acquired above on the same live fd.
    assert_eq!(unsafe { flock(lock.as_raw_fd(), LOCK_RELEASE) }, 0);
    floor.advance(bound(1)).unwrap();
    assert_eq!(floor.current().unwrap(), bound(1));
}
