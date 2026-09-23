"""Durably retain observation-only authority qualification continuity.

This writer has no key, signature, deployment, broadcast or activation
capability. Caller-supplied digests remain CAS inputs, not authenticated roots.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile

from usdt_observer.common import require, word


MAX_FILE_BYTES = 4 * 1024 * 1024
CHECKPOINT_FIELDS = {
    "schema", "reviewPolicySha256", "ceremonyPackageCanonicalSha256",
    "lastQualificationSequence", "lastQualificationSha256",
}
OBSERVATION_FIELDS = {
    "schema", "ceremonyPackageCanonicalSha256", "manifestCanonicalSha256",
    "authorityPolicySha256", "custodyCeremonySha256",
    "nativeRolesCeremonySha256", "activationAuthorityCeremonySha256",
    "reviewPolicySha256", "qualificationCheckpointSha256",
    "qualificationSequence", "previousQualificationSha256",
    "qualificationPackageCanonicalSha256", "reviewerCount", "reviewThreshold",
    "externalRecordsAuthenticated", "custodyQualified", "authoritiesQualified",
    "keysLoaded", "signingAllowed", "deploymentAllowed", "broadcastAllowed",
    "activationAuthorized",
}
FALSE_FIELDS = {
    "externalRecordsAuthenticated", "custodyQualified", "authoritiesQualified",
    "keysLoaded", "signingAllowed", "deploymentAllowed", "broadcastAllowed",
    "activationAuthorized",
}


def _canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")


def _digest(value):
    return "0x" + hashlib.sha256(_canonical(value)[:-1]).hexdigest()


def _pin(value, label, *, zero=False):
    raw = word(value, 32)
    require(zero or (any(raw) and len(set(raw)) > 1),
            f"{label}: non-placeholder digest required")
    canonical = "0x" + raw.hex()
    require(type(value) is str and value == canonical,
            f"{label}: canonical lowercase digest required")
    return canonical


def _uint64(value, label):
    require(type(value) is str and value.isascii() and value.isdecimal()
            and (value == "0" or value[0] != "0") and len(value) <= 20,
            f"{label}: canonical uint64 required")
    number = int(value)
    require(number <= 2**64 - 1, f"{label}: canonical uint64 required")
    return number


def _checkpoint(value):
    require(type(value) is dict and set(value) == CHECKPOINT_FIELDS,
            "checkpoint: exact fields required")
    require(value["schema"]
            == "postern.bridge-authority-qualification-checkpoint.v1",
            "unsupported checkpoint")
    _pin(value["reviewPolicySha256"], "checkpoint review policy")
    _pin(value["ceremonyPackageCanonicalSha256"], "checkpoint ceremony")
    sequence = _uint64(value["lastQualificationSequence"], "checkpoint sequence")
    previous = _pin(
        value["lastQualificationSha256"], "checkpoint predecessor", zero=True
    )
    require((sequence == 0) == (previous == "0x" + "00" * 32),
            "checkpoint genesis/predecessor mismatch")
    return sequence


def _observation(value):
    require(type(value) is dict and set(value) == OBSERVATION_FIELDS,
            "observation: exact fields required")
    require(value["schema"]
            == "postern.bridge-authority-external-observation.v1",
            "observation-only authority report required")
    require(all(value[field] is False for field in FALSE_FIELDS),
            "observation must not claim authentication or authority")
    for field in (
        "ceremonyPackageCanonicalSha256", "manifestCanonicalSha256",
        "authorityPolicySha256", "custodyCeremonySha256",
        "nativeRolesCeremonySha256", "activationAuthorityCeremonySha256",
        "reviewPolicySha256", "qualificationCheckpointSha256",
        "qualificationPackageCanonicalSha256",
    ):
        _pin(value[field], f"observation {field}")
    _pin(value["previousQualificationSha256"], "observation predecessor", zero=True)
    sequence = _uint64(value["qualificationSequence"], "observation sequence")
    require(sequence > 0, "observation sequence must be positive")
    return sequence


def _safe_directory(root):
    root = Path(root)
    require(root.is_absolute(), "absolute checkpoint directory required")
    metadata = root.lstat()
    require(stat.S_ISDIR(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode)
            and metadata.st_uid == os.geteuid() and metadata.st_mode & 0o077 == 0,
            "private operator-owned checkpoint directory required")
    return root


def _read(path, label, *, missing=False, empty=False):
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        if missing:
            return None
        raise
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and before.st_size <= MAX_FILE_BYTES and not before.st_mode & 0o022,
                f"unsafe {label}")
        chunks, remaining = [], MAX_FILE_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        require((empty or len(raw) > 0) and len(raw) <= MAX_FILE_BYTES
                and (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
                f"{label} changed while reading")
        return raw
    finally:
        os.close(descriptor)


def _parse_canonical(raw, label):
    try:
        value = json.loads(raw, object_pairs_hook=_unique)
    except (ValueError, TypeError, UnicodeDecodeError) as error:
        raise ValueError(f"invalid {label}") from error
    require(raw == _canonical(value), f"non-canonical {label}")
    return value


def _unique(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, "duplicate JSON field")
        value[key] = item
    return value


def _fsync_directory(root):
    descriptor = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _atomic_checkpoint(root, value):
    raw = _canonical(value)
    descriptor, temporary = tempfile.mkstemp(prefix=".checkpoint-", dir=root)
    try:
        os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:])
            require(written > 0, "partial checkpoint write")
            offset += written
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.replace(temporary, root / "checkpoint.json")
        _fsync_directory(root)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _append_journal(path, value):
    raw = _canonical(value)
    descriptor = os.open(
        path, os.O_WRONLY | os.O_APPEND | os.O_CREAT
        | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0), 0o600,
    )
    try:
        metadata = os.fstat(descriptor)
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1
                and not metadata.st_mode & 0o022
                and metadata.st_size + len(raw) <= MAX_FILE_BYTES,
                "unsafe checkpoint journal")
        offset = 0
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:])
            require(written > 0, "partial checkpoint journal write")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _journal(raw):
    records = []
    for line in raw.splitlines(keepends=True):
        records.append(_parse_canonical(line, "checkpoint journal record"))
    require(records, "checkpoint journal is empty or corrupt")
    previous = None
    complete = len(records) - (len(records) % 2)
    for index in range(0, complete, 2):
        prepare, commit = records[index:index + 2]
        require(prepare.get("schema") == "postern.bridge-qualification-journal-prepare.v1"
                and set(prepare) == {
                    "schema", "transitionId", "previousCheckpointSha256",
                    "nextCheckpoint", "nextCheckpointSha256", "observationSha256",
                }, "invalid checkpoint journal prepare")
        for field in (
            "transitionId", "previousCheckpointSha256",
            "nextCheckpointSha256", "observationSha256",
        ):
            _pin(prepare[field], f"journal prepare {field}")
        require(commit.get("schema") == "postern.bridge-qualification-journal-commit.v1"
                and set(commit) == {"schema", "transitionId", "nextCheckpointSha256"},
                "invalid checkpoint journal commit")
        _pin(commit["transitionId"], "journal commit transition")
        _pin(commit["nextCheckpointSha256"], "journal commit checkpoint")
        _checkpoint(prepare["nextCheckpoint"])
        require(_digest(prepare["nextCheckpoint"]) == prepare["nextCheckpointSha256"]
                and commit["transitionId"] == prepare["transitionId"]
                and commit["nextCheckpointSha256"] == prepare["nextCheckpointSha256"],
                "checkpoint journal commitment mismatch")
        if previous is not None:
            require(prepare["previousCheckpointSha256"] == previous,
                    "checkpoint journal chain rollback")
        previous = prepare["nextCheckpointSha256"]
    pending = None
    if len(records) % 2:
        pending = records[-1]
        require(pending.get("schema")
                == "postern.bridge-qualification-journal-prepare.v1"
                and set(pending) == {
                    "schema", "transitionId", "previousCheckpointSha256",
                    "nextCheckpoint", "nextCheckpointSha256", "observationSha256",
                }, "invalid pending checkpoint journal prepare")
        for field in (
            "transitionId", "previousCheckpointSha256",
            "nextCheckpointSha256", "observationSha256",
        ):
            _pin(pending[field], f"pending journal {field}")
        _checkpoint(pending["nextCheckpoint"])
        require(_digest(pending["nextCheckpoint"])
                == pending["nextCheckpointSha256"],
                "pending checkpoint journal commitment mismatch")
        if previous is not None:
            require(pending["previousCheckpointSha256"] == previous,
                    "pending checkpoint journal chain rollback")
    return records, previous, pending


def provision_checkpoint(root, checkpoint):
    """Create an observation-only genesis checkpoint and empty durable journal."""
    root = _safe_directory(root)
    require(_checkpoint(checkpoint) == 0, "genesis checkpoint required")
    lock = root / "checkpoint.lock"
    descriptor = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_EXCL
                         | getattr(os, "O_CLOEXEC", 0)
                         | getattr(os, "O_NOFOLLOW", 0), 0o600)
    os.close(descriptor)
    journal = root / "checkpoint.journal"
    descriptor = os.open(journal, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.fsync(descriptor)
    os.close(descriptor)
    _atomic_checkpoint(root, checkpoint)
    _fsync_directory(root)
    return {"checkpointSha256": _digest(checkpoint), "observationOnly": True}


def advance_checkpoint(root, observation, expected_checkpoint_sha256,
                       expected_observation_sha256):
    """CAS one exact successor into the durable observation-only journal."""
    root = _safe_directory(root)
    root_identity = root.lstat()
    _observation(observation)
    require(_digest(observation) == _pin(
        expected_observation_sha256, "expected observation"
    ), "observation does not match expected digest")
    lock_path = root / "checkpoint.lock"
    lock = os.open(lock_path, os.O_RDWR | getattr(os, "O_CLOEXEC", 0)
                   | getattr(os, "O_NOFOLLOW", 0))
    metadata = None
    try:
        metadata = os.fstat(lock)
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1
                and not metadata.st_mode & 0o022, "unsafe checkpoint lock")
        fcntl.flock(lock, fcntl.LOCK_EX)
        lock_current = lock_path.lstat()
        require((metadata.st_dev, metadata.st_ino)
                == (lock_current.st_dev, lock_current.st_ino),
                "checkpoint lock pathname was replaced")
        checkpoint = _parse_canonical(
            _read(root / "checkpoint.json", "checkpoint"), "checkpoint"
        )
        sequence = _checkpoint(checkpoint)
        current_digest = _digest(checkpoint)
        journal_raw = _read(root / "checkpoint.journal", "checkpoint journal",
                            missing=True, empty=True)
        pending = None
        if journal_raw:
            _, journal_tip, pending = _journal(journal_raw)
            if pending is not None:
                require(current_digest in {
                    pending["previousCheckpointSha256"],
                    pending["nextCheckpointSha256"],
                }, "checkpoint does not match pending journal transition")
                if current_digest == pending["previousCheckpointSha256"]:
                    _atomic_checkpoint(root, pending["nextCheckpoint"])
                _append_journal(root / "checkpoint.journal", {
                    "schema": "postern.bridge-qualification-journal-commit.v1",
                    "transitionId": pending["transitionId"],
                    "nextCheckpointSha256": pending["nextCheckpointSha256"],
                })
                checkpoint = pending["nextCheckpoint"]
                sequence = _checkpoint(checkpoint)
                current_digest = pending["nextCheckpointSha256"]
                if (pending["observationSha256"] == expected_observation_sha256
                        and pending["previousCheckpointSha256"]
                        == expected_checkpoint_sha256):
                    return {
                        "schema": "postern.bridge-qualification-checkpoint-write.v1",
                        "previousCheckpointSha256": expected_checkpoint_sha256,
                        "checkpointSha256": current_digest,
                        "observationSha256": expected_observation_sha256,
                        "qualificationSequence": checkpoint[
                            "lastQualificationSequence"
                        ],
                        "observationOnly": True,
                        "externalRecordsAuthenticated": False,
                        "activationAuthorized": False,
                        "recovered": True,
                    }
                journal_tip = current_digest
            require(journal_tip == current_digest,
                    "checkpoint and journal tip mismatch")
        else:
            require(sequence == 0, "non-genesis checkpoint lacks journal history")
        require(current_digest == _pin(
            expected_checkpoint_sha256, "expected checkpoint"
        ), "checkpoint CAS mismatch")
        observation_sequence = _uint64(
            observation["qualificationSequence"], "observation sequence"
        )
        require(sequence < 2**64 - 1 and observation_sequence == sequence + 1,
                "observation is not the exact checkpoint successor")
        require(observation["qualificationCheckpointSha256"] == current_digest,
                "observation binds another checkpoint")
        require(observation["reviewPolicySha256"] == checkpoint["reviewPolicySha256"]
                and observation["ceremonyPackageCanonicalSha256"]
                == checkpoint["ceremonyPackageCanonicalSha256"],
                "observation context does not match checkpoint")
        require(observation["previousQualificationSha256"]
                == checkpoint["lastQualificationSha256"],
                "observation predecessor does not match checkpoint")
        successor = {
            "schema": "postern.bridge-authority-qualification-checkpoint.v1",
            "reviewPolicySha256": checkpoint["reviewPolicySha256"],
            "ceremonyPackageCanonicalSha256": checkpoint[
                "ceremonyPackageCanonicalSha256"
            ],
            "lastQualificationSequence": observation["qualificationSequence"],
            "lastQualificationSha256": observation[
                "qualificationPackageCanonicalSha256"
            ],
        }
        successor_digest = _digest(successor)
        transition_id = "0x" + hashlib.sha256(
            (current_digest + successor_digest + expected_observation_sha256).encode("ascii")
        ).hexdigest()
        prepare = {
            "schema": "postern.bridge-qualification-journal-prepare.v1",
            "transitionId": transition_id,
            "previousCheckpointSha256": current_digest,
            "nextCheckpoint": successor,
            "nextCheckpointSha256": successor_digest,
            "observationSha256": expected_observation_sha256,
        }
        _append_journal(root / "checkpoint.journal", prepare)
        _atomic_checkpoint(root, successor)
        _append_journal(root / "checkpoint.journal", {
            "schema": "postern.bridge-qualification-journal-commit.v1",
            "transitionId": transition_id,
            "nextCheckpointSha256": successor_digest,
        })
        _fsync_directory(root)
        return {
            "schema": "postern.bridge-qualification-checkpoint-write.v1",
            "previousCheckpointSha256": current_digest,
            "checkpointSha256": successor_digest,
            "observationSha256": expected_observation_sha256,
            "qualificationSequence": observation["qualificationSequence"],
            "observationOnly": True,
            "externalRecordsAuthenticated": False,
            "activationAuthorized": False,
            "recovered": False,
        }
    finally:
        try:
            if metadata is not None:
                lock_current = lock_path.lstat()
                root_current = root.lstat()
                require((metadata.st_dev, metadata.st_ino)
                        == (lock_current.st_dev, lock_current.st_ino),
                        "checkpoint lock changed while held")
                require((root_identity.st_dev, root_identity.st_ino)
                        == (root_current.st_dev, root_current.st_ino),
                        "checkpoint directory changed while locked")
        finally:
            os.close(lock)
