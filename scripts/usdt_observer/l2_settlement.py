"""Authenticate an explicit L2/native settlement through a pinned verifier.

This adapter does not implement Bloch consensus or an L2 proof system.  The
operator supplies the exact, independently reviewed verifier executable and
its authenticated SHA-256 pin.  A successful verifier decision satisfies only
the settlement prerequisite; it never authorizes minting, release or bridge
activation on its own.
"""
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile

from .common import UINT64_MAX, require, word
from .verifier_process import run_verifier


L2_CHAIN_ID = 700771
BLOCH_MAINNET_GENESIS = (
    "0x9953da73a2794e190b1c551a787f39d6486a288f40b69ecc361281d5a893e415"
)
MAX_VERIFIER_BYTES = 64 * 1024 * 1024
MAX_PROOF_ARTIFACT_BYTES = 32 * 1024 * 1024
FIELDS = {
    "schema", "route_id", "l2_chain_id", "l2_block_number", "l2_block_hash",
    "l2_state_root", "l2_execution_domain", "proof_program_hash", "source_cursor",
    "native_network", "native_genesis_hash", "native_checkpoint_height",
    "native_checkpoint_root", "native_settlement_record", "native_transaction_id",
    "ancestry_proof_sha256", "execution_proof_sha256", "settlement_proof_sha256",
}


def _decimal(value, label, *, positive=False):
    require(
        type(value) is str
        and 1 <= len(value) <= 20
        and value.isascii()
        and value.isdecimal()
        and (value == "0" or value[0] != "0"),
        f"{label}: canonical uint64 required",
    )
    number = int(value)
    require(number <= UINT64_MAX and (not positive or number > 0),
            f"{label}: canonical uint64 required")
    return number


def _stage_verifier(path):
    path = Path(path)
    require(path.is_absolute(), "absolute settlement verifier required")
    common_flags = getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    source = os.open(path, os.O_RDONLY | common_flags)
    temporary = tempfile.TemporaryDirectory(prefix="bloch-settlement-verifier-")
    staged_path = Path(temporary.name) / "verifier"
    staged = None
    try:
        before = os.fstat(source)
        current = path.lstat()
        require(
            stat.S_ISREG(before.st_mode)
            and (before.st_dev, before.st_ino) == (current.st_dev, current.st_ino)
            and before.st_size > 0
            and before.st_size <= MAX_VERIFIER_BYTES
            and not before.st_mode & 0o022,
            "immutable regular settlement verifier required",
        )
        staged = os.open(
            staged_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | common_flags, 0o500
        )
        digest = hashlib.sha256()
        while chunk := os.read(source, 1024 * 1024):
            digest.update(chunk)
            pending = memoryview(chunk)
            while pending:
                pending = pending[os.write(staged, pending):]
        os.fsync(staged)
        after = os.fstat(source)
        require(
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
            "settlement verifier changed while hashing",
        )
        os.close(staged)
        staged = None
        os.close(source)
        return temporary, staged_path, digest.digest()
    except BaseException:
        if staged is not None:
            os.close(staged)
        os.close(source)
        temporary.cleanup()
        raise


def _stage_proof(source_path, destination, expected_digest):
    source_path = Path(source_path)
    require(source_path.is_absolute(), "absolute settlement proof path required")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    source = os.open(source_path, flags)
    output = None
    try:
        before = os.fstat(source)
        current = source_path.lstat()
        require(
            stat.S_ISREG(before.st_mode)
            and (before.st_dev, before.st_ino) == (current.st_dev, current.st_ino)
            and 0 < before.st_size <= MAX_PROOF_ARTIFACT_BYTES,
            "bounded regular settlement proof required",
        )
        output = os.open(
            destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | flags, 0o400
        )
        digest = hashlib.sha256()
        while chunk := os.read(source, 1024 * 1024):
            digest.update(chunk)
            pending = memoryview(chunk)
            while pending:
                pending = pending[os.write(output, pending):]
        os.fsync(output)
        after = os.fstat(source)
        require(
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
            "settlement proof changed while hashing",
        )
        require(digest.digest() == expected_digest,
                "settlement proof checksum mismatch")
    finally:
        if output is not None:
            os.close(output)
        os.close(source)


def verify_l2_settlement(
    executable, expected_verifier_sha256, evidence, route_id, *,
    ancestry_proof, execution_proof, settlement_proof,
):
    """Ask one checksum-pinned verifier to authenticate exact settlement evidence.

    The verifier protocol is deliberately one-shot and bounded.  Standard input
    is the domain tag followed by canonical JSON.  On acceptance stdout must be
    the lowercase SHA-256 of that complete request plus one newline.
    """
    require(type(evidence) is dict and set(evidence) == FIELDS,
            "exact L2/native settlement evidence required")
    require(evidence["schema"] == "postern.l2-native-settlement-evidence.v1",
            "unsupported settlement evidence schema")
    route = word(route_id, 32)
    require(any(route) and word(evidence["route_id"], 32) == route,
            "settlement route mismatch")
    require(type(evidence["l2_chain_id"]) is int
            and not isinstance(evidence["l2_chain_id"], bool)
            and evidence["l2_chain_id"] == L2_CHAIN_ID,
            "selected L2 chain ID required")
    l2_height = _decimal(evidence["l2_block_number"], "L2 block", positive=True)
    native_height = _decimal(
        evidence["native_checkpoint_height"], "native checkpoint", positive=True
    )
    require(evidence["native_network"] == "bloch-mainnet"
            and evidence["native_genesis_hash"].lower() == BLOCH_MAINNET_GENESIS,
            "canonical Bloch native network required")

    for field in (
        "l2_block_hash", "l2_state_root", "l2_execution_domain",
        "proof_program_hash", "source_cursor", "native_checkpoint_root",
        "native_settlement_record", "native_transaction_id",
        "ancestry_proof_sha256", "execution_proof_sha256",
        "settlement_proof_sha256",
    ):
        value = word(evidence[field], 32)
        require(any(value), f"zero {field}")

    expected_digest = word(expected_verifier_sha256, 32)
    encoded = json.dumps(
        evidence, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    request = b"BLOCH-L2-NATIVE-SETTLEMENT-VERIFY-v1\0" + encoded
    require(len(request) <= 65536, "settlement evidence exceeds verifier limit")
    temporary = None
    try:
        temporary, staged_path, actual_digest = _stage_verifier(executable)
        require(actual_digest == expected_digest,
                "settlement verifier checksum mismatch")
        proof_paths = []
        for label, source, digest_field in (
            ("ancestry", ancestry_proof, "ancestry_proof_sha256"),
            ("execution", execution_proof, "execution_proof_sha256"),
            ("settlement", settlement_proof, "settlement_proof_sha256"),
        ):
            destination = staged_path.parent / f"{label}.proof"
            _stage_proof(source, destination, word(evidence[digest_field], 32))
            proof_paths.append(destination)
        # Execute an exact private copy of the inode that was hashed, not the
        # operator path that can be replaced between verification and spawn.
        result = run_verifier(
            [
                str(staged_path),
                "--ancestry-proof", str(proof_paths[0]),
                "--execution-proof", str(proof_paths[1]),
                "--settlement-proof", str(proof_paths[2]),
            ],
            input=request,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError("settlement verifier unavailable") from exc
    finally:
        if temporary is not None:
            temporary.cleanup()
    commitment = hashlib.sha256(request).hexdigest()
    require(result.returncode == 0
            and result.stdout == (commitment + "\n").encode("ascii"),
            "L2/native settlement verifier refused")
    return {
        "schema": "postern.l2-native-settlement-verification.v1",
        "routeId": "0x" + route.hex(),
        "l2ChainId": L2_CHAIN_ID,
        "l2BlockNumber": str(l2_height),
        "l2BlockHash": evidence["l2_block_hash"].lower(),
        "nativeCheckpointHeight": str(native_height),
        "nativeCheckpointRoot": evidence["native_checkpoint_root"].lower(),
        "nativeSettlementRecord": evidence["native_settlement_record"].lower(),
        "verifierSha256": "0x" + expected_digest.hex(),
        "evidenceCommitmentSha256": "0x" + commitment,
        "settlementGateSatisfied": True,
        "finalityVerifiedForSettlement": True,
        "activationAuthorized": False,
        "mintAuthorized": False,
        "releaseAuthorized": False,
        "bridgeReady": False,
    }
