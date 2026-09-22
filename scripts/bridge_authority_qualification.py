"""Authenticate an independent review quorum for one authority ceremony.

The trust policy is a separate operator input.  This module verifies public
Ed25519 signatures only; it cannot create keys, sign, deploy or authorize any
bridge operation.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile

from bridge_authority_ceremony import verify_bridge_authority_ceremony
from custody_deployment_manifest import canonical_sha256
from usdt_observer.common import require, word


DOMAIN = b"BLOCH-BRIDGE-AUTHORITY-QUALIFICATION-v1\0"
SSH_NAMESPACE = "bloch-bridge-authority-qualification-v1"
POLICY_FIELDS = {"schema", "threshold", "reviewers"}
REVIEWER_FIELDS = {"reviewerId", "organizationId", "algorithm", "publicKey"}
PACKAGE_FIELDS = {
    "schema", "ceremonyPackageCanonicalSha256", "manifestCanonicalSha256",
    "authorityPolicySha256", "custodyCeremonySha256", "nativeRolesCeremonySha256",
    "activationAuthorityCeremonySha256", "reviewPolicySha256", "attestations",
    "controls",
}
ATTESTATION_FIELDS = {
    "reviewerId", "organizationId", "ceremonyPackageCanonicalSha256",
    "manifestCanonicalSha256", "authorityPolicySha256", "custodyCeremonySha256",
    "nativeRolesCeremonySha256", "activationAuthorityCeremonySha256",
    "reviewPolicySha256", "reviewRecordSha256", "decision", "signature",
}
CONTROLS = {
    "keysLoaded": False,
    "signingAllowed": False,
    "deploymentAllowed": False,
    "broadcastAllowed": False,
    "activationAuthorized": False,
}
MAX_SIGNATURE_VERIFIER_BYTES = 32 * 1024 * 1024


def _fields(value, expected, label):
    require(type(value) is dict and set(value) == expected,
            f"{label}: exact fields required")


def _pin(value, size, label):
    raw = word(value, size)
    require(any(raw) and len(set(raw)) > 1,
            f"{label}: non-placeholder value required")
    return raw


def _review_policy(policy, ceremony):
    _fields(policy, POLICY_FIELDS, "external review policy")
    require(policy["schema"] == "postern.bridge-authority-review-policy.v1",
            "unsupported external review policy")
    require(type(policy["threshold"]) is int
            and not isinstance(policy["threshold"], bool)
            and policy["threshold"] == 3, "three-reviewer quorum required")
    reviewers = policy["reviewers"]
    require(type(reviewers) is list and len(reviewers) == 5,
            "exactly five independent reviewers required")

    authority_ids = {word(item["operatorId"], 32) for item in ceremony["appointments"]}
    authority_orgs = {
        word(item["organizationId"], 32) for item in ceremony["appointments"]
    }
    authority_keys = {
        word(item["publicKeySha256"], 32) for item in ceremony["appointments"]
    }
    identities = []
    for index, reviewer in enumerate(reviewers, 1):
        _fields(reviewer, REVIEWER_FIELDS, f"reviewer {index}")
        require(reviewer["algorithm"] == "ed25519", "Ed25519 reviewer required")
        reviewer_id = _pin(reviewer["reviewerId"], 32, f"reviewer {index} identity")
        organization = _pin(
            reviewer["organizationId"], 32, f"reviewer {index} organization"
        )
        public_key, raw_public_key = _ssh_public_key(
            reviewer["publicKey"], f"reviewer {index} public key"
        )
        require(reviewer_id not in authority_ids,
                "reviewer identity overlaps a bridge authority")
        require(organization not in authority_orgs,
                "reviewer organization overlaps a bridge authority")
        require(hashlib.sha256(raw_public_key).digest() not in authority_keys,
                "reviewer key overlaps a bridge authority")
        identities.append((reviewer_id, organization, public_key))
    for position, label in ((0, "identity"), (1, "organization"), (2, "public key")):
        require(len({item[position] for item in identities}) == 5,
                f"reviewer {label}s must be independent")
    return identities


def _ssh_public_key(value, label):
    require(type(value) is str and value.count(" ") == 1,
            f"{label}: canonical OpenSSH Ed25519 key required")
    algorithm, encoded = value.split(" ")
    require(algorithm == "ssh-ed25519" and encoded and encoded.isascii(),
            f"{label}: canonical OpenSSH Ed25519 key required")
    try:
        blob = base64.b64decode(encoded, validate=True)
    except (ValueError, TypeError) as error:
        raise ValueError(f"{label}: invalid base64") from error
    require(base64.b64encode(blob).decode("ascii") == encoded,
            f"{label}: non-canonical base64")
    expected = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20"
    require(len(blob) == len(expected) + 32 and blob.startswith(expected),
            f"{label}: malformed Ed25519 key")
    raw = blob[len(expected):]
    require(any(raw) and len(set(raw)) > 1, f"{label}: placeholder key refused")
    return value, raw


def _verify_ed25519(reviewer_id, public_key, message, signature, ssh_keygen):
    require(type(signature) is str and signature.isascii()
            and 100 <= len(signature) <= 4096
            and signature.startswith("-----BEGIN SSH SIGNATURE-----\n")
            and signature.endswith("-----END SSH SIGNATURE-----\n"),
            "canonical armored SSH signature required")
    with tempfile.TemporaryDirectory(prefix="bloch-authority-review-") as directory:
        root = Path(directory)
        identity = reviewer_id.hex()
        allowed = root / "allowed_signers"
        signature_path = root / "signature"
        allowed.write_text(f"{identity} {public_key}\n", encoding="ascii")
        allowed.chmod(0o600)
        signature_path.write_text(signature, encoding="ascii")
        try:
            completed = subprocess.run(
                [ssh_keygen, "-Y", "verify", "-f", str(allowed),
                 "-I", identity, "-n", SSH_NAMESPACE, "-s", str(signature_path)],
                input=message, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, timeout=10, check=False,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise ValueError("review signature verifier unavailable") from error
    require(completed.returncode == 0, "review signature authentication failed")


def _open_signature_verifier(path, trusted_sha256):
    """Authenticate one root-administered verifier and retain its open inode."""
    path = Path(path)
    require(path.is_absolute(), "absolute signature verifier required")
    expected = _pin(trusted_sha256, 32, "trusted signature verifier")
    canonical_expected = "0x" + expected.hex()
    require(type(trusted_sha256) is str and trusted_sha256 == canonical_expected,
            "trusted signature verifier digest must be canonical lowercase hex")
    flags = getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    source = os.open(path, os.O_RDONLY | flags)
    try:
        before = os.fstat(source)
        current = path.lstat()
        require(stat.S_ISREG(before.st_mode)
                and (before.st_dev, before.st_ino) == (current.st_dev, current.st_ino)
                and 0 < before.st_size <= MAX_SIGNATURE_VERIFIER_BYTES
                and before.st_uid == 0 and not before.st_mode & 0o022,
                "immutable regular signature verifier required")
        for parent in (path.parent, *path.parent.parents):
            parent_stat = parent.stat()
            require(parent_stat.st_uid == 0 and not parent_stat.st_mode & 0o022,
                    "root-administered signature verifier path required")
        digest = hashlib.sha256()
        while chunk := os.read(source, 1024 * 1024):
            digest.update(chunk)
        os.lseek(source, 0, os.SEEK_SET)
        after = os.fstat(source)
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
                "signature verifier changed while hashing")
        require(digest.digest() == expected, "signature verifier checksum mismatch")
        return source, path, before
    except BaseException:
        os.close(source)
        raise


def _close_signature_verifier(source, path, before):
    """Refuse replacement or mutation while the authenticated verifier ran."""
    try:
        after = os.fstat(source)
        current = path.lstat()
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                and (after.st_dev, after.st_ino)
                == (current.st_dev, current.st_ino),
                "signature verifier changed while in use")
    finally:
        os.close(source)


def verify_bridge_authority_qualification(
    ceremony, qualification, policy, trusted_review_policy_sha256, *,
    ssh_keygen, trusted_ssh_keygen_sha256,
):
    """Authenticate the exact ceremony with an externally selected quorum."""
    preflight = verify_bridge_authority_ceremony(ceremony)
    _fields(qualification, PACKAGE_FIELDS, "authority qualification")
    require(qualification["schema"] == "postern.bridge-authority-qualification-review.v1",
            "unsupported authority qualification")
    identities = _review_policy(policy, ceremony)
    policy_digest = canonical_sha256(policy).lower()
    trusted_policy_digest = "0x" + _pin(
        trusted_review_policy_sha256, 32, "trusted external review policy"
    ).hex()
    require(type(trusted_review_policy_sha256) is str
            and trusted_review_policy_sha256 == trusted_policy_digest,
            "trusted review policy digest must be canonical lowercase hex")
    require(policy_digest == trusted_policy_digest,
            "external review policy does not match trusted digest")
    expected = {
        "ceremonyPackageCanonicalSha256": preflight["packageCanonicalSha256"].lower(),
        "manifestCanonicalSha256": preflight["manifestCanonicalSha256"].lower(),
        "authorityPolicySha256": preflight["authorityPolicySha256"].lower(),
        "custodyCeremonySha256": preflight["custodyCeremonySha256"].lower(),
        "nativeRolesCeremonySha256": preflight["nativeRolesCeremonySha256"].lower(),
        "activationAuthorityCeremonySha256": preflight[
            "activationAuthorityCeremonySha256"
        ].lower(),
        "reviewPolicySha256": policy_digest,
    }
    for field, value in expected.items():
        require(type(qualification[field]) is str
                and qualification[field] == value,
                f"qualification {field} mismatch")
    require(qualification["controls"] == CONTROLS
            and all(type(value) is bool for value in qualification["controls"].values()),
            "qualification controls must remain disabled")

    attestations = qualification["attestations"]
    require(type(attestations) is list
            and policy["threshold"] <= len(attestations) <= len(identities),
            "external reviewer quorum not satisfied")
    trusted = {identity[0]: identity for identity in identities}
    verifier_source, staged_verifier, verifier_before = _open_signature_verifier(
        ssh_keygen, trusted_ssh_keygen_sha256
    )
    try:
        seen, review_records = set(), set()
        for attestation in attestations:
            _fields(attestation, ATTESTATION_FIELDS, "review attestation")
            reviewer_id = _pin(attestation["reviewerId"], 32, "attestation reviewer")
            require(reviewer_id in trusted and reviewer_id not in seen,
                    "reviewer is untrusted or duplicated")
            seen.add(reviewer_id)
            identity = trusted[reviewer_id]
            require(_pin(attestation["organizationId"], 32, "attestation organization")
                    == identity[1], "attestation organization mismatch")
            for field, value in expected.items():
                require(type(attestation[field]) is str
                        and attestation[field] == value,
                        f"attestation {field} mismatch")
            record = _pin(attestation["reviewRecordSha256"], 32, "review record")
            require(record not in review_records, "review records must be distinct")
            review_records.add(record)
            require(attestation["decision"] == "qualify-authorities-without-activation",
                    "non-authorizing qualification decision required")
            signature = attestation["signature"]
            signed = {
                key: value for key, value in attestation.items() if key != "signature"
            }
            message = DOMAIN + json.dumps(
                signed, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
            ).encode("ascii")
            _verify_ed25519(
                reviewer_id, identity[2], message, signature, str(staged_verifier)
            )
    finally:
        _close_signature_verifier(
            verifier_source, staged_verifier, verifier_before
        )

    return {
        "schema": "postern.bridge-authority-external-qualification.v1",
        **expected,
        "reviewerCount": len(attestations),
        "reviewThreshold": policy["threshold"],
        "externalRecordsAuthenticated": True,
        "custodyQualified": True,
        "authoritiesQualified": True,
        **CONTROLS,
    }
