#!/usr/bin/env python3
"""Prepare public, offline bridge authority signing requests.

This coordinator never generates, reads or stores a private key.  Its output
is untrusted ceremony material until the independently built, anchor-pinned
Rust verifier accepts the completed intake.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile


ROOT_POP_DOMAIN = b"BLOCH-BRIDGE-TRUST-ROOT-POP-v1\0"
AUTHORITY_POP_DOMAIN = b"BLOCH-BRIDGE-OPERATIONAL-AUTHORITY-POP-v1\0"
APPROVAL_DOMAIN = b"BLOCH-BRIDGE-OPERATIONAL-AUTHORITY-APPROVAL-v1\0"
ROLES = [
    "custodian-1", "custodian-2", "custodian-3", "custodian-4",
    "custodian-5", "native-issuer", "fee-sponsor", "activation-authority",
]
REQUEST_FIELDS = [
    "schema", "kind", "authorityId", "role", "publicKey", "messageFile",
    "messageSha256", "messageBytes", "signatureAlgorithm",
    "privateKeyIncluded", "authorizing",
]
RESPONSE_FIELDS = [
    "schema", "kind", "authorityId", "role", "publicKey", "messageSha256",
    "messageBytes", "signatureAlgorithm", "signature",
]
ROOT_FIELDS = [
    "authorityId", "organizationId", "publicKey",
    "recoveryDeclarationSha256", "conflictDeclarationSha256",
    "proofOfPossessionSignature",
]
AUTHORITY_FIELDS = [
    "role", "authorityId", "organizationId", "publicKey",
    "appointmentRecordSha256", "recoveryDeclarationSha256",
    "conflictDeclarationSha256", "proofOfPossessionSignature",
]


def refuse(message):
    raise ValueError(message)


def exact(value, fields, label):
    if type(value) is not dict or list(value) != fields:
        refuse(f"{label}: exact ordered fields required")


def word(value, size, label, *, zero=False):
    if type(value) is not str or not value.startswith("0x"):
        refuse(f"{label}: canonical 0x hex required")
    raw = value[2:]
    if len(raw) != size * 2 or any(c not in "0123456789abcdef" for c in raw):
        refuse(f"{label}: canonical lowercase {size}-byte hex required")
    decoded = bytes.fromhex(raw)
    if not zero and (not any(decoded) or len(set(decoded)) == 1):
        refuse(f"{label}: placeholder refused")
    return decoded


def compact(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()


def sha256(value):
    return "0x" + hashlib.sha256(value).hexdigest()


def read_public(path, limit, label):
    path_metadata = os.lstat(path)
    if stat.S_ISLNK(path_metadata.st_mode):
        refuse(f"{label}: symlink refused")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        metadata = os.fstat(descriptor)
        if (path_metadata.st_dev, path_metadata.st_ino) != (metadata.st_dev, metadata.st_ino):
            refuse(f"{label}: file changed while opening")
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size < 1 or metadata.st_size > limit:
            refuse(f"{label}: invalid file type or size")
        chunks = []
        remaining = limit + 1
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        value = b"".join(chunks)
        if len(value) != metadata.st_size:
            refuse(f"{label}: unstable or oversized input")
        return value
    finally:
        os.close(descriptor)


def load(path):
    value = json.loads(read_public(path, 1024 * 1024, "intake").decode("utf-8"))
    exact(value, ["schema", "trustAnchorPackage", "operationalAuthorityPackage"],
          "intake")
    if value["schema"] != "postern.bridge-authority-trust-intake.v1":
        refuse("unsupported intake schema")
    return value


def signature_field(value, size, label, mode):
    if value is None:
        if mode == "all":
            refuse(f"{label}: signature required")
        return
    if mode == "none":
        refuse(f"{label}: signature must be null before signing")
    word(value, size, label)


def anchor(intake, *, signatures):
    value = intake["trustAnchorPackage"]
    exact(value, ["schema", "domain", "packageSequence",
                  "previousPackageSha256", "roots"], "trust anchor")
    if value["schema"] != "postern.bridge-authority-trust-anchor.v1":
        refuse("unsupported trust anchor schema")
    if value["domain"] != "bloch-bridge-authority-trust-v1":
        refuse("unsupported trust anchor domain")
    sequence = value["packageSequence"]
    if (type(sequence) is not str or not sequence.isascii() or not sequence.isdigit()
            or (len(sequence) > 1 and sequence.startswith("0")) or len(sequence) > 20):
        refuse("canonical package sequence required")
    previous = word(value["previousPackageSha256"], 32, "previous package", zero=True)
    if (sequence == "1") != (previous == bytes(32)):
        refuse("package sequence/predecessor mismatch")
    if type(value["roots"]) is not list or len(value["roots"]) != 3:
        refuse("exactly three trust roots required")
    identities, organizations, keys, records = set(), set(), set(), set()
    for index, item in enumerate(value["roots"], 1):
        exact(item, ROOT_FIELDS, f"root {index}")
        identity = word(item["authorityId"], 32, f"root {index} authority")
        organization = word(item["organizationId"], 32, f"root {index} organization")
        key = word(item["publicKey"], 32, f"root {index} public key")
        recovery = word(item["recoveryDeclarationSha256"], 32,
                        f"root {index} recovery declaration")
        conflict = word(item["conflictDeclarationSha256"], 32,
                        f"root {index} conflict declaration")
        if identity in identities or organization in organizations or key in keys:
            refuse("trust root identities, organizations and keys must be distinct")
        if recovery in records or conflict in records or recovery == conflict:
            refuse("trust root declarations must be globally distinct")
        identities.add(identity); organizations.add(organization); keys.add(key)
        records.update((recovery, conflict))
        signature_field(item["proofOfPossessionSignature"], 64,
                        f"root {index} proof of possession", signatures)
    return value


def operational(intake, *, signatures, approvals):
    value = intake["operationalAuthorityPackage"]
    exact(value, ["schema", "manifestCanonicalSha256",
                  "ceremonyPackageCanonicalSha256", "custodyThreshold",
                  "authorities", "rootApprovals"], "operational package")
    if value["schema"] != "postern.bridge-operational-authority-package.v1":
        refuse("unsupported operational package schema")
    word(value["manifestCanonicalSha256"], 32, "manifest commitment")
    word(value["ceremonyPackageCanonicalSha256"], 32, "ceremony commitment")
    if value["custodyThreshold"] != 3:
        refuse("custody threshold must be three")
    if type(value["authorities"]) is not list or len(value["authorities"]) != 8:
        refuse("exactly eight operational authorities required")
    identities, organizations, keys, records = set(), set(), set(), set()
    for index, (item, role) in enumerate(zip(value["authorities"], ROLES), 1):
        exact(item, AUTHORITY_FIELDS, f"authority {index}")
        if item["role"] != role:
            refuse("operational authorities must use the exact role order")
        identity = word(item["authorityId"], 32, f"{role} authority")
        organization = word(item["organizationId"], 32, f"{role} organization")
        key = word(item["publicKey"], 32, f"{role} public key")
        evidence = [
            word(item["appointmentRecordSha256"], 32, f"{role} appointment"),
            word(item["recoveryDeclarationSha256"], 32, f"{role} recovery"),
            word(item["conflictDeclarationSha256"], 32, f"{role} conflict"),
        ]
        if identity in identities or organization in organizations or key in keys:
            refuse("operational identities, organizations and keys must be distinct")
        if any(record in records for record in evidence) or len(set(evidence)) != 3:
            refuse("operational evidence records must be globally distinct")
        identities.add(identity); organizations.add(organization); keys.add(key)
        records.update(evidence)
        signature_field(item["proofOfPossessionSignature"], 64,
                        f"{role} proof of possession", signatures)
    root_approvals = value["rootApprovals"]
    if type(root_approvals) is not list:
        refuse("root approvals must be a list")
    if approvals == "all":
        if len(root_approvals) not in (2, 3):
            refuse("two or three root approvals required")
    elif approvals == "none" and root_approvals:
        refuse("root approvals must be empty before approval signing")
    elif approvals == "partial" and len(root_approvals) > 3:
        refuse("at most three root approvals allowed")
    for index, item in enumerate(root_approvals, 1):
        exact(item, ["authorityId", "signature"], f"root approval {index}")
        word(item["authorityId"], 32, f"approval {index} authority")
        word(item["signature"], 64, f"approval {index} signature")
    return value


def root_pop(item, package):
    return {
        "domain": package["domain"],
        "packageSequence": package["packageSequence"],
        "previousPackageSha256": package["previousPackageSha256"],
        "authorityId": item["authorityId"],
        "organizationId": item["organizationId"],
        "publicKey": item["publicKey"],
        "recoveryDeclarationSha256": item["recoveryDeclarationSha256"],
        "conflictDeclarationSha256": item["conflictDeclarationSha256"],
    }


def authority_pop(item, package):
    return {
        "role": item["role"],
        "authorityId": item["authorityId"],
        "organizationId": item["organizationId"],
        "publicKey": item["publicKey"],
        "appointmentRecordSha256": item["appointmentRecordSha256"],
        "recoveryDeclarationSha256": item["recoveryDeclarationSha256"],
        "conflictDeclarationSha256": item["conflictDeclarationSha256"],
        "manifestCanonicalSha256": package["manifestCanonicalSha256"],
        "ceremonyPackageCanonicalSha256": package["ceremonyPackageCanonicalSha256"],
    }


def require_independence(anchor_package, operational_package):
    roots = anchor_package["roots"]
    authorities = operational_package["authorities"]
    for field in ("authorityId", "organizationId", "publicKey"):
        if {item[field] for item in roots}.intersection(
                item[field] for item in authorities):
            refuse(f"operational authority overlaps a trust root: {field}")
    root_records = {
        item[field]
        for item in roots
        for field in ("recoveryDeclarationSha256", "conflictDeclarationSha256")
    }
    operational_records = {
        item[field]
        for item in authorities
        for field in ("appointmentRecordSha256", "recoveryDeclarationSha256",
                      "conflictDeclarationSha256")
    }
    if root_records.intersection(operational_records):
        refuse("operational and trust-root evidence records must be distinct")


def require_approval_roots(anchor_package, operational_package):
    allowed = {item["authorityId"] for item in anchor_package["roots"]}
    supplied = [item["authorityId"] for item in operational_package["rootApprovals"]]
    if len(set(supplied)) != len(supplied) or not set(supplied).issubset(allowed):
        refuse("approvals must come from distinct selected trust roots")


def write_requests(directory, kind, requests):
    output = Path(directory)
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    output.chmod(0o700)
    inventory = []
    for name, identity, role, public_key, message in requests:
        message_path = output / f"{name}.message.bin"
        request_path = output / f"{name}.request.json"
        write_private(message_path, message)
        metadata = {
            "schema": "postern.bridge-offline-signing-request.v1",
            "kind": kind,
            "authorityId": identity,
            "role": role,
            "publicKey": public_key,
            "messageFile": message_path.name,
            "messageSha256": sha256(message),
            "messageBytes": len(message),
            "signatureAlgorithm": "ed25519",
            "privateKeyIncluded": False,
            "authorizing": False,
        }
        write_private(request_path, (json.dumps(metadata, indent=2) + "\n").encode())
        inventory.append(metadata)
        response = {
            "schema": "postern.bridge-offline-signature-response.v1",
            "kind": kind,
            "authorityId": identity,
            "role": role,
            "publicKey": public_key,
            "messageSha256": metadata["messageSha256"],
            "messageBytes": metadata["messageBytes"],
            "signatureAlgorithm": "ed25519",
            "signature": None,
        }
        write_private(output / f"{name}.response.pending.json",
                      (json.dumps(response, indent=2) + "\n").encode())
    write_private(output / "inventory.json", (json.dumps({
        "schema": "postern.bridge-offline-signing-inventory.v1",
        "kind": kind,
        "requests": inventory,
        "privateKeysIncluded": False,
        "activationAuthorized": False,
    }, indent=2) + "\n").encode())
    directory_fd = os.open(output, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def write_private(path, value, mode=0o600):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(path, mode)
    finally:
        os.close(descriptor)


def template():
    roots = [{field: None for field in ROOT_FIELDS} for _ in range(3)]
    authorities = []
    for role in ROLES:
        item = {field: None for field in AUTHORITY_FIELDS}
        item["role"] = role
        authorities.append(item)
    return {
        "schema": "postern.bridge-authority-trust-intake.v1",
        "trustAnchorPackage": {
            "schema": "postern.bridge-authority-trust-anchor.v1",
            "domain": "bloch-bridge-authority-trust-v1",
            "packageSequence": None,
            "previousPackageSha256": None,
            "roots": roots,
        },
        "operationalAuthorityPackage": {
            "schema": "postern.bridge-operational-authority-package.v1",
            "manifestCanonicalSha256": None,
            "ceremonyPackageCanonicalSha256": None,
            "custodyThreshold": 3,
            "authorities": authorities,
            "rootApprovals": [],
        },
    }


def command_root_requests(args):
    intake = load(args.intake)
    package = anchor(intake, signatures="none")
    requests = []
    for index, item in enumerate(package["roots"], 1):
        requests.append((f"trust-root-{index}-pop", item["authorityId"],
                         f"trust-root-{index}", item["publicKey"],
                         ROOT_POP_DOMAIN + compact(root_pop(item, package))))
    write_requests(args.output, "trust-root-proof-of-possession", requests)


def command_authority_requests(args):
    intake = load(args.intake)
    anchor_package = anchor(intake, signatures="all")
    package = operational(intake, signatures="none", approvals="none")
    require_independence(anchor_package, package)
    requests = []
    for item in package["authorities"]:
        requests.append((f"{item['role']}-pop", item["authorityId"],
                         item["role"], item["publicKey"],
                         AUTHORITY_POP_DOMAIN + compact(authority_pop(item, package))))
    write_requests(args.output, "operational-proof-of-possession", requests)


def command_approval_requests(args):
    intake = load(args.intake)
    anchor_package = anchor(intake, signatures="all")
    package = operational(intake, signatures="all", approvals="none")
    require_independence(anchor_package, package)
    anchor_digest = hashlib.sha256(compact(anchor_package)).digest()
    unsigned = {
        "schema": package["schema"],
        "manifestCanonicalSha256": package["manifestCanonicalSha256"],
        "ceremonyPackageCanonicalSha256": package["ceremonyPackageCanonicalSha256"],
        "custodyThreshold": package["custodyThreshold"],
        "authorities": package["authorities"],
    }
    message = APPROVAL_DOMAIN + anchor_digest + compact(unsigned)
    requests = [
        (f"trust-root-{index}-approval", item["authorityId"],
         f"trust-root-{index}", item["publicKey"], message)
        for index, item in enumerate(anchor_package["roots"], 1)
    ]
    write_requests(args.output, "operational-package-approval", requests)
    print(json.dumps({
        "trustAnchorPackageCanonicalSha256": "0x" + anchor_digest.hex(),
        "approvalMessageSha256": sha256(message),
        "approvalMessageBytes": len(message),
    }, indent=2))


def approval_message(anchor_package, package):
    anchor_digest = hashlib.sha256(compact(anchor_package)).digest()
    unsigned = {
        "schema": package["schema"],
        "manifestCanonicalSha256": package["manifestCanonicalSha256"],
        "ceremonyPackageCanonicalSha256": package["ceremonyPackageCanonicalSha256"],
        "custodyThreshold": package["custodyThreshold"],
        "authorities": package["authorities"],
    }
    return APPROVAL_DOMAIN + anchor_digest + compact(unsigned)


def run_private_executable(executable, arguments, input_value, prefix):
    with tempfile.TemporaryDirectory(prefix=prefix) as directory:
        os.chmod(directory, 0o700)
        binary = Path(directory) / "reviewed-verifier"
        write_private(binary, executable, mode=0o700)
        return subprocess.run([str(binary), *arguments], input=input_value,
                              capture_output=True, timeout=30, check=False)


def pinned_public_verifier(args):
    expected = word(args.public_signature_verifier_sha256, 32,
                    "public signature verifier SHA-256")
    executable = reviewed_executable_bytes(args.public_signature_verifier)
    if hashlib.sha256(executable).digest() != expected:
        refuse("public signature verifier does not match its reviewed SHA-256")
    return executable


def verify_ed25519(public_key, message, signature, executable):
    result = run_private_executable(
        executable,
        ["0x" + public_key.hex(), "0x" + signature.hex()],
        message,
        "bridge-public-signature-",
    )
    if result.returncode != 0 or result.stdout or result.stderr:
        refuse("Ed25519 signature verification failed")


def validate_detached(value, message, label, verifier):
    exact(value, RESPONSE_FIELDS, label)
    if value["schema"] != "postern.bridge-offline-signature-response.v1":
        refuse(f"{label}: unsupported response schema")
    if value["signatureAlgorithm"] != "ed25519":
        refuse(f"{label}: Ed25519 required")
    identity = word(value["authorityId"], 32, f"{label} authority")
    public_key = word(value["publicKey"], 32, f"{label} public key")
    signature = word(value["signature"], 64, f"{label} signature")
    if (type(value["messageBytes"]) is not int
            or isinstance(value["messageBytes"], bool)
            or value["messageBytes"] != len(message)):
        refuse(f"{label}: message length mismatch")
    if value["messageSha256"] != sha256(message):
        refuse(f"{label}: message SHA-256 mismatch")
    verify_ed25519(public_key, message, signature, verifier)
    return identity, public_key, signature


def write_canonical_new(path, value):
    output = Path(path)
    write_private(output, compact(value) + b"\n")
    directory_fd = os.open(output.parent, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def command_import_signature(args):
    verifier = pinned_public_verifier(args)
    request = json.loads(read_public(
        args.request, 64 * 1024, "signing request").decode("utf-8"))
    exact(request, REQUEST_FIELDS, "signing request")
    if request["schema"] != "postern.bridge-offline-signing-request.v1":
        refuse("unsupported signing request schema")
    if request["signatureAlgorithm"] != "ed25519":
        refuse("Ed25519 request required")
    if request["privateKeyIncluded"] is not False or request["authorizing"] is not False:
        refuse("request must remain public and non-authorizing")
    message = read_public(args.message, 128 * 1024, "signing message")
    if Path(args.message).name != request["messageFile"]:
        refuse("message filename does not match request")
    signature = read_public(args.signature, 64, "detached signature")
    response = {
        "schema": "postern.bridge-offline-signature-response.v1",
        "kind": request["kind"],
        "authorityId": request["authorityId"],
        "role": request["role"],
        "publicKey": request["publicKey"],
        "messageSha256": request["messageSha256"],
        "messageBytes": request["messageBytes"],
        "signatureAlgorithm": request["signatureAlgorithm"],
        "signature": "0x" + signature.hex(),
    }
    validate_detached(response, message, "detached signature", verifier)
    write_canonical_new(args.output, response)


def load_response(path):
    return json.loads(read_public(
        path, 64 * 1024, "signature response").decode("utf-8"))


def command_apply_signature(args):
    verifier = pinned_public_verifier(args)
    intake = load(args.intake)
    response = load_response(args.response)
    if type(response) is not dict or response.get("kind") not in {
        "trust-root-proof-of-possession", "operational-proof-of-possession",
        "operational-package-approval",
    }:
        refuse("unsupported detached signature kind")
    result = copy.deepcopy(intake)

    if response["kind"] == "trust-root-proof-of-possession":
        anchor_package = anchor(intake, signatures="partial")
        operational_package = operational(
            intake, signatures="partial", approvals="partial")
        require_independence(anchor_package, operational_package)
        matches = [
            (index, item) for index, item in enumerate(anchor_package["roots"])
            if item["authorityId"] == response.get("authorityId")
        ]
        if len(matches) != 1:
            refuse("root response authority does not identify one exact slot")
        index, item = matches[0]
        message = ROOT_POP_DOMAIN + compact(root_pop(item, anchor_package))
        expected_role = f"trust-root-{index + 1}"
        if (response.get("role") != expected_role
                or response.get("publicKey") != item["publicKey"]):
            refuse("root response role or public key substitution")
        if item["proofOfPossessionSignature"] is not None:
            refuse("root proof slot is already populated")
        validate_detached(response, message, "root proof response", verifier)
        result["trustAnchorPackage"]["roots"][index][
            "proofOfPossessionSignature"] = response["signature"]

    elif response["kind"] == "operational-proof-of-possession":
        anchor_package = anchor(intake, signatures="all")
        package = operational(intake, signatures="partial", approvals="none")
        require_independence(anchor_package, package)
        matches = [
            (index, item) for index, item in enumerate(package["authorities"])
            if item["authorityId"] == response.get("authorityId")
        ]
        if len(matches) != 1:
            refuse("authority response does not identify one exact slot")
        index, item = matches[0]
        message = AUTHORITY_POP_DOMAIN + compact(authority_pop(item, package))
        if (response.get("role") != item["role"]
                or response.get("publicKey") != item["publicKey"]):
            refuse("operational response role or public key substitution")
        if item["proofOfPossessionSignature"] is not None:
            refuse("operational proof slot is already populated")
        validate_detached(response, message, "operational proof response", verifier)
        result["operationalAuthorityPackage"]["authorities"][index][
            "proofOfPossessionSignature"] = response["signature"]

    else:
        anchor_package = anchor(intake, signatures="all")
        package = operational(intake, signatures="all", approvals="partial")
        require_independence(anchor_package, package)
        require_approval_roots(anchor_package, package)
        matches = [
            (index, item) for index, item in enumerate(anchor_package["roots"])
            if item["authorityId"] == response.get("authorityId")
        ]
        if len(matches) != 1:
            refuse("approval response does not identify one selected root")
        index, item = matches[0]
        if (response.get("role") != f"trust-root-{index + 1}"
                or response.get("publicKey") != item["publicKey"]):
            refuse("approval response role or public key substitution")
        if any(approval["authorityId"] == item["authorityId"]
               for approval in package["rootApprovals"]):
            refuse("duplicate root approval refused")
        validate_detached(response, approval_message(anchor_package, package),
                          "root approval response", verifier)
        approvals = result["operationalAuthorityPackage"]["rootApprovals"]
        approvals.append({
            "authorityId": item["authorityId"],
            "signature": response["signature"],
        })
        order = {root["authorityId"]: position
                 for position, root in enumerate(anchor_package["roots"])}
        approvals.sort(key=lambda approval: order[approval["authorityId"]])

    write_canonical_new(args.output, result)


def reviewed_executable_bytes(path):
    path_metadata = os.lstat(path)
    if stat.S_ISLNK(path_metadata.st_mode):
        refuse("verifier symlink refused")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if (path_metadata.st_dev, path_metadata.st_ino) != (metadata.st_dev, metadata.st_ino):
            refuse("verifier changed while it was opened")
        if not stat.S_ISREG(metadata.st_mode):
            refuse("verifier must be a regular file")
        if metadata.st_nlink != 1:
            refuse("verifier must have exactly one hard link")
        if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            refuse("verifier must not be group- or world-writable")
        chunks = []
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            chunks.append(block)
            if sum(map(len, chunks)) > 128 * 1024 * 1024:
                refuse("verifier exceeds the ceremony size limit")
        value = b"".join(chunks)
        if not value:
            refuse("empty verifier refused")
        return value
    finally:
        os.close(descriptor)


def command_verify(args):
    expected = word(args.verifier_sha256, 32, "reviewed verifier SHA-256")
    executable = reviewed_executable_bytes(args.verifier)
    if hashlib.sha256(executable).digest() != expected:
        refuse("verifier executable does not match the independently reviewed SHA-256")
    intake = load(args.intake)
    anchor_package = anchor(intake, signatures="all")
    operational_package = operational(intake, signatures="all", approvals="all")
    require_independence(anchor_package, operational_package)
    require_approval_roots(anchor_package, operational_package)
    encoded = compact(intake)
    with tempfile.TemporaryDirectory(prefix="bridge-authority-verifier-") as directory:
        os.chmod(directory, 0o700)
        verifier = Path(directory) / "reviewed-verifier"
        write_private(verifier, executable, mode=0o700)
        result = subprocess.run([str(verifier)], input=encoded,
                                capture_output=True, timeout=30, check=False)
    if result.returncode != 0:
        refuse("anchor-pinned verifier refused the completed intake")
    commitment = result.stdout.decode("ascii").strip()
    word(commitment, 32, "verified intake commitment")
    print(json.dumps({
        "schema": "postern.bridge-authority-trust-verification-observation.v1",
        "intakeCanonicalSha256": commitment,
        "verifierSha256": args.verifier_sha256,
        "anchorPinnedVerifierAccepted": True,
        "proofsAndApprovalsCryptographicallyConsistent": True,
        "verifierPinExternallyAuthenticated": False,
        "externalIdentitiesAuthenticated": False,
        "authoritiesQualified": False,
        "deploymentAllowed": False,
        "broadcastAllowed": False,
        "activationAuthorized": False,
    }, indent=2))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("template", help="print an identity-free intake template")
    for name, function in (("root-requests", command_root_requests),
                           ("authority-requests", command_authority_requests),
                           ("approval-requests", command_approval_requests)):
        command = commands.add_parser(name)
        command.add_argument("intake")
        command.add_argument("output")
        command.set_defaults(function=function)
    imported = commands.add_parser(
        "import-signature", help="validate a detached signature and create a response")
    imported.add_argument("request")
    imported.add_argument("message")
    imported.add_argument("signature")
    imported.add_argument("output")
    imported.add_argument("--public-signature-verifier", required=True)
    imported.add_argument("--public-signature-verifier-sha256", required=True)
    imported.set_defaults(function=command_import_signature)
    apply = commands.add_parser(
        "apply-signature", help="verify and apply one response to a new intake")
    apply.add_argument("intake")
    apply.add_argument("response")
    apply.add_argument("output")
    apply.add_argument("--public-signature-verifier", required=True)
    apply.add_argument("--public-signature-verifier-sha256", required=True)
    apply.set_defaults(function=command_apply_signature)
    verify = commands.add_parser("verify")
    verify.add_argument("intake")
    verify.add_argument("--verifier", required=True)
    verify.add_argument("--verifier-sha256", required=True)
    verify.set_defaults(function=command_verify)
    args = parser.parse_args(argv)
    try:
        if args.command == "template":
            print(json.dumps(template(), indent=2))
        else:
            args.function(args)
    except (ValueError, OSError, json.JSONDecodeError, subprocess.SubprocessError):
        print('{"activationAuthorized":false,"error":"offline-ceremony-refused"}',
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
