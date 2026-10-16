"""Compare bounded saved deployment captures without authenticating sources."""
import json
import re

from custody_deployment_evidence import validate_custody_deployment_evidence
from custody_deployment_manifest import canonical_sha256
from usdt_observer.common import MAX_JSON, parse_json, quantity, require, word


MAX_CAPTURES = 8
NON_AUTHORIZING = {
    "sourceRpcAuthenticated": False,
    "deploymentAuthenticated": False,
    "operatorIndependenceVerified": False,
    "reportsFresh": False,
    "finalityVerified": False,
    "finalityAncestryVerified": False,
    "activationAuthorized": False,
    "broadcastAllowed": False,
    "mintAuthorized": False,
    "releaseAuthorized": False,
    "bridgeReady": False,
}


def _bounded_copy(value):
    # Apply the file decoder's restrictions to library callers too. Retain the
    # complete evidence, including provider-specific fields, in its commitment.
    encoded = json.dumps(value, separators=(",", ":"), ensure_ascii=True,
                         allow_nan=False).encode("ascii")
    require(len(encoded) <= MAX_JSON, "deployment capture exceeds limit")
    return parse_json(encoded)


def compare_custody_deployment_evidence(manifest, captures):
    """Compare 2–8 labelled captures of one deployment, entirely offline.

    A label is supplied by the operator; distinct labels do not establish
    independence. Different finalized tips are retained, not interpreted as
    evidence that one tip descends from another.
    """
    require(type(captures) is list and 2 <= len(captures) <= MAX_CAPTURES,
            "two to eight deployment captures required")
    labels, capture_reports = set(), []
    snapshots, verifications, checkpoints = set(), set(), set()
    hashes_by_height, heights_by_hash, block_objects = {}, {}, {}
    first_verification = None
    for capture in captures:
        require(type(capture) is dict and set(capture) == {"source", "evidence"},
                "exact labelled deployment capture required")
        source = capture["source"]
        require(type(source) is str and re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,63}", source)
                and source not in labels, "distinct lowercase source labels required")
        labels.add(source)
        evidence = _bounded_copy(capture["evidence"])
        verification = validate_custody_deployment_evidence(manifest, evidence)
        if first_verification is None:
            first_verification = verification
        verifications.add(canonical_sha256(verification))
        source_evidence = evidence["source_evidence"]
        finalized = source_evidence["finalized_block"]
        final_height = quantity(finalized["number"])
        final_hash = "0x" + word(finalized["hash"], 32).hex()
        checkpoints.add((final_height, final_hash))

        # Detect both a fork at one reported height and one hash assigned two
        # heights, including a finalized tip contradicting the deployment block.
        for height, block_hash, block_object in (
            (int(verification["blockNumber"]), verification["blockHash"],
             source_evidence["canonical_block"]),
            (final_height, final_hash, finalized),
        ):
            require(hashes_by_height.get(height, block_hash) == block_hash
                    and heights_by_hash.get(block_hash, height) == height,
                    "conflicting reported block identities")
            hashes_by_height[height] = block_hash
            heights_by_hash[block_hash] = height
            object_digest = canonical_sha256(block_object)
            require(block_objects.get(block_hash, object_digest) == object_digest,
                    "conflicting captured objects for one block identity")
            block_objects[block_hash] = object_digest

        # Compare every captured field except the moving finalized tip. A
        # matching summary alone would miss divergent transaction lists or
        # receipt fields that the deployment verifier need not interpret.
        snapshot = {
            **evidence,
            "source_evidence": {
                key: value for key, value in source_evidence.items()
                if key != "finalized_block"
            },
        }
        snapshot_digest = canonical_sha256(snapshot)
        snapshots.add(snapshot_digest)
        capture_reports.append({
            "source": source,
            "evidenceCanonicalSha256": canonical_sha256(evidence),
            "finalizedBlockCanonicalSha256": canonical_sha256(finalized),
            "finalizedBlockNumber": str(final_height),
            "finalizedBlockHash": final_hash,
        })

    require(len(snapshots) == 1 and len(verifications) == 1,
            "deployment capture disagreement")
    return {
        "schema": "postern.custody-deployment-comparison.v1",
        "manifestCanonicalSha256": first_verification["manifestCanonicalSha256"],
        "routeId": first_verification["routeId"],
        "transactionHash": first_verification["transactionHash"],
        "blockHash": first_verification["blockHash"],
        "blockNumber": first_verification["blockNumber"],
        "deploymentSnapshotCanonicalSha256": next(iter(snapshots)),
        "deploymentVerificationCanonicalSha256": next(iter(verifications)),
        "captureCount": len(capture_reports),
        "distinctEvidenceCount": len({row["evidenceCanonicalSha256"] for row in capture_reports}),
        "deploymentSnapshotAgreement": True,
        "finalizedCheckpointIdentitiesMatch": len(checkpoints) == 1,
        "captures": sorted(capture_reports, key=lambda row: row["source"]),
        **NON_AUTHORIZING,
    }
