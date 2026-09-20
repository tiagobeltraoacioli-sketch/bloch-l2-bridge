"""Strict offline qualification for an inert Ethereum USDC/Bloch bUSDC plan.

This module validates public configuration only. It has no network, key,
signing, deployment, funding, broadcast, or activation capability.
"""
import hashlib
import json

from usdt_observer.common import require, word


ETHEREUM_GENESIS = (
    "0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
)
ETHEREUM_USDC = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
BLOCH_MAINNET_DOMAIN = (
    "0xf47d3e498ff978e34471dafff5f94fe139fc3ff489b1a00f469c030258311966"
)
BLOCH_MAINNET_GENESIS = (
    "0x9953da73a2794e190b1c551a787f39d6486a288f40b69ecc361281d5a893e415"
)
UINT64_MAX = (1 << 64) - 1


def _fields(value, names, label):
    require(type(value) is dict and set(value) == set(names.split()),
            f"{label}: exact fields required")


def _pin(value, size, label):
    raw = word(value, size)
    require(len(set(raw)) > 1, f"{label}: repeated-byte placeholder")
    return raw


def _positive_u64(value, label):
    require(type(value) is int and 0 < value <= UINT64_MAX,
            f"{label}: positive uint64 required")
    return value


def _authority(value, label, include_source_signer):
    names = "operator_id organization_id bloch_public_key_sha256 custody_attestation_sha256"
    if include_source_signer:
        names += " ethereum_signer"
    _fields(value, names, label)
    result = {
        "operator": _pin(value["operator_id"], 32, f"{label} operator"),
        "organization": _pin(value["organization_id"], 32, f"{label} organization"),
        "key": _pin(value["bloch_public_key_sha256"], 32, f"{label} Bloch key"),
        "attestation": _pin(
            value["custody_attestation_sha256"], 32, f"{label} custody attestation"
        ),
    }
    if include_source_signer:
        result["source_signer"] = _pin(
            value["ethereum_signer"], 20, f"{label} Ethereum signer"
        )
    return result


def canonical_sha256(value):
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    return "0x" + hashlib.sha256(encoded).hexdigest()


def validate_custody_deployment_manifest(manifest):
    """Validate one public, paused deployment candidate without authorizing it."""
    _fields(manifest, "schema source native cap custody roles controls approvals", "manifest")
    require(manifest["schema"] == "postern.custody-deployment-plan.v1",
            "unsupported custody deployment schema")

    source = manifest["source"]
    _fields(source, "network chain_id genesis_hash token_symbol token_address token_decimals "
                    "token_proxy_runtime_sha256 token_implementation_address "
                    "token_implementation_runtime_sha256 vault_address vault_runtime_sha256 "
                    "vault_build_sha256", "Ethereum source")
    require(source["network"] == "ethereum-mainnet" and source["chain_id"] == "eip155:1",
            "Ethereum mainnet source required")
    require(source["genesis_hash"].lower() == ETHEREUM_GENESIS,
            "canonical Ethereum genesis required")
    require(source["token_symbol"] == "USDC" and source["token_decimals"] == 6,
            "six-decimal USDC source required")
    token = _pin(source["token_address"], 20, "USDC token")
    require("0x" + token.hex() == ETHEREUM_USDC, "canonical Ethereum USDC required")
    _pin(source["token_proxy_runtime_sha256"], 32, "USDC proxy runtime")
    implementation = _pin(
        source["token_implementation_address"], 20, "USDC implementation"
    )
    _pin(source["token_implementation_runtime_sha256"], 32,
         "USDC implementation runtime")
    vault = _pin(source["vault_address"], 20, "source vault")
    _pin(source["vault_runtime_sha256"], 32, "source vault runtime")
    _pin(source["vault_build_sha256"], 32, "source vault reviewed build")
    require(len({token, implementation, vault}) == 3,
            "token, implementation and vault identities must differ")

    native = manifest["native"]
    _fields(native, "network format genesis_hash domain asset_symbol asset_id "
                    "gateway_runtime_sha256 gateway_manifest_sha256", "Bloch destination")
    require(native["network"] == "bloch-mainnet" and native["format"] == "BPOSMAN1",
            "canonical Bloch mainnet destination required")
    require(native["genesis_hash"].lower() == BLOCH_MAINNET_GENESIS and
            native["domain"].lower() == BLOCH_MAINNET_DOMAIN,
            "canonical Bloch mainnet anchors required")
    require(native["asset_symbol"] == "bUSDC", "bUSDC native asset required")
    asset = _pin(native["asset_id"], 32, "bUSDC asset identity")
    domain = _pin(native["domain"], 32, "Bloch domain")
    require(asset != domain, "native asset and domain must differ")
    _pin(native["gateway_runtime_sha256"], 32, "Bloch gateway runtime")
    _pin(native["gateway_manifest_sha256"], 32, "Bloch gateway manifest")

    cap = manifest["cap"]
    _fields(cap, "decimals base_units", "supply cap")
    require(cap["decimals"] == 6, "supply cap must use USDC base units")
    _positive_u64(cap["base_units"], "supply cap")

    custody = manifest["custody"]
    _fields(custody, "threshold custodians independence_review_sha256", "custody policy")
    require(custody["threshold"] == 3, "custody threshold must be 3")
    require(type(custody["custodians"]) is list and len(custody["custodians"]) == 5,
            "exactly five custodian records required")
    _pin(custody["independence_review_sha256"], 32, "custody independence review")
    authorities = [
        _authority(value, f"custodian {index}", True)
        for index, value in enumerate(custody["custodians"])
    ]
    signers = [value["source_signer"] for value in authorities]
    require(signers == sorted(set(signers)),
            "five distinct Ethereum custodians must be sorted by address")
    require(not set(signers).intersection({token, implementation, vault}),
            "custodian signer cannot be a token, implementation or vault identity")

    roles = manifest["roles"]
    _fields(roles, "issuer sponsor", "native roles")
    authorities.extend([
        _authority(roles["issuer"], "native issuer", False),
        _authority(roles["sponsor"], "native sponsor", False),
    ])
    for field, label in (("operator", "operator"), ("organization", "organization"),
                         ("key", "Bloch public key"),
                         ("attestation", "custody attestation")):
        values = [authority[field] for authority in authorities]
        require(len(set(values)) == 7,
                f"custodians, issuer and sponsor must have distinct {label} identities")

    controls = manifest["controls"]
    _fields(controls, "paused deposits_enabled releases_enabled activation_authorized "
                      "broadcast_allowed", "initial controls")
    require(all(type(value) is bool for value in controls.values()),
            "initial controls must be booleans")
    require(controls == {
        "paused": True,
        "deposits_enabled": False,
        "releases_enabled": False,
        "activation_authorized": False,
        "broadcast_allowed": False,
    }, "candidate must remain paused, disabled and unauthorized")

    approvals = manifest["approvals"]
    _fields(approvals, "security_review_sha256 deployment_runbook_sha256", "review pins")
    _pin(approvals["security_review_sha256"], 32, "security review")
    _pin(approvals["deployment_runbook_sha256"], 32, "deployment runbook")

    return {
        "schema": "postern.custody-deployment-preflight.v1",
        "manifestCanonicalSha256": canonical_sha256(manifest),
        "configurationConsistent": True,
        "target": "Ethereum USDC to Bloch mainnet bUSDC",
        "custodianCount": 5,
        "custodyThreshold": 3,
        "issuerSponsorSeparated": True,
        "paused": True,
        "offlineOnly": True,
        "keysLoaded": False,
        "fundsObserved": False,
        "deploymentObserved": False,
        "readyForDeployment": False,
        "activationAuthorized": False,
        "broadcastAllowed": False,
    }
