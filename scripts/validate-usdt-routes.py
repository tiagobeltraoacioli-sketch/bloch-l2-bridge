#!/usr/bin/env python3
"""Offline USDT route consistency checks; never authenticates a deployment."""
import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

ETH_USDT = "dac17f958d2ee523a2206206994597c13d831ec7"
TRON_USDT = "a614f803b6fd780986a42c78ec9c7f77e6ded13c"
NETWORKS = {"ethereum-mainnet": ("eip155:1", ETH_USDT, 0),
            "tron-mainnet": ("tron:728126428", TRON_USDT, 1)}
BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
LIMIT = 1_048_576


class Invalid(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise Invalid(message)


def fields(value, expected, label):
    require(isinstance(value, dict) and set(value) == set(expected.split()),
            f"{label}: missing or unknown fields")


def word(value, size, label):
    require(isinstance(value, str) and re.fullmatch(r"0x[0-9a-fA-F]{%d}" % (size * 2), value),
            f"{label}: expected {size}-byte 0x hex")
    raw = bytes.fromhex(value[2:])
    require(any(raw), f"{label}: zero value")
    require(len(set(raw)) > 1, f"{label}: repeated-byte placeholder")
    return raw


def uint(value, label, maximum=(1 << 64) - 1):
    require(type(value) is int and 0 < value <= maximum, f"{label}: invalid positive integer")
    return value


def tron_address(value):
    """Accept only canonical Base58Check or 41-prefixed hex; return TVM bytes."""
    require(isinstance(value, str), "TRON address: expected string")
    if re.fullmatch(r"41[0-9a-fA-F]{40}", value):
        payload = bytes.fromhex(value)
    else:
        require(len(value) == 34 and value.startswith("T") and all(c in BASE58 for c in value),
                "TRON address: invalid Base58 format")
        number = 0
        for char in value:
            number = number * 58 + BASE58.index(char)
        require(number.bit_length() <= 200, "TRON address: overflow")
        decoded = number.to_bytes(25, "big")
        payload, checksum = decoded[:21], decoded[21:]
        require(hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] == checksum,
                "TRON address: invalid checksum")
    require(payload[0] == 0x41 and any(payload[1:]), "TRON address: invalid prefix or zero")
    require(len(set(payload[1:])) > 1, "TRON address: repeated-byte placeholder")
    return payload[1:]


def source_domain(network, genesis):
    # This is an offline configuration convention, not a consensus identity proof.
    return hashlib.sha256(b"BLOCH-USDT-SOURCE-CONFIG-v1\0" + network.encode("ascii") + b"\0" + genesis).digest()


def route_id(route, native_domain, native_asset, token, vault, domain):
    parts = [b"BLOCH-USDT-ROUTE-v1".ljust(32, b"\0"), domain, native_domain,
             native_asset, token.rjust(32, b"\0"), vault.rjust(32, b"\0"),
             (6).to_bytes(32, "big"), route["cap"].to_bytes(32, "big")]
    return hashlib.sha256(b"".join(parts)).hexdigest()


def validate(config, allow_synthetic=False):
    require(isinstance(config, dict), "configuration: expected object")
    require(type(config.get("version")) is int and config["version"] == 2,
            "unsupported version: version 2 with native_supply_cap is required")
    fields(config, "version synthetic native_domain native_asset native_supply_cap routes", "configuration")
    require(type(config["synthetic"]) is bool, "synthetic must be boolean")
    require(not config["synthetic"] or allow_synthetic, "synthetic fixture requires --allow-synthetic")
    native = word(config["native_domain"], 32, "native_domain")
    asset = word(config["native_asset"], 32, "native_asset")
    require(native != asset, "native asset and domain must differ")
    native_supply_cap = uint(config["native_supply_cap"], "native_supply_cap")
    require(isinstance(config["routes"], list) and len(config["routes"]) == 2,
            "exactly two source routes are required")
    seen, domains, output = set(), set(), []
    total_source_capacity = 0
    for route in config["routes"]:
        fields(route, "network chain_id genesis_hash source_domain token vault decimals cap transfer_mode deployment committee", "route")
        network = route["network"]
        require(isinstance(network, str) and network in NETWORKS and network not in seen,
                "unknown or duplicate source network")
        seen.add(network)
        identity, expected_token, mode = NETWORKS[network]
        require(route["chain_id"] == identity, "source chain namespace/ID mismatch")
        genesis = word(route["genesis_hash"], 32, "genesis_hash")
        domain = word(route["source_domain"], 32, "source_domain")
        require(domain == source_domain(network, genesis), "source_domain does not bind network and genesis")
        require(domain != native and domain not in domains, "source/native domains must be distinct")
        domains.add(domain)
        address = tron_address if network == "tron-mainnet" else lambda x: word(x, 20, "Ethereum address")
        token, vault = address(route["token"]), address(route["vault"])
        require(token.hex() == expected_token, "noncanonical source USDT token")
        require(vault != token, "vault must differ from token")
        require(type(route["decimals"]) is int and route["decimals"] == 6, "USDT decimals must be 6")
        total_source_capacity += uint(route["cap"], "cap")
        # Independent vaults can fill simultaneously. Each route fitting on its
        # own does not ensure their common native asset can represent both.
        require(total_source_capacity <= native_supply_cap,
                "combined source route caps exceed native_supply_cap")
        require(type(route["transfer_mode"]) is int and route["transfer_mode"] == mode,
                "incorrect source transfer mode")
        deployment = route["deployment"]
        fields(deployment, "transaction block_hash block_number runtime_code runtime_sha256", "deployment")
        word(deployment["transaction"], 32, "deployment transaction")
        word(deployment["block_hash"], 32, "deployment block hash")
        uint(deployment["block_number"], "deployment block number")
        code = deployment["runtime_code"]
        require(isinstance(code, str) and re.fullmatch(r"0x(?:[0-9a-fA-F]{2}){2,65536}", code),
                "missing or malformed runtime code")
        code = bytes.fromhex(code[2:])
        require(len(set(code)) > 1, "runtime code placeholder")
        digest = word(deployment["runtime_sha256"], 32, "runtime_sha256")
        require(hashlib.sha256(code).digest() == digest, "runtime SHA-256 mismatch")
        committee = route["committee"]
        fields(committee, "threshold signers", "committee")
        signers = committee["signers"]
        require(isinstance(signers, list) and 2 <= len(signers) <= 16, "committee size must be 2..16")
        # Source-vault ECDSA signer identities, not native gateway PQ keys.
        normalized = [address(signer) for signer in signers]
        require(normalized == sorted(set(normalized)), "committee must be distinct and sorted by address bytes")
        require(token not in normalized and vault not in normalized, "token/vault cannot be committee signer")
        uint(committee["threshold"], "committee threshold", len(signers))
        require(committee["threshold"] >= 2, "committee threshold must be at least 2")
        output.append({"network": network, "token_vm_hex": "0x" + token.hex(),
                       "vault_vm_hex": "0x" + vault.hex(),
                       "route_id": "0x" + route_id(route, native, asset, token, vault, domain)})
    return {"validation": "offline-configuration-consistency-only", "synthetic": config["synthetic"],
            "deployment_verified": False, "finality_verified": False, "mainnet_ready": False,
            "native_supply_cap": native_supply_cap, "total_source_capacity": total_source_capacity,
            "routes": output}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config", type=Path)
    parser.add_argument("--allow-synthetic", action="store_true", help="validate explicitly synthetic test fixtures")
    args = parser.parse_args()
    try:
        with args.config.open("rb") as stream:
            raw = stream.read(LIMIT + 1)
        require(len(raw) <= LIMIT, "configuration exceeds 1 MiB")
        config = json.loads(raw, object_pairs_hook=unique_object,
                            parse_constant=lambda _: (_ for _ in ()).throw(Invalid("nonfinite JSON number")))
        print(json.dumps(validate(config, args.allow_synthetic), indent=2))
    except (ValueError, OSError, TypeError, RecursionError) as error:
        print(f"Invalid configuration: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
