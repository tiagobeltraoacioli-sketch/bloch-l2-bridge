"""Adversarial offline tests for the inert mainnet custody plan."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

from custody_deployment_manifest import (  # noqa: E402
    BLOCH_MAINNET_DOMAIN,
    BLOCH_MAINNET_GENESIS,
    ETHEREUM_GENESIS,
    ETHEREUM_USDC,
    validate_custody_deployment_manifest,
)


def pin(label, size=32):
    output = bytearray()
    counter = 0
    while len(output) < size:
        output.extend(hashlib.sha256(f"{label}:{counter}".encode()).digest())
        counter += 1
    return "0x" + bytes(output[:size]).hex()


def authority(index, source=True):
    value = {
        "operator_id": pin(f"operator-{index}"),
        "organization_id": pin(f"organization-{index}"),
        "bloch_public_key_sha256": pin(f"bloch-key-{index}"),
        "custody_attestation_sha256": pin(f"attestation-{index}"),
    }
    if source:
        value["ethereum_signer"] = "0x" + index.to_bytes(20, "big").hex()
    return value


def candidate():
    return {
        "schema": "postern.custody-deployment-plan.v1",
        "source": {
            "network": "ethereum-mainnet",
            "chain_id": "eip155:1",
            "genesis_hash": ETHEREUM_GENESIS,
            "token_symbol": "USDC",
            "token_address": ETHEREUM_USDC,
            "token_decimals": 6,
            "token_proxy_runtime_sha256": pin("proxy-runtime"),
            "token_implementation_address": pin("implementation", 20),
            "token_implementation_runtime_sha256": pin("implementation-runtime"),
            "vault_address": pin("vault", 20),
            "vault_runtime_sha256": pin("vault-runtime"),
            "vault_build_sha256": pin("vault-build"),
        },
        "native": {
            "network": "bloch-mainnet",
            "format": "BPOSMAN1",
            "genesis_hash": BLOCH_MAINNET_GENESIS,
            "domain": BLOCH_MAINNET_DOMAIN,
            "asset_symbol": "bUSDC",
            "asset_id": pin("native-asset"),
            "gateway_runtime_sha256": pin("gateway-runtime"),
            "gateway_manifest_sha256": pin("gateway-manifest"),
        },
        "cap": {"decimals": 6, "base_units": 1_000_000_000},
        "custody": {
            "threshold": 3,
            "custodians": [authority(index) for index in range(1, 6)],
            "independence_review_sha256": pin("independence-review"),
        },
        "roles": {
            "issuer": authority(6, False),
            "sponsor": authority(7, False),
        },
        "controls": {
            "paused": True,
            "deposits_enabled": False,
            "releases_enabled": False,
            "activation_authorized": False,
            "broadcast_allowed": False,
        },
        "approvals": {
            "security_review_sha256": pin("security-review"),
            "deployment_runbook_sha256": pin("deployment-runbook"),
        },
    }


class CustodyDeploymentManifestTest(unittest.TestCase):
    def test_valid_plan_is_still_inert_and_non_authorizing(self):
        report = validate_custody_deployment_manifest(candidate())
        self.assertTrue(report["configurationConsistent"])
        self.assertEqual(report["custodianCount"], 5)
        self.assertEqual(report["custodyThreshold"], 3)
        self.assertTrue(report["paused"])
        for field in ("keysLoaded", "fundsObserved", "deploymentObserved",
                      "readyForDeployment", "activationAuthorized", "broadcastAllowed"):
            self.assertFalse(report[field])

    def test_exactly_five_distinct_sorted_custodians_are_required(self):
        mutations = []
        mutations.append(lambda value: value["custody"]["custodians"].pop())
        mutations.append(lambda value: value["custody"].update(threshold=2))
        mutations.append(lambda value: value["custody"]["custodians"].reverse())
        mutations.append(lambda value: value["custody"]["custodians"][1].update(
            operator_id=value["custody"]["custodians"][0]["operator_id"]))
        mutations.append(lambda value: value["custody"]["custodians"][1].update(
            organization_id=value["custody"]["custodians"][0]["organization_id"]))
        mutations.append(lambda value: value["custody"]["custodians"][1].update(
            bloch_public_key_sha256=value["custody"]["custodians"][0]["bloch_public_key_sha256"]))
        mutations.append(lambda value: value["custody"]["custodians"][1].update(
            ethereum_signer=value["custody"]["custodians"][0]["ethereum_signer"]))
        mutations.append(lambda value: value["custody"]["custodians"][0].update(
            ethereum_signer=value["source"]["vault_address"]))
        mutations.append(lambda value: value["custody"]["custodians"][1].update(
            custody_attestation_sha256=
            value["custody"]["custodians"][0]["custody_attestation_sha256"]))
        for mutate in mutations:
            value = candidate()
            mutate(value)
            with self.subTest(mutation=mutate), self.assertRaises(ValueError):
                validate_custody_deployment_manifest(value)

    def test_issuer_and_sponsor_are_separate_from_every_custodian(self):
        for role, field, source in (
            ("issuer", "operator_id", "operator_id"),
            ("issuer", "organization_id", "organization_id"),
            ("sponsor", "bloch_public_key_sha256", "bloch_public_key_sha256"),
        ):
            value = candidate()
            value["roles"][role][field] = value["custody"]["custodians"][0][source]
            with self.subTest(role=role, field=field), self.assertRaises(ValueError):
                validate_custody_deployment_manifest(value)
        value = candidate()
        value["roles"]["sponsor"]["operator_id"] = value["roles"]["issuer"]["operator_id"]
        with self.assertRaises(ValueError):
            validate_custody_deployment_manifest(value)

    def test_any_enablement_or_authority_claim_is_refused(self):
        for field, changed in (
            ("paused", False),
            ("deposits_enabled", True),
            ("releases_enabled", True),
            ("activation_authorized", True),
            ("broadcast_allowed", True),
        ):
            value = candidate()
            value["controls"][field] = changed
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate_custody_deployment_manifest(value)

    def test_numeric_controls_are_not_accepted_as_booleans(self):
        for field, changed in (
            ("paused", 1),
            ("deposits_enabled", 0),
            ("releases_enabled", 0),
            ("activation_authorized", 0),
            ("broadcast_allowed", 0),
        ):
            value = candidate()
            value["controls"][field] = changed
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate_custody_deployment_manifest(value)

    def test_cap_chain_asset_vault_and_runtime_pins_are_fail_closed(self):
        mutations = [
            lambda value: value["cap"].update(base_units=0),
            lambda value: value["cap"].update(base_units=True),
            lambda value: value["cap"].update(base_units=1 << 64),
            lambda value: value["source"].update(chain_id="eip155:11155111"),
            lambda value: value["source"].update(token_address=pin("other-token", 20)),
            lambda value: value["source"].update(vault_address=value["source"]["token_address"]),
            lambda value: value["source"].update(vault_runtime_sha256="0x" + "11" * 32),
            lambda value: value["native"].update(format="BPOSLAB1"),
            lambda value: value["native"].update(domain=pin("other-domain")),
            lambda value: value["native"].update(asset_symbol="USDC"),
            lambda value: value["native"].update(gateway_runtime_sha256=None),
        ]
        for mutate in mutations:
            value = candidate()
            mutate(value)
            with self.subTest(mutation=mutate), self.assertRaises((ValueError, TypeError)):
                validate_custody_deployment_manifest(value)

    def test_unknown_fields_and_pending_template_are_refused(self):
        value = candidate()
        value["controls"]["unpause_after_deploy"] = True
        with self.assertRaises(ValueError):
            validate_custody_deployment_manifest(value)
        pending = json.loads((ROOT / "mainnet-custody/manifest.pending.json").read_text())
        with self.assertRaises((ValueError, TypeError)):
            validate_custody_deployment_manifest(pending)

    def test_cli_has_no_mode_that_can_authorize_or_broadcast(self):
        cli = SCRIPTS / "check-custody-deployment-manifest.py"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            path.write_text(json.dumps(candidate()))
            result = subprocess.run(
                [sys.executable, str(cli), str(path)], capture_output=True, text=True,
                timeout=10, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout)
            self.assertFalse(report["readyForDeployment"])
            self.assertFalse(report["activationAuthorized"])
            self.assertFalse(report["broadcastAllowed"])
            self.assertEqual(
                subprocess.run(
                    [sys.executable, str(cli), str(path), "--broadcast"],
                    capture_output=True, timeout=10, check=False,
                ).returncode,
                2,
            )


if __name__ == "__main__":
    unittest.main()
