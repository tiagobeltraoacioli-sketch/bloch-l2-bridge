"""Offline adversarial configuration tests; no real deployments or keys."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "validate-usdt-routes.py"
EXAMPLE = SCRIPT.with_name("usdt-routes.synthetic.json")
spec = importlib.util.spec_from_file_location("validate_usdt_routes", SCRIPT)
validator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validator)


class RouteValidation(unittest.TestCase):
    def setUp(self):
        self.config = json.loads(EXAMPLE.read_text())

    def rejected(self, mutation):
        changed = copy.deepcopy(self.config)
        mutation(changed)
        with self.assertRaises(validator.Invalid):
            validator.validate(changed, allow_synthetic=True)

    def test_two_routes_and_no_readiness_claim(self):
        result = validator.validate(self.config, allow_synthetic=True)
        self.assertFalse(result["deployment_verified"])
        self.assertFalse(result["finality_verified"])
        self.assertFalse(result["mainnet_ready"])
        self.assertNotEqual(result["routes"][0]["route_id"], result["routes"][1]["route_id"])
        self.assertEqual(result["routes"][1]["token_vm_hex"], "0x" + validator.TRON_USDT)

    def test_synthetic_requires_explicit_flag(self):
        with self.assertRaises(validator.Invalid):
            validator.validate(self.config)
        result = subprocess.run([sys.executable, str(SCRIPT), str(EXAMPLE)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn("--allow-synthetic", result.stderr)

    def test_shared_capacity_boundary_and_route_order(self):
        self.config["native_supply_cap"] = (1 << 64) - 1
        self.config["routes"][0]["cap"] = (1 << 64) - 2
        self.config["routes"][1]["cap"] = 1
        result = validator.validate(self.config, allow_synthetic=True)
        self.assertEqual(result["total_source_capacity"], (1 << 64) - 1)
        self.assertEqual(result["native_supply_cap"], result["total_source_capacity"])
        expected_ids = {r["network"]: r["route_id"] for r in result["routes"]}
        self.config["routes"].reverse()
        reordered = validator.validate(self.config, allow_synthetic=True)
        self.assertEqual(expected_ids, {r["network"]: r["route_id"] for r in reordered["routes"]})
        # Both individual caps still fit, but filling both vaults would overflow
        # the shared native supply. Reject in either route order.
        self.config["routes"][0]["cap"] = 2
        for _ in range(2):
            with self.assertRaisesRegex(validator.Invalid, "combined source route caps"):
                validator.validate(self.config, allow_synthetic=True)
            self.config["routes"].reverse()

    def test_shared_capacity_is_not_just_a_uint64_overflow_check(self):
        # Ordinary small caps can overcommit a smaller native supply as well.
        self.rejected(lambda c: c.update(native_supply_cap=1_999_999_999))
        self.rejected(lambda c: c["routes"][0].update(cap=2_000_000_001))
        for value in [0, -1, True, "2000000000", 2.0, 1 << 64]:
            with self.subTest(value=value):
                self.rejected(lambda c, v=value: c.update(native_supply_cap=v))
        self.rejected(lambda c: c.pop("native_supply_cap"))

    def test_legacy_manifest_requires_explicit_capacity_migration(self):
        self.config["version"] = 1
        self.config.pop("native_supply_cap")
        with self.assertRaisesRegex(validator.Invalid, "version 2 with native_supply_cap"):
            validator.validate(self.config, allow_synthetic=True)

    def test_declaring_operational_manifest_never_asserts_readiness(self):
        # Merely relabeling arbitrary offline data cannot authenticate it.
        self.config["synthetic"] = False
        result = validator.validate(self.config)
        for flag in ["deployment_verified", "finality_verified", "mainnet_ready"]:
            self.assertIs(result[flag], False)

    def test_cli_accepts_only_explicit_synthetic_fixture(self):
        result = subprocess.run([sys.executable, str(SCRIPT), str(EXAMPLE), "--allow-synthetic"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(json.loads(result.stdout)["mainnet_ready"])

    def test_tron_checksum_and_normalization(self):
        self.assertEqual(validator.tron_address("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"),
                         validator.tron_address("41" + validator.TRON_USDT))
        for value in ["TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6u", "0x" + validator.TRON_USDT,
                      "42" + validator.TRON_USDT, "41" + "00" * 20, "T" * 1000]:
            with self.subTest(value=value), self.assertRaises(validator.Invalid):
                validator.tron_address(value)

    def test_network_domain_token_and_policy_mismatches(self):
        mutations = [
            lambda c: c["routes"][0].update(chain_id="tron:728126428"),
            lambda c: c["routes"][1].update(network="ethereum-mainnet"),
            lambda c: c["routes"][0].update(source_domain=c["native_domain"]),
            lambda c: c["routes"][1].update(source_domain=c["routes"][0]["source_domain"]),
            lambda c: c["routes"][0].update(token=c["routes"][0]["vault"]),
            lambda c: c["routes"][0].update(transfer_mode=1),
            lambda c: c["routes"][1].update(transfer_mode=0),
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.rejected(mutation)

    def test_missing_placeholder_or_unbounded_values(self):
        for name in ["deployment", "committee", "source_domain"]:
            self.rejected(lambda c, n=name: c["routes"][0].pop(n))
        for value in [0, -1, True, "100", 1 << 64]:
            self.rejected(lambda c, v=value: c["routes"][0].update(cap=v))
        for value in [True, 18, "6"]:
            self.rejected(lambda c, v=value: c["routes"][0].update(decimals=v))
        for value in ["TODO", "0x" + "00" * 32, "0x" + "11" * 32]:
            self.rejected(lambda c, v=value: c["routes"][0]["deployment"].update(runtime_sha256=v))
        self.rejected(lambda c: c["routes"][0].update(vault="0x" + "00" * 20))
        self.rejected(lambda c: c["routes"][0]["deployment"].update(runtime_code="0x"))
        self.rejected(lambda c: c["routes"][0]["deployment"].update(runtime_code="0x60016000fd"))
        self.rejected(lambda c: c.update(mainnet_ready=True))

    def test_committee_duplicate_unordered_or_weak(self):
        self.rejected(lambda c: c["routes"][0]["committee"].update(threshold=1))
        self.rejected(lambda c: c["routes"][0]["committee"].update(threshold=True))
        self.rejected(lambda c: c["routes"][0]["committee"].update(threshold=4))
        self.rejected(lambda c: c["routes"][0]["committee"]["signers"].reverse())
        self.rejected(lambda c: c["routes"][0]["committee"]["signers"].append(c["routes"][0]["committee"]["signers"][0]))
        self.rejected(lambda c: c["routes"][0]["committee"].update(signers=[]))

    def test_duplicate_json_fields_rejected(self):
        with self.assertRaises(validator.Invalid):
            json.loads('{"version":1,"version":2}', object_pairs_hook=validator.unique_object)


if __name__ == "__main__":
    unittest.main()
