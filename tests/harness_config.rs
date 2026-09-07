// SPDX-License-Identifier: MIT OR Apache-2.0
//! Deploy-harness config tests: parse deploy/testnet.json, validate it,
//! and assert the referenced WBLCH.sol exists and hashes stably.
//! NOTE: this is a CONFIG test — nothing is compiled or deployed.

use std::path::Path;

use bloch_l2_bridge::harness::{
    compile_deployed_bytecode, default_config_path, find_solc, load_config, resolve_source_path,
    solc_version, validate, verify_deployed_bytecode, CompilerConfig, HarnessError,
    TESTNET_CHAIN_ID, WBLCH_PREDEPLOY_ADDRESS,
};
use bloch_l2_bridge::hex;
use bloch_l2_bridge::merkle::keccak256;

fn crate_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// Find a solc whose version exactly matches the WBLCH compiler pin, or
/// `None`. The pinned deployed-bytecode hash is only byte-for-byte
/// reproducible under that exact version, so a mismatched (or absent) solc
/// means the compile assertion is skipped (loudly) rather than run against
/// a compiler that would legitimately produce different bytes. Set `$SOLC`
/// to a solc 0.8.24 binary to enforce the assertion.
///
/// CI GATE: with `REQUIRE_SOLC` set in the environment, a missing or
/// mismatched solc is a hard FAILURE instead of a skip — a compile job that
/// silently degraded to "source pin only" would otherwise never be noticed.
fn pinned_solc() -> Option<std::path::PathBuf> {
    let config = load_config(&default_config_path()).expect("deploy/testnet.json must parse");
    let want = &config.predeploys[0].compiler.solc_version_exact;
    let require = std::env::var_os("REQUIRE_SOLC").is_some();
    let skip = |why: String| -> Option<std::path::PathBuf> {
        if require {
            panic!("REQUIRE_SOLC is set but the pinned solc {want} is unusable: {why}");
        }
        eprintln!("SKIP compile assertion: {why}");
        None
    };
    let Some(solc) = find_solc() else {
        return skip(format!(
            "no solc on PATH and $SOLC unset (set $SOLC to a solc {want} binary to enforce)"
        ));
    };
    match solc_version(&solc) {
        Ok(v) if &v == want => Some(solc),
        Ok(v) => skip(format!(
            "found solc {v}, pin wants {want} (set $SOLC to a solc {want} binary to enforce)"
        )),
        Err(e) => skip(format!("cannot query solc: {e}")),
    }
}

/// The `bridge_contracts_design` section of deploy/testnet.json is
/// deliberately outside the typed `DeployConfig` (serde ignores it), so its
/// pins would otherwise be enforced by nothing. This test walks the raw JSON
/// and checks, for every design contract: the referenced source exists
/// INSIDE the crate, its keccak256 equals `source_keccak256`, and its
/// deployed-bytecode pin is honestly labelled (`placeholder` iff all-zero).
/// With the pinned solc present it also recompiles each contract under the
/// pinned settings and asserts the deployed-bytecode hash.
#[test]
fn design_contract_pins_match_on_disk_and_compile() {
    let raw: serde_json::Value =
        serde_json::from_slice(&std::fs::read(default_config_path()).unwrap()).unwrap();
    let design = raw["bridge_contracts_design"]
        .as_object()
        .expect("bridge_contracts_design section present");
    let solc = pinned_solc();
    let mut checked = 0;
    for (key, entry) in design {
        let Some(obj) = entry.as_object() else {
            continue; // `_comment`
        };
        let name = obj["name"].as_str().expect("name");
        let source_path = obj["source_path"].as_str().expect("source_path");
        let pinned_source = obj["source_keccak256"].as_str().expect("source_keccak256");
        let pinned_bytecode = obj["deployed_bytecode_keccak256"]
            .as_str()
            .expect("deployed_bytecode_keccak256");
        let placeholder = obj["placeholder"].as_bool().expect("placeholder flag");

        let path =
            resolve_source_path(crate_root(), source_path).unwrap_or_else(|e| panic!("{key}: {e}"));
        assert!(path.is_file(), "{key}: {} must exist", path.display());
        let actual_source = hex::encode_prefixed(&keccak256(&std::fs::read(&path).unwrap()));
        assert_eq!(
            actual_source,
            pinned_source.to_lowercase(),
            "{key}: source_keccak256 drifted for {source_path} (update deploy/testnet.json if the \
             contract legitimately changed)"
        );

        let bytecode_pin = hex::decode(pinned_bytecode).unwrap();
        assert_eq!(
            bytecode_pin.len(),
            32,
            "{key}: bytecode pin must be 32 bytes"
        );
        let is_zero = bytecode_pin == vec![0u8; 32];
        assert_eq!(
            placeholder, is_zero,
            "{key}: placeholder flag must be true iff the bytecode hash is all-zero"
        );

        if let (Some(solc), false) = (&solc, is_zero) {
            let cfg: CompilerConfig = serde_json::from_value(obj["compiler"].clone())
                .unwrap_or_else(|e| panic!("{key}: compiler block required for a real pin: {e}"));
            let bytecode = compile_deployed_bytecode(solc, name, &path, &cfg)
                .unwrap_or_else(|e| panic!("{key}: compile failed: {e}"));
            assert_eq!(
                hex::encode_prefixed(&keccak256(&bytecode)),
                pinned_bytecode.to_lowercase(),
                "{key}: deployed-bytecode hash drifted (compiled under the pinned solc)"
            );
        }
        checked += 1;
    }
    assert_eq!(checked, 2, "both design contracts must be pinned");
}

#[test]
fn testnet_config_parses_and_validates() {
    let config = load_config(&default_config_path()).expect("deploy/testnet.json must parse");
    assert_eq!(config.chain_id, TESTNET_CHAIN_ID);
    assert_eq!(config.network, "bloch-l2-testnet");
    assert_eq!(config.solc_version, "^0.8.24");
    // honesty banner is present and says the load-bearing words
    assert!(config.honesty.contains("SCAFFOLD"));
    assert!(config.honesty.contains("UNAUDITED"));
    assert!(config.honesty.contains("not a working L2"));
    assert!(config.honesty.contains("CUSTODY"));

    let validated = validate(&config, crate_root()).expect("config must validate");
    assert_eq!(validated.chain_id, 700_771);

    // the WBLCH predeploy is pinned to the OP-convention address 0x42..06
    let wblch = validated
        .predeploys
        .iter()
        .find(|p| p.name == "WBLCH")
        .expect("WBLCH predeploy present");
    assert_eq!(
        hex::encode_prefixed(&wblch.address),
        WBLCH_PREDEPLOY_ADDRESS.to_lowercase()
    );
}

#[test]
fn wblch_source_exists_and_hashes_stably() {
    let config = load_config(&default_config_path()).unwrap();
    let wblch = config
        .predeploys
        .iter()
        .find(|p| p.name == "WBLCH")
        .expect("WBLCH predeploy present");

    // the referenced file exists on disk...
    let source_path = crate_root().join(&wblch.source_path);
    assert!(
        source_path.is_file(),
        "WBLCH.sol must exist at {}",
        source_path.display()
    );

    // ...pins the expected pragma...
    let source = std::fs::read(&source_path).unwrap();
    assert!(
        String::from_utf8_lossy(&source).contains("pragma solidity ^0.8.24"),
        "WBLCH.sol must pin solc ^0.8.24"
    );

    // ...and hashes STABLY: two independent reads agree, and both match
    // the hash pinned in the config (so config and source cannot drift
    // silently — validate() enforces the same equality).
    let first = keccak256(&source);
    let second = keccak256(&std::fs::read(&source_path).unwrap());
    assert_eq!(first, second, "hash must be stable across reads");
    assert_eq!(
        hex::encode_prefixed(&first),
        wblch.source_keccak256.to_lowercase(),
        "config source_keccak256 must pin the on-disk WBLCH.sol (update deploy/testnet.json if the contract legitimately changed; actual hash is printed above)"
    );
}

/// THE acceptance check: compile WBLCH.sol with the pinned exact solc and
/// settings, take the keccak256 of the DEPLOYED (runtime) bytecode, and
/// assert it equals the `deployed_bytecode_keccak256` pinned in
/// deploy/testnet.json. Fails if the source — or the compiler pin — drifts.
///
/// Skips (loudly) when solc 0.8.24 is not available, so solc-less CI stays
/// green; the unconditional `source_keccak256` pin still catches any source
/// drift on its own. Nothing is deployed: solc is invoked, nothing else.
#[test]
fn wblch_deployed_bytecode_matches_pinned_hash() {
    let config = load_config(&default_config_path()).unwrap();
    let wblch = config
        .predeploys
        .iter()
        .find(|p| p.name == "WBLCH")
        .expect("WBLCH predeploy present");

    // The pin must be a real, non-zero 32-byte hash regardless of solc.
    let pinned = hex::decode(&wblch.deployed_bytecode_keccak256).unwrap();
    assert_eq!(
        pinned.len(),
        32,
        "deployed_bytecode_keccak256 must be 32 bytes"
    );
    assert_ne!(
        pinned,
        vec![0u8; 32],
        "deployed-bytecode hash must be real, not a placeholder"
    );

    let solc = match pinned_solc() {
        Some(s) => s,
        None => {
            eprintln!(
                "SKIP: solc {} unavailable; source_keccak256 pin still guards source drift",
                wblch.compiler.solc_version_exact
            );
            return;
        }
    };

    // Compile + assert equality. Errors (compile failure, version drift,
    // hash mismatch) fail the test with a descriptive message.
    let hash = verify_deployed_bytecode(&solc, wblch, crate_root())
        .expect("compiled WBLCH deployed bytecode must match the pinned hash");
    assert_eq!(
        hex::encode_prefixed(&hash),
        wblch.deployed_bytecode_keccak256.to_lowercase(),
        "compiled deployed-bytecode hash must equal the pinned value"
    );
}

/// The compile check actually DETECTS drift: feed the compiler a predeploy
/// with a tampered pinned hash and confirm it reports a mismatch (only when
/// the pinned solc is present).
#[test]
fn wblch_bytecode_check_detects_drift() {
    let solc = match pinned_solc() {
        Some(s) => s,
        None => return, // covered by the positive test's skip note
    };
    let mut config = load_config(&default_config_path()).unwrap();
    config.predeploys[0].deployed_bytecode_keccak256 =
        "0xdeadbeef00000000000000000000000000000000000000000000000000000000".to_string();
    match verify_deployed_bytecode(&solc, &config.predeploys[0], crate_root()) {
        Err(HarnessError::DeployedBytecodeMismatch { expected, actual }) => {
            assert!(expected.starts_with("0xdeadbeef"));
            assert!(actual.starts_with("0x"));
            assert_ne!(expected, actual);
        }
        other => panic!("expected DeployedBytecodeMismatch, got {other:?}"),
    }
}

#[test]
fn uniswap_artifacts_are_honest_placeholders() {
    let config = load_config(&default_config_path()).unwrap();
    for artifact in [&config.uniswap_v2.factory, &config.uniswap_v2.router02] {
        // mainnet provenance is documented with a well-formed address
        assert!(artifact.ethereum_mainnet_address.starts_with("0x"));
        assert_eq!(artifact.ethereum_mainnet_address.len(), 42);
        // placeholder hashes MUST be labelled as placeholders
        let hash = hex::decode(&artifact.artifact_keccak256).unwrap();
        if hash == vec![0u8; 32] {
            assert!(
                artifact.placeholder,
                "{}: all-zero hash must set placeholder=true",
                artifact.name
            );
        }
        assert!(artifact.origin.contains("unchanged"));
    }
}

#[test]
fn validation_rejects_wrong_chain_id() {
    let mut config = load_config(&default_config_path()).unwrap();
    config.chain_id = 1; // Ethereum mainnet — absolutely not
    match validate(&config, crate_root()) {
        Err(HarnessError::ChainIdMismatch { expected, actual }) => {
            assert_eq!(expected, 700_771);
            assert_eq!(actual, 1);
        }
        other => panic!("expected ChainIdMismatch, got {other:?}"),
    }
}

#[test]
fn validation_rejects_moved_wblch_address() {
    let mut config = load_config(&default_config_path()).unwrap();
    config.predeploys[0].address = "0x4200000000000000000000000000000000000007".to_string();
    assert!(matches!(
        validate(&config, crate_root()),
        Err(HarnessError::WblchAddressMismatch { .. })
    ));
}

#[test]
fn validation_rejects_missing_source() {
    let mut config = load_config(&default_config_path()).unwrap();
    config.predeploys[0].source_path = "contracts/wblch/DOES_NOT_EXIST.sol".to_string();
    assert!(matches!(
        validate(&config, crate_root()),
        Err(HarnessError::SourceMissing { .. })
    ));
}

/// A `source_path` that would resolve outside the crate root (`..`
/// traversal or an absolute path) is refused BEFORE any file is read —
/// even when it would point at an existing file.
#[test]
fn validation_rejects_source_path_escaping_crate_root() {
    let real = crate_root().join("contracts/wblch/WBLCH.sol");
    for escaping in [
        "../bloch-l2-bridge/contracts/wblch/WBLCH.sol".to_string(),
        "../../etc/passwd".to_string(),
        real.to_string_lossy().into_owned(), // absolute path to the real file
    ] {
        let mut config = load_config(&default_config_path()).unwrap();
        config.predeploys[0].source_path = escaping.clone();
        assert!(
            matches!(
                validate(&config, crate_root()),
                Err(HarnessError::SourceEscapesBaseDir { .. })
            ),
            "{escaping} must be refused"
        );
    }
}

#[test]
fn validation_rejects_tampered_source_hash() {
    let mut config = load_config(&default_config_path()).unwrap();
    config.predeploys[0].source_keccak256 =
        "0x1111111111111111111111111111111111111111111111111111111111111111".to_string();
    match validate(&config, crate_root()) {
        Err(HarnessError::SourceHashMismatch {
            expected, actual, ..
        }) => {
            assert!(expected.starts_with("0x1111"));
            assert!(actual.starts_with("0x"));
        }
        other => panic!("expected SourceHashMismatch, got {other:?}"),
    }
}

#[test]
fn validation_rejects_missing_honesty_banner() {
    let mut config = load_config(&default_config_path()).unwrap();
    config.honesty = "   ".to_string();
    assert!(matches!(
        validate(&config, crate_root()),
        Err(HarnessError::EmptyHonestyBanner)
    ));
}

#[test]
fn validation_rejects_unlabelled_placeholder() {
    let mut config = load_config(&default_config_path()).unwrap();
    config.uniswap_v2.factory.placeholder = false; // lying about the zero hash
    assert!(matches!(
        validate(&config, crate_root()),
        Err(HarnessError::UnlabelledPlaceholder { .. })
    ));
}

#[test]
fn config_round_trips_through_serde() {
    let config = load_config(&default_config_path()).unwrap();
    let json = serde_json::to_string_pretty(&config).unwrap();
    let back: bloch_l2_bridge::harness::DeployConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
}
