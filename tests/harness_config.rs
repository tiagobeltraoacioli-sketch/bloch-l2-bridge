// SPDX-License-Identifier: MIT OR Apache-2.0
//! Deploy-harness config tests: parse deploy/testnet.json, validate it,
//! assert every referenced Solidity source exists and hashes stably, and —
//! when the pinned solc 0.8.24 is present — recompile each pinned contract
//! and assert its deployed-bytecode hash.
//! NOTE: this is a CONFIG test — solc is only ever invoked to compile and
//! hash; nothing is deployed.

use std::path::Path;

use bloch_l2_bridge::harness::{
    compile_deployed_bytecode, default_config_path, find_solc, load_config, parse_address,
    resolve_source_path, solc_version, validate, verify_deployed_bytecode, CompilerConfig,
    HarnessError, TESTNET_CHAIN_ID, WBLCH_PREDEPLOY_ADDRESS,
};
use bloch_l2_bridge::hex;
use bloch_l2_bridge::merkle::keccak256;

/// The L2BlochBridge withdrawal predeploy address (§5, OP convention).
const L2_BLOCH_BRIDGE_ADDRESS: &str = "0x4200000000000000000000000000000000000010";

fn crate_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn config_loader_bounds_input_before_json_decode() {
    let suffix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "bloch-bridge-config-{}-{suffix}.json",
        std::process::id()
    ));
    std::fs::write(
        &path,
        vec![b' '; bloch_l2_bridge::harness::MAX_CONFIG_BYTES as usize + 1],
    )
    .unwrap();
    let result = load_config(&path);
    std::fs::remove_file(path).unwrap();
    assert!(matches!(result, Err(HarnessError::ConfigTooLarge { .. })));
}

#[test]
fn config_loader_rejects_unknown_fields_in_security_critical_entries() {
    let raw = std::fs::read(default_config_path()).unwrap();
    let original: serde_json::Value = serde_json::from_slice(&raw).unwrap();

    let mut cases = Vec::new();

    let mut predeploy = original.clone();
    predeploy["predeploys"][0]["unreviewed_override"] = serde_json::json!(true);
    cases.push(predeploy);

    let mut compiler = original.clone();
    compiler["predeploys"][0]["compiler"]["optimizer_details"] = serde_json::json!({"yul": false});
    cases.push(compiler);

    let mut uniswap = original.clone();
    uniswap["uniswap_v2"]["shadow_router"] = serde_json::json!({});
    cases.push(uniswap);

    let mut artifact = original;
    artifact["uniswap_v2"]["factory"]["creation_bytecode"] = serde_json::json!("0x00");
    cases.push(artifact);

    for value in cases {
        assert!(
            serde_json::from_value::<bloch_l2_bridge::harness::DeployConfig>(value).is_err(),
            "unknown fields inside typed deployment entries must fail closed"
        );
    }
}

/// Find a solc whose version exactly matches the compiler pin, or `None`.
/// The pinned deployed-bytecode hashes are only byte-for-byte reproducible
/// under that exact version, so a mismatched (or absent) solc means the
/// compile assertions are skipped (loudly) rather than run against a
/// compiler that would legitimately produce different bytes. Set `$SOLC`
/// to a solc 0.8.24 binary to enforce them.
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
        let why = match std::env::var_os("SOLC") {
            Some(p) => format!(
                "$SOLC={} is not a file, and no solc on PATH (point $SOLC at a solc {want} binary)",
                Path::new(&p).display()
            ),
            None => format!(
                "no solc on PATH and $SOLC unset (set $SOLC to a solc {want} binary to enforce)"
            ),
        };
        return skip(why);
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
/// INSIDE the crate, its keccak256 equals `source_keccak256`, its `address`
/// (when not null) parses, and its deployed-bytecode pin is honestly
/// labelled (`placeholder` iff all-zero). With the pinned solc present it
/// also checks the entry's OWN `compiler.solc_version_exact` against the
/// binary, recompiles the contract under the pinned settings and asserts the
/// deployed-bytecode hash.
#[test]
fn design_contract_pins_match_on_disk_and_compile() {
    let raw: serde_json::Value =
        serde_json::from_slice(&std::fs::read(default_config_path()).unwrap()).unwrap();
    let design = raw["bridge_contracts_design"]
        .as_object()
        .expect("bridge_contracts_design section present");
    let solc = pinned_solc();
    let mut checked = Vec::new();
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
        if let Some(addr) = obj["address"].as_str() {
            parse_address(addr).unwrap_or_else(|e| panic!("{key}: bad address {addr}: {e}"));
        }

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
            let found = solc_version(solc).unwrap();
            assert_eq!(
                cfg.solc_version_exact, found,
                "{key}: entry pins solc {} but the available solc is {found}",
                cfg.solc_version_exact
            );
            let bytecode = compile_deployed_bytecode(solc, name, &path, &cfg)
                .unwrap_or_else(|e| panic!("{key}: compile failed: {e}"));
            assert_eq!(
                hex::encode_prefixed(&keccak256(&bytecode)),
                pinned_bytecode.to_lowercase(),
                "{key}: deployed-bytecode hash drifted (compiled under the pinned solc)"
            );
        }
        checked.push(name.to_string());
    }
    assert_eq!(
        checked,
        vec!["L1ReleaseVerifier".to_string()],
        "the design section holds exactly the L1ReleaseVerifier stub (L2BlochBridge graduated \
         into `predeploys`)"
    );
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
    // and the L2BlochBridge withdrawal predeploy at 0x42..10
    let bridge = validated
        .predeploys
        .iter()
        .find(|p| p.name == "L2BlochBridge")
        .expect("L2BlochBridge predeploy present");
    assert_eq!(
        hex::encode_prefixed(&bridge.address),
        L2_BLOCH_BRIDGE_ADDRESS.to_lowercase()
    );
    assert_eq!(validated.predeploys.len(), 2);
}

#[test]
fn predeploy_sources_exist_and_hash_stably() {
    let config = load_config(&default_config_path()).unwrap();
    assert!(!config.predeploys.is_empty());
    for p in &config.predeploys {
        // the referenced file exists on disk, inside the crate...
        let source_path = resolve_source_path(crate_root(), &p.source_path).unwrap();
        assert!(
            source_path.is_file(),
            "{} must exist at {}",
            p.name,
            source_path.display()
        );

        // ...pins the expected pragma...
        let source = std::fs::read(&source_path).unwrap();
        assert!(
            String::from_utf8_lossy(&source).contains("pragma solidity ^0.8.24"),
            "{} must pin solc ^0.8.24",
            p.name
        );

        // ...and hashes STABLY: two independent reads agree, and both match
        // the hash pinned in the config (so config and source cannot drift
        // silently — validate() enforces the same equality).
        let first = keccak256(&source);
        let second = keccak256(&std::fs::read(&source_path).unwrap());
        assert_eq!(first, second, "hash must be stable across reads");
        assert_eq!(
            hex::encode_prefixed(&first),
            p.source_keccak256.to_lowercase(),
            "{}: config source_keccak256 must pin the on-disk source (update deploy/testnet.json \
             if the contract legitimately changed; actual hash is printed above)",
            p.name
        );
    }
}

/// THE acceptance check: compile every predeploy's source with the pinned
/// exact solc and settings, take the keccak256 of the DEPLOYED (runtime)
/// bytecode, and assert it equals the `deployed_bytecode_keccak256` pinned
/// in deploy/testnet.json. Fails if the source — or the compiler pin —
/// drifts.
///
/// Skips (loudly) when solc 0.8.24 is not available, so solc-less CI stays
/// green unless `REQUIRE_SOLC` is set; the unconditional `source_keccak256`
/// pin still catches any source drift on its own. Nothing is deployed: solc
/// is invoked, nothing else.
#[test]
fn predeploy_deployed_bytecode_matches_pinned_hash() {
    let config = load_config(&default_config_path()).unwrap();
    for p in &config.predeploys {
        // The pin must be a real, non-zero 32-byte hash regardless of solc.
        let pinned = hex::decode(&p.deployed_bytecode_keccak256).unwrap();
        assert_eq!(
            pinned.len(),
            32,
            "{}: deployed_bytecode_keccak256 must be 32 bytes",
            p.name
        );
        assert_ne!(
            pinned,
            vec![0u8; 32],
            "{}: deployed-bytecode hash must be real, not a placeholder",
            p.name
        );
    }

    let solc = match pinned_solc() {
        Some(s) => s,
        None => {
            eprintln!(
                "SKIP: pinned solc unavailable; source_keccak256 pins still guard source drift"
            );
            return;
        }
    };

    // Compile + assert equality for every predeploy. Errors (compile
    // failure, version drift, hash mismatch) fail the test descriptively.
    for p in &config.predeploys {
        let hash = verify_deployed_bytecode(&solc, p, crate_root()).unwrap_or_else(|e| {
            panic!(
                "{}: compiled deployed bytecode must match the pinned hash: {e}",
                p.name
            )
        });
        assert_eq!(
            hex::encode_prefixed(&hash),
            p.deployed_bytecode_keccak256.to_lowercase(),
            "{}: compiled deployed-bytecode hash must equal the pinned value",
            p.name
        );
    }
}

/// The compile check actually DETECTS drift: feed the compiler a predeploy
/// with a tampered pinned hash and confirm it reports a mismatch (only when
/// the pinned solc is present).
#[test]
fn bytecode_check_detects_drift() {
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
fn validation_rejects_zero_predeploy_bytecode_pin() {
    let mut config = load_config(&default_config_path()).unwrap();
    config.predeploys[1].deployed_bytecode_keccak256 =
        "0x0000000000000000000000000000000000000000000000000000000000000000".to_string();
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
