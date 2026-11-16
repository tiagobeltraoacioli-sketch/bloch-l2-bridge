#!/bin/sh
# Builds the vault and the test helper for SBF and runs every Rust test of the Solana vault.
# Needs on PATH: cargo (Rust 1.95.0) and cargo-build-sbf (Agave v4.4.1). Build output goes to $SOL_TARGET
# (default: ./target), never to a directory shared with another checkout.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
target=${SOL_TARGET:-$here/target}
jobs=${JOBS:-6}
(cd "$here/bloch-sol-vault" && CARGO_TARGET_DIR="$target/vault" cargo test --locked -j "$jobs")
(cd "$here/bloch-sol-vault" && CARGO_TARGET_DIR="$target/vault" cargo build-sbf --jobs "$jobs" -- --locked)
(cd "$here/test-helper-program" && CARGO_TARGET_DIR="$target/helper" cargo build-sbf --jobs "$jobs" -- --locked)
sha256sum "$target/vault/deploy/bloch_sol_vault.so"
(cd "$here/vault-tests" && VAULT_SO="$target/vault/deploy/bloch_sol_vault.so" HELPER_SO="$target/helper/deploy/bloch_sol_test_helper.so" \
  CARGO_TARGET_DIR="$target/tests" cargo test --locked -j "$jobs" -- --nocapture --test-threads 4)
