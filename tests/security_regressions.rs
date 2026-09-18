// SPDX-License-Identifier: MIT OR Apache-2.0
//! Adversarial regressions for the follow-up state-integrity audit.
use bloch_l2_bridge::envelope::{DepositEnvelope, TxOutput};
use bloch_l2_bridge::harness::{default_config_path, load_config, validate};
use bloch_l2_bridge::status::{ConfirmationRequirement, ATOMS_PER_BLCH};
use bloch_l2_bridge::watcher::{
    BlockSource, DepositPhase, DepositWatcher, L1Block, L1Tx, MemorySource, VaultSet, WatcherState,
};

const CHAIN: u64 = 700_771;
const VAULT: [u8; 20] = [0xa0; 20];

fn fixture(amount: u64, blocks: u64) -> (DepositWatcher, MemorySource) {
    let mut source = MemorySource::new();
    let mut parent = [0; 32];
    for height in 0..blocks {
        let hash = bloch_l2_bridge::merkle::keccak256(&height.to_le_bytes());
        source
            .push(L1Block {
                height,
                hash,
                parent_hash: parent,
                txs: if height == 0 {
                    vec![L1Tx {
                        txid: [0x11; 32],
                        outputs: vec![
                            TxOutput {
                                value: amount,
                                script_pubkey: VAULT.to_vec(),
                            },
                            TxOutput {
                                value: 0,
                                script_pubkey: DepositEnvelope {
                                    l2_chain_id: CHAIN,
                                    l2_recipient: [0x22; 20],
                                }
                                .encode()
                                .to_vec(),
                            },
                        ],
                    }]
                } else {
                    vec![]
                },
            })
            .unwrap();
        parent = hash;
    }
    let mut watcher = DepositWatcher::new(VaultSet::new([VAULT]), CHAIN);
    watcher.sync(&source);
    (watcher, source)
}

fn reject(state: WatcherState) {
    // Exercise the actual JSON persistence boundary as well as typed restore.
    let encoded = serde_json::to_vec(&state).unwrap();
    let decoded = serde_json::from_slice(&encoded).unwrap();
    assert!(DepositWatcher::from_state(decoded).is_err());
}

#[test]
fn restore_refuses_weakened_confirmation_schedule() {
    let (watcher, _) = fixture(1001 * ATOMS_PER_BLCH, 1);
    let mut state = watcher.state();
    state.tracked[0].1.requirement = ConfirmationRequirement::Automatic { depth: 1 };
    reject(state);
}

#[test]
fn restore_binds_map_identity_to_deposit_identity() {
    let (watcher, _) = fixture(1, 1);
    let mut state = watcher.state();
    state.tracked[0].0 .0 = [0xff; 32];
    reject(state);
}

#[test]
fn restore_refuses_foreign_chain_zero_amount_and_zero_recipient() {
    let (watcher, _) = fixture(1, 1);
    for field in 0..3 {
        let mut state = watcher.state();
        let event = &mut state.tracked[0].1.event;
        match field {
            0 => event.l2_chain_id += 1,
            1 => event.amount_atoms = 0,
            _ => event.l2_recipient = [0; 20],
        }
        reject(state);
    }
}

#[test]
fn restore_refuses_forged_creditable_phase_below_k() {
    let (watcher, _) = fixture(1, 1);
    let mut state = watcher.state();
    state.tracked[0].1.phase = DepositPhase::Creditable;
    state.credited.insert(state.tracked[0].0);
    reject(state);
}

#[test]
fn restore_requires_durable_log_for_creditable_deposit() {
    let (watcher, _) = fixture(1, 24);
    let mut state = watcher.state();
    state.credited.clear();
    reject(state);
}

#[test]
fn restore_refuses_unaccounted_credit_log_entry() {
    let (watcher, _) = fixture(1, 24);
    let mut state = watcher.state();
    state.tracked.clear();
    state.credit_reorg_alarms.clear();
    reject(state);
}

#[test]
fn restore_binds_reorg_alarms_to_credit_tier_and_configuration() {
    let (watcher, _) = fixture(1, 24);
    let mut foreign = watcher.state();
    let mut alarm = foreign.tracked[0].1.event;
    alarm.l2_chain_id += 1;
    foreign.credit_reorg_alarms.push(alarm);
    reject(foreign);

    let (pending, _) = fixture(1, 1);
    let mut missing_credit = pending.state();
    missing_credit
        .credit_reorg_alarms
        .push(missing_credit.tracked[0].1.event);
    reject(missing_credit);
}

#[test]
fn restore_cannot_auto_credit_operator_review_tier() {
    let (watcher, _) = fixture(1001 * ATOMS_PER_BLCH, 288);
    let mut state = watcher.state();
    state.tracked[0].1.phase = DepositPhase::Creditable;
    state.credited.insert(state.tracked[0].0);
    reject(state);
}

#[test]
fn lost_confirmations_remove_deposit_from_restart_mint_worklist() {
    let (mut watcher, mut source) = fixture(1, 24);
    assert_eq!(watcher.creditable().count(), 1);
    source.reorg_to(1); // Deposit survives, but has only one confirmation.
    watcher.sync(&source);
    assert_eq!(watcher.creditable().count(), 0);
    assert_eq!(watcher.credited().len(), 1, "dedup history must survive");
}

struct MissingSource;
impl BlockSource for MissingSource {
    fn tip_height(&self) -> Option<u64> {
        Some(23)
    }
    fn block_at(&self, _: u64) -> Option<L1Block> {
        None
    }
}

#[test]
fn missing_rpc_blocks_do_not_erase_history_or_fabricate_reorg_alarm() {
    let (mut watcher, _) = fixture(1, 24);
    let before = watcher.state();
    assert!(watcher.sync(&MissingSource).is_empty());
    assert_eq!(watcher.state(), before);
    assert!(watcher.credit_reorg_alarms().is_empty());
}

#[test]
fn genesis_validator_refuses_missing_or_moved_withdrawal_bridge() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let original = load_config(&default_config_path()).unwrap();
    let mut missing = original.clone();
    missing.predeploys.retain(|p| p.name != "L2BlochBridge");
    assert!(validate(&missing, root).is_err());
    let mut moved = original;
    moved
        .predeploys
        .iter_mut()
        .find(|p| p.name == "L2BlochBridge")
        .unwrap()
        .address = "0x4200000000000000000000000000000000000011".to_string();
    assert!(validate(&moved, root).is_err());
}

#[test]
fn genesis_validator_refuses_duplicate_predeploys_and_address_aliases() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let original = load_config(&default_config_path()).unwrap();
    for alias in [false, true] {
        let mut config = original.clone();
        let mut duplicate = config.predeploys[0].clone();
        if alias {
            duplicate.name = "AliasAtWblchAddress".to_string();
        }
        config.predeploys.push(duplicate);
        assert!(validate(&config, root).is_err());
    }
}

#[test]
fn restore_and_failed_sync_require_fresh_view_before_mint_retry() {
    let (watcher, source) = fixture(1, 24);
    let mut restored = DepositWatcher::from_state(watcher.state()).unwrap();
    assert_eq!(restored.creditable().count(), 0);
    assert!(restored.try_sync(&source).unwrap().is_empty());
    assert_eq!(restored.creditable().count(), 1);
    assert!(restored.try_sync(&MissingSource).is_err());
    assert_eq!(restored.creditable().count(), 0);
    restored.try_sync(&source).unwrap();
    assert_eq!(restored.creditable().count(), 1);
}

#[test]
fn restore_binds_independently_trusted_configuration() {
    let (watcher, _) = fixture(1, 24);
    assert!(
        DepositWatcher::from_state_for(watcher.state(), &VaultSet::new([VAULT]), CHAIN).is_ok()
    );
    assert!(
        DepositWatcher::from_state_for(watcher.state(), &VaultSet::new([[0xbb; 20]]), CHAIN)
            .is_err()
    );
    assert!(
        DepositWatcher::from_state_for(watcher.state(), &VaultSet::new([VAULT]), CHAIN + 1)
            .is_err()
    );
}

#[test]
fn demoted_deposit_reages_without_second_credit_and_restores() {
    use bloch_l2_bridge::watcher::WatcherUpdate;
    let (mut watcher, full) = fixture(1, 24);
    let mut short = full.clone();
    short.reorg_to(1);
    let updates = watcher.try_sync(&short).unwrap();
    assert!(matches!(
        updates.as_slice(),
        [WatcherUpdate::ConfirmationsLost { .. }]
    ));
    let mut restored = DepositWatcher::from_state(watcher.state()).unwrap();
    assert!(restored.try_sync(&full).unwrap().is_empty());
    assert_eq!(restored.creditable().count(), 1);
    assert_eq!(restored.credited().len(), 1);
}

#[test]
fn demoted_previously_credited_deposit_still_alarms_when_removed() {
    use bloch_l2_bridge::watcher::WatcherUpdate;
    let (mut watcher, mut source) = fixture(1, 24);
    source.reorg_to(1);
    watcher.try_sync(&source).unwrap();
    let mut fork = MemorySource::new();
    fork.push(L1Block {
        height: 0,
        hash: [0xff; 32],
        parent_hash: [0; 32],
        txs: vec![],
    })
    .unwrap();
    let updates = watcher.try_sync(&fork).unwrap();
    assert!(matches!(
        updates.as_slice(),
        [WatcherUpdate::CreditableReorged { .. }]
    ));
    assert_eq!(watcher.credit_reorg_alarms().len(), 1);
    assert_eq!(watcher.credited().len(), 1);
}

#[test]
fn empty_source_is_unavailable_not_proof_of_entire_chain_reorg() {
    let (mut watcher, _) = fixture(1, 24);
    let before = watcher.state();
    assert!(watcher.try_sync(&MemorySource::new()).is_err());
    assert_eq!(watcher.state(), before);
}

#[test]
fn deep_rewind_requires_explicit_work_budget_without_partial_mutation() {
    let (mut watcher, mut source) = fixture(1, 24);
    source.reorg_to(1);
    let before = watcher.state();
    assert!(watcher.try_sync_with_limit(&source, 8).is_err());
    assert_eq!(watcher.state(), before);
    watcher.try_sync_with_limit(&source, 24).unwrap();
    assert_eq!(watcher.tip_height(), Some(0));
    assert!(watcher.try_sync_with_limit(&source, 0).is_err());
}

#[test]
fn catchup_is_chunked_and_only_ages_at_verified_local_depth() {
    let (_, source) = fixture(1, 24);
    let mut watcher = DepositWatcher::new(VaultSet::new([VAULT]), CHAIN);
    watcher.try_sync_with_limit(&source, 8).unwrap();
    assert_eq!(watcher.tip_height(), Some(7));
    assert_eq!(watcher.creditable().count(), 0);
    watcher.try_sync_with_limit(&source, 8).unwrap();
    assert_eq!(watcher.tip_height(), Some(15));
    assert_eq!(watcher.creditable().count(), 0);
    watcher.try_sync_with_limit(&source, 8).unwrap();
    assert_eq!(watcher.creditable().count(), 1);
}

struct FabricatedTip {
    calls: std::cell::Cell<usize>,
}
impl BlockSource for FabricatedTip {
    fn tip_height(&self) -> Option<u64> {
        Some(u64::MAX)
    }
    fn block_at(&self, height: u64) -> Option<L1Block> {
        self.calls.set(self.calls.get() + 1);
        assert!(
            self.calls.get() <= 20,
            "sync exceeded the explicit request budget"
        );
        let mut hash = [0; 32];
        hash[..8].copy_from_slice(&height.to_le_bytes());
        let mut parent_hash = [0; 32];
        parent_hash[..8].copy_from_slice(&height.saturating_sub(1).to_le_bytes());
        Some(L1Block {
            height,
            hash,
            parent_hash,
            txs: vec![],
        })
    }
}

#[test]
fn arbitrary_u64_tip_cannot_force_unbounded_catchup() {
    let source = FabricatedTip {
        calls: std::cell::Cell::new(0),
    };
    let mut watcher = DepositWatcher::new(VaultSet::new([VAULT]), CHAIN);
    watcher.try_sync_with_limit(&source, 8).unwrap();
    assert_eq!(watcher.tip_height(), Some(7));
    assert!(source.calls.get() <= 20);
}

struct WrongHeightSource(MemorySource);
impl BlockSource for WrongHeightSource {
    fn tip_height(&self) -> Option<u64> {
        self.0.tip_height()
    }
    fn block_at(&self, height: u64) -> Option<L1Block> {
        self.0.block_at(height).map(|mut block| {
            block.height += 1;
            block
        })
    }
}

#[test]
fn wrong_height_even_with_matching_hash_is_refused_atomically() {
    let (mut watcher, source) = fixture(1, 24);
    let before = watcher.state();
    assert!(watcher.try_sync(&WrongHeightSource(source)).is_err());
    assert_eq!(watcher.state(), before);
}

#[cfg(unix)]
#[test]
fn source_symlink_cannot_escape_crate_root() {
    use bloch_l2_bridge::harness::resolve_source_path;
    use std::os::unix::fs::symlink;
    let suffix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("bloch-source-{suffix}-{}", std::process::id()));
    std::fs::create_dir(&dir).unwrap();
    let root = dir.join("crate");
    std::fs::create_dir(&root).unwrap();
    std::fs::write(dir.join("outside.sol"), "outside").unwrap();
    symlink(dir.join("outside.sol"), root.join("linked.sol")).unwrap();
    let result = resolve_source_path(&root, "linked.sol");
    std::fs::remove_dir_all(&dir).unwrap();
    assert!(result.is_err());
}

#[test]
fn historical_and_current_roots_match_independent_python_and_evm_vectors() {
    use bloch_l2_bridge::{WithdrawalMessage, WithdrawalQueue};
    let mut queue = WithdrawalQueue::new();
    for nonce in 0..17 {
        queue
            .initiate(WithdrawalMessage {
                nonce,
                l2_sender: [0xaa; 20],
                l1_recipient: [0xbb; 20],
                amount_atoms: nonce + 1,
                epoch_number: nonce / 3,
            })
            .unwrap();
    }
    // Generated with the independent Python Keccak implementation; also
    // executed against the genesis predeploy in BridgeSecurity.t.sol.
    for (count, expected) in [
        (
            7,
            "2a4786e095abbcdfd22cc0056887d00e211109adc3e9074e52cbabc124a7d961",
        ),
        (
            17,
            "100fec66641dbfe9ea1ca07da955144d82c7794dd4aadecf957a593f8760064f",
        ),
    ] {
        for index in 0..count {
            let bundle = queue.prove_at(index, count).unwrap();
            assert_eq!(bloch_l2_bridge::hex::encode(&bundle.root), expected);
            assert_eq!(Some(bundle.root), queue.root_at(count));
            assert!(bundle.verify().is_included());
        }
    }
}
