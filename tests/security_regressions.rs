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
                            TxOutput { value: amount, script_pubkey: VAULT.to_vec() },
                            TxOutput {
                                value: 0,
                                script_pubkey: DepositEnvelope {
                                    l2_chain_id: CHAIN,
                                    l2_recipient: [0x22; 20],
                                }.encode().to_vec(),
                            },
                        ],
                    }]
                } else { vec![] },
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
    state.tracked[0].0.0 = [0xff; 32];
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
    fn tip_height(&self) -> Option<u64> { Some(23) }
    fn block_at(&self, _: u64) -> Option<L1Block> { None }
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
    moved.predeploys.iter_mut().find(|p| p.name == "L2BlochBridge").unwrap().address =
        "0x4200000000000000000000000000000000000011".to_string();
    assert!(validate(&moved, root).is_err());
}

#[test]
fn genesis_validator_refuses_duplicate_predeploys_and_address_aliases() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let original = load_config(&default_config_path()).unwrap();
    for alias in [false, true] {
        let mut config = original.clone();
        let mut duplicate = config.predeploys[0].clone();
        if alias { duplicate.name = "AliasAtWblchAddress".to_string(); }
        config.predeploys.push(duplicate);
        assert!(validate(&config, root).is_err());
    }
}
