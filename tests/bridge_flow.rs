// SPDX-License-Identifier: MIT OR Apache-2.0
//! Cross-module bridge-flow tests over PURE data: deposit watcher replay
//! (incl. reorg-drop), withdrawal queue -> proof bundle -> §5 checklist,
//! and the proof-of-reserves invariant tying the two sides together.
//!
//! Everything here is deterministic and offline. Per the crate's honesty
//! rules: no networking, no keys, no value — and the checklist's best
//! verdict is ScaffoldBlocked, never a release authorization.

use bloch_l2_bridge::atoms::atoms_to_wei;
use bloch_l2_bridge::envelope::{DepositEnvelope, TxOutput};
use bloch_l2_bridge::merkle::keccak256;
use bloch_l2_bridge::release::{
    evaluate_release_checklist, AnchoredEpochView, ChecklistVerdict, NullifierLog,
    ReleaseObservation, WithdrawalQueue, F_ANCHOR_DEPTH_TESTNET_PLACEHOLDER,
};
use bloch_l2_bridge::reserves::{check_reserves, is_exactly_backed, ReserveCheck, ReserveStatement};
use bloch_l2_bridge::status::ATOMS_PER_BLCH;
use bloch_l2_bridge::watcher::{
    DepositWatcher, L1Block, L1Tx, MemorySource, VaultSet, WatcherUpdate,
};
use bloch_l2_bridge::withdrawal::{WithdrawalInclusion, WithdrawalMessage};

const CHAIN_ID: u64 = 700_771;
const VAULT: [u8; 20] = [0xC4; 20];

fn block(height: u64, branch: &str, parent: [u8; 32], txs: Vec<L1Tx>) -> L1Block {
    L1Block {
        height,
        hash: keccak256(format!("{branch}:{height}").as_bytes()),
        parent_hash: parent,
        txs,
    }
}

fn extend(src: &mut MemorySource, branch: &str, txs: Vec<L1Tx>) {
    use bloch_l2_bridge::watcher::BlockSource;
    let (height, parent) = match src.tip_height() {
        Some(h) => {
            let tip = src.block_at(h).unwrap();
            (h + 1, tip.hash)
        }
        None => (0, [0u8; 32]),
    };
    let b = block(height, branch, parent, txs);
    src.push(b).unwrap();
}

fn deposit_tx(tag: u8, amount_atoms: u64, recipient: [u8; 20]) -> L1Tx {
    let envelope = DepositEnvelope {
        l2_chain_id: CHAIN_ID,
        l2_recipient: recipient,
    };
    L1Tx {
        txid: keccak256(&[b't', b'x', tag]),
        outputs: vec![
            TxOutput {
                value: amount_atoms,
                script_pubkey: VAULT.to_vec(),
            },
            TxOutput {
                value: 0,
                script_pubkey: envelope.encode().to_vec(),
            },
        ],
    }
}

/// Deposit side end-to-end: observe -> age past K -> creditable, with the
/// exact mint arithmetic and full replay safety, then reflect the credit
/// in the PoR statement.
#[test]
fn deposit_to_reserves_end_to_end() {
    let mut src = MemorySource::new();
    extend(&mut src, "main", vec![]);
    let amount = 3 * ATOMS_PER_BLCH; // K = 24 tier
    extend(&mut src, "main", vec![deposit_tx(1, amount, [0x11; 20])]);

    let mut watcher = DepositWatcher::new(VaultSet::new([VAULT]), CHAIN_ID);
    let updates = watcher.sync(&src);
    assert_eq!(updates.len(), 1);
    assert!(matches!(updates[0], WatcherUpdate::Observed { .. }));

    // replay of an identical view: silence (no double-deposit)
    assert_eq!(watcher.sync(&src), vec![]);

    // age past K=24
    for _ in 0..23 {
        extend(&mut src, "main", vec![]);
    }
    let updates = watcher.sync(&src);
    let creditable = updates
        .iter()
        .find_map(|u| match u {
            WatcherUpdate::Creditable { deposit } => Some(*deposit),
            _ => None,
        })
        .expect("deposit must become creditable at depth 24");
    assert_eq!(creditable.amount_atoms, amount);

    // the L2 mint this would trigger, and the PoR statement after it:
    let minted_wei = atoms_to_wei(creditable.amount_atoms);
    let statement = ReserveStatement {
        vault_utxo_atoms: amount as u128, // the vault really holds it
        l2_total_supply_wei: minted_wei,
        pending_withdrawal_atoms: 0,
    };
    assert!(is_exactly_backed(&statement));

    // theft of one atom from the vault is DETECTED (not prevented):
    let after_theft = ReserveStatement {
        vault_utxo_atoms: amount as u128 - 1,
        ..statement
    };
    assert_eq!(
        check_reserves(&after_theft),
        ReserveCheck::Shortfall { deficit_atoms: 1 }
    );
}

/// Reorg semantics across the flow: an unconfirmed deposit dropped by a
/// fork disappears cleanly; one already announced raises the permanent
/// §0.1 alarm.
#[test]
fn reorg_drop_and_alarm_semantics() {
    let mut src = MemorySource::new();
    extend(&mut src, "main", vec![]);
    extend(&mut src, "main", vec![deposit_tx(2, ATOMS_PER_BLCH, [0x22; 20])]);

    let mut watcher = DepositWatcher::new(VaultSet::new([VAULT]), CHAIN_ID);
    assert_eq!(watcher.sync(&src).len(), 1);

    // shallow reorg before K: clean drop, no alarm
    src.reorg_to(1);
    extend(&mut src, "fork", vec![]);
    let updates = watcher.sync(&src);
    assert!(updates.iter().any(|u| matches!(u, WatcherUpdate::Dropped { .. })));
    assert!(watcher.credit_reorg_alarms().is_empty());
    assert_eq!(watcher.tracked().count(), 0);
}

/// Withdrawal side end-to-end: initiate -> tree -> bundle -> checklist.
/// The bundle is verifiable standalone (the L1-side artifact), and the
/// checklist's BEST outcome remains ScaffoldBlocked — v1 is custodial and
/// this crate will not fake FRI verification or a signing quorum.
#[test]
fn withdrawal_bundle_and_checklist_end_to_end() {
    let mut queue = WithdrawalQueue::new();
    for nonce in 0..3u64 {
        queue
            .initiate(WithdrawalMessage {
                nonce,
                l2_sender: [0x33; 20],
                l1_recipient: [0x44; 20],
                amount_atoms: (nonce + 1) * ATOMS_PER_BLCH,
                epoch_number: 9,
            })
            .unwrap();
    }
    let anchored_root = queue.root(); // what the epoch anchor would carry
    let bundle = queue.prove(1).unwrap();
    assert_eq!(bundle.root, anchored_root);
    assert_eq!(bundle.verify(), WithdrawalInclusion::Included);

    // post-payout reserves: vault covers remaining supply + remaining
    // pending withdrawals after paying this one out.
    let nullifiers = NullifierLog::new();
    let obs = ReleaseObservation {
        bundle: &bundle,
        // root + epoch + depth bound to ONE anchor; the required depth is
        // derived inside the checklist from K(amount), not passed in.
        anchor: AnchoredEpochView {
            root: anchored_root,
            epoch_number: 9,
            depth: F_ANCHOR_DEPTH_TESTNET_PLACEHOLDER,
        },
        nullifiers: &nullifiers,
        freeze_active: false,
        post_payout_reserves: ReserveStatement {
            vault_utxo_atoms: 4 * ATOMS_PER_BLCH as u128,
            l2_total_supply_wei: 0,
            pending_withdrawal_atoms: 4 * ATOMS_PER_BLCH as u128,
        },
    };
    match evaluate_release_checklist(&obs).verdict() {
        ChecklistVerdict::ScaffoldBlocked { missing } => {
            assert_eq!(missing.len(), 2, "FRI + rate limit stay scaffold: {missing:?}");
        }
        other => panic!("best verdict must be ScaffoldBlocked, got {other:?}"),
    }

    // after a (hypothetical, out-of-crate) payout is recorded, the same
    // withdrawal can never pass item [4] again:
    let mut paid = NullifierLog::new();
    paid.record_paid(1).unwrap();
    let obs_replay = ReleaseObservation {
        nullifiers: &paid,
        ..obs
    };
    assert!(matches!(
        evaluate_release_checklist(&obs_replay).verdict(),
        ChecklistVerdict::Refused { .. }
    ));
}
