//! Review 330 (round 17, second pass of the Solana bridge review): its demonstrations and attack cases against
//! the vault program, on the built program in the in-process SVM. Brought into the developer's line by agent 336.
//!
//! The program image did not change in round 17 (coordinator's decision: the fixes of R330-SOL-1 and R330-SOL-3
//! are in the tools and the periphery; sha256 33f7027d...7316). Two of the reviewer's demonstrations therefore
//! still describe what the PROGRAM does, and they are RESTATED rather than inverted, with the reason:
//!
//!   r330_sol_1_the_vault_pays_curve_points_that_are_not_wallets
//!     -> program_boundary_r330_sol_1_the_vault_pays_whatever_wallet_bytes_were_certified
//!        The program sees 32 bytes that hash to the burn's 20 and cannot read who owns an address it is not
//!        given. The rule "the destination is a wallet" is the signers' (sol_recipient.destination, read at
//!        `finalized`) and the router's (small-order points, the mint, the token programs). The test stays as
//!        the statement of that boundary: an approval certified by five signers is paid.
//!   r330_sol_3_zero_retention_closes_a_record_in_the_transaction_that_pays_it
//!     -> program_boundary_r330_sol_3_zero_retention_is_valid_for_the_program
//!        The program's bound on `record_retention` is an upper one only. The floor (259,200 s) is in the
//!        mainnet policy of the tools and the deploy check (solana_lib.retention_floor, sol_vault.py validate,
//!        init and verify), which refuse this configuration; tools/signatario-solana/test_r330_review.py.
//!
//! `r330_sol_6_*` (Info) is unchanged behaviour, now documented (docs/SOLANA-VAULT.md 11). The tests named
//! `attack_*` are attacks that the program refuses; they pass because the program holds.

mod common;
use common::*;
use solana_address::Address;
use solana_instruction::{account_meta::AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_signer::Signer;

const L2: Addr20 = [0x11; 20];

/// The identity point of Ed25519 (y = 1): on the curve, of order 1. No private key exists for it.
fn identity_point() -> Address {
    let mut b = [0u8; 32];
    b[0] = 1;
    Address::new_from_array(b)
}

/// R330-SOL-1 (program side). The vault pays the associated token account of ANY 32 bytes that hash to the burn's
/// 20 bytes. Two addresses that are points of the curve and are not wallets: the address of the mint itself (a
/// token-program account created at a keypair address, as Circle's USDC mint is), and the identity point, for
/// which no key can exist. Since round 17 the router refuses both and the signers hold both (forge test
/// R330SolanaBurnRouter, tool test test_r330_review.py, and the validator rehearsal); the program itself, given an
/// approval for them, still pays: it is the last link and cannot know. Restated, see the head of this file.
#[test]
fn program_boundary_r330_sol_1_the_vault_pays_whatever_wallet_bytes_were_certified() {
    let mut rig = Rig::new();
    rig.deposit(500 * USDC, L2);
    let payer = rig.payer.pubkey();
    let mint = rig.mint;
    for (nonce, owner) in [(1u64, mint), (2u64, identity_point())] {
        let r = rig.release_for(nonce, &owner, 100 * USDC);
        ok(rig.approve(&r));
        // Anyone creates the associated token account of any address: the program does not ask who the owner is.
        let create = create_ata_ix(&payer, &owner, &mint);
        ok(rig.send(&[create]));
        ok(rig.execute(nonce, &owner));
        assert_eq!(token_balance(&rig.svm, &ata(&owner, &mint)), 100 * USDC - 50_000);
    }
    // The first "wallet" is a mint account of the token program, the second does not exist as an account.
    assert_eq!(rig.svm.get_account(&mint).unwrap().owner, token_program());
    assert!(rig.svm.get_account(&identity_point()).is_none());
    rig.check_backing();
}

/// R330-SOL-3. `record_retention` 0 is a valid configuration for the PROGRAM (the tools refuse it since round 17,
/// see the head of this file): the payment and the closing of
/// its record then share one transaction, and no observer ever reads a paid record (amount, recipient, burn).
#[test]
fn program_boundary_r330_sol_3_zero_retention_is_valid_for_the_program() {
    let mut rig = Rig::with(|c| c.record_retention = 0);
    rig.deposit(5_000 * USDC, L2);
    let owner = rig.new_recipient();
    let payer = rig.payer.pubkey();
    let r = rig.release_for(1, &owner, 100 * USDC);
    ok(rig.approve(&r));
    let pay = rig.execute_ix(1, &owner, &ata(&owner, &rig.mint));
    let close = rig.close_ix(1, &payer);
    ok(rig.send(&[pay, close]));
    assert!(rig.paid_bit(1));
    assert!(rig.svm.get_account(&rig.release_record(1)).map(|a| a.lamports == 0).unwrap_or(true), "no paid record was ever visible");
    assert_eq!(token_balance(&rig.svm, &ata(&owner, &rig.mint)), 100 * USDC - 50_000);
}

/// Info (R330-SOL-6): a recipient who gives the ownership of its associated token account away (classic SPL
/// `SetAuthority`, which associated accounts of the classic program allow) can no longer be paid: the payment
/// requires the account at the wallet's associated address to be owned by the wallet.
#[test]
fn r330_sol_6_a_wallet_whose_associated_account_changed_owner_cannot_be_paid() {
    let mut rig = Rig::new();
    rig.deposit(500 * USDC, L2);
    let wallet = Keypair::new();
    rig.svm.airdrop(&wallet.pubkey(), 1_000_000_000).unwrap();
    let other = Keypair::new().pubkey();
    let payer = rig.payer.pubkey();
    let create = create_ata_ix(&payer, &wallet.pubkey(), &rig.mint);
    ok(rig.send(&[create]));
    let r = rig.release_for(1, &wallet.pubkey(), 100 * USDC);
    ok(rig.approve(&r));
    // TokenInstruction::SetAuthority { authority_type: AccountOwner (2), new_authority: Some(other) }
    let mut data = vec![6u8, 2, 1];
    data.extend_from_slice(other.as_ref());
    let set = Instruction {
        program_id: token_program(),
        accounts: vec![AccountMeta::new(ata(&wallet.pubkey(), &rig.mint), false), AccountMeta::new_readonly(wallet.pubkey(), true)],
        data,
    };
    ok(send(&mut rig.svm, &wallet, &[], &[set]));
    refused(rig.execute(1, &wallet.pubkey()), E_RECIPIENT);
    refused(rig.execute(1, &other), E_RECIPIENT);
}

// ── attacks the program refuses ─────────────────────────────────────────────

/// A paid record is closed and, in the same transaction, lamports are sent back to its address so that the
/// emptied account survives. The nonce stays spent, and nothing can be done with the surviving account.
#[test]
fn attack_closed_record_kept_alive_in_the_same_transaction_stays_spent() {
    let mut rig = Rig::new();
    rig.deposit(5_000 * USDC, L2);
    let owner = rig.new_recipient();
    let payer = rig.payer.pubkey();
    let r = rig.release_for(7, &owner, 100 * USDC);
    ok(rig.approve(&r));
    ok(rig.execute(7, &owner));
    rig.advance(604_800);
    let record = rig.release_record(7);
    let close = rig.close_ix(7, &payer);
    ok(rig.send(&[close, system_transfer(&payer, &record, 5_000_000)]));
    let left = rig.svm.get_account(&record).expect("the emptied account survives with the lamports sent to it");
    assert_eq!(left.owner, rig.program);
    assert_eq!(left.data.len(), 208);
    assert!(left.data.iter().all(|b| *b == 0));
    assert!(rig.paid_bit(7));
    let again = rig.release_for(7, &owner, 100 * USDC);
    refused(rig.approve(&again), E_ALREADY);
    refused(rig.execute(7, &owner), E_ACCOUNT);
    let close = rig.close_ix(7, &payer);
    refused(rig.send(&[close]), E_ACCOUNT);
    let before = token_balance(&rig.svm, &ata(&owner, &rig.mint));
    assert_eq!(before, 100 * USDC - 50_000);
    rig.check_backing();
}

/// One certificate, two vault instructions behind it: the second one looks at the instruction before itself,
/// which is the first approval, not a secp256k1 verification. A certificate is counted once.
#[test]
fn attack_one_certificate_cannot_serve_two_instructions() {
    let mut rig = Rig::new();
    rig.deposit(5_000 * USDC, L2);
    let owner = rig.new_recipient();
    let a = rig.release_for(1, &owner, 100 * USDC);
    let b = rig.release_for(2, &owner, 100 * USDC);
    let mut ixs = rig.approve_ixs(&a, 5);
    ixs.push(rig.approve_ix(&b));
    refused(rig.send(&ixs), E_CERT);
    // The same approval twice behind one certificate.
    let mut ixs = rig.approve_ixs(&a, 5);
    ixs.push(rig.approve_ix(&a));
    refused(rig.send(&ixs), E_CERT);
    // A release certificate in front of a guardian pause, a control change and an unpause: each computes its own
    // authorization, and the committee's signatures over a release are not a signature over any of them.
    let now = rig.now();
    for data in [
        [vec![4u8], (now + 600).to_le_bytes().to_vec()].concat(),
        [vec![6u8, 0, 0], 1u64.to_le_bytes().to_vec(), (now + 600).to_le_bytes().to_vec()].concat(),
    ] {
        let mut ixs = rig.approve_ixs(&a, 5);
        ixs[1] = Instruction {
            program_id: rig.program,
            accounts: vec![AccountMeta::new(rig.vault, false), AccountMeta::new_readonly(instructions_sysvar(), false)],
            data,
        };
        refused(rig.send(&ixs), E_CERT);
    }
    // Two certificates and two approvals of the same release in one transaction: the second is a replay.
    let mut ixs = rig.approve_ixs(&a, 5);
    let mut second = rig.approve_ixs(&a, 5);
    // the second secp256k1 instruction sits at index 2 and must say so in its offsets
    let signers: Vec<&EthKey> = rig.signers.iter().take(5).collect();
    second[0] = secp_ix(secp_data(&signers, &rig.release_authorization(&a), 2));
    ixs.extend(second);
    let size = tx_size(&rig.payer, &ixs);
    if size <= 1232 {
        refused(rig.send(&ixs), E_ALREADY);
    }
    ok(rig.approve(&a));
    ok(rig.approve(&b));
}

/// Deposit candidates: the same record address named eight times, and candidates that are other accounts of the
/// vault (its own account, its token account, an existing deposit record). Only the record of the count found is
/// created; nothing else is written.
#[test]
fn attack_deposit_candidates_cannot_touch_other_accounts() {
    let mut rig = Rig::new();
    rig.deposit(100 * USDC, L2);
    let (user, source) = rig.fund_user(300 * USDC);
    let mut ix = rig.deposit_ix(&user.pubkey(), &source, 100 * USDC, &L2);
    let right = rig.deposit_record(1);
    for _ in 0..7 {
        ix.accounts.push(AccountMeta::new(right, false));
    }
    ok(send(&mut rig.svm, &user, &[], &[ix]));
    assert_eq!(rig.state().deposit_count, 2);
    let first_before = rig.svm.get_account(&rig.deposit_record(0)).unwrap().data;
    let mut ix = rig.deposit_ix(&user.pubkey(), &source, 100 * USDC, &L2);
    ix.accounts[5] = AccountMeta::new(rig.deposit_record(0), false); // an existing record in the first place
    ix.accounts.push(AccountMeta::new(rig.vault, false));
    ix.accounts.push(AccountMeta::new(rig.tokens, false));
    ix.accounts.push(AccountMeta::new(rig.deposit_record(2), false));
    ok(send(&mut rig.svm, &user, &[], &[ix]));
    assert_eq!(rig.state().deposit_count, 3);
    assert_eq!(rig.svm.get_account(&rig.deposit_record(0)).unwrap().data, first_before);
    // No candidate is the record of the count found: nothing moves.
    let mut ix = rig.deposit_ix(&user.pubkey(), &source, 100 * USDC, &L2);
    ix.accounts[5] = AccountMeta::new(rig.deposit_record(0), false);
    refused(send(&mut rig.svm, &user, &[], &[ix]), E_ACCOUNT);
    assert_eq!(token_balance(&rig.svm, &source), 100 * USDC);
    rig.check_backing();
}

/// The record of a release is closed by a stranger who names himself, the vault, the page or the record as the
/// account that receives the rent; and a record of another vault's nonce is offered. All refused.
#[test]
fn attack_rent_of_a_closed_record_goes_nowhere_else() {
    let mut rig = Rig::new();
    rig.deposit(5_000 * USDC, L2);
    let owner = rig.new_recipient();
    let payer = rig.payer.pubkey();
    let r = rig.release_for(3, &owner, 100 * USDC);
    ok(rig.approve(&r));
    ok(rig.execute(3, &owner));
    rig.advance(604_800);
    for refund in [owner, rig.vault, rig.paid_page(3), rig.release_record(3), rig.tokens] {
        let ix = rig.close_ix(3, &refund);
        failed(rig.send(&[ix]));
    }
    // The nonce in the data differs from the record given.
    let mut ix = rig.close_ix(3, &payer);
    ix.data = [vec![8u8], 4u64.to_le_bytes().to_vec()].concat();
    failed(rig.send(&[ix]));
    assert!(!rig.paid_bit(3) && !rig.paid_bit(4));
    let ix = rig.close_ix(3, &payer);
    ok(rig.send(&[ix]));
    assert!(rig.paid_bit(3));
}

/// A guardian pause between approval and payment, then the pause runs out: the approval stays void, the same
/// certificate is dead, a re-approval by another fee payer keeps the first payer as the one the rent returns to,
/// and the release is paid once.
#[test]
fn attack_voided_approval_reapproved_by_another_payer_keeps_the_rent_owner() {
    let mut rig = Rig::new();
    rig.deposit(5_000 * USDC, L2);
    let owner = rig.new_recipient();
    let first_payer = rig.payer.pubkey();
    let r = rig.release_for(5, &owner, 2_000 * USDC);
    ok(rig.approve(&r));
    ok(rig.guardian_pause(0, 1));
    rig.advance(259_200);
    refused(rig.execute(5, &owner), E_VOIDED);
    let other = Keypair::new();
    rig.svm.airdrop(&other.pubkey(), 10_000_000_000).unwrap();
    let fresh = rig.release_for(5, &owner, 2_000 * USDC);
    let mut ixs = rig.approve_ixs(&fresh, 5);
    ixs[1].accounts[0] = AccountMeta::new(other.pubkey(), true);
    ok(send(&mut rig.svm, &other, &[], &ixs));
    let data = rig.svm.get_account(&rig.release_record(5)).unwrap().data;
    assert_eq!(&data[176..208], first_payer.as_ref());
    rig.advance(3_600);
    ok(rig.execute(5, &owner));
    refused(rig.execute(5, &owner), E_ALREADY);
    rig.advance(604_800);
    let ix = rig.close_ix(5, &other.pubkey());
    refused(rig.send(&[ix]), E_ACCOUNT);
    let ix = rig.close_ix(5, &first_payer);
    ok(rig.send(&[ix]));
    rig.check_backing();
}
