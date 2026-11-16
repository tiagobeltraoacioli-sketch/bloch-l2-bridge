//! The vault program, built for SBF, in an in-process SVM: honest paths, limits, and the attacks a bridge of this
//! shape is known to fall to (forged and replayed releases, a secp256k1 verification that belongs to another
//! program, another instruction or other bytes, wrong mint, wrong token accounts, fake state accounts).

mod common;
use common::*;
use solana_address::Address;
use solana_instruction::{account_meta::AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_signer::Signer;

const L2: Addr20 = [0x11; 20];

/// The rig's committee keys (the same deterministic throwaway keys), not borrowed from the rig.
fn committee() -> &'static [EthKey] {
    Box::leak(keys(7, 1).into_boxed_slice())
}

// ── initialization ──────────────────────────────────────────────────────────

#[test]
fn initialize_fixes_everything_and_takes_no_authority() {
    let rig = Rig::new();
    let d = rig.vault_data();
    assert_eq!(d[0], 1);
    // config bytes are stored verbatim after the 36-byte header
    assert_eq!(&d[36..36 + 280], &rig.config.encode()[..280]);
    let derived = 4 + 32 + 280 + 320 + 140;
    assert_eq!(&d[derived..derived + 20], &rig.vault20);
    assert_eq!(&d[derived + 20..derived + 40], &rig.mint20);
    assert_eq!(&d[derived + 40..derived + 72], &rig.route);
    assert_eq!(&d[derived + 72..derived + 104], &rig.genesis);
    assert_eq!(&d[derived + 104..derived + 136], rig.tokens.as_ref());
    assert_eq!(&d[derived + 136..derived + 168], ata(&rig.fee_owner, &rig.mint).as_ref());
    assert_eq!(rig.state().head, rig.genesis);
    // the vault's token account: the mint, owned (token authority) by the vault address, empty, no delegate,
    // no close authority
    let t = rig.svm.get_account(&rig.tokens).unwrap();
    assert_eq!(t.owner, token_program());
    assert_eq!(&t.data[0..32], rig.mint.as_ref());
    assert_eq!(&t.data[32..64], rig.vault.as_ref());
    assert_eq!(token_balance(&rig.svm, &rig.tokens), 0);
    assert_eq!(&t.data[72..76], &[0, 0, 0, 0], "no delegate");
    assert_eq!(&t.data[129..133], &[0, 0, 0, 0], "no close authority");
}

#[test]
fn initialize_twice_or_at_another_address_is_refused() {
    let mut rig = Rig::new();
    let ix = initialize_ix(&rig.program, &rig.payer.pubkey(), &rig.config);
    refused(rig.send(&[ix]), E_ACCOUNT);
    // Other values give another address: the same accounts with a changed configuration do not match.
    let mut other = rig.config.clone();
    other.cap += 1;
    let mut ix = initialize_ix(&rig.program, &rig.payer.pubkey(), &other);
    let (fresh_vault, _) = vault_address(&rig.program, &other);
    assert_ne!(fresh_vault, rig.vault);
    ix.accounts[1] = AccountMeta::new(rig.vault, false);
    refused(rig.send(&[ix]), E_ACCOUNT);
}

#[test]
fn initialize_refuses_an_upgradeable_program() {
    let mut rig = Rig::uninitialized(|_| {});
    // Rewrite the program data header as the loader writes it for a program that still has an upgrade authority.
    let pd = program_data(&rig.program);
    let mut account = rig.svm.get_account(&pd).unwrap();
    account.data[12] = 1;
    account.data[13..45].copy_from_slice(Keypair::new().pubkey().as_ref());
    rig.svm.set_account(pd, account).unwrap();
    let ix = initialize_ix(&rig.program, &rig.payer.pubkey(), &rig.config);
    refused(rig.send(&[ix]), E_UPGRADEABLE);
    // A look-alike program data account at another address is not accepted either.
    let fake = Keypair::new().pubkey();
    let mut data = vec![0u8; 45];
    data[0] = 3;
    rig.set_raw_account(fake, loader(), data);
    let mut ix = initialize_ix(&rig.program, &rig.payer.pubkey(), &rig.config);
    ix.accounts[4] = AccountMeta::new_readonly(fake, false);
    refused(rig.send(&[ix]), E_ACCOUNT);
}

#[test]
fn initialize_refuses_bad_configurations() {
    let cases: Vec<(&str, Box<dyn Fn(&mut Config)>)> = vec![
        ("fee above 30 bps", Box::new(|c| c.deposit_fee_bps = 31)),
        ("release fee above 30 bps", Box::new(|c| c.release_fee_bps = 31)),
        ("threshold 1", Box::new(|c| c.threshold = 1)),
        ("threshold above the set", Box::new(|c| c.threshold = 8)),
        ("switch threshold below threshold", Box::new(|c| c.switch_threshold = 4)),
        ("window above cap", Box::new(|c| c.window_limit = c.cap + 1)),
        ("zero window", Box::new(|c| c.window_seconds = 0)),
        ("zero cap", Box::new(|c| c.cap = 0)),
        ("min deposit nets below the L2 min burn", Box::new(|c| c.min_deposit = c.l2_min_burn)),
        ("signers not ascending", Box::new(|c| c.signers.swap(0, 1))),
        ("duplicate signer", Box::new(|c| c.signers[1] = c.signers[0])),
        ("zero signer", Box::new(|c| c.signers[0] = [0; 20])),
        ("guardian is a signer", Box::new(|c| c.guardians[0] = c.signers[0])),
        ("guardians not ascending", Box::new(|c| c.guardians.swap(0, 1))),
        ("cooldown below duration", Box::new(|c| c.pause_cooldown = c.pause_duration - 1)),
        ("pause above 14 days", Box::new(|c| c.pause_duration = 14 * 86_400 + 1)),
        ("release delay above 14 days", Box::new(|c| c.release_delay = 14 * 86_400 + 1)),
        ("large threshold without a delay", Box::new(|c| c.release_delay = 0)),
        ("validity window too long", Box::new(|c| c.max_valid_seconds = 86_401)),
        ("zero chain id", Box::new(|c| c.source_chain_id = [0; 32])),
        ("same domains", Box::new(|c| c.native_domain = c.source_domain)),
        ("zero fee owner", Box::new(|c| c.fee_owner = Address::new_from_array([0; 32]))),
    ];
    for (name, change) in cases {
        let mut rig = Rig::uninitialized(|c| change(c));
        let ix = initialize_ix(&rig.program, &rig.payer.pubkey(), &rig.config);
        let result = rig.send(&[ix]);
        assert_eq!(custom(&result), Some(E_CONFIG), "{name}: {:?}", result.err().map(|f| f.err));
    }
    // 17 signers or 8 guardians do not parse.
    let mut rig = Rig::uninitialized(|c| c.signers = keys(17, 9).iter().map(|k| k.address).collect());
    let ix = initialize_ix(&rig.program, &rig.payer.pubkey(), &rig.config);
    refused(rig.send(&[ix]), E_CONFIG);
    // Trailing bytes after the configuration are refused (one configuration, one encoding, one address).
    let mut rig = Rig::uninitialized(|_| {});
    let mut ix = initialize_ix(&rig.program, &rig.payer.pubkey(), &rig.config);
    ix.data.push(0);
    failed(rig.send(&[ix]));
}

#[test]
fn initialize_refuses_token_2022_and_other_decimals() {
    // A Token-2022 mint (transfer fees, hooks, permanent delegates live there) is not a classic mint.
    let authority = Keypair::new().pubkey();
    let mut rig = Rig::uninitialized(|_| {});
    let payer = rig.payer.insecure_clone();
    let mint22 = create_mint(&mut rig.svm, &payer, &authority, 6, &token_2022_program());
    rig.config.mint = mint22;
    let ix = initialize_ix(&rig.program, &rig.payer.pubkey(), &rig.config);
    refused(rig.send(&[ix]), E_ACCOUNT);
    // A classic mint with 9 decimals.
    let mut rig = Rig::uninitialized(|_| {});
    let payer = rig.payer.insecure_clone();
    let nine = create_mint(&mut rig.svm, &payer, &authority, 9, &token_program());
    rig.config.mint = nine;
    let ix = initialize_ix(&rig.program, &rig.payer.pubkey(), &rig.config);
    refused(rig.send(&[ix]), E_CONFIG);
}

#[test]
fn initialize_survives_lamports_sent_to_its_addresses_first() {
    let mut rig = Rig::uninitialized(|_| {});
    let ixs = [
        system_transfer(&rig.payer.pubkey(), &rig.vault, 1_000_000),
        system_transfer(&rig.payer.pubkey(), &rig.tokens, 5_000_000_000),
    ];
    ok(rig.send(&ixs));
    let ix = initialize_ix(&rig.program, &rig.payer.pubkey(), &rig.config);
    ok(rig.send(&[ix]));
    assert_eq!(rig.vault_data()[0], 1);
}

// ── deposits ────────────────────────────────────────────────────────────────

#[test]
fn deposit_locks_the_net_amount_and_extends_the_chain() {
    let mut rig = Rig::new();
    let mut users = vec![];
    for (i, amount) in [100 * USDC, 11 * USDC, 9_999 * USDC + 123].into_iter().enumerate() {
        let user = rig.deposit(amount, [i as u8 + 1; 20]);
        users.push((user, amount));
    }
    let s = rig.state();
    assert_eq!(s.deposit_count, 3);
    let fees: u64 = users.iter().map(|(_, a)| a * 5 / 10_000).sum();
    let total: u64 = users.iter().map(|(_, a)| a).sum();
    assert_eq!(s.fees_accrued, fees);
    assert_eq!(s.total_locked, total - fees);
    assert_eq!(token_balance(&rig.svm, &rig.tokens), total);
    assert_eq!(s.head, rig.chain[2].3, "the vault's head is the chain recomputed from the specification");
    for (n, (user, amount)) in users.iter().enumerate() {
        let d = rig.svm.get_account(&rig.deposit_record(n as u64)).unwrap().data;
        assert_eq!(d.len(), 211);
        assert_eq!(d[0], 2);
        assert_eq!(&d[3..35], rig.vault.as_ref());
        assert_eq!(u64::from_le_bytes(d[35..43].try_into().unwrap()), n as u64);
        assert_eq!(&d[43..75], &rig.chain[n].0, "deposit id");
        assert_eq!(&d[43..51], &(n as u64).to_be_bytes(), "the id carries its nonce in the top 8 bytes");
        assert_eq!(&d[75..107], user.pubkey().as_ref());
        assert_eq!(&d[107..127], &account_id(&user.pubkey()));
        assert_eq!(&d[127..147], &[n as u8 + 1; 20]);
        assert_eq!(u64::from_le_bytes(d[147..155].try_into().unwrap()), amount - amount * 5 / 10_000);
        assert_eq!(u64::from_le_bytes(d[155..163].try_into().unwrap()), amount * 5 / 10_000);
        assert_eq!(&d[163..195], &rig.chain[n].3, "head after");
    }
}

#[test]
fn deposit_limits() {
    let mut rig = Rig::with(|c| c.cap = 15_000 * USDC);
    let (user, source) = rig.fund_user(50_000 * USDC);
    let key = user.pubkey();
    let attempt = |rig: &mut Rig, amount: u64, l2: Addr20| {
        let ix = rig.deposit_ix(&key, &source, amount, &l2);
        send(&mut rig.svm, &user, &[], &[ix])
    };
    refused(attempt(&mut rig, 11 * USDC - 1, L2), E_TRANSFER); // below the minimum
    refused(attempt(&mut rig, 10_000 * USDC + 1, L2), E_TRANSFER); // above the window
    refused(attempt(&mut rig, 100 * USDC, [0; 20]), E_TRANSFER); // no L2 recipient
    ok(attempt(&mut rig, 10_000 * USDC, L2));
    refused(attempt(&mut rig, 5_100 * USDC, L2), E_TRANSFER); // above the cap (net 9,995 + 5,097.45)
    ok(attempt(&mut rig, 5_000 * USDC, L2));
    rig.check_backing();
    // Deposits switched off by the committee.
    ok(rig.set_controls(false, true, 1, 5));
    refused(attempt(&mut rig, 11 * USDC, L2), E_TRANSFER);
}

#[test]
fn deposit_before_the_committee_opens_the_vault_is_refused() {
    let mut rig = Rig::uninitialized(|_| {});
    let ix = initialize_ix(&rig.program, &rig.payer.pubkey(), &rig.config);
    ok(rig.send(&[ix]));
    let (user, source) = rig.fund_user(100 * USDC);
    let ix = rig.deposit_ix(&user.pubkey(), &source, 100 * USDC, &L2);
    refused(send(&mut rig.svm, &user, &[], &[ix]), E_TRANSFER);
}

#[test]
fn deposit_refuses_wrong_mint_wrong_token_accounts_and_fake_state() {
    let mut rig = Rig::new();
    let (user, source) = rig.fund_user(1_000 * USDC);
    let payer = rig.payer.insecure_clone();
    let good = rig.deposit_ix(&user.pubkey(), &source, 100 * USDC, &L2);

    // Another classic mint the attacker controls, and a token account of it as the source.
    let evil_authority = Keypair::new();
    let evil_mint = create_mint(&mut rig.svm, &payer, &evil_authority.pubkey(), 6, &token_program());
    let evil_source = ata(&user.pubkey(), &evil_mint);
    let ixs = [
        create_ata_ix(&payer.pubkey(), &user.pubkey(), &evil_mint),
        mint_to_ix(&evil_mint, &evil_source, &evil_authority.pubkey(), 1_000_000 * USDC),
    ];
    ok(send(&mut rig.svm, &payer, &[&evil_authority], &ixs));
    let mut ix = good.clone();
    ix.accounts[4] = AccountMeta::new_readonly(evil_mint, false);
    refused(send(&mut rig.svm, &user, &[], &[ix]), E_ACCOUNT); // wrong mint account
    let mut ix = good.clone();
    ix.accounts[1] = AccountMeta::new(evil_source, false);
    refused(send(&mut rig.svm, &user, &[], &[ix]), E_ACCOUNT); // source of another mint
    let mut ix = good.clone();
    ix.accounts[1] = AccountMeta::new(evil_source, false);
    ix.accounts[4] = AccountMeta::new_readonly(evil_mint, false);
    refused(send(&mut rig.svm, &user, &[], &[ix]), E_ACCOUNT); // both: a worthless token deposited as USDC

    // The "vault token account" is one the attacker owns (the deposit would be credited and kept by the attacker).
    let attacker = Keypair::new().pubkey();
    let attacker_tokens = ata(&attacker, &rig.mint);
    let create = create_ata_ix(&payer.pubkey(), &attacker, &rig.mint);
    ok(send(&mut rig.svm, &payer, &[], &[create]));
    let mut ix = good.clone();
    ix.accounts[3] = AccountMeta::new(attacker_tokens, false);
    refused(send(&mut rig.svm, &user, &[], &[ix]), E_ACCOUNT);
    // Source and destination the same account.
    let mut ix = good.clone();
    ix.accounts[1] = AccountMeta::new(rig.tokens, false);
    refused(send(&mut rig.svm, &user, &[], &[ix]), E_ACCOUNT);

    // A look-alike vault state: the real bytes in an account owned by another program.
    let fake = Keypair::new().pubkey();
    let bytes = rig.vault_data();
    rig.set_raw_account(fake, rig.helper, bytes.clone());
    let mut ix = good.clone();
    ix.accounts[2] = AccountMeta::new(fake, false);
    refused(send(&mut rig.svm, &user, &[], &[ix]), E_ACCOUNT);
    // The real bytes in an account owned by the vault program at an address the configuration does not derive
    // (cannot be created through the program; forced here to prove the address check is independent).
    let forced = Keypair::new().pubkey();
    rig.set_raw_account(forced, rig.program, bytes);
    let mut ix = good.clone();
    ix.accounts[2] = AccountMeta::new(forced, false);
    refused(send(&mut rig.svm, &user, &[], &[ix]), E_ACCOUNT);

    // Another program in the token program's place (it would "transfer" nothing).
    let mut ix = good.clone();
    ix.accounts[6] = AccountMeta::new_readonly(rig.helper, false);
    refused(send(&mut rig.svm, &user, &[], &[ix]), E_ACCOUNT);
    let mut ix = good.clone();
    ix.accounts[6] = AccountMeta::new_readonly(token_2022_program(), false);
    refused(send(&mut rig.svm, &user, &[], &[ix]), E_ACCOUNT);
    // A deposit record address of another nonce.
    let mut ix = good.clone();
    ix.accounts[5] = AccountMeta::new(rig.deposit_record(7), false);
    refused(send(&mut rig.svm, &user, &[], &[ix]), E_ACCOUNT);

    // Someone else's tokens: the depositor signs but is not the token authority. The token program refuses.
    let (victim, victim_source) = rig.fund_user(500 * USDC);
    let mut ix = good.clone();
    ix.accounts[1] = AccountMeta::new(victim_source, false);
    failed(send(&mut rig.svm, &user, &[], &[ix]));
    assert_eq!(token_balance(&rig.svm, &victim_source), 500 * USDC);
    let _ = victim;

    assert_eq!(rig.state().deposit_count, 0);
    ok(send(&mut rig.svm, &user, &[], &[good]));
    assert_eq!(rig.state().deposit_count, 1);
}

#[test]
fn deposit_record_address_cannot_be_blocked_with_lamports() {
    let mut rig = Rig::new();
    let record = rig.deposit_record(0);
    // (The runtime refuses to leave less than the rent-exempt minimum in a new account.)
    let ix = system_transfer(&rig.payer.pubkey(), &record, 1_000_000);
    ok(rig.send(&[ix]));
    rig.deposit(100 * USDC, L2);
    assert_eq!(rig.svm.get_account(&record).unwrap().owner, rig.program);
}

#[test]
fn tokens_sent_to_the_vault_directly_change_no_accounting() {
    let mut rig = Rig::new();
    rig.deposit(100 * USDC, L2);
    let (donor, source) = rig.fund_user(50 * USDC);
    let ix = token_transfer_ix(&source, &rig.tokens, &donor.pubkey(), 50 * USDC);
    ok(send(&mut rig.svm, &donor, &[], &[ix]));
    let s = rig.state();
    assert_eq!(s.total_locked + s.fees_accrued, 100 * USDC);
    rig.deposit(100 * USDC, L2);
    rig.check_backing();
}

// ── releases ────────────────────────────────────────────────────────────────

#[test]
fn release_pays_the_committed_wallet_once_less_the_fee() {
    let mut rig = Rig::new();
    rig.deposit(500 * USDC, L2);
    let owner = rig.new_recipient();
    let r = rig.release_for(0, &owner, 200 * USDC);
    let approve_cu = ok(rig.approve(&r));
    let locked_before = rig.state().total_locked;
    let execute_cu = ok(rig.execute(0, &owner));
    println!("compute units: approve_release with 5 signatures {approve_cu}, execute_release {execute_cu}");
    let fee = 200 * USDC * 5 / 10_000;
    assert_eq!(token_balance(&rig.svm, &ata(&owner, &rig.mint)), 200 * USDC - fee);
    let s = rig.state();
    assert_eq!(s.total_locked, locked_before - 200 * USDC);
    assert_eq!(s.fees_accrued, 500 * USDC * 5 / 10_000 + fee);
    rig.check_backing();
    // Replays: the same certificate again, a fresh certificate for the same nonce, the payment again.
    refused(rig.approve(&r), E_ALREADY);
    let again = rig.release_for(0, &owner, 100 * USDC);
    refused(rig.approve(&again), E_ALREADY);
    refused(rig.execute(0, &owner), E_ALREADY);
    assert_eq!(token_balance(&rig.svm, &ata(&owner, &rig.mint)), 200 * USDC - fee);
}

#[test]
fn approved_but_unpaid_release_cannot_be_replaced() {
    let mut rig = Rig::new();
    rig.deposit(500 * USDC, L2);
    let owner = rig.new_recipient();
    let thief = rig.new_recipient();
    let r = rig.release_for(0, &owner, 200 * USDC);
    ok(rig.approve(&r));
    // Even the committee cannot overwrite a standing approval (only a guardian pause voids it).
    let other = rig.release_for(0, &thief, 200 * USDC);
    refused(rig.approve(&other), E_ALREADY);
    ok(rig.execute(0, &owner));
}

#[test]
fn release_needs_the_threshold_of_distinct_committee_members() {
    let mut rig = Rig::new();
    rig.deposit(500 * USDC, L2);
    let owner = rig.new_recipient();
    let r = rig.release_for(0, &owner, 200 * USDC);
    let auth = rig.release_authorization(&r);
    let approve = rig.approve_ix(&r);

    // 4 of 7.
    refused(rig.send(&rig.approve_ixs(&r, 4)), E_CERT);
    // 5 valid signatures by keys that are not the committee.
    let strangers = keys(5, 77);
    let refs: Vec<&EthKey> = strangers.iter().collect();
    refused(rig.send(&[secp_ix(secp_data(&refs, &auth, 0)), approve.clone()]), E_CERT);
    // 4 members and one stranger.
    let mut mixed: Vec<EthKey> = rig.signers[..4].to_vec();
    mixed.push(strangers[0].clone());
    mixed.sort_by_key(|k| k.address);
    let refs: Vec<&EthKey> = mixed.iter().collect();
    refused(rig.send(&[secp_ix(secp_data(&refs, &auth, 0)), approve.clone()]), E_CERT);
    // One member five times.
    let one = rig.signers[0].clone();
    let refs: Vec<&EthKey> = (0..5).map(|_| &one).collect();
    refused(rig.send(&[secp_ix(secp_data(&refs, &auth, 0)), approve.clone()]), E_CERT);
    // Members in descending order.
    let refs: Vec<&EthKey> = rig.signers[..5].iter().rev().collect();
    refused(rig.send(&[secp_ix(secp_data(&refs, &auth, 0)), approve.clone()]), E_CERT);
    // The 3 guardians and 2 members: guardians are not signers.
    let mut with_guardians: Vec<EthKey> = rig.guardians.clone();
    with_guardians.extend_from_slice(&rig.signers[..2]);
    with_guardians.sort_by_key(|k| k.address);
    let refs: Vec<&EthKey> = with_guardians.iter().collect();
    refused(rig.send(&[secp_ix(secp_data(&refs, &auth, 0)), approve.clone()]), E_CERT);
    // 8 entries (more than the set).
    let mut eight: Vec<&EthKey> = committee().iter().collect();
    eight.push(&strangers[0]);
    failed(rig.send(&[secp_ix(secp_data(&eight, &auth, 0)), approve.clone()]));
    // A corrupted signature: the native program itself fails the transaction.
    let refs: Vec<&EthKey> = committee().iter().take(5).collect();
    let mut data = secp_data(&refs, &auth, 0);
    data[1 + 55 + 10] ^= 1;
    let text = failed(rig.send(&[secp_ix(data), approve.clone()]));
    assert!(text.contains("InstructionError(0"), "{text}");
    // More than the threshold is fine (6 here; whether such a transaction fits a packet is measured in
    // transaction_sizes_and_compute_units).
    ok(rig.send(&rig.approve_ixs(&r, 6)));
}

#[test]
fn certificate_for_one_release_does_not_approve_another() {
    let mut rig = Rig::new();
    rig.deposit(5_000 * USDC, L2);
    let owner = rig.new_recipient();
    let thief = rig.new_recipient();
    let honest = rig.release_for(0, &owner, 200 * USDC);
    let auth = rig.release_authorization(&honest);
    let refs: Vec<&EthKey> = committee().iter().take(5).collect();
    let cert = secp_ix(secp_data(&refs, &auth, 0));
    // The certificate is real; each field of the instruction is changed in turn. The native program has verified
    // the honest message, and the vault computes another authorization from what it was asked to do.
    let mut cases: Vec<Release> = vec![];
    for i in 0..11 {
        let mut f = rig.release_for(0, &owner, 200 * USDC);
        f.native_burn = honest.native_burn;
        f.valid_until = honest.valid_until;
        match i {
            0 => f.amount = 4_000 * USDC,
            1 => f.recipient = account_id(&thief),
            2 => f.nonce = 1,
            3 => f.native_burn = [9; 32],
            4 => f.valid_until += 1,
            5 => f.anchor_slot += 1,
            6 => f.anchor_hash = [1; 32],
            7 => f.native_number += 1,
            8 => f.native_hash = [2; 32],
            9 => f.minted_total += 1,
            _ => f.mint_count = 1, // same value: control, must pass below
        }
        cases.push(f);
    }
    let control = cases.pop().unwrap();
    for (i, forged) in cases.iter().enumerate() {
        let result = rig.send(&[cert.clone(), rig.approve_ix(forged)]);
        assert_eq!(custom(&result), Some(E_CERT), "field {i}");
    }
    ok(rig.send(&[cert, rig.approve_ix(&control)]));
}

#[test]
fn certificate_of_another_vault_or_chain_is_refused() {
    // Two vaults of the same program and committee that differ in one configuration value.
    let mut a = Rig::new();
    a.deposit(500 * USDC, L2);
    let owner = a.new_recipient();
    let r = a.release_for(0, &owner, 200 * USDC);
    let mut wrong_chain = Rig::with(|c| c.source_chain_id = keccak(&[b"another-chain"]));
    wrong_chain.vault20 = a.vault20;
    wrong_chain.route = a.route;
    let foreign_auth = wrong_chain.release_authorization(&r);
    let refs: Vec<&EthKey> = committee().iter().take(5).collect();
    refused(a.send(&[secp_ix(secp_data(&refs, &foreign_auth, 0)), a.approve_ix(&r)]), E_CERT);
    let mut other_vault = Rig::with(|c| c.cap += 1);
    other_vault.config.source_chain_id = a.config.source_chain_id;
    assert_ne!(other_vault.vault20, a.vault20);
    let foreign_auth = other_vault.release_authorization(&r);
    refused(a.send(&[secp_ix(secp_data(&refs, &foreign_auth, 0)), a.approve_ix(&r)]), E_CERT);
}

// ── the secp256k1 verification must be the vault's own ──────────────────────

fn helper_ix(rig: &Rig, data: Vec<u8>) -> Instruction {
    Instruction { program_id: rig.helper, accounts: vec![], data }
}

#[test]
fn secp_verification_missing_misplaced_or_by_another_program() {
    let mut rig = Rig::new();
    rig.deposit(500 * USDC, L2);
    let owner = rig.new_recipient();
    let r = rig.release_for(0, &owner, 200 * USDC);
    let auth = rig.release_authorization(&r);
    let approve = rig.approve_ix(&r);
    let refs: Vec<&EthKey> = committee().iter().take(5).collect();

    // No certificate at all (the approval is the first instruction).
    refused(rig.send(&[approve.clone()]), E_CERT);
    // The certificate after the approval.
    refused(rig.send(&[approve.clone(), secp_ix(secp_data(&refs, &auth, 1))]), E_CERT);
    // WRONG PROGRAM: the exact certificate bytes, with forged signatures, given to a program that accepts
    // anything. Nothing was verified; the bytes only look like a verification.
    let mut forged = secp_data(&refs, &auth, 0);
    for i in 0..5 {
        let e = 1 + 55 + 85 * i;
        forged[e..e + 65].fill(0x42);
    }
    refused(rig.send(&[helper_ix(&rig, forged.clone()), approve.clone()]), E_CERT);
    // A real certificate, but another instruction between it and the approval.
    refused(rig.send(&[secp_ix(secp_data(&refs, &auth, 0)), helper_ix(&rig, vec![0]), approve.clone()]), E_CERT);
    // A real certificate two places before, and the forged look-alike immediately before.
    let mut forged1 = forged.clone();
    for i in 0..5 {
        for at in [2usize, 5, 10] {
            forged1[1 + 11 * i + at] = 1;
        }
    }
    refused(rig.send(&[secp_ix(secp_data(&refs, &auth, 0)), helper_ix(&rig, forged1), approve.clone()]), E_CERT);
    // The native program with an account attached (it ignores accounts; the canonical form has none).
    let mut with_account = secp_ix(secp_data(&refs, &auth, 0));
    with_account.accounts.push(AccountMeta::new_readonly(rig.vault, false));
    refused(rig.send(&[with_account, approve.clone()]), E_CERT);
    // A fake instructions sysvar: an account the attacker filled, in the sysvar's place.
    let fake_sysvar = Keypair::new().pubkey();
    let real = rig.svm.get_account(&instructions_sysvar()).map(|a| a.data).unwrap_or_else(|| vec![0u8; 64]);
    rig.set_raw_account(fake_sysvar, rig.helper, real);
    let mut bad = approve.clone();
    bad.accounts[4] = AccountMeta::new_readonly(fake_sysvar, false);
    let text = failed(rig.send(&[secp_ix(secp_data(&refs, &auth, 0)), bad]));
    assert!(text.contains("UnsupportedSysvar"), "{text}");
    // Through a CPI from another program, with a real certificate just before the outer instruction.
    let mut relay = Instruction { program_id: rig.helper, accounts: vec![AccountMeta::new_readonly(rig.program, false)], data: vec![0xC1] };
    relay.accounts.extend(approve.accounts.iter().cloned());
    relay.data.extend_from_slice(&approve.data);
    refused(rig.send(&[secp_ix(secp_data(&refs, &auth, 0)), relay]), E_NOT_TOP);

    // Nothing above created the release.
    assert!(rig.svm.get_account(&rig.release_record(0)).map(|a| a.data.is_empty()).unwrap_or(true));
    ok(rig.send(&[secp_ix(secp_data(&refs, &auth, 0)), approve]));
}

#[test]
fn secp_verification_of_other_bytes_than_the_ones_shown() {
    // WRONG INSTRUCTION / WRONG OFFSETS: the native program verifies whatever the offsets point at. The attacker
    // holds no committee key (first two cases) or one committee key (last case).
    let mut rig = Rig::new();
    rig.deposit(500 * USDC, L2);
    let thief = rig.new_recipient();
    let r = rig.release_for(0, &thief, 200 * USDC);
    let auth = rig.release_authorization(&r);
    let approve = rig.approve_ix(&r);
    let refs: Vec<&EthKey> = committee().iter().take(5).collect();
    let attacker = EthKey::from_seed(200, 200);

    // Case 1: the attacker's own valid signature, address and message live in the data of instruction 0 (a
    // program that accepts anything). The secp256k1 instruction (index 1) shows the committee's addresses and the
    // right message in the canonical places, but every offset structure points into instruction 0.
    let other_message = [0x33u8; 60];
    let digest = keccak(&[&other_message]);
    let (sig, rec) = libsecp256k1::sign(&libsecp256k1::Message::parse(&digest), &attacker.secret);
    let mut carrier = vec![0u8]; // first byte 0: the helper does nothing
    carrier.extend_from_slice(&sig.serialize());
    carrier.push(rec.serialize());
    carrier.extend_from_slice(&attacker.address);
    carrier.extend_from_slice(&other_message);
    let mut shown = secp_data(&refs, &auth, 1);
    for i in 0..5 {
        let e = 1 + 55 + 85 * i;
        shown[e..e + 65].fill(0x42); // no committee signature exists
        let o = 1 + 11 * i;
        shown[o..o + 2].copy_from_slice(&1u16.to_le_bytes());
        shown[o + 2] = 0;
        shown[o + 3..o + 5].copy_from_slice(&66u16.to_le_bytes());
        shown[o + 5] = 0;
        shown[o + 6..o + 8].copy_from_slice(&86u16.to_le_bytes());
        shown[o + 8..o + 10].copy_from_slice(&60u16.to_le_bytes());
        shown[o + 10] = 0;
    }
    let result = rig.send(&[helper_ix(&rig, carrier.clone()), secp_ix(shown.clone()), approve.clone()]);
    refused(result, E_CERT); // the native program passed (the transaction reached the vault); the vault refused

    // Case 2: the same, but only the signature and message are taken from instruction 0 and the address offsets
    // stay canonical would fail in the native program; instead point only the MESSAGE elsewhere: the committee
    // really signed some other message (here: an honest release to someone else), shown message is the theft.
    let honest_owner = rig.new_recipient();
    let honest = rig.release_for(0, &honest_owner, 200 * USDC);
    let honest_auth = rig.release_authorization(&honest);
    let mut honest_message = PREFIX.to_vec();
    honest_message.extend_from_slice(&honest_auth);
    let mut carrier2 = vec![0u8];
    carrier2.extend_from_slice(&honest_message);
    let mut shown2 = secp_data(&refs, &honest_auth, 1); // real committee signatures over the honest message
    let message_at = 1 + 96 * 5;
    shown2[message_at + 28..].copy_from_slice(&auth); // the shown message is the theft
    for i in 0..5 {
        let o = 1 + 11 * i;
        shown2[o + 6..o + 8].copy_from_slice(&1u16.to_le_bytes());
        shown2[o + 10] = 0; // message_instruction_index -> instruction 0
    }
    let result = rig.send(&[helper_ix(&rig, carrier2), secp_ix(shown2), approve.clone()]);
    refused(result, E_CERT);

    // Case 3: one compromised committee key. Five offset structures, all pointing at the one real entry; the
    // other four entries name other members with junk signatures.
    let mut shown3 = secp_data(&refs, &auth, 0);
    for i in 1..5 {
        let e = 1 + 55 + 85 * i;
        shown3[e..e + 65].fill(0x42);
        let o = 1 + 11 * i;
        let first = (1 + 55) as u16;
        shown3[o..o + 2].copy_from_slice(&first.to_le_bytes());
        shown3[o + 3..o + 5].copy_from_slice(&(first + 65).to_le_bytes());
    }
    refused(rig.send(&[secp_ix(shown3), approve.clone()]), E_CERT);

    // Case 4: canonical offsets, but a longer instruction with the real signatures of a 5-signature certificate
    // for another message appended after the canonical part.
    let mut shown4 = secp_data(&refs, &auth, 0);
    for i in 0..5 {
        let e = 1 + 55 + 85 * i;
        shown4[e..e + 65].fill(0x42);
    }
    shown4.extend_from_slice(&secp_data(&refs, &honest_auth, 0));
    failed(rig.send(&[secp_ix(shown4), approve.clone()]));

    assert!(rig.svm.get_account(&rig.release_record(0)).map(|a| a.data.is_empty()).unwrap_or(true));
    assert_eq!(token_balance(&rig.svm, &ata(&thief, &rig.mint)), 0);
}

#[test]
fn the_sdk_layout_and_any_other_layout_is_not_the_canonical_one() {
    let mut rig = Rig::new();
    // The Solana SDK's own single-signature layout (address, signature, recovery id, message) for a guardian
    // pause: valid for the native program, refused by the vault, which accepts one layout only.
    let valid_until = rig.now() + 600;
    let auth = rig.pause_authorization(1, valid_until);
    let (sig, rec) = rig.guardians[0].sign(&auth);
    let mut d = vec![0u8; 12];
    d[0] = 1;
    d[1..3].copy_from_slice(&32u16.to_le_bytes()); // signature at 12 + 20
    d[3] = 0;
    d[4..6].copy_from_slice(&12u16.to_le_bytes()); // address at 12
    d[6] = 0;
    d[7..9].copy_from_slice(&97u16.to_le_bytes()); // message at 12 + 20 + 65
    d[9..11].copy_from_slice(&60u16.to_le_bytes());
    d[11] = 0;
    d.extend_from_slice(&rig.guardians[0].address);
    d.extend_from_slice(&sig);
    d.push(rec);
    d.extend_from_slice(PREFIX);
    d.extend_from_slice(&auth);
    let pause = rig.pause_ixs(&rig.guardians[0].clone(), 1, valid_until).pop().unwrap();
    refused(rig.send(&[secp_ix(d), pause]), E_CERT);
    ok(rig.guardian_pause(0, 1));
}

// ── recipients ──────────────────────────────────────────────────────────────

#[test]
fn payment_goes_only_to_the_committed_wallets_associated_account() {
    let mut rig = Rig::new();
    rig.deposit(500 * USDC, L2);
    let owner = rig.new_recipient();
    let thief = rig.new_recipient();
    let payer = rig.payer.insecure_clone();
    let r = rig.release_for(0, &owner, 200 * USDC);
    ok(rig.approve(&r));
    // Another wallet.
    refused(rig.execute(0, &thief), E_RECIPIENT);
    // The right wallet named, the thief's token account given.
    let ix = rig.execute_ix(0, &owner, &ata(&thief, &rig.mint));
    refused(rig.send(&[ix]), E_ACCOUNT);
    // The right wallet named, the vault's own token account given.
    let ix = rig.execute_ix(0, &owner, &rig.tokens);
    refused(rig.send(&[ix]), E_ACCOUNT);
    // The right wallet's token account of another mint, with that mint.
    let evil_mint = create_mint(&mut rig.svm, &payer, &payer.pubkey(), 6, &token_program());
    let create = create_ata_ix(&payer.pubkey(), &owner, &evil_mint);
    ok(rig.send(&[create]));
    let mut ix = rig.execute_ix(0, &owner, &ata(&owner, &evil_mint));
    refused(rig.send(&[ix.clone()]), E_ACCOUNT);
    ix.accounts[2] = AccountMeta::new_readonly(evil_mint, false);
    refused(rig.send(&[ix]), E_ACCOUNT);
    // A wrong vault token account (the attacker's, to be drained instead: pointless, and refused).
    let mut ix = rig.execute_ix(0, &owner, &ata(&owner, &rig.mint));
    ix.accounts[1] = AccountMeta::new(ata(&thief, &rig.mint), false);
    refused(rig.send(&[ix]), E_ACCOUNT);
    // The release record of another nonce.
    let mut ix = rig.execute_ix(0, &owner, &ata(&owner, &rig.mint));
    ix.accounts[3] = AccountMeta::new(rig.release_record(1), false);
    refused(rig.send(&[ix]), E_NOT_APPROVED);
    // A wallet without its associated account yet: nothing is paid until someone creates it.
    let late = Keypair::new().pubkey();
    let r2 = rig.release_for(1, &late, 100 * USDC);
    ok(rig.approve(&r2));
    failed(rig.execute(1, &late));
    let create = create_ata_ix(&payer.pubkey(), &late, &rig.mint);
    ok(rig.send(&[create]));
    ok(rig.execute(1, &late));
    ok(rig.execute(0, &owner));
    assert_eq!(token_balance(&rig.svm, &ata(&thief, &rig.mint)), 0);
    rig.check_backing();
}

#[test]
fn release_to_the_vault_itself_is_refused() {
    let mut rig = Rig::new();
    rig.deposit(500 * USDC, L2);
    let vault = rig.vault;
    let r = rig.release_for(0, &vault, 100 * USDC);
    ok(rig.approve(&r));
    let create = create_ata_ix(&rig.payer.pubkey(), &vault, &rig.mint);
    ok(rig.send(&[create]));
    refused(rig.execute(0, &vault), E_RECIPIENT);
}

// ── provenance ──────────────────────────────────────────────────────────────

#[test]
fn release_under_a_mint_chain_the_deposits_do_not_back_is_refused() {
    let mut rig = Rig::new();
    rig.deposit(500 * USDC, L2);
    rig.deposit(300 * USDC, [0x22; 20]);
    let owner = rig.new_recipient();
    // The L2 credited something that is not deposit 1 (a forged mint): its chain head differs.
    let mut forged = rig.release_for(0, &owner, 100 * USDC);
    forged.mint_head = keccak(&[&rig.chain[0].3, &[0xEE; 32], &w64(300 * USDC), &waddr(&[0x22; 20])]);
    refused(rig.approve(&forged), E_PROVENANCE);
    // More mints than deposits.
    let mut ahead = rig.release_for(0, &owner, 100 * USDC);
    ahead.mint_count = 3;
    let result = rig.approve(&ahead);
    assert!(result.is_err());
    // Zero mints.
    let mut none = rig.release_for(0, &owner, 100 * USDC);
    none.mint_count = 0;
    none.mint_head = rig.genesis;
    refused(rig.approve(&none), E_PROVENANCE);
    // The head of deposit 0 claimed for count 2, and the deposit record of nonce 0 given for count 2.
    let mut stale = rig.release_for(0, &owner, 100 * USDC);
    stale.mint_head = rig.chain[0].3;
    refused(rig.approve(&stale), E_PROVENANCE);
    let mut ixs = rig.approve_ixs(&stale, 5);
    ixs[1].accounts[3] = AccountMeta::new_readonly(rig.deposit_record(0), false);
    refused(rig.send(&ixs), E_ACCOUNT);
    // A burn made after only the first deposit was credited is fine, at count 1.
    let mut early = rig.release_for(0, &owner, 100 * USDC);
    early.mint_count = 1;
    early.minted_total = rig.chain[0].1;
    early.mint_head = rig.chain[0].3;
    ok(rig.approve(&early));
    // More than what is locked.
    let too_much = rig.release_for(1, &owner, 801 * USDC);
    refused(rig.approve(&too_much), E_RELEASE);
}

// ── limits and the large-release delay ──────────────────────────────────────

#[test]
fn release_bucket_caps_what_leaves_per_window() {
    let mut rig = Rig::with(|c| {
        c.window_limit = 1_000 * USDC;
        c.release_delay = 0;
        c.large_release_threshold = 0;
    });
    for _ in 0..3 {
        rig.deposit(1_000 * USDC, L2);
    }
    let owner = rig.new_recipient();
    for nonce in 0..3 {
        let r = rig.release_for(nonce, &owner, 600 * USDC);
        ok(rig.approve(&r));
    }
    ok(rig.execute(0, &owner));
    refused(rig.execute(1, &owner), E_RATE); // 400 left in the bucket
    rig.advance(86_400 / 10); // +100
    refused(rig.execute(1, &owner), E_RATE);
    rig.advance(86_400 / 10 + 1); // +100: 600 available
    ok(rig.execute(1, &owner));
    refused(rig.execute(2, &owner), E_RATE);
    rig.advance(10 * 86_400); // never above the capacity
    ok(rig.execute(2, &owner));
    let r = rig.release_for(3, &owner, 600 * USDC);
    ok(rig.approve(&r));
    refused(rig.execute(3, &owner), E_RATE);
    rig.check_backing();
}

#[test]
fn large_release_waits_and_small_release_does_not() {
    let mut rig = Rig::new(); // threshold 1,000 USDC, delay 1 hour
    rig.deposit(5_000 * USDC, L2);
    let owner = rig.new_recipient();
    let small = rig.release_for(0, &owner, 1_000 * USDC);
    let large = rig.release_for(1, &owner, 1_000 * USDC + 1);
    ok(rig.approve(&small));
    ok(rig.approve(&large));
    ok(rig.execute(0, &owner));
    refused(rig.execute(1, &owner), E_NOT_READY);
    rig.advance(3_599);
    refused(rig.execute(1, &owner), E_NOT_READY);
    rig.advance(1);
    ok(rig.execute(1, &owner));
}

#[test]
fn certificates_expire_and_cannot_be_dated_far_ahead() {
    let mut rig = Rig::new();
    rig.deposit(500 * USDC, L2);
    let owner = rig.new_recipient();
    let mut far = rig.release_for(0, &owner, 100 * USDC);
    far.valid_until = rig.now() + 3_601;
    refused(rig.approve(&far), E_CONTEXT);
    let mut future_anchor = rig.release_for(0, &owner, 100 * USDC);
    future_anchor.anchor_slot = rig.slot();
    refused(rig.approve(&future_anchor), E_CONTEXT);
    let r = rig.release_for(0, &owner, 100 * USDC);
    rig.advance(1_801);
    refused(rig.approve(&r), E_EXPIRED);
    let fresh = rig.release_for(0, &owner, 100 * USDC);
    ok(rig.approve(&fresh));
}

// ── guardians ───────────────────────────────────────────────────────────────

#[test]
fn guardian_pause_stops_everything_and_voids_waiting_approvals() {
    let mut rig = Rig::new();
    rig.deposit(5_000 * USDC, L2);
    let owner = rig.new_recipient();
    let waiting = rig.release_for(0, &owner, 2_000 * USDC); // large: waits an hour
    ok(rig.approve(&waiting));

    // Not a guardian: a committee member, a stranger.
    let member = rig.signers[0].clone();
    let ixs = rig.pause_ixs(&member, 1, rig.now() + 600);
    refused(rig.send(&ixs), E_CERT);
    let stranger = EthKey::from_seed(9, 9);
    let ixs = rig.pause_ixs(&stranger, 1, rig.now() + 600);
    refused(rig.send(&ixs), E_CERT);
    // A pause authorization for another pause number.
    refused(rig.guardian_pause(0, 2), E_CERT);

    // One guardian key pauses; anyone delivers it (the payer here is not a guardian).
    let pause = rig.pause_ixs(&rig.guardians[0].clone(), 1, rig.now() + 600);
    ok(rig.send(&pause));
    // Replay of the same authorization.
    refused(rig.send(&pause), E_CERT);

    let (user, source) = rig.fund_user(100 * USDC);
    let ix = rig.deposit_ix(&user.pubkey(), &source, 100 * USDC, &L2);
    refused(send(&mut rig.svm, &user, &[], &[ix.clone()]), E_PAUSED);
    let r = rig.release_for(1, &owner, 100 * USDC);
    refused(rig.approve(&r), E_PAUSED);
    rig.advance(3_600);
    refused(rig.execute(0, &owner), E_PAUSED);
    // Another guardian cannot stack a pause on a running one.
    refused(rig.guardian_pause(1, 2), E_PAUSE);

    // After the pause: the old approval is void, and the committee approves again.
    rig.advance(259_200);
    refused(rig.execute(0, &owner), E_VOIDED);
    ok(send(&mut rig.svm, &user, &[], &[ix]));
    let again = rig.release_for(0, &owner, 2_000 * USDC);
    ok(rig.approve(&again));
    rig.advance(3_600);
    ok(rig.execute(0, &owner));
    rig.check_backing();
}

#[test]
fn guardian_pause_chain_and_committee_unpause() {
    let mut rig = Rig::new();
    ok(rig.guardian_pause(0, 1));
    rig.advance(259_200);
    // Same guardian, same chain: refused. Another guardian renews at once.
    refused(rig.guardian_pause(0, 2), E_PAUSE);
    ok(rig.guardian_pause(1, 2));
    rig.advance(259_200);
    refused(rig.guardian_pause(1, 3), E_PAUSE);
    ok(rig.guardian_pause(2, 3));
    rig.advance(259_200);
    // All three used: the vault is open for at least the cooldown.
    for g in 0..3 {
        refused(rig.guardian_pause(g, 4), E_PAUSE);
    }
    rig.advance(259_200);
    ok(rig.guardian_pause(0, 4)); // a new chain

    // Ending a pause early takes 6 of 7, for this pause only.
    refused(rig.unpause(4, 5), E_CERT);
    refused(rig.unpause(3, 6), E_PAUSE);
    ok(rig.unpause(4, 6));
    refused(rig.unpause(4, 6), E_PAUSE);
    // Guardians wait the cooldown after a committee unpause.
    refused(rig.guardian_pause(1, 5), E_PAUSE);
    rig.advance(259_200);
    ok(rig.guardian_pause(1, 5));
}

#[test]
fn vault_without_guardians_cannot_be_paused() {
    let mut rig = Rig::with(|c| {
        c.guardians.clear();
        c.pause_duration = 0;
        c.pause_cooldown = 0;
    });
    let key = EthKey::from_seed(0, 2);
    let ixs = rig.pause_ixs(&key, 1, rig.now() + 600);
    refused(rig.send(&ixs), E_NOT_GUARDIAN);
}

// ── controls and fees ───────────────────────────────────────────────────────

#[test]
fn controls_need_the_threshold_and_the_next_nonce() {
    let mut rig = Rig::new(); // nonce 0 was used to open the vault
    refused(rig.set_controls(false, false, 1, 4), E_CERT);
    refused(rig.set_controls(false, false, 0, 5), E_CONTROLS); // replayed nonce
    refused(rig.set_controls(true, true, 1, 5), E_CONTROLS); // no change
    ok(rig.set_controls(true, false, 1, 5));
    rig.deposit(500 * USDC, L2);
    let owner = rig.new_recipient();
    let r = rig.release_for(0, &owner, 100 * USDC);
    refused(rig.approve(&r), E_RELEASE);
    assert_eq!(rig.state().control_nonce, 2);
    // The exact transaction that opened the vault, sent again.
    let ixs = rig.controls_ixs(true, true, 0, 5, rig.now() + 600);
    refused(rig.send(&ixs), E_CONTROLS);
}

#[test]
fn fees_go_only_to_the_fee_owners_associated_account() {
    let mut rig = Rig::new();
    rig.deposit(10_000 * USDC, L2);
    let owner = rig.new_recipient();
    let r = rig.release_for(0, &owner, 1_000 * USDC);
    ok(rig.approve(&r));
    ok(rig.execute(0, &owner));
    let accrued = rig.state().fees_accrued;
    assert_eq!(accrued, 5 * USDC + USDC / 2);
    let fee_account = ata(&rig.fee_owner, &rig.mint);
    // The fee account does not exist yet: nothing is lost, the sweep just fails.
    failed(rig.send(&[rig.sweep_ix(&fee_account)]));
    // Somebody else's account.
    refused(rig.send(&[rig.sweep_ix(&ata(&owner, &rig.mint))]), E_ACCOUNT);
    // Anyone creates the fee owner's associated account; anyone sweeps.
    let create = create_ata_ix(&rig.payer.pubkey(), &rig.fee_owner, &rig.mint);
    ok(rig.send(&[create]));
    let locked = rig.state().total_locked;
    ok(rig.send(&[rig.sweep_ix(&fee_account)]));
    assert_eq!(token_balance(&rig.svm, &fee_account), accrued);
    assert_eq!(rig.state().fees_accrued, 0);
    assert_eq!(rig.state().total_locked, locked);
    assert_eq!(token_balance(&rig.svm, &rig.tokens), locked);
    // Nothing to sweep: a no-op.
    ok(rig.send(&[rig.sweep_ix(&fee_account)]));
    assert_eq!(token_balance(&rig.svm, &fee_account), accrued);
}

// ── size and compute ────────────────────────────────────────────────────────

#[test]
fn transaction_sizes_and_compute_units() {
    let mut rig = Rig::new();
    rig.deposit(5_000 * USDC, L2);
    let owner = rig.new_recipient();
    let payer = rig.payer.insecure_clone();
    println!("| instruction | signatures | transaction bytes (limit 1232) | compute units |");
    for k in 5..=7usize {
        let r = rig.release_for(k as u64, &owner, 100 * USDC);
        let ixs = rig.approve_ixs(&r, k);
        let size = tx_size(&payer, &ixs);
        if size <= 1232 {
            let cu = ok(rig.send(&ixs));
            println!("| approve_release | {k} | {size} | {cu} |");
        } else {
            // The in-process SVM does not enforce the 1232-byte packet limit; a validator never receives this.
            println!("| approve_release | {k} | {size} (does not fit) | - |");
        }
    }
    let ix = rig.execute_ix(5, &owner, &ata(&owner, &rig.mint));
    let size = tx_size(&payer, &[ix.clone()]);
    println!("| execute_release | 0 | {size} | {} |", ok(rig.send(&[ix])));
    let (user, source) = rig.fund_user(100 * USDC);
    let ix = rig.deposit_ix(&user.pubkey(), &source, 100 * USDC, &L2);
    let size = tx_size(&user, &[ix.clone()]);
    println!("| deposit | 0 | {size} | {} |", ok(send(&mut rig.svm, &user, &[], &[ix])));
    let ixs = rig.pause_ixs(&rig.guardians[0].clone(), 1, rig.now() + 600);
    let size = tx_size(&payer, &ixs);
    println!("| guardian_pause | 1 | {size} | {} |", ok(rig.send(&ixs)));
    for k in 6..=7usize {
        let ixs = rig.unpause_ixs(1, k, rig.now() + 600);
        let size = tx_size(&payer, &ixs);
        if k == 6 {
            println!("| unpause | {k} | {size} | {} |", ok(rig.send(&ixs)));
        } else {
            println!("| unpause | {k} | {size} | (not sent) |");
        }
    }
    let ixs = rig.controls_ixs(false, true, 1, 5, rig.now() + 600);
    let size = tx_size(&payer, &ixs);
    println!("| set_controls | 5 | {size} | {} |", ok(rig.send(&ixs)));
    let init = initialize_ix(&rig.program, &payer.pubkey(), &rig.config);
    println!("| initialize (7 signers, 3 guardians) | 0 | {} | - |", tx_size(&payer, &[init]));
}
