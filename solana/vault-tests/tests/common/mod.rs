//! Test rig: an in-process SVM with the built vault program, a classic SPL mint standing in for USDC, throwaway
//! secp256k1 committee and guardian keys, and encoders written from the specification (docs/SOLANA-VAULT.md),
//! independent of the program's own code.
#![allow(dead_code)]

use litesvm::{types::TransactionResult, LiteSVM};
use sha2::{Digest as _, Sha256};
use sha3::Keccak256;
use solana_account::Account;
use solana_address::Address;
use solana_clock::Clock;
use solana_instruction::{account_meta::AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_message::Message;
use solana_signer::Signer;
use solana_transaction::Transaction;
use solana_transaction_error::TransactionError;
use std::str::FromStr;

pub type Word = [u8; 32];
pub type Addr20 = [u8; 20];

pub const USDC: u64 = 1_000_000;
pub const T0: i64 = 1_800_000_000;

pub fn addr(s: &str) -> Address {
    Address::from_str(s).unwrap()
}
pub fn token_program() -> Address {
    addr("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
}
pub fn token_2022_program() -> Address {
    addr("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb")
}
pub fn ata_program() -> Address {
    addr("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")
}
pub fn system_program() -> Address {
    addr("11111111111111111111111111111111")
}
pub fn secp_program() -> Address {
    addr("KeccakSecp256k11111111111111111111111111111")
}
pub fn instructions_sysvar() -> Address {
    addr("Sysvar1nstructions1111111111111111111111111")
}
pub fn loader() -> Address {
    addr("BPFLoaderUpgradeab1e11111111111111111111111")
}

// ── hashing, from the specification ─────────────────────────────────────────

pub fn keccak(parts: &[&[u8]]) -> Word {
    let mut h = Keccak256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}
pub fn sha256(parts: &[&[u8]]) -> Word {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}
pub fn tag(text: &str) -> Word {
    let mut w = [0u8; 32];
    w[..text.len()].copy_from_slice(text.as_bytes());
    w
}
pub fn w64(v: u64) -> Word {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&v.to_be_bytes());
    w
}
pub fn waddr(a: &Addr20) -> Word {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(a);
    w
}
pub fn id20(domain: &str, parts: &[&[u8]]) -> Addr20 {
    let mut all: Vec<&[u8]> = vec![domain.as_bytes()];
    all.extend_from_slice(parts);
    keccak(&all)[12..].try_into().unwrap()
}
pub fn account_id(key: &Address) -> Addr20 {
    id20("BLOCH-SVM-ACCOUNT-ID-v1", &[key.as_ref()])
}
pub const PREFIX: &[u8; 28] = b"\x19Ethereum Signed Message:\n32";

// ── secp256k1 keys ──────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct EthKey {
    pub secret: libsecp256k1::SecretKey,
    pub address: Addr20,
}

impl EthKey {
    pub fn from_seed(seed: u8, salt: u8) -> EthKey {
        let secret = libsecp256k1::SecretKey::parse(&sha256(&[b"bloch-test-key", &[seed, salt]])).unwrap();
        let public = libsecp256k1::PublicKey::from_secret_key(&secret).serialize();
        EthKey { secret, address: keccak(&[&public[1..]])[12..].try_into().unwrap() }
    }
    /// EIP-191 signature of a 32-byte authorization, as `cast wallet sign` makes it: (r || s, recovery id).
    pub fn sign(&self, authorization: &Word) -> ([u8; 64], u8) {
        let digest = keccak(&[PREFIX, authorization]);
        let (sig, rec) = libsecp256k1::sign(&libsecp256k1::Message::parse(&digest), &self.secret);
        (sig.serialize(), rec.serialize())
    }
}

/// `n` keys sorted by address, as the vault requires its sets.
pub fn keys(n: u8, salt: u8) -> Vec<EthKey> {
    let mut v: Vec<EthKey> = (0..n).map(|i| EthKey::from_seed(i, salt)).collect();
    v.sort_by_key(|k| k.address);
    v
}

/// The canonical secp256k1 instruction data for these signers over `authorization`, with every instruction
/// index set to `index` (the position the instruction will have in the transaction).
pub fn secp_data(signers: &[&EthKey], authorization: &Word, index: u8) -> Vec<u8> {
    let n = signers.len();
    let mut d = vec![0u8; 1 + 96 * n + 60];
    d[0] = n as u8;
    let entries = 1 + 11 * n;
    let message = 1 + 96 * n;
    for (i, key) in signers.iter().enumerate() {
        let o = 1 + 11 * i;
        let e = entries + 85 * i;
        d[o..o + 2].copy_from_slice(&(e as u16).to_le_bytes());
        d[o + 2] = index;
        d[o + 3..o + 5].copy_from_slice(&((e + 65) as u16).to_le_bytes());
        d[o + 5] = index;
        d[o + 6..o + 8].copy_from_slice(&(message as u16).to_le_bytes());
        d[o + 8..o + 10].copy_from_slice(&60u16.to_le_bytes());
        d[o + 10] = index;
        let (sig, rec) = key.sign(authorization);
        d[e..e + 64].copy_from_slice(&sig);
        d[e + 64] = rec;
        d[e + 65..e + 85].copy_from_slice(&key.address);
    }
    d[message..message + 28].copy_from_slice(PREFIX);
    d[message + 28..].copy_from_slice(authorization);
    d
}

pub fn secp_ix(data: Vec<u8>) -> Instruction {
    Instruction { program_id: secp_program(), accounts: vec![], data }
}

// ── configuration ───────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct Config {
    pub mint: Address,
    pub fee_owner: Address,
    pub source_chain_id: Word,
    pub source_domain: Word,
    pub native_domain: Word,
    pub native_asset: Word,
    pub cap: u64,
    pub window_limit: u64,
    pub window_seconds: u64,
    pub min_deposit: u64,
    pub l2_min_burn: u64,
    pub large_release_threshold: u64,
    pub release_delay: u64,
    pub pause_duration: u64,
    pub pause_cooldown: u64,
    pub max_valid_seconds: u64,
    pub deposit_fee_bps: u16,
    pub release_fee_bps: u16,
    pub threshold: u8,
    pub switch_threshold: u8,
    pub signers: Vec<Addr20>,
    pub guardians: Vec<Addr20>,
}

impl Config {
    pub fn encode(&self) -> Vec<u8> {
        let mut d = Vec::new();
        d.extend_from_slice(self.mint.as_ref());
        d.extend_from_slice(self.fee_owner.as_ref());
        for w in [&self.source_chain_id, &self.source_domain, &self.native_domain, &self.native_asset] {
            d.extend_from_slice(w);
        }
        for v in [
            self.cap,
            self.window_limit,
            self.window_seconds,
            self.min_deposit,
            self.l2_min_burn,
            self.large_release_threshold,
            self.release_delay,
            self.pause_duration,
            self.pause_cooldown,
            self.max_valid_seconds,
        ] {
            d.extend_from_slice(&v.to_le_bytes());
        }
        d.extend_from_slice(&self.deposit_fee_bps.to_le_bytes());
        d.extend_from_slice(&self.release_fee_bps.to_le_bytes());
        d.extend_from_slice(&[self.threshold, self.switch_threshold, self.signers.len() as u8, self.guardians.len() as u8]);
        for s in &self.signers {
            d.extend_from_slice(s);
        }
        for g in &self.guardians {
            d.extend_from_slice(g);
        }
        d
    }
}

pub struct Release {
    pub nonce: u64,
    pub recipient: Addr20,
    pub amount: u64,
    pub native_burn: Word,
    pub mint_count: u64,
    pub minted_total: u64,
    pub mint_head: Word,
    pub valid_until: u64,
    pub anchor_slot: u64,
    pub anchor_hash: Word,
    pub native_number: u64,
    pub native_hash: Word,
}

impl Release {
    pub fn encode(&self) -> Vec<u8> {
        let mut d = vec![2u8];
        d.extend_from_slice(&self.nonce.to_le_bytes());
        d.extend_from_slice(&self.recipient);
        d.extend_from_slice(&self.amount.to_le_bytes());
        d.extend_from_slice(&self.native_burn);
        d.extend_from_slice(&self.mint_count.to_le_bytes());
        d.extend_from_slice(&self.minted_total.to_le_bytes());
        d.extend_from_slice(&self.mint_head);
        d.extend_from_slice(&self.valid_until.to_le_bytes());
        d.extend_from_slice(&self.anchor_slot.to_le_bytes());
        d.extend_from_slice(&self.anchor_hash);
        d.extend_from_slice(&self.native_number.to_le_bytes());
        d.extend_from_slice(&self.native_hash);
        d
    }
}

// ── the rig ─────────────────────────────────────────────────────────────────

pub struct Rig {
    pub svm: LiteSVM,
    pub program: Address,
    pub helper: Address,
    pub payer: Keypair,
    pub mint_authority: Keypair,
    pub mint: Address,
    pub config: Config,
    pub vault: Address,
    pub tokens: Address,
    pub signers: Vec<EthKey>,
    pub guardians: Vec<EthKey>,
    pub fee_owner: Address,
    pub vault20: Addr20,
    pub mint20: Addr20,
    pub route: Word,
    pub genesis: Word,
    /// (id, net, l2 recipient, head after) of each deposit made through `deposit`.
    pub chain: Vec<(Word, u64, Addr20, Word)>,
    pub burn_counter: u64,
}

fn so(var: &str, default: &str) -> Vec<u8> {
    let path = std::env::var(var).unwrap_or_else(|_| format!("{}/{}", env!("CARGO_MANIFEST_DIR"), default));
    std::fs::read(&path).unwrap_or_else(|e| panic!("{var}: cannot read {path}: {e}"))
}

pub fn custom(result: &TransactionResult) -> Option<u32> {
    match result {
        Err(f) => match &f.err {
            TransactionError::InstructionError(_, e) => {
                let text = format!("{e:?}");
                text.strip_prefix("Custom(").and_then(|t| t.strip_suffix(')')).and_then(|t| t.parse().ok())
            }
            _ => None,
        },
        Ok(_) => None,
    }
}

/// Asserts the transaction failed with this custom error code of the vault.
#[track_caller]
pub fn refused(result: TransactionResult, code: u32) {
    match &result {
        Ok(_) => panic!("accepted, expected the vault's error {code}"),
        Err(f) => assert_eq!(custom(&result), Some(code), "expected the vault's error {code}, got {:?}\n{:#?}", f.err, f.meta.logs),
    }
}

#[track_caller]
pub fn failed(result: TransactionResult) -> String {
    match result {
        Ok(_) => panic!("accepted, expected a failure"),
        Err(f) => format!("{:?}", f.err),
    }
}

#[track_caller]
pub fn ok(result: TransactionResult) -> u64 {
    match result {
        Ok(meta) => meta.compute_units_consumed,
        Err(f) => panic!("refused: {:?}\n{:#?}", f.err, f.meta.logs),
    }
}

pub const E_CONFIG: u32 = 100;
pub const E_ACCOUNT: u32 = 101;
pub const E_TRANSFER: u32 = 102;
pub const E_RELEASE: u32 = 103;
pub const E_CERT: u32 = 104;
pub const E_CONTROLS: u32 = 105;
pub const E_BACKING: u32 = 106;
pub const E_CONTEXT: u32 = 107;
pub const E_RATE: u32 = 108;
pub const E_NOT_GUARDIAN: u32 = 109;
pub const E_PAUSE: u32 = 110;
pub const E_PAUSED: u32 = 111;
pub const E_PROVENANCE: u32 = 112;
pub const E_NOT_APPROVED: u32 = 113;
pub const E_NOT_READY: u32 = 114;
pub const E_ALREADY: u32 = 115;
pub const E_VOIDED: u32 = 116;
pub const E_NOT_TOP: u32 = 117;
pub const E_UPGRADEABLE: u32 = 118;
pub const E_RECIPIENT: u32 = 119;
pub const E_EXPIRED: u32 = 120;

pub fn base_svm() -> (LiteSVM, Address, Address, Keypair) {
    let mut svm = LiteSVM::new();
    let program = Keypair::new().pubkey();
    let helper = Keypair::new().pubkey();
    svm.add_program(program, &so("VAULT_SO", "../bloch-sol-vault/target/deploy/bloch_sol_vault.so")).unwrap();
    svm.add_program(helper, &so("HELPER_SO", "../test-helper-program/target/deploy/bloch_sol_test_helper.so")).unwrap();
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 1_000_000_000_000).unwrap();
    svm.warp_to_slot(1_000);
    let mut clock: Clock = svm.get_sysvar();
    clock.unix_timestamp = T0;
    svm.set_sysvar(&clock);
    (svm, program, helper, payer)
}

pub fn send(svm: &mut LiteSVM, payer: &Keypair, extra: &[&Keypair], ixs: &[Instruction]) -> TransactionResult {
    svm.expire_blockhash();
    let mut signers: Vec<&Keypair> = vec![payer];
    signers.extend_from_slice(extra);
    let tx = Transaction::new(&signers, Message::new(ixs, Some(&payer.pubkey())), svm.latest_blockhash());
    svm.send_transaction(tx)
}

pub fn tx_size(payer: &Keypair, ixs: &[Instruction]) -> usize {
    let tx = Transaction::new_unsigned(Message::new(ixs, Some(&payer.pubkey())));
    // compact length of signatures (1) + 64 per signature + message
    1 + 64 * tx.message.header.num_required_signatures as usize + tx.message_data().len()
}

pub fn system_create(from: &Address, new: &Address, lamports: u64, space: u64, owner: &Address) -> Instruction {
    let mut data = 0u32.to_le_bytes().to_vec();
    data.extend_from_slice(&lamports.to_le_bytes());
    data.extend_from_slice(&space.to_le_bytes());
    data.extend_from_slice(owner.as_ref());
    Instruction { program_id: system_program(), accounts: vec![AccountMeta::new(*from, true), AccountMeta::new(*new, true)], data }
}

pub fn system_transfer(from: &Address, to: &Address, lamports: u64) -> Instruction {
    let mut data = 2u32.to_le_bytes().to_vec();
    data.extend_from_slice(&lamports.to_le_bytes());
    Instruction { program_id: system_program(), accounts: vec![AccountMeta::new(*from, true), AccountMeta::new(*to, false)], data }
}

/// A new mint under `program` (the classic token program, or Token-2022 for the refusal test).
pub fn create_mint(svm: &mut LiteSVM, payer: &Keypair, authority: &Address, decimals: u8, program: &Address) -> Address {
    let mint = Keypair::new();
    let rent = svm.minimum_balance_for_rent_exemption(82);
    let mut data = vec![20u8, decimals];
    data.extend_from_slice(authority.as_ref());
    data.push(1);
    data.extend_from_slice(authority.as_ref());
    let init = Instruction { program_id: *program, accounts: vec![AccountMeta::new(mint.pubkey(), false)], data };
    ok(send(svm, payer, &[&mint], &[system_create(&payer.pubkey(), &mint.pubkey(), rent, 82, program), init]));
    mint.pubkey()
}

pub fn ata(owner: &Address, mint: &Address) -> Address {
    Address::find_program_address(&[owner.as_ref(), token_program().as_ref(), mint.as_ref()], &ata_program()).0
}

pub fn create_ata_ix(payer: &Address, owner: &Address, mint: &Address) -> Instruction {
    Instruction {
        program_id: ata_program(),
        accounts: vec![
            AccountMeta::new(*payer, true),
            AccountMeta::new(ata(owner, mint), false),
            AccountMeta::new_readonly(*owner, false),
            AccountMeta::new_readonly(*mint, false),
            AccountMeta::new_readonly(system_program(), false),
            AccountMeta::new_readonly(token_program(), false),
        ],
        data: vec![1],
    }
}

pub fn mint_to_ix(mint: &Address, destination: &Address, authority: &Address, amount: u64) -> Instruction {
    let mut data = vec![7u8];
    data.extend_from_slice(&amount.to_le_bytes());
    Instruction {
        program_id: token_program(),
        accounts: vec![AccountMeta::new(*mint, false), AccountMeta::new(*destination, false), AccountMeta::new_readonly(*authority, true)],
        data,
    }
}

pub fn token_transfer_ix(source: &Address, destination: &Address, authority: &Address, amount: u64) -> Instruction {
    let mut data = vec![3u8];
    data.extend_from_slice(&amount.to_le_bytes());
    Instruction {
        program_id: token_program(),
        accounts: vec![AccountMeta::new(*source, false), AccountMeta::new(*destination, false), AccountMeta::new_readonly(*authority, true)],
        data,
    }
}

pub fn token_balance(svm: &LiteSVM, account: &Address) -> u64 {
    let a = svm.get_account(account).expect("token account");
    u64::from_le_bytes(a.data[64..72].try_into().unwrap())
}

pub fn default_config(mint: Address, fee_owner: Address, signers: &[EthKey], guardians: &[EthKey]) -> Config {
    Config {
        mint,
        fee_owner,
        source_chain_id: keccak(&[b"test-chain"]),
        source_domain: tag("solana-localnet"),
        native_domain: tag("bloch-l2-700770"),
        native_asset: tag("USDC"),
        cap: 100_000 * USDC,
        window_limit: 10_000 * USDC,
        window_seconds: 86_400,
        min_deposit: 11 * USDC,
        l2_min_burn: 10 * USDC,
        large_release_threshold: 1_000 * USDC,
        release_delay: 3_600,
        pause_duration: 259_200,
        pause_cooldown: 259_200,
        max_valid_seconds: 3_600,
        deposit_fee_bps: 5,
        release_fee_bps: 5,
        threshold: 5,
        switch_threshold: 6,
        signers: signers.iter().map(|k| k.address).collect(),
        guardians: guardians.iter().map(|k| k.address).collect(),
    }
}

pub fn vault_address(program: &Address, config: &Config) -> (Address, Address) {
    let hash = sha256(&[b"BLOCH-SVM-VAULT-CONFIG-v1", &config.encode()]);
    let vault = Address::find_program_address(&[b"vault", &hash], program).0;
    let tokens = Address::find_program_address(&[b"tokens", vault.as_ref()], program).0;
    (vault, tokens)
}

pub fn program_data(program: &Address) -> Address {
    Address::find_program_address(&[program.as_ref()], &loader()).0
}

pub fn initialize_ix(program: &Address, payer: &Address, config: &Config) -> Instruction {
    let (vault, tokens) = vault_address(program, config);
    let mut data = vec![0u8];
    data.extend_from_slice(&config.encode());
    Instruction {
        program_id: *program,
        accounts: vec![
            AccountMeta::new(*payer, true),
            AccountMeta::new(vault, false),
            AccountMeta::new(tokens, false),
            AccountMeta::new_readonly(config.mint, false),
            AccountMeta::new_readonly(program_data(program), false),
            AccountMeta::new_readonly(token_program(), false),
            AccountMeta::new_readonly(system_program(), false),
        ],
        data,
    }
}

impl Rig {
    /// A vault with the default test configuration, initialized, with deposits and releases switched on.
    pub fn new() -> Rig {
        Rig::with(|_| {})
    }

    pub fn with(change: impl FnOnce(&mut Config)) -> Rig {
        let mut rig = Rig::uninitialized(change);
        let ix = initialize_ix(&rig.program, &rig.payer.pubkey(), &rig.config);
        ok(send(&mut rig.svm, &rig.payer, &[], &[ix]));
        ok(rig.set_controls(true, true, 0, 5));
        rig
    }

    pub fn uninitialized(change: impl FnOnce(&mut Config)) -> Rig {
        let (mut svm, program, helper, payer) = base_svm();
        let mint_authority = Keypair::new();
        let mint = create_mint(&mut svm, &payer, &mint_authority.pubkey(), 6, &token_program());
        let signers = keys(7, 1);
        let guardians = keys(3, 2);
        let fee_owner = Keypair::new().pubkey();
        let mut config = default_config(mint, fee_owner, &signers, &guardians);
        change(&mut config);
        let (vault, tokens) = vault_address(&program, &config);
        let vault20 = id20("BLOCH-SVM-VAULT-ID-v1", &[program.as_ref(), vault.as_ref()]);
        let mint20 = id20("BLOCH-SVM-MINT-ID-v1", &[config.mint.as_ref()]);
        let route = sha256(&[
            &tag("BLOCH-USDT-ROUTE-v1"),
            &config.source_domain,
            &config.native_domain,
            &config.native_asset,
            &waddr(&mint20),
            &waddr(&vault20),
            &w64(6),
            &w64(config.cap),
        ]);
        let genesis = keccak(&[&tag("BLOCH-USDT-MINT-CHAIN-v1"), &config.source_chain_id, &waddr(&vault20), &route]);
        Rig {
            svm,
            program,
            helper,
            payer,
            mint_authority,
            mint,
            config,
            vault,
            tokens,
            signers,
            guardians,
            fee_owner,
            vault20,
            mint20,
            route,
            genesis,
            chain: vec![],
            burn_counter: 0,
        }
    }

    pub fn now(&self) -> u64 {
        self.svm.get_sysvar::<Clock>().unix_timestamp as u64
    }

    pub fn slot(&self) -> u64 {
        self.svm.get_sysvar::<Clock>().slot
    }

    pub fn advance(&mut self, seconds: u64) {
        let mut clock: Clock = self.svm.get_sysvar();
        clock.unix_timestamp += seconds as i64;
        clock.slot += seconds * 5 / 2;
        self.svm.set_sysvar(&clock);
    }

    pub fn vault_data(&self) -> Vec<u8> {
        self.svm.get_account(&self.vault).expect("vault").data
    }

    /// Dynamic fields of the vault account (layout: docs/SOLANA-VAULT.md section 4).
    pub fn state(&self) -> VaultState {
        let d = self.vault_data();
        let mut at = 4 + 32 + 280 + 320 + 140 + 20 + 20 + 32 + 32 + 32 + 32;
        let head: Word = d[at..at + 32].try_into().unwrap();
        at += 32;
        let mut next = || {
            let v = u64::from_le_bytes(d[at..at + 8].try_into().unwrap());
            at += 8;
            v
        };
        let deposit_count = next();
        let total_locked = next();
        let fees_accrued = next();
        let control_nonce = next();
        VaultState { head, deposit_count, total_locked, fees_accrued, control_nonce }
    }

    /// The accounting invariant: the vault's token balance covers what is locked plus the fees not yet swept.
    #[track_caller]
    pub fn check_backing(&self) {
        let s = self.state();
        assert!(token_balance(&self.svm, &self.tokens) >= s.total_locked + s.fees_accrued, "backing broken");
    }

    pub fn fund_user(&mut self, amount: u64) -> (Keypair, Address) {
        let user = Keypair::new();
        self.svm.airdrop(&user.pubkey(), 10_000_000_000).unwrap();
        let account = ata(&user.pubkey(), &self.mint);
        let ixs = [
            create_ata_ix(&self.payer.pubkey(), &user.pubkey(), &self.mint),
            mint_to_ix(&self.mint, &account, &self.mint_authority.pubkey(), amount),
        ];
        let authority = self.mint_authority.insecure_clone();
        ok(send(&mut self.svm, &self.payer, &[&authority], &ixs));
        (user, account)
    }

    pub fn deposit_record(&self, nonce: u64) -> Address {
        Address::find_program_address(&[b"deposit", self.vault.as_ref(), &nonce.to_le_bytes()], &self.program).0
    }

    pub fn release_record(&self, nonce: u64) -> Address {
        Address::find_program_address(&[b"release", self.vault.as_ref(), &nonce.to_le_bytes()], &self.program).0
    }

    pub fn deposit_ix(&self, user: &Address, source: &Address, amount: u64, l2: &Addr20) -> Instruction {
        let mut data = vec![1u8];
        data.extend_from_slice(&amount.to_le_bytes());
        data.extend_from_slice(l2);
        Instruction {
            program_id: self.program,
            accounts: vec![
                AccountMeta::new(*user, true),
                AccountMeta::new(*source, false),
                AccountMeta::new(self.vault, false),
                AccountMeta::new(self.tokens, false),
                AccountMeta::new_readonly(self.mint, false),
                AccountMeta::new(self.deposit_record(self.state().deposit_count), false),
                AccountMeta::new_readonly(token_program(), false),
                AccountMeta::new_readonly(system_program(), false),
            ],
            data,
        }
    }

    /// A deposit by a new funded user. Returns the user, and records the expected chain step.
    pub fn deposit(&mut self, amount: u64, l2: Addr20) -> Keypair {
        let (user, source) = self.fund_user(amount);
        let nonce = self.state().deposit_count;
        let ix = self.deposit_ix(&user.pubkey(), &source, amount, &l2);
        ok(send(&mut self.svm, &user, &[], &[ix]));
        let net = amount - amount * self.config.deposit_fee_bps as u64 / 10_000;
        let h = sha256(&[
            &tag("BLOCH-USDT-DEPOSIT-v2"),
            &self.route,
            &w64(nonce),
            &waddr(&account_id(&user.pubkey())),
            &w64(net),
            &waddr(&l2),
        ]);
        let mut id = h;
        id[..8].copy_from_slice(&nonce.to_be_bytes());
        let before = self.chain.last().map(|c| c.3).unwrap_or(self.genesis);
        let head = keccak(&[&before, &id, &w64(net), &waddr(&l2)]);
        self.chain.push((id, net, l2, head));
        self.check_backing();
        user
    }

    /// An honest release for a burn of `amount` to `owner`, made under the current mint chain.
    pub fn release_for(&mut self, nonce: u64, owner: &Address, amount: u64) -> Release {
        self.burn_counter += 1;
        let count = self.chain.len() as u64;
        Release {
            nonce,
            recipient: account_id(owner),
            amount,
            native_burn: keccak(&[b"burn", &self.burn_counter.to_le_bytes()]),
            mint_count: count,
            minted_total: self.chain.iter().map(|c| c.1).sum(),
            mint_head: self.chain.last().map(|c| c.3).unwrap_or(self.genesis),
            valid_until: self.now() + 1_800,
            anchor_slot: self.slot() - 10,
            anchor_hash: [0x5a; 32],
            native_number: 812,
            native_hash: [0x77; 32],
        }
    }

    pub fn release_authorization(&self, r: &Release) -> Word {
        let id = sha256(&[
            &tag("BLOCH-USDT-RELEASE-v2"),
            &self.route,
            &w64(r.nonce),
            &waddr(&r.recipient),
            &w64(r.amount),
            &r.native_burn,
            &w64(r.mint_count),
            &w64(r.minted_total),
            &r.mint_head,
        ]);
        keccak(&[
            &tag("BLOCH-USDT-RELEASE-AUTH-v2"),
            &self.config.source_chain_id,
            &waddr(&self.vault20),
            &id,
            &w64(r.valid_until),
            &w64(r.anchor_slot),
            &r.anchor_hash,
            &w64(r.native_number),
            &r.native_hash,
        ])
    }

    pub fn approve_ix(&self, r: &Release) -> Instruction {
        Instruction {
            program_id: self.program,
            accounts: vec![
                AccountMeta::new(self.payer.pubkey(), true),
                AccountMeta::new(self.vault, false),
                AccountMeta::new(self.release_record(r.nonce), false),
                AccountMeta::new_readonly(self.deposit_record(r.mint_count.saturating_sub(1)), false),
                AccountMeta::new_readonly(instructions_sysvar(), false),
                AccountMeta::new_readonly(system_program(), false),
            ],
            data: r.encode(),
        }
    }

    /// The honest two instructions: the committee's certificate (first `k` signers), then the approval.
    pub fn approve_ixs(&self, r: &Release, k: usize) -> Vec<Instruction> {
        let signers: Vec<&EthKey> = self.signers.iter().take(k).collect();
        vec![secp_ix(secp_data(&signers, &self.release_authorization(r), 0)), self.approve_ix(r)]
    }

    pub fn approve(&mut self, r: &Release) -> TransactionResult {
        let ixs = self.approve_ixs(r, self.config.threshold as usize);
        let payer = self.payer.insecure_clone();
        send(&mut self.svm, &payer, &[], &ixs)
    }

    pub fn execute_ix(&self, nonce: u64, owner: &Address, destination: &Address) -> Instruction {
        let mut data = vec![3u8];
        data.extend_from_slice(&nonce.to_le_bytes());
        data.extend_from_slice(owner.as_ref());
        Instruction {
            program_id: self.program,
            accounts: vec![
                AccountMeta::new(self.vault, false),
                AccountMeta::new(self.tokens, false),
                AccountMeta::new_readonly(self.mint, false),
                AccountMeta::new(self.release_record(nonce), false),
                AccountMeta::new(*destination, false),
                AccountMeta::new_readonly(token_program(), false),
            ],
            data,
        }
    }

    pub fn execute(&mut self, nonce: u64, owner: &Address) -> TransactionResult {
        let ix = self.execute_ix(nonce, owner, &ata(owner, &self.mint));
        let payer = self.payer.insecure_clone();
        send(&mut self.svm, &payer, &[], &[ix])
    }

    pub fn new_recipient(&mut self) -> Address {
        let owner = Keypair::new().pubkey();
        let ix = create_ata_ix(&self.payer.pubkey(), &owner, &self.mint);
        let payer = self.payer.insecure_clone();
        ok(send(&mut self.svm, &payer, &[], &[ix]));
        owner
    }

    fn simple_ix(&self, data: Vec<u8>) -> Instruction {
        Instruction {
            program_id: self.program,
            accounts: vec![AccountMeta::new(self.vault, false), AccountMeta::new_readonly(instructions_sysvar(), false)],
            data,
        }
    }

    pub fn controls_authorization(&self, deposits: bool, releases: bool, nonce: u64, valid_until: u64) -> Word {
        keccak(&[
            &tag("BLOCH-USDT-CONTROLS-v1"),
            &self.config.source_chain_id,
            &waddr(&self.vault20),
            &self.route,
            &w64(deposits as u64),
            &w64(releases as u64),
            &w64(nonce),
            &w64(valid_until),
        ])
    }

    pub fn controls_ixs(&self, deposits: bool, releases: bool, nonce: u64, k: usize, valid_until: u64) -> Vec<Instruction> {
        let auth = self.controls_authorization(deposits, releases, nonce, valid_until);
        let signers: Vec<&EthKey> = self.signers.iter().take(k).collect();
        let mut data = vec![6u8, deposits as u8, releases as u8];
        data.extend_from_slice(&nonce.to_le_bytes());
        data.extend_from_slice(&valid_until.to_le_bytes());
        vec![secp_ix(secp_data(&signers, &auth, 0)), self.simple_ix(data)]
    }

    pub fn set_controls(&mut self, deposits: bool, releases: bool, nonce: u64, k: usize) -> TransactionResult {
        let ixs = self.controls_ixs(deposits, releases, nonce, k, self.now() + 600);
        let payer = self.payer.insecure_clone();
        send(&mut self.svm, &payer, &[], &ixs)
    }

    pub fn pause_authorization(&self, count: u64, valid_until: u64) -> Word {
        keccak(&[
            &tag("BLOCH-SVM-GUARDIAN-PAUSE-v1"),
            &self.config.source_chain_id,
            &waddr(&self.vault20),
            &self.route,
            &w64(count),
            &w64(valid_until),
        ])
    }

    pub fn pause_ixs(&self, key: &EthKey, count: u64, valid_until: u64) -> Vec<Instruction> {
        let auth = self.pause_authorization(count, valid_until);
        let mut data = vec![4u8];
        data.extend_from_slice(&valid_until.to_le_bytes());
        vec![secp_ix(secp_data(&[key], &auth, 0)), self.simple_ix(data)]
    }

    /// Guardian `g` pauses; `count` is the pause this starts (pause count + 1).
    pub fn guardian_pause(&mut self, g: usize, count: u64) -> TransactionResult {
        let key = self.guardians[g].clone();
        let ixs = self.pause_ixs(&key, count, self.now() + 600);
        let payer = self.payer.insecure_clone();
        send(&mut self.svm, &payer, &[], &ixs)
    }

    pub fn unpause_ixs(&self, count: u64, k: usize, valid_until: u64) -> Vec<Instruction> {
        let auth = keccak(&[
            &tag("BLOCH-USDT-UNPAUSE-v1"),
            &self.config.source_chain_id,
            &waddr(&self.vault20),
            &self.route,
            &w64(count),
            &w64(valid_until),
        ]);
        let signers: Vec<&EthKey> = self.signers.iter().take(k).collect();
        let mut data = vec![5u8];
        data.extend_from_slice(&count.to_le_bytes());
        data.extend_from_slice(&valid_until.to_le_bytes());
        vec![secp_ix(secp_data(&signers, &auth, 0)), self.simple_ix(data)]
    }

    pub fn unpause(&mut self, count: u64, k: usize) -> TransactionResult {
        let ixs = self.unpause_ixs(count, k, self.now() + 600);
        let payer = self.payer.insecure_clone();
        send(&mut self.svm, &payer, &[], &ixs)
    }

    pub fn sweep_ix(&self, fee_account: &Address) -> Instruction {
        Instruction {
            program_id: self.program,
            accounts: vec![
                AccountMeta::new(self.vault, false),
                AccountMeta::new(self.tokens, false),
                AccountMeta::new_readonly(self.mint, false),
                AccountMeta::new(*fee_account, false),
                AccountMeta::new_readonly(token_program(), false),
            ],
            data: vec![7u8],
        }
    }

    pub fn send(&mut self, ixs: &[Instruction]) -> TransactionResult {
        let payer = self.payer.insecure_clone();
        send(&mut self.svm, &payer, &[], ixs)
    }

    pub fn set_raw_account(&mut self, address: Address, owner: Address, data: Vec<u8>) {
        let lamports = self.svm.minimum_balance_for_rent_exemption(data.len());
        self.svm.set_account(address, Account { lamports, data, owner, executable: false, rent_epoch: 0 }).unwrap();
    }
}

pub struct VaultState {
    pub head: Word,
    pub deposit_count: u64,
    pub total_locked: u64,
    pub fees_accrued: u64,
    pub control_nonce: u64,
}
