use crate::{
    abi::{self, Addr20, ReleaseContext, ReleaseItem},
    cert::check_certificate,
    error::VaultError,
    state::*,
};
use solana_program::{
    account_info::AccountInfo,
    entrypoint::ProgramResult,
    instruction::{AccountMeta, Instruction},
    log::sol_log_data,
    program::{invoke, invoke_signed},
    program_error::ProgramError,
    pubkey::Pubkey,
    sysvar::{clock::Clock, rent::Rent, Sysvar},
};

/// The classic SPL Token program: the only token program this vault accepts (USDC on Solana is a classic mint).
pub const TOKEN_PROGRAM_ID: Pubkey = solana_program::pubkey!("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
pub const ASSOCIATED_TOKEN_PROGRAM_ID: Pubkey = solana_program::pubkey!("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
pub const SYSTEM_PROGRAM_ID: Pubkey = solana_program::pubkey!("11111111111111111111111111111111");
pub const UPGRADEABLE_LOADER_ID: Pubkey = solana_program::pubkey!("BPFLoaderUpgradeab1e11111111111111111111111");

pub const SEED_VAULT: &[u8] = b"vault";
pub const SEED_TOKENS: &[u8] = b"tokens";
pub const SEED_DEPOSIT: &[u8] = b"deposit";
pub const SEED_RELEASE: &[u8] = b"release";

pub const IX_INITIALIZE: u8 = 0;
pub const IX_DEPOSIT: u8 = 1;
pub const IX_APPROVE_RELEASE: u8 = 2;
pub const IX_EXECUTE_RELEASE: u8 = 3;
pub const IX_GUARDIAN_PAUSE: u8 = 4;
pub const IX_UNPAUSE: u8 = 5;
pub const IX_SET_CONTROLS: u8 = 6;
pub const IX_SWEEP_FEES: u8 = 7;

const TOKEN_ACCOUNT_LEN: usize = 165;
const MINT_LEN: usize = 82;

pub fn process(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let (kind, rest) = data.split_first().ok_or(ProgramError::InvalidInstructionData)?;
    match *kind {
        IX_INITIALIZE => initialize(program_id, accounts, rest),
        IX_DEPOSIT => deposit(program_id, accounts, rest),
        IX_APPROVE_RELEASE => approve_release(program_id, accounts, rest),
        IX_EXECUTE_RELEASE => execute_release(program_id, accounts, rest),
        IX_GUARDIAN_PAUSE => guardian_pause(program_id, accounts, rest),
        IX_UNPAUSE => unpause(program_id, accounts, rest),
        IX_SET_CONTROLS => set_controls(program_id, accounts, rest),
        IX_SWEEP_FEES => sweep_fees(program_id, accounts, rest),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

// ── helpers ─────────────────────────────────────────────────────────────────

fn accounts_exact<'a, 'b, const N: usize>(accounts: &'a [AccountInfo<'b>]) -> Result<&'a [AccountInfo<'b>; N], ProgramError> {
    accounts.try_into().map_err(|_| ProgramError::NotEnoughAccountKeys)
}

fn now() -> Result<(u64, u64), ProgramError> {
    let clock = Clock::get()?;
    if clock.unix_timestamp <= 0 {
        return Err(VaultError::InvalidContext.into());
    }
    Ok((clock.unix_timestamp as u64, clock.slot))
}

fn require(condition: bool, error: VaultError) -> ProgramResult {
    if condition {
        Ok(())
    } else {
        Err(error.into())
    }
}

fn require_key(account: &AccountInfo, key: &Pubkey) -> ProgramResult {
    require(account.key == key, VaultError::InvalidAccount)
}

/// `valid_until` is not past and not further ahead than the vault allows: a certificate cannot be kept for later.
fn check_validity(vault: &Vault, now: u64, valid_until: u64) -> ProgramResult {
    require(now <= valid_until, VaultError::Expired)?;
    require(valid_until - now <= vault.config.max_valid_seconds, VaultError::InvalidContext)
}

/// Loads the vault: owned by this program, the vault layout, and at the address its own configuration derives.
fn load_vault(program_id: &Pubkey, account: &AccountInfo) -> Result<Vault, ProgramError> {
    require(account.owner == program_id && account.is_writable, VaultError::InvalidAccount)?;
    let vault = Vault::load(&account.try_borrow_data()?)?;
    let expected = Pubkey::create_program_address(&[SEED_VAULT, &vault.config_hash, &[vault.bump]], program_id)
        .map_err(|_| VaultError::InvalidAccount)?;
    require_key(account, &expected)?;
    Ok(vault)
}

fn store_vault(vault: &Vault, account: &AccountInfo) -> ProgramResult {
    vault.store(&mut account.try_borrow_mut_data()?)
}

/// A classic SPL token account's (mint, owner, amount), after checking who owns the account and its size and state.
fn token_account(account: &AccountInfo) -> Result<(Pubkey, Pubkey, u64), ProgramError> {
    require(account.owner == &TOKEN_PROGRAM_ID, VaultError::InvalidAccount)?;
    let data = account.try_borrow_data()?;
    // state at 108: 1 = initialized, 2 = frozen (a frozen account fails in the token program, not here).
    require(data.len() == TOKEN_ACCOUNT_LEN && data[108] != 0, VaultError::InvalidAccount)?;
    let mint = Pubkey::new_from_array(data[0..32].try_into().unwrap());
    let owner = Pubkey::new_from_array(data[32..64].try_into().unwrap());
    let amount = u64::from_le_bytes(data[64..72].try_into().unwrap());
    Ok((mint, owner, amount))
}

fn check_mint(vault: &Vault, mint: &AccountInfo) -> ProgramResult {
    require(mint.key.to_bytes() == vault.config.mint && mint.owner == &TOKEN_PROGRAM_ID, VaultError::InvalidAccount)
}

fn check_vault_tokens(vault: &Vault, tokens: &AccountInfo) -> Result<u64, ProgramError> {
    require(tokens.key.to_bytes() == vault.token_account && tokens.is_writable, VaultError::InvalidAccount)?;
    let (_, _, amount) = token_account(tokens)?;
    Ok(amount)
}

fn transfer_checked_ix(source: &Pubkey, mint: &Pubkey, destination: &Pubkey, authority: &Pubkey, amount: u64) -> Instruction {
    let mut data = Vec::with_capacity(10);
    data.push(12); // TokenInstruction::TransferChecked
    data.extend_from_slice(&amount.to_le_bytes());
    data.push(DECIMALS);
    Instruction {
        program_id: TOKEN_PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(*source, false),
            AccountMeta::new_readonly(*mint, false),
            AccountMeta::new(*destination, false),
            AccountMeta::new_readonly(*authority, true),
        ],
        data,
    }
}

fn system_ix(tag: u32, body: &[&[u8]], accounts: Vec<AccountMeta>) -> Instruction {
    let mut data = tag.to_le_bytes().to_vec();
    for part in body {
        data.extend_from_slice(part);
    }
    Instruction { program_id: SYSTEM_PROGRAM_ID, accounts, data }
}

/// Creates a program-derived account. An address that already holds lamports (anyone can send some to block a
/// plain `CreateAccount`) is topped up, allocated and assigned instead.
fn create_pda<'a>(
    payer: &AccountInfo<'a>,
    target: &AccountInfo<'a>,
    system_program: &AccountInfo<'a>,
    space: usize,
    owner: &Pubkey,
    seeds: &[&[u8]],
) -> ProgramResult {
    require_key(system_program, &SYSTEM_PROGRAM_ID)?;
    require(payer.is_signer && payer.is_writable && target.is_writable, VaultError::InvalidAccount)?;
    require(target.owner == &SYSTEM_PROGRAM_ID && target.data_is_empty(), VaultError::InvalidAccount)?;
    let lamports = Rent::get()?.minimum_balance(space);
    let space_bytes = (space as u64).to_le_bytes();
    let infos = [payer.clone(), target.clone(), system_program.clone()];
    if target.lamports() == 0 {
        let ix = system_ix(
            0, // CreateAccount
            &[&lamports.to_le_bytes(), &space_bytes, owner.as_ref()],
            vec![AccountMeta::new(*payer.key, true), AccountMeta::new(*target.key, true)],
        );
        return invoke_signed(&ix, &infos, &[seeds]);
    }
    let missing = lamports.saturating_sub(target.lamports());
    if missing > 0 {
        let ix = system_ix(
            2, // Transfer
            &[&missing.to_le_bytes()],
            vec![AccountMeta::new(*payer.key, true), AccountMeta::new(*target.key, false)],
        );
        invoke(&ix, &infos)?;
    }
    let allocate = system_ix(8, &[&space_bytes], vec![AccountMeta::new(*target.key, true)]);
    invoke_signed(&allocate, &infos, &[seeds])?;
    let assign = system_ix(1, &[owner.as_ref()], vec![AccountMeta::new(*target.key, true)]);
    invoke_signed(&assign, &infos, &[seeds])
}

fn associated_token_address(owner: &Pubkey, mint: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[owner.as_ref(), TOKEN_PROGRAM_ID.as_ref(), mint.as_ref()], &ASSOCIATED_TOKEN_PROGRAM_ID).0
}

fn id_account(key: &Pubkey) -> Addr20 {
    abi::id20(abi::ID_ACCOUNT, &[key.as_ref()])
}

// ── initialize ──────────────────────────────────────────────────────────────

/// Accounts: payer (signer, writable), vault (writable), vault token account (writable), mint, this program's
/// program data account, token program, system program. Data: the configuration (state::Config::parse).
///
/// Anyone may call it: the vault address is a function of the whole configuration, so the only vault that can
/// exist at an address is the one with exactly that configuration. No authority is recorded anywhere.
fn initialize(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let [payer, vault_ai, tokens_ai, mint_ai, program_data_ai, token_program, system_program] = accounts_exact::<7>(accounts)?;
    let config = Config::parse(data)?;
    config.validate()?;

    // The program must already be final. An upgradeable program is an administrator key over every vault.
    let (program_data_key, _) = Pubkey::find_program_address(&[program_id.as_ref()], &UPGRADEABLE_LOADER_ID);
    require_key(program_data_ai, &program_data_key)?;
    require(program_data_ai.owner == &UPGRADEABLE_LOADER_ID, VaultError::ProgramUpgradeable)?;
    {
        // UpgradeableLoaderState::ProgramData { slot: u64, upgrade_authority_address: Option<Pubkey> }, bincode.
        let d = program_data_ai.try_borrow_data()?;
        require(d.len() >= 13 && d[0..4] == [3, 0, 0, 0] && d[12] == 0, VaultError::ProgramUpgradeable)?;
    }

    require_key(token_program, &TOKEN_PROGRAM_ID)?;
    require(mint_ai.key.to_bytes() == config.mint && mint_ai.owner == &TOKEN_PROGRAM_ID, VaultError::InvalidAccount)?;
    {
        let d = mint_ai.try_borrow_data()?;
        // Mint layout: decimals at 44, is_initialized at 45.
        require(d.len() == MINT_LEN && d[44] == DECIMALS && d[45] == 1, VaultError::InvalidConfiguration)?;
    }

    let config_hash = abi::sha256_words(&[abi::CONFIG_TAG, data]);
    let (vault_key, bump) = Pubkey::find_program_address(&[SEED_VAULT, &config_hash], program_id);
    require_key(vault_ai, &vault_key)?;
    let (tokens_key, token_bump) = Pubkey::find_program_address(&[SEED_TOKENS, vault_key.as_ref()], program_id);
    require_key(tokens_ai, &tokens_key)?;
    let fee_owner = Pubkey::new_from_array(config.fee_owner);
    require(fee_owner != vault_key && fee_owner != tokens_key && fee_owner != *mint_ai.key, VaultError::InvalidConfiguration)?;

    create_pda(payer, vault_ai, system_program, VAULT_LEN, program_id, &[SEED_VAULT, &config_hash, &[bump]])?;
    create_pda(
        payer,
        tokens_ai,
        system_program,
        TOKEN_ACCOUNT_LEN,
        &TOKEN_PROGRAM_ID,
        &[SEED_TOKENS, vault_key.as_ref(), &[token_bump]],
    )?;
    // TokenInstruction::InitializeAccount3 { owner }: the vault address is the token account's authority.
    let mut init = vec![18u8];
    init.extend_from_slice(vault_key.as_ref());
    invoke(
        &Instruction {
            program_id: TOKEN_PROGRAM_ID,
            accounts: vec![AccountMeta::new(tokens_key, false), AccountMeta::new_readonly(*mint_ai.key, false)],
            data: init,
        },
        &[tokens_ai.clone(), mint_ai.clone(), token_program.clone()],
    )?;

    let vault20 = abi::id20(abi::ID_VAULT, &[program_id.as_ref(), vault_key.as_ref()]);
    let mint20 = abi::id20(abi::ID_MINT, &[mint_ai.key.as_ref()]);
    let route = abi::route_id(&config.source_domain, &config.native_domain, &config.native_asset, &mint20, &vault20, config.cap);
    let genesis = abi::mint_chain_genesis(&config.source_chain_id, &vault20, &route);
    let (timestamp, _) = now()?;
    let vault = Vault {
        bump,
        token_bump,
        config_hash,
        vault20,
        mint20,
        route,
        genesis,
        token_account: tokens_key.to_bytes(),
        fee_token_account: associated_token_address(&fee_owner, mint_ai.key).to_bytes(),
        head: genesis,
        deposit_count: 0,
        total_locked: 0,
        fees_accrued: 0,
        control_nonce: 0,
        deposits_enabled: false,
        releases_enabled: false,
        release_bucket: config.window_limit,
        bucket_updated_at: timestamp,
        paused_until: 0,
        pause_count: 0,
        guardian_blocked_until: 0,
        pause_chain: 0,
        guardian_last_chain: [0; MAX_GUARDIANS],
        approval_seq: 0,
        void_through_seq: 0,
        config,
    };
    store_vault(&vault, vault_ai)?;
    sol_log_data(&[b"BLOCH-SVM-VAULT-INITIALIZED-v1", vault_key.as_ref(), &vault.vault20, &vault.route]);
    Ok(())
}

// ── deposit ─────────────────────────────────────────────────────────────────

/// Accounts: depositor (signer, writable; the token authority, pays the record's rent), depositor token account
/// (writable), vault (writable), vault token account (writable), mint, deposit record (writable), token program,
/// system program. Data: amount u64, L2 recipient (20 bytes).
fn deposit(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let [depositor, source_ai, vault_ai, tokens_ai, mint_ai, record_ai, token_program, system_program] =
        accounts_exact::<8>(accounts)?;
    let mut r = Reader::new(data);
    let amount = r.u64()?;
    let l2_recipient = r.addr()?;
    r.done()?;

    let mut vault = load_vault(program_id, vault_ai)?;
    let (timestamp, slot) = now()?;
    require(!vault.paused(timestamp), VaultError::Paused)?;
    require_key(token_program, &TOKEN_PROGRAM_ID)?;
    check_mint(&vault, mint_ai)?;
    let before_vault = check_vault_tokens(&vault, tokens_ai)?;
    require(depositor.is_signer, VaultError::InvalidAccount)?;
    require(source_ai.key != tokens_ai.key, VaultError::InvalidAccount)?;
    let (source_mint, _, before_source) = token_account(source_ai)?;
    require(source_mint.to_bytes() == vault.config.mint, VaultError::InvalidAccount)?;

    let fee = fee(amount, vault.config.deposit_fee_bps);
    let net = amount - fee;
    let c = &vault.config;
    require(
        vault.deposits_enabled
            && amount >= c.min_deposit
            && amount <= c.window_limit
            && l2_recipient != [0u8; 20]
            && vault.total_locked as u128 + net as u128 <= c.cap as u128
            && vault.deposit_count != u64::MAX,
        VaultError::InvalidTransfer,
    )?;
    require(before_vault as u128 >= vault.total_locked as u128 + vault.fees_accrued as u128, VaultError::InsufficientBacking)?;

    invoke(
        &transfer_checked_ix(source_ai.key, mint_ai.key, tokens_ai.key, depositor.key, amount),
        &[source_ai.clone(), mint_ai.clone(), tokens_ai.clone(), depositor.clone(), token_program.clone()],
    )?;
    let (_, _, after_vault) = token_account(tokens_ai)?;
    let (_, _, after_source) = token_account(source_ai)?;
    require(
        after_vault as u128 == before_vault as u128 + amount as u128 && after_source as u128 + amount as u128 == before_source as u128,
        VaultError::InvalidTransfer,
    )?;

    let nonce = vault.deposit_count;
    let sender20 = id_account(depositor.key);
    // From here on the deposit is its NET amount: what the L2 token mints and what stays locked.
    let id = abi::deposit_id(&vault.route, nonce, &sender20, net, &l2_recipient);
    let head_after = abi::chain_step(&vault.head, &id, net, &l2_recipient);
    vault.deposit_count = nonce + 1;
    vault.total_locked += net;
    vault.fees_accrued += fee;
    vault.head = head_after;

    let nonce_bytes = nonce.to_le_bytes();
    let (record_key, bump) = Pubkey::find_program_address(&[SEED_DEPOSIT, vault_ai.key.as_ref(), &nonce_bytes], program_id);
    require_key(record_ai, &record_key)?;
    create_pda(
        depositor,
        record_ai,
        system_program,
        DEPOSIT_LEN,
        program_id,
        &[SEED_DEPOSIT, vault_ai.key.as_ref(), &nonce_bytes, &[bump]],
    )?;
    let record = DepositRecord {
        bump,
        vault: vault_ai.key.to_bytes(),
        nonce,
        id,
        depositor: depositor.key.to_bytes(),
        sender20,
        l2_recipient,
        amount: net,
        fee,
        head_after,
        slot,
        timestamp,
    };
    record.store(&mut record_ai.try_borrow_mut_data()?);
    store_vault(&vault, vault_ai)?;
    sol_log_data(&[b"BLOCH-SVM-DEPOSITED-v1", &record_ai.try_borrow_data()?]);
    Ok(())
}

// ── releases ────────────────────────────────────────────────────────────────

/// Accounts: payer (signer, writable), vault (writable), release record (writable), deposit record of nonce
/// `mint_count - 1`, instructions sysvar, system program. The instruction before this one must be the canonical
/// secp256k1 instruction over this release's authorization (cert.rs).
/// Data: nonce u64, recipient (20), amount u64, native burn (32), mint count u64, minted total u64, mint head
/// (32), valid until u64, source anchor slot u64, source anchor hash (32), native finalized number u64, native
/// finalized hash (32).
fn approve_release(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let [payer, vault_ai, record_ai, deposit_ai, instructions, system_program] = accounts_exact::<6>(accounts)?;
    let mut r = Reader::new(data);
    let nonce = r.u64()?;
    let recipient = r.addr()?;
    let amount = r.u64()?;
    let native_burn = r.word()?;
    let mint_count = r.u64()?;
    let minted_total = r.u64()?;
    let mint_head = r.word()?;
    let context = ReleaseContext {
        valid_until: r.u64()?,
        source_anchor_slot: r.u64()?,
        source_anchor_hash: r.word()?,
        native_finalized_number: r.u64()?,
        native_finalized_hash: r.word()?,
    };
    r.done()?;

    let mut vault = load_vault(program_id, vault_ai)?;
    let (timestamp, slot) = now()?;
    require(!vault.paused(timestamp), VaultError::Paused)?;
    require(vault.releases_enabled, VaultError::InvalidRelease)?;
    check_validity(&vault, timestamp, context.valid_until)?;
    require(
        amount != 0 && recipient != [0u8; 20] && native_burn != [0u8; 32] && amount <= vault.total_locked,
        VaultError::InvalidRelease,
    )?;
    // The anchor is a slot of this cluster that the signers saw finalized: it cannot be ahead of the clock.
    require(
        context.source_anchor_slot < slot && context.source_anchor_hash != [0u8; 32] && context.native_finalized_hash != [0u8; 32],
        VaultError::InvalidContext,
    )?;

    // Provenance (mode 1): the burn was made under the mint chain that equals this vault's deposit chain after
    // the same number of deposits. A token credited from anything but these deposits, in order, never matches.
    require(mint_count != 0 && mint_count <= vault.deposit_count, VaultError::ProvenanceMismatch)?;
    require(deposit_ai.owner == program_id, VaultError::InvalidAccount)?;
    let backing = DepositRecord::load(&deposit_ai.try_borrow_data()?)?;
    let backing_nonce = (mint_count - 1).to_le_bytes();
    let backing_key = Pubkey::create_program_address(
        &[SEED_DEPOSIT, vault_ai.key.as_ref(), &backing_nonce, &[backing.bump]],
        program_id,
    )
    .map_err(|_| VaultError::InvalidAccount)?;
    require_key(deposit_ai, &backing_key)?;
    require(backing.vault == vault_ai.key.to_bytes() && backing.nonce == mint_count - 1, VaultError::InvalidAccount)?;
    require(backing.head_after == mint_head, VaultError::ProvenanceMismatch)?;

    let item = ReleaseItem { route: vault.route, nonce, recipient, amount, native_burn, mint_count, minted_total, mint_head };
    let id = abi::release_id(&item);
    let authorization = abi::release_authorization(&vault.config.source_chain_id, &vault.vault20, &id, &context);
    check_certificate(instructions, &authorization, vault.config.signer_set(), vault.config.threshold as usize)?;

    // One record per burn nonce. It exists already only if an earlier approval was voided by a guardian pause;
    // a paid or still valid approval is final for this nonce.
    let nonce_bytes = nonce.to_le_bytes();
    let (record_key, bump) = Pubkey::find_program_address(&[SEED_RELEASE, vault_ai.key.as_ref(), &nonce_bytes], program_id);
    require_key(record_ai, &record_key)?;
    if record_ai.owner == program_id {
        let old = ReleaseRecord::load(&record_ai.try_borrow_data()?)?;
        require(old.vault == vault_ai.key.to_bytes() && old.nonce == nonce, VaultError::InvalidAccount)?;
        require(old.state == RELEASE_APPROVED && old.seq <= vault.void_through_seq, VaultError::AlreadyReleased)?;
    } else {
        create_pda(
            payer,
            record_ai,
            system_program,
            RELEASE_LEN,
            program_id,
            &[SEED_RELEASE, vault_ai.key.as_ref(), &nonce_bytes, &[bump]],
        )?;
    }
    vault.approval_seq += 1;
    let delayed = vault.config.release_delay != 0 && amount > vault.config.large_release_threshold;
    let record = ReleaseRecord {
        bump,
        state: RELEASE_APPROVED,
        vault: vault_ai.key.to_bytes(),
        nonce,
        release_id: id,
        recipient,
        amount,
        native_burn,
        ready_at: if delayed { timestamp + vault.config.release_delay } else { timestamp },
        seq: vault.approval_seq,
        approved_at: timestamp,
        paid_at: 0,
        paid_amount: 0,
    };
    record.store(&mut record_ai.try_borrow_mut_data()?);
    store_vault(&vault, vault_ai)?;
    sol_log_data(&[b"BLOCH-SVM-RELEASE-APPROVED-v1", &record_ai.try_borrow_data()?]);
    Ok(())
}

/// Accounts: vault (writable), vault token account (writable), mint, release record (writable), recipient token
/// account (writable), token program. Data: nonce u64, the recipient's wallet address (32).
///
/// Anyone may call it. The L2 burn names a 20-byte commitment; the wallet given here must hash to it, and the
/// payment goes only to that wallet's associated token account.
fn execute_release(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let [vault_ai, tokens_ai, mint_ai, record_ai, destination_ai, token_program] = accounts_exact::<6>(accounts)?;
    let mut r = Reader::new(data);
    let nonce = r.u64()?;
    let owner = Pubkey::new_from_array(r.word()?);
    r.done()?;

    let mut vault = load_vault(program_id, vault_ai)?;
    let (timestamp, _) = now()?;
    require(!vault.paused(timestamp), VaultError::Paused)?;
    require_key(token_program, &TOKEN_PROGRAM_ID)?;
    check_mint(&vault, mint_ai)?;
    let before_vault = check_vault_tokens(&vault, tokens_ai)?;

    require(record_ai.owner == program_id && record_ai.is_writable, VaultError::NotApproved)?;
    let mut record = ReleaseRecord::load(&record_ai.try_borrow_data()?)?;
    let record_key = Pubkey::create_program_address(
        &[SEED_RELEASE, vault_ai.key.as_ref(), &nonce.to_le_bytes(), &[record.bump]],
        program_id,
    )
    .map_err(|_| VaultError::InvalidAccount)?;
    require_key(record_ai, &record_key)?;
    require(record.vault == vault_ai.key.to_bytes() && record.nonce == nonce, VaultError::InvalidAccount)?;
    require(record.state == RELEASE_APPROVED, VaultError::AlreadyReleased)?;
    require(record.seq > vault.void_through_seq, VaultError::Voided)?;
    require(timestamp >= record.ready_at, VaultError::NotReady)?;

    require(id_account(&owner) == record.recipient, VaultError::WrongRecipient)?;
    require(owner != *vault_ai.key && owner != *tokens_ai.key, VaultError::WrongRecipient)?;
    require_key(destination_ai, &associated_token_address(&owner, mint_ai.key))?;
    require(destination_ai.key != tokens_ai.key, VaultError::WrongRecipient)?;
    let (destination_mint, destination_owner, before_destination) = token_account(destination_ai)?;
    require(destination_mint == *mint_ai.key && destination_owner == owner, VaultError::WrongRecipient)?;

    let amount = record.amount;
    let available = vault.available_to_release(timestamp);
    require(amount <= available, VaultError::RateLimited)?;
    require(amount <= vault.total_locked, VaultError::InsufficientBacking)?;
    require(before_vault as u128 >= vault.total_locked as u128 + vault.fees_accrued as u128, VaultError::InsufficientBacking)?;
    // The bucket and `total_locked` take the full burned amount; the recipient gets it less the release fee,
    // which moves from backing to `fees_accrued` (the burn already removed the same amount of the L2 token).
    vault.release_bucket = available - amount;
    vault.bucket_updated_at = timestamp;
    let fee = fee(amount, vault.config.release_fee_bps);
    let paid = amount - fee;
    vault.total_locked -= amount;
    vault.fees_accrued += fee;
    record.state = RELEASE_PAID;
    record.paid_at = timestamp;
    record.paid_amount = paid;
    record.store(&mut record_ai.try_borrow_mut_data()?);
    store_vault(&vault, vault_ai)?;

    invoke_signed(
        &transfer_checked_ix(tokens_ai.key, mint_ai.key, destination_ai.key, vault_ai.key, paid),
        &[tokens_ai.clone(), mint_ai.clone(), destination_ai.clone(), vault_ai.clone(), token_program.clone()],
        &[&[SEED_VAULT, &vault.config_hash, &[vault.bump]]],
    )?;
    let (_, _, after_vault) = token_account(tokens_ai)?;
    let (_, _, after_destination) = token_account(destination_ai)?;
    require(
        after_vault as u128 + paid as u128 == before_vault as u128 && after_destination as u128 == before_destination as u128 + paid as u128,
        VaultError::InvalidTransfer,
    )?;
    sol_log_data(&[b"BLOCH-SVM-RELEASED-v1", &record_ai.try_borrow_data()?, owner.as_ref()]);
    Ok(())
}

// ── pause, controls, fees ───────────────────────────────────────────────────

/// Accounts: vault (writable), instructions sysvar. Data: valid until u64. The instruction before this one must
/// be the canonical secp256k1 instruction with exactly one signature, a guardian's, over the pause authorization
/// for pause number `pause_count + 1`. Anyone may deliver it: the guardian's power is its secp256k1 key.
///
/// The pause stops deposits, approvals and payments for `pause_duration`, and voids every approval not yet paid.
fn guardian_pause(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let [vault_ai, instructions] = accounts_exact::<2>(accounts)?;
    let mut r = Reader::new(data);
    let valid_until = r.u64()?;
    r.done()?;
    let mut vault = load_vault(program_id, vault_ai)?;
    let (timestamp, _) = now()?;
    check_validity(&vault, timestamp, valid_until)?;
    require(vault.config.guardian_count != 0, VaultError::NotGuardian)?;
    let count = vault.pause_count.checked_add(1).ok_or(VaultError::InvalidPause)?;
    let authorization = abi::guardian_pause_authorization(&vault.config.source_chain_id, &vault.vault20, &vault.route, count, valid_until);
    let signed = check_certificate(instructions, &authorization, vault.config.guardian_set(), 1)?;
    require(signed.count_ones() == 1, VaultError::NotGuardian)?;
    let guardian = signed.trailing_zeros() as usize;

    let chain_ended = vault.chain_ended(timestamp);
    require(
        timestamp >= vault.paused_until
            && timestamp >= vault.guardian_blocked_until
            && (chain_ended || vault.guardian_last_chain[guardian] != vault.pause_chain),
        VaultError::InvalidPause,
    )?;
    if chain_ended {
        vault.pause_chain += 1;
    }
    vault.guardian_last_chain[guardian] = vault.pause_chain;
    vault.pause_count = count;
    vault.paused_until = timestamp + vault.config.pause_duration;
    vault.void_through_seq = vault.approval_seq;
    store_vault(&vault, vault_ai)?;
    sol_log_data(&[
        b"BLOCH-SVM-GUARDIAN-PAUSED-v1",
        &vault.config.guardians[guardian],
        &count.to_le_bytes(),
        &vault.paused_until.to_le_bytes(),
    ]);
    Ok(())
}

/// Accounts: vault (writable), instructions sysvar. Data: pause count u64, valid until u64. `switch_threshold`
/// signers end the current pause early; guardians then wait `pause_cooldown`. Voided approvals stay voided.
fn unpause(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let [vault_ai, instructions] = accounts_exact::<2>(accounts)?;
    let mut r = Reader::new(data);
    let count = r.u64()?;
    let valid_until = r.u64()?;
    r.done()?;
    let mut vault = load_vault(program_id, vault_ai)?;
    let (timestamp, _) = now()?;
    require(timestamp < vault.paused_until && count == vault.pause_count, VaultError::InvalidPause)?;
    check_validity(&vault, timestamp, valid_until)?;
    let authorization = abi::unpause_authorization(&vault.config.source_chain_id, &vault.vault20, &vault.route, count, valid_until);
    check_certificate(instructions, &authorization, vault.config.signer_set(), vault.config.switch_threshold as usize)?;
    vault.paused_until = timestamp;
    vault.guardian_blocked_until = timestamp + vault.config.pause_cooldown;
    store_vault(&vault, vault_ai)?;
    sol_log_data(&[b"BLOCH-SVM-UNPAUSED-v1", &count.to_le_bytes(), &vault.guardian_blocked_until.to_le_bytes()]);
    Ok(())
}

/// Accounts: vault (writable), instructions sysvar. Data: deposits u8, releases u8, nonce u64, valid until u64.
/// `threshold` signers switch deposits and new approvals on or off (`ProvenanceSourceVault.setControls`).
fn set_controls(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let [vault_ai, instructions] = accounts_exact::<2>(accounts)?;
    let mut r = Reader::new(data);
    let deposits = r.u8()?;
    let releases = r.u8()?;
    let nonce = r.u64()?;
    let valid_until = r.u64()?;
    r.done()?;
    require(deposits <= 1 && releases <= 1, VaultError::InvalidControls)?;
    let (deposits, releases) = (deposits == 1, releases == 1);
    let mut vault = load_vault(program_id, vault_ai)?;
    let (timestamp, _) = now()?;
    require(
        nonce == vault.control_nonce && nonce != u64::MAX && (deposits != vault.deposits_enabled || releases != vault.releases_enabled),
        VaultError::InvalidControls,
    )?;
    check_validity(&vault, timestamp, valid_until)?;
    let authorization =
        abi::controls_authorization(&vault.config.source_chain_id, &vault.vault20, &vault.route, deposits, releases, nonce, valid_until);
    check_certificate(instructions, &authorization, vault.config.signer_set(), vault.config.threshold as usize)?;
    vault.control_nonce = nonce + 1;
    vault.deposits_enabled = deposits;
    vault.releases_enabled = releases;
    store_vault(&vault, vault_ai)?;
    sol_log_data(&[b"BLOCH-SVM-CONTROLS-v1", &nonce.to_le_bytes(), &[deposits as u8, releases as u8]]);
    Ok(())
}

/// Accounts: vault (writable), vault token account (writable), mint, fee token account (writable), token program.
/// Anyone may call it. It pays every accrued fee to the fee owner's associated token account, fixed at
/// initialization, and never touches backing.
fn sweep_fees(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let [vault_ai, tokens_ai, mint_ai, fee_ai, token_program] = accounts_exact::<5>(accounts)?;
    require(data.is_empty(), VaultError::InvalidTransfer)?;
    let mut vault = load_vault(program_id, vault_ai)?;
    require_key(token_program, &TOKEN_PROGRAM_ID)?;
    check_mint(&vault, mint_ai)?;
    let before_vault = check_vault_tokens(&vault, tokens_ai)?;
    require(fee_ai.key.to_bytes() == vault.fee_token_account, VaultError::InvalidAccount)?;
    let (fee_mint, fee_owner, before_fee) = token_account(fee_ai)?;
    require(fee_mint == *mint_ai.key && fee_owner.to_bytes() == vault.config.fee_owner, VaultError::InvalidAccount)?;
    let amount = vault.fees_accrued;
    if amount == 0 {
        return Ok(());
    }
    require(before_vault as u128 >= vault.total_locked as u128 + amount as u128, VaultError::InsufficientBacking)?;
    vault.fees_accrued = 0;
    store_vault(&vault, vault_ai)?;
    invoke_signed(
        &transfer_checked_ix(tokens_ai.key, mint_ai.key, fee_ai.key, vault_ai.key, amount),
        &[tokens_ai.clone(), mint_ai.clone(), fee_ai.clone(), vault_ai.clone(), token_program.clone()],
        &[&[SEED_VAULT, &vault.config_hash, &[vault.bump]]],
    )?;
    let (_, _, after_vault) = token_account(tokens_ai)?;
    let (_, _, after_fee) = token_account(fee_ai)?;
    require(
        after_vault as u128 + amount as u128 == before_vault as u128 && after_fee as u128 == before_fee as u128 + amount as u128,
        VaultError::InvalidTransfer,
    )?;
    sol_log_data(&[b"BLOCH-SVM-FEES-SWEPT-v1", &amount.to_le_bytes()]);
    Ok(())
}
