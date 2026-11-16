//! Account layouts. Every account of this program starts with a type tag and a layout version; all integers are
//! little-endian; nothing is reallocated after creation.

use crate::abi::{Addr20, Word};
use crate::error::VaultError;
use solana_program::program_error::ProgramError;

pub const MAX_SIGNERS: usize = 16;
pub const MAX_GUARDIANS: usize = 7;
pub const MAX_FEE_BPS: u16 = 30;
pub const BPS: u128 = 10_000;
pub const MAX_PAUSE_DURATION: u64 = 14 * 86_400;
pub const MAX_RELEASE_DELAY: u64 = 14 * 86_400;
pub const MIN_VALID_SECONDS: u64 = 60;
pub const MAX_VALID_SECONDS: u64 = 86_400;
pub const DECIMALS: u8 = 6;

pub const TAG_VAULT: u8 = 1;
pub const TAG_DEPOSIT: u8 = 2;
pub const TAG_RELEASE: u8 = 3;
pub const LAYOUT_VERSION: u8 = 1;

pub const CONFIG_FIXED_LEN: usize = 6 * 32 + 10 * 8 + 2 * 2 + 4;

pub struct Reader<'a> {
    data: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, at: 0 }
    }
    pub fn take(&mut self, n: usize) -> Result<&'a [u8], ProgramError> {
        let end = self.at.checked_add(n).ok_or(ProgramError::InvalidInstructionData)?;
        let s = self.data.get(self.at..end).ok_or(ProgramError::InvalidInstructionData)?;
        self.at = end;
        Ok(s)
    }
    pub fn u8(&mut self) -> Result<u8, ProgramError> {
        Ok(self.take(1)?[0])
    }
    pub fn u16(&mut self) -> Result<u16, ProgramError> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }
    pub fn u64(&mut self) -> Result<u64, ProgramError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    pub fn word(&mut self) -> Result<Word, ProgramError> {
        Ok(self.take(32)?.try_into().unwrap())
    }
    pub fn addr(&mut self) -> Result<Addr20, ProgramError> {
        Ok(self.take(20)?.try_into().unwrap())
    }
    pub fn done(&self) -> Result<(), ProgramError> {
        if self.at == self.data.len() {
            Ok(())
        } else {
            Err(ProgramError::InvalidInstructionData)
        }
    }
}

pub struct Writer<'a> {
    data: &'a mut [u8],
    at: usize,
}

impl<'a> Writer<'a> {
    pub fn new(data: &'a mut [u8]) -> Self {
        Self { data, at: 0 }
    }
    pub fn put(&mut self, bytes: &[u8]) {
        self.data[self.at..self.at + bytes.len()].copy_from_slice(bytes);
        self.at += bytes.len();
    }
    pub fn u8(&mut self, v: u8) {
        self.put(&[v]);
    }
    pub fn u16(&mut self, v: u16) {
        self.put(&v.to_le_bytes());
    }
    pub fn u64(&mut self, v: u64) {
        self.put(&v.to_le_bytes());
    }
    pub fn at(&self) -> usize {
        self.at
    }
}

/// Everything fixed at initialization. The vault's address is derived from the hash of these bytes, so a vault
/// with other values is another vault at another address, and nobody can take this address with other values.
#[derive(Clone)]
pub struct Config {
    pub mint: Word,
    pub fee_owner: Word,
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
    pub signer_count: u8,
    pub guardian_count: u8,
    pub signers: [Addr20; MAX_SIGNERS],
    pub guardians: [Addr20; MAX_GUARDIANS],
}

pub fn fee(amount: u64, bps: u16) -> u64 {
    (amount as u128 * bps as u128 / BPS) as u64
}

impl Config {
    fn read_fixed(r: &mut Reader) -> Result<Config, ProgramError> {
        Ok(Config {
            mint: r.word()?,
            fee_owner: r.word()?,
            source_chain_id: r.word()?,
            source_domain: r.word()?,
            native_domain: r.word()?,
            native_asset: r.word()?,
            cap: r.u64()?,
            window_limit: r.u64()?,
            window_seconds: r.u64()?,
            min_deposit: r.u64()?,
            l2_min_burn: r.u64()?,
            large_release_threshold: r.u64()?,
            release_delay: r.u64()?,
            pause_duration: r.u64()?,
            pause_cooldown: r.u64()?,
            max_valid_seconds: r.u64()?,
            deposit_fee_bps: r.u16()?,
            release_fee_bps: r.u16()?,
            threshold: r.u8()?,
            switch_threshold: r.u8()?,
            signer_count: r.u8()?,
            guardian_count: r.u8()?,
            signers: [[0u8; 20]; MAX_SIGNERS],
            guardians: [[0u8; 20]; MAX_GUARDIANS],
        })
    }

    fn write_fixed(&self, w: &mut Writer) {
        w.put(&self.mint);
        w.put(&self.fee_owner);
        w.put(&self.source_chain_id);
        w.put(&self.source_domain);
        w.put(&self.native_domain);
        w.put(&self.native_asset);
        w.u64(self.cap);
        w.u64(self.window_limit);
        w.u64(self.window_seconds);
        w.u64(self.min_deposit);
        w.u64(self.l2_min_burn);
        w.u64(self.large_release_threshold);
        w.u64(self.release_delay);
        w.u64(self.pause_duration);
        w.u64(self.pause_cooldown);
        w.u64(self.max_valid_seconds);
        w.u16(self.deposit_fee_bps);
        w.u16(self.release_fee_bps);
        w.u8(self.threshold);
        w.u8(self.switch_threshold);
        w.u8(self.signer_count);
        w.u8(self.guardian_count);
    }

    /// The canonical instruction encoding: the fixed part, then exactly `signer_count` and `guardian_count`
    /// 20-byte addresses, and nothing after them.
    pub fn parse(data: &[u8]) -> Result<Config, ProgramError> {
        let mut r = Reader::new(data);
        let mut c = Self::read_fixed(&mut r)?;
        if c.signer_count as usize > MAX_SIGNERS || c.guardian_count as usize > MAX_GUARDIANS {
            return Err(VaultError::InvalidConfiguration.into());
        }
        for i in 0..c.signer_count as usize {
            c.signers[i] = r.addr()?;
        }
        for i in 0..c.guardian_count as usize {
            c.guardians[i] = r.addr()?;
        }
        r.done()?;
        Ok(c)
    }

    pub fn signer_set(&self) -> &[Addr20] {
        &self.signers[..self.signer_count as usize]
    }

    pub fn guardian_set(&self) -> &[Addr20] {
        &self.guardians[..self.guardian_count as usize]
    }

    /// The rules of the `ProvenanceSourceVault` constructor, plus the two Solana-only values.
    pub fn validate(&self) -> Result<(), ProgramError> {
        let zero = [0u8; 32];
        let n = self.signer_count as usize;
        let g = self.guardian_count as usize;
        let bad = self.deposit_fee_bps > MAX_FEE_BPS
            || self.release_fee_bps > MAX_FEE_BPS
            || self.fee_owner == zero
            || self.mint == zero
            || self.source_chain_id == zero
            || self.source_domain == zero
            || self.native_domain == zero
            || self.source_domain == self.native_domain
            || self.native_asset == zero
            || self.cap == 0
            || self.threshold < 2
            || self.threshold as usize > n
            || self.switch_threshold < self.threshold
            || self.switch_threshold as usize > n
            || self.window_limit == 0
            || self.window_limit > self.cap
            || self.window_seconds == 0
            || self.l2_min_burn == 0
            || self.min_deposit < self.l2_min_burn
            || self.min_deposit > self.window_limit
            || self.min_deposit - fee(self.min_deposit, self.deposit_fee_bps) < self.l2_min_burn
            || self.release_delay > MAX_RELEASE_DELAY
            || (self.release_delay == 0 && self.large_release_threshold != 0)
            || self.max_valid_seconds < MIN_VALID_SECONDS
            || self.max_valid_seconds > MAX_VALID_SECONDS
            || (g == 0 && (self.pause_duration != 0 || self.pause_cooldown != 0))
            || (g != 0
                && (self.pause_duration == 0
                    || self.pause_duration > MAX_PAUSE_DURATION
                    || self.pause_cooldown < self.pause_duration
                    || self.pause_cooldown > MAX_PAUSE_DURATION));
        if bad {
            return Err(VaultError::InvalidConfiguration.into());
        }
        // Strictly ascending: no zero address, no duplicate. Guardians are never signers.
        let mut previous = [0u8; 20];
        for s in self.signer_set() {
            if *s <= previous {
                return Err(VaultError::InvalidConfiguration.into());
            }
            previous = *s;
        }
        previous = [0u8; 20];
        for a in self.guardian_set() {
            if *a <= previous || self.signer_set().contains(a) {
                return Err(VaultError::InvalidConfiguration.into());
            }
            previous = *a;
        }
        Ok(())
    }
}

pub const VAULT_LEN: usize = 4 + 32 + CONFIG_FIXED_LEN + 20 * MAX_SIGNERS + 20 * MAX_GUARDIANS // header, config
    + 20 + 20 + 32 + 32 + 32 + 32 // vault20, mint20, route, genesis, token account, fee token account
    + 32 + 8 * 4 + 2 + 8 * 6 + 8 * MAX_GUARDIANS + 8 * 2; // head and counters

pub struct Vault {
    pub bump: u8,
    pub token_bump: u8,
    pub config_hash: Word,
    pub config: Config,
    pub vault20: Addr20,
    pub mint20: Addr20,
    pub route: Word,
    pub genesis: Word,
    pub token_account: Word,
    pub fee_token_account: Word,
    /// Deposit-chain head after `deposit_count` deposits (the genesis before any).
    pub head: Word,
    pub deposit_count: u64,
    pub total_locked: u64,
    pub fees_accrued: u64,
    pub control_nonce: u64,
    pub deposits_enabled: bool,
    pub releases_enabled: bool,
    pub release_bucket: u64,
    pub bucket_updated_at: u64,
    pub paused_until: u64,
    pub pause_count: u64,
    pub guardian_blocked_until: u64,
    pub pause_chain: u64,
    pub guardian_last_chain: [u64; MAX_GUARDIANS],
    /// Approvals so far; each approval takes the next number.
    pub approval_seq: u64,
    /// Approvals numbered at or below this were voided by a guardian pause and must be approved again.
    pub void_through_seq: u64,
}

impl Vault {
    pub fn load(data: &[u8]) -> Result<Vault, ProgramError> {
        if data.len() != VAULT_LEN || data[0] != TAG_VAULT || data[1] != LAYOUT_VERSION {
            return Err(VaultError::InvalidAccount.into());
        }
        let mut r = Reader::new(data);
        r.take(2)?;
        let bump = r.u8()?;
        let token_bump = r.u8()?;
        let config_hash = r.word()?;
        let mut config = Config::read_fixed(&mut r)?;
        for i in 0..MAX_SIGNERS {
            config.signers[i] = r.addr()?;
        }
        for i in 0..MAX_GUARDIANS {
            config.guardians[i] = r.addr()?;
        }
        let mut v = Vault {
            bump,
            token_bump,
            config_hash,
            config,
            vault20: r.addr()?,
            mint20: r.addr()?,
            route: r.word()?,
            genesis: r.word()?,
            token_account: r.word()?,
            fee_token_account: r.word()?,
            head: r.word()?,
            deposit_count: r.u64()?,
            total_locked: r.u64()?,
            fees_accrued: r.u64()?,
            control_nonce: r.u64()?,
            deposits_enabled: r.u8()? == 1,
            releases_enabled: r.u8()? == 1,
            release_bucket: r.u64()?,
            bucket_updated_at: r.u64()?,
            paused_until: r.u64()?,
            pause_count: r.u64()?,
            guardian_blocked_until: r.u64()?,
            pause_chain: r.u64()?,
            guardian_last_chain: [0u64; MAX_GUARDIANS],
            approval_seq: 0,
            void_through_seq: 0,
        };
        for i in 0..MAX_GUARDIANS {
            v.guardian_last_chain[i] = r.u64()?;
        }
        v.approval_seq = r.u64()?;
        v.void_through_seq = r.u64()?;
        r.done().map_err(|_| VaultError::InvalidAccount)?;
        Ok(v)
    }

    pub fn store(&self, data: &mut [u8]) -> Result<(), ProgramError> {
        if data.len() != VAULT_LEN {
            return Err(VaultError::InvalidAccount.into());
        }
        let mut w = Writer::new(data);
        w.u8(TAG_VAULT);
        w.u8(LAYOUT_VERSION);
        w.u8(self.bump);
        w.u8(self.token_bump);
        w.put(&self.config_hash);
        self.config.write_fixed(&mut w);
        for s in &self.config.signers {
            w.put(s);
        }
        for g in &self.config.guardians {
            w.put(g);
        }
        w.put(&self.vault20);
        w.put(&self.mint20);
        w.put(&self.route);
        w.put(&self.genesis);
        w.put(&self.token_account);
        w.put(&self.fee_token_account);
        w.put(&self.head);
        w.u64(self.deposit_count);
        w.u64(self.total_locked);
        w.u64(self.fees_accrued);
        w.u64(self.control_nonce);
        w.u8(self.deposits_enabled as u8);
        w.u8(self.releases_enabled as u8);
        w.u64(self.release_bucket);
        w.u64(self.bucket_updated_at);
        w.u64(self.paused_until);
        w.u64(self.pause_count);
        w.u64(self.guardian_blocked_until);
        w.u64(self.pause_chain);
        for c in &self.guardian_last_chain {
            w.u64(*c);
        }
        w.u64(self.approval_seq);
        w.u64(self.void_through_seq);
        debug_assert_eq!(w.at(), VAULT_LEN);
        Ok(())
    }

    /// What the release bucket allows at `now`: capacity `window_limit`, refilled continuously over
    /// `window_seconds` (`ProvenanceSourceVault.availableToRelease`).
    pub fn available_to_release(&self, now: u64) -> u64 {
        let elapsed = now.saturating_sub(self.bucket_updated_at) as u128;
        let refilled = self.release_bucket as u128 + elapsed * self.config.window_limit as u128 / self.config.window_seconds as u128;
        core::cmp::min(refilled, self.config.window_limit as u128) as u64
    }

    pub fn paused(&self, now: u64) -> bool {
        now < self.paused_until
    }

    pub fn chain_ended(&self, now: u64) -> bool {
        self.pause_count == 0 || now >= self.paused_until.saturating_add(self.config.pause_cooldown)
    }
}

/// One deposit, written once and never changed or closed: the canonical record the watchers read.
pub const DEPOSIT_LEN: usize = 2 + 1 + 32 + 8 + 32 + 32 + 20 + 20 + 8 + 8 + 32 + 8 + 8;

pub struct DepositRecord {
    pub bump: u8,
    pub vault: Word,
    pub nonce: u64,
    pub id: Word,
    pub depositor: Word,
    pub sender20: Addr20,
    pub l2_recipient: Addr20,
    /// Net amount: what the L2 token mints and what stays locked.
    pub amount: u64,
    pub fee: u64,
    /// Deposit-chain head after this deposit (`depositHead[nonce + 1]`).
    pub head_after: Word,
    pub slot: u64,
    pub timestamp: u64,
}

impl DepositRecord {
    pub fn load(data: &[u8]) -> Result<DepositRecord, ProgramError> {
        if data.len() != DEPOSIT_LEN || data[0] != TAG_DEPOSIT || data[1] != LAYOUT_VERSION {
            return Err(VaultError::InvalidAccount.into());
        }
        let mut r = Reader::new(&data[2..]);
        Ok(DepositRecord {
            bump: r.u8()?,
            vault: r.word()?,
            nonce: r.u64()?,
            id: r.word()?,
            depositor: r.word()?,
            sender20: r.addr()?,
            l2_recipient: r.addr()?,
            amount: r.u64()?,
            fee: r.u64()?,
            head_after: r.word()?,
            slot: r.u64()?,
            timestamp: r.u64()?,
        })
    }

    pub fn store(&self, data: &mut [u8]) {
        let mut w = Writer::new(data);
        w.u8(TAG_DEPOSIT);
        w.u8(LAYOUT_VERSION);
        w.u8(self.bump);
        w.put(&self.vault);
        w.u64(self.nonce);
        w.put(&self.id);
        w.put(&self.depositor);
        w.put(&self.sender20);
        w.put(&self.l2_recipient);
        w.u64(self.amount);
        w.u64(self.fee);
        w.put(&self.head_after);
        w.u64(self.slot);
        w.u64(self.timestamp);
        debug_assert_eq!(w.at(), DEPOSIT_LEN);
    }
}

pub const RELEASE_APPROVED: u8 = 1;
pub const RELEASE_PAID: u8 = 2;

/// One release per burn nonce: approved by a certificate, then paid once. Never closed (replay protection).
pub const RELEASE_LEN: usize = 2 + 1 + 1 + 32 + 8 + 32 + 20 + 8 + 32 + 8 + 8 + 8 + 8 + 8;

pub struct ReleaseRecord {
    pub bump: u8,
    pub state: u8,
    pub vault: Word,
    pub nonce: u64,
    pub release_id: Word,
    pub recipient: Addr20,
    pub amount: u64,
    pub native_burn: Word,
    pub ready_at: u64,
    pub seq: u64,
    pub approved_at: u64,
    pub paid_at: u64,
    pub paid_amount: u64,
}

impl ReleaseRecord {
    pub fn load(data: &[u8]) -> Result<ReleaseRecord, ProgramError> {
        if data.len() != RELEASE_LEN || data[0] != TAG_RELEASE || data[1] != LAYOUT_VERSION {
            return Err(VaultError::InvalidAccount.into());
        }
        let mut r = Reader::new(&data[2..]);
        Ok(ReleaseRecord {
            bump: r.u8()?,
            state: r.u8()?,
            vault: r.word()?,
            nonce: r.u64()?,
            release_id: r.word()?,
            recipient: r.addr()?,
            amount: r.u64()?,
            native_burn: r.word()?,
            ready_at: r.u64()?,
            seq: r.u64()?,
            approved_at: r.u64()?,
            paid_at: r.u64()?,
            paid_amount: r.u64()?,
        })
    }

    pub fn store(&self, data: &mut [u8]) {
        let mut w = Writer::new(data);
        w.u8(TAG_RELEASE);
        w.u8(LAYOUT_VERSION);
        w.u8(self.bump);
        w.u8(self.state);
        w.put(&self.vault);
        w.u64(self.nonce);
        w.put(&self.release_id);
        w.put(&self.recipient);
        w.u64(self.amount);
        w.put(&self.native_burn);
        w.u64(self.ready_at);
        w.u64(self.seq);
        w.u64(self.approved_at);
        w.u64(self.paid_at);
        w.u64(self.paid_amount);
        debug_assert_eq!(w.at(), RELEASE_LEN);
    }
}
