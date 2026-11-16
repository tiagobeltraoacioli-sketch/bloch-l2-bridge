//! Bloch bridge source vault on Stellar (Soroban): custody of one Stellar asset (issuer-native USDC through its
//! Stellar Asset Contract) for one wrapped token on the Bloch L2 (`BridgedStablecoinV3`, `bUSDC.xlm`).
//!
//! STATUS: PROTOTYPE, UNAUDITED. Not for deployment.
//!
//! It is the Stellar counterpart of `contracts/usdt/ProvenanceSourceVault.sol` in provenance mode 1, with the same
//! committee: the signers and guardians are the 20-byte Ethereum addresses of secp256k1 keys, and every certificate
//! is checked with the host's secp256k1 recovery and keccak256. No Stellar (ed25519) key holds any power here.
//!
//! What it keeps from the Ethereum vault:
//! - books in the L2 token's 6-decimal units (`total_locked`, `fees_accrued`), net of the deposit fee;
//! - a deposit id whose top 8 bytes are the deposit nonce, and a hash chain over `(id, net amount, L2 recipient)`
//!   that is byte-identical to the chain `BridgedStablecoinV3` extends over its mints; a release is paid only if the
//!   burn states this vault's head at the burn's mint count;
//! - a release token bucket (`window_limit` per `window_seconds`), a supply cap, a minimum deposit;
//! - pause-only guardians with the same chain rule, ended early only by `switch_threshold` signers;
//! - replay protection by burn nonce and burn id;
//! - a fee of `deposit_fee_bps` and `release_fee_bps`, held outside the backing, swept by anyone to one address
//!   fixed at deployment.
//!
//! What differs (see docs/STELLAR-BRIDGE.md for the full table):
//! - there is no upgrade, no administrator and no light-client switch: the contract never calls
//!   `update_current_contract_wasm`, so its code cannot change;
//! - Stellar assets have 7 decimals: amounts cross the token interface in stroops and must be multiples of
//!   `STROOPS_PER_UNIT`; nothing is rounded;
//! - a guardian pauses with a signature (its secp256k1 key cannot sign a Stellar transaction);
//! - releases above `large_release_threshold` wait `release_delay` in a queue (both fixed at deployment; delay 0
//!   means no queue). Guardians have no other power than the pause, and a pause voids: every certificate signed
//!   before it and every release still queued is dead (both carry the pause count they were made under). A voided
//!   burn loses nothing: the committee certifies it again with the ordinary threshold, once per pause, and it waits
//!   the delay again. An unpause revives nothing;
//! - there is no block-hash anchor (Soroban exposes none and Stellar has no forks); a certificate binds the network
//!   id, this contract and the vault's pause count, and expires at `valid_until`, at most `MAX_VALIDITY` ahead;
//! - every digest is signed as an Ethereum personal message (EIP-191, "\x19Ethereum Signed Message:\n32"), as on
//!   the other routes; the digest itself starts with a `BLOCH-XLM-...` tag and binds the network id and contract id;
//! - the recipient of a release is a Stellar address, which the 20-byte recipient of the L2 burn commits to.
//!
//! Storage and archival: replay records are persistent entries. A persistent entry whose TTL ends is archived, never
//! deleted, and an archived entry can only be restored, never created again, so an expired record cannot re-enable
//! a release. Independently, a certificate expires at most `MAX_VALIDITY` after it is signed, and every record is
//! written with a TTL far above that. Nothing here uses temporary storage.
#![no_std]

use soroban_sdk::{
    address_payload::AddressPayload, contract, contracterror, contractevent, contractimpl, contracttype,
    crypto::Hash, panic_with_error, token, Address, Bytes, BytesN, Env, Map, Vec,
};

/// Stellar classic assets have 7 decimals; the L2 token has 6.
pub const STROOPS_PER_UNIT: i128 = 10;
pub const TOKEN_DECIMALS: u32 = 7;
pub const MAX_SIGNERS: u32 = 16;
pub const MAX_GUARDIANS: u32 = 7;
pub const MAX_PAUSE_DURATION: u64 = 14 * 86_400;
pub const MAX_RELEASE_DELAY: u64 = 14 * 86_400;
pub const MAX_FEE_BPS: u32 = 30;
const BPS: u64 = 10_000;
/// A certificate's `valid_until` is at most this far ahead of the ledger that accepts it.
pub const MAX_VALIDITY: u64 = 86_400;
/// Ledgers. Replay records, chain heads and queued releases are written with at least this TTL (30 days at 5 s a
/// ledger), capped by the network's maximum. The network's own minimum for a new persistent entry is higher today.
#[cfg(not(feature = "rehearsal-short-ttl"))]
pub const RECORD_TTL: u32 = 518_400;
/// Rehearsal builds only (never deployed): records live 30 ledgers, so a local network can show one expiring.
#[cfg(feature = "rehearsal-short-ttl")]
pub const RECORD_TTL: u32 = 30;
/// The instance (configuration and books) is extended to `INSTANCE_TTL` whenever it is below `INSTANCE_TTL / 2`.
pub const INSTANCE_TTL: u32 = 1_555_200;

/// secp256k1 group order / 2: signatures with a higher `s` are refused (no malleable twin).
const HALF_ORDER: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x5d, 0x57, 0x6e,
    0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
];

/// The tag of the mint chain. It must equal `MINT_CHAIN_TAG` of `BridgedStablecoinV3`.
const TAG_MINT_CHAIN: &[u8] = b"BLOCH-USDT-MINT-CHAIN-v1";
const TAG_ROUTE: &[u8] = b"BLOCH-XLM-ROUTE-v1";
const TAG_DEPOSIT: &[u8] = b"BLOCH-XLM-DEPOSIT-v1";
const TAG_SENDER: &[u8] = b"BLOCH-XLM-SENDER-v1";
const TAG_RECIPIENT: &[u8] = b"BLOCH-XLM-RECIPIENT-v1";
const TAG_RELEASE: &[u8] = b"BLOCH-XLM-RELEASE-v1";
const TAG_RELEASE_AUTH: &[u8] = b"BLOCH-XLM-RELEASE-AUTH-v1";
const TAG_CONTROLS: &[u8] = b"BLOCH-XLM-CONTROLS-v1";
const TAG_PAUSE: &[u8] = b"BLOCH-XLM-GUARDIAN-PAUSE-v1";
const TAG_UNPAUSE: &[u8] = b"BLOCH-XLM-UNPAUSE-v1";
/// EIP-191 personal-message prefix for a 32-byte message: what the committee's keys actually sign.
const PERSONAL_PREFIX: &[u8] = b"\x19Ethereum Signed Message:\n32";

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    InvalidConfiguration = 1,
    InvalidTransfer = 2,
    InvalidRelease = 3,
    InvalidCertificate = 4,
    InvalidControls = 5,
    InsufficientBacking = 6,
    InvalidContext = 7,
    RateLimited = 8,
    InvalidPause = 9,
    Paused = 10,
    ProvenanceMismatch = 11,
    NotQueued = 12,
    NotReady = 13,
    /// A queued release from before a guardian pause: dead; the burn must be certified again.
    Voided = 14,
    NotGuardian = 15,
}

/// Everything fixed at deployment. No function changes any of it.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Config {
    /// The Stellar Asset Contract of the asset in custody.
    pub token: Address,
    /// Labels of the route, as on the Ethereum vault: source network, native network, asset.
    pub source_domain: BytesN<32>,
    pub native_domain: BytesN<32>,
    pub asset: BytesN<32>,
    /// Units below are the L2 token's (6 decimals). One unit is `STROOPS_PER_UNIT` stroops.
    pub cap: u64,
    pub window_limit: u64,
    pub window_seconds: u64,
    pub min_deposit: u64,
    pub l2_min_burn: u64,
    /// secp256k1 committee, as Ethereum addresses, strictly ascending.
    pub signers: Vec<BytesN<20>>,
    pub threshold: u32,
    /// Signatures that end a pause early (>= threshold).
    pub switch_threshold: u32,
    /// Pause-only guardians, strictly ascending, never signers. A pause voids the queue and older certificates.
    pub guardians: Vec<BytesN<20>>,
    pub pause_duration: u64,
    pub pause_cooldown: u64,
    /// A release above this amount waits `release_delay` seconds in the queue. Delay 0: nothing queues.
    pub large_release_threshold: u64,
    pub release_delay: u64,
    pub fee_recipient: Address,
    pub deposit_fee_bps: u32,
    pub release_fee_bps: u32,
}

/// Values derived once from the configuration and the deployment itself.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Derived {
    /// sha256 of the network passphrase. As a uint256 it is the L2 token's `sourceChainId`.
    pub network_id: BytesN<32>,
    /// This contract's id (the 32 bytes behind its `C...` address).
    pub vault_id: BytesN<32>,
    /// The last 20 bytes of `vault_id`: the L2 token's `sourceVault`.
    pub vault20: BytesN<20>,
    /// The L2 token's `sourceRoute`.
    pub route: BytesN<32>,
    /// Head of the deposit chain before any deposit; the L2 token's `mintHead` at deployment.
    pub genesis: BytesN<32>,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct State {
    pub deposit_count: u64,
    pub total_locked: u64,
    pub fees_accrued: u64,
    pub deposit_head: BytesN<32>,
    pub control_nonce: u64,
    pub deposits_enabled: bool,
    pub releases_enabled: bool,
    pub bucket: u64,
    pub bucket_updated_at: u64,
    pub paused_until: u64,
    pub pause_count: u64,
    pub guardian_blocked_until: u64,
    pub pause_chain: u64,
    pub guardian_last_chain: Map<BytesN<20>, u64>,
}

/// A burn the L2 token recorded, as its `Burned` log states it, and where to pay it.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Release {
    pub route: BytesN<32>,
    /// The L2 token's burn nonce.
    pub nonce: u64,
    /// Stellar address paid. The burn's 20-byte recipient must be `recipient_commitment(recipient)`.
    pub recipient: Address,
    /// Burned amount in units; the recipient gets it less the release fee.
    pub amount: u64,
    /// The L2 token's burn id.
    pub native_burn: BytesN<32>,
    pub mint_count: u64,
    pub minted_total: u64,
    pub mint_head: BytesN<32>,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseContext {
    /// Ledger close time (seconds) after which the certificate is dead.
    pub valid_until: u64,
    /// The vault's `pause_count` when the certificate was signed. A guardian pause raises the count, so no
    /// certificate from before a pause is accepted after it, however the pause ends.
    pub pause_count: u64,
    /// Bloch L2 block, final on the Bloch L1, holding the burn.
    pub native_finalized_number: u64,
    pub native_finalized_hash: BytesN<32>,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BurnRecord {
    pub burn: BytesN<32>,
    /// The vault's `pause_count` when this release was accepted.
    pub pause_count: u64,
    /// False while the release waits in the queue. An unpaid record from before the latest pause is void: the nonce
    /// is open again for one certificate.
    pub paid: bool,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Pending {
    pub recipient: Address,
    pub amount: u64,
    pub ready_at: u64,
    pub nonce: u64,
    /// The vault's `pause_count` when it was queued; it is executed only while the count is still that.
    pub pause_count: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Backing {
    /// The vault's balance of the asset, in stroops.
    pub balance: i128,
    /// What the books need: `(total_locked + fees_accrued) * STROOPS_PER_UNIT`.
    pub required: i128,
}

#[contracttype]
#[derive(Clone)]
enum Key {
    Config,
    Derived,
    State,
    /// Deposit-chain head after n deposits (n >= 1). Persistent.
    Head(u64),
    /// Replay record by burn nonce. Persistent.
    Nonce(u64),
    /// Replay record by burn id: the nonce it was released under. Persistent. It counts only while that nonce's
    /// record names this id and is paid or still queued under the current pause count.
    Burn(BytesN<32>),
    /// A queued release, by release id. Persistent.
    Pending(BytesN<32>),
}

#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Deposited {
    #[topic]
    pub id: BytesN<32>,
    pub nonce: u64,
    pub sender: Address,
    /// Net amount in units: what the L2 token mints.
    pub amount: u64,
    pub fee: u64,
    pub l2_recipient: BytesN<20>,
    /// Deposit-chain head after this deposit.
    pub head: BytesN<32>,
}

#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Released {
    #[topic]
    pub id: BytesN<32>,
    pub nonce: u64,
    pub recipient: Address,
    pub amount: u64,
    pub fee: u64,
    pub native_burn: BytesN<32>,
}

#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseQueued {
    #[topic]
    pub id: BytesN<32>,
    pub nonce: u64,
    pub recipient: Address,
    pub amount: u64,
    pub native_burn: BytesN<32>,
    pub ready_at: u64,
}

#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControlsUpdated {
    #[topic]
    pub nonce: u64,
    pub deposits_enabled: bool,
    pub releases_enabled: bool,
}

#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuardianPaused {
    #[topic]
    pub guardian: BytesN<20>,
    pub pause_count: u64,
    pub paused_until: u64,
}

#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Unpaused {
    #[topic]
    pub pause_count: u64,
    pub guardian_blocked_until: u64,
}

#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FeesSwept {
    #[topic]
    pub recipient: Address,
    pub amount: u64,
}

/// 32-byte words, as Solidity's `abi.encode` lays out static values.
struct Words {
    bytes: Bytes,
}

impl Words {
    fn new(env: &Env) -> Self {
        Words { bytes: Bytes::new(env) }
    }
    /// `bytes32("TAG")`: left-aligned, zero-padded.
    fn tag(mut self, tag: &[u8]) -> Self {
        let mut w = [0u8; 32];
        w[..tag.len()].copy_from_slice(tag);
        self.bytes.extend_from_array(&w);
        self
    }
    fn b32(mut self, v: &BytesN<32>) -> Self {
        self.bytes.extend_from_array(&v.to_array());
        self
    }
    /// `uint256(v)`.
    fn uint(mut self, v: u64) -> Self {
        let mut w = [0u8; 32];
        w[24..].copy_from_slice(&v.to_be_bytes());
        self.bytes.extend_from_array(&w);
        self
    }
    /// `address`: left-padded.
    fn addr20(mut self, v: &BytesN<20>) -> Self {
        let mut w = [0u8; 32];
        w[12..].copy_from_slice(&v.to_array());
        self.bytes.extend_from_array(&w);
        self
    }
    fn keccak(self, env: &Env) -> Hash<32> {
        env.crypto().keccak256(&self.bytes)
    }
    fn sha256(self, env: &Env) -> Hash<32> {
        env.crypto().sha256(&self.bytes)
    }
}

fn fail(env: &Env, e: Error) -> ! {
    panic_with_error!(env, e)
}

fn fee_of(amount: u64, bps: u32) -> u64 {
    ((amount as u128) * (bps as u128) / (BPS as u128)) as u64
}

fn contract_id(env: &Env, a: &Address) -> BytesN<32> {
    match a.to_payload() {
        Some(AddressPayload::ContractIdHash(h)) => h,
        _ => fail(env, Error::InvalidConfiguration),
    }
}

/// keccak256(bytes32(tag) ‖ the address's strkey, 56 ASCII bytes).
fn address_hash(env: &Env, tag: &[u8], a: &Address) -> BytesN<32> {
    let s = a.to_string();
    if s.len() != 56 {
        fail(env, Error::InvalidTransfer);
    }
    let mut strkey = [0u8; 56];
    s.copy_into_slice(&mut strkey);
    let mut w = Words::new(env).tag(tag);
    w.bytes.extend_from_array(&strkey);
    w.keccak(env).to_bytes()
}

fn load_config(env: &Env) -> Config {
    env.storage().instance().get(&Key::Config).unwrap()
}

fn load_derived(env: &Env) -> Derived {
    env.storage().instance().get(&Key::Derived).unwrap()
}

fn load_state(env: &Env) -> State {
    env.storage().instance().get(&Key::State).unwrap()
}

fn save_state(env: &Env, st: &State) {
    env.storage().instance().set(&Key::State, st);
    let ttl = INSTANCE_TTL.min(env.storage().max_ttl());
    env.storage().instance().extend_ttl(ttl / 2, ttl);
}

fn put<V: soroban_sdk::IntoVal<Env, soroban_sdk::Val>>(env: &Env, key: &Key, value: &V) {
    env.storage().persistent().set(key, value);
    let ttl = RECORD_TTL.min(env.storage().max_ttl());
    env.storage().persistent().extend_ttl(key, ttl, ttl);
}

fn available(cfg: &Config, st: &State, now: u64) -> u64 {
    let elapsed = now.saturating_sub(st.bucket_updated_at) as u128;
    let refilled = st.bucket as u128 + elapsed * cfg.window_limit as u128 / cfg.window_seconds as u128;
    if refilled > cfg.window_limit as u128 {
        cfg.window_limit
    } else {
        refilled as u64
    }
}

fn required_stroops(st: &State) -> i128 {
    (st.total_locked as i128 + st.fees_accrued as i128) * STROOPS_PER_UNIT
}

/// The Ethereum address of the key that signed `digest` as a personal message (EIP-191): the signature is over
/// keccak256("\x19Ethereum Signed Message:\n32" ‖ digest). Refuses a high `s` and any `v` but 27 or 28.
fn recover(env: &Env, digest: &Hash<32>, signature: &BytesN<65>) -> BytesN<20> {
    let mut message = Bytes::from_slice(env, PERSONAL_PREFIX);
    message.extend_from_array(&digest.to_array());
    let digest = &env.crypto().keccak256(&message);
    let sig = signature.to_array();
    let v = sig[64];
    if (v != 27 && v != 28) || sig[32..64] > HALF_ORDER[..] {
        fail(env, Error::InvalidCertificate);
    }
    let mut rs = [0u8; 64];
    rs.copy_from_slice(&sig[..64]);
    let key = env
        .crypto()
        .secp256k1_recover(digest, &BytesN::from_array(env, &rs), (v - 27) as u32)
        .to_array();
    let hash = env.crypto().keccak256(&Bytes::from_slice(env, &key[1..])).to_array();
    let mut out = [0u8; 20];
    out.copy_from_slice(&hash[12..]);
    BytesN::from_array(env, &out)
}

/// `required` or more signatures of distinct members of `set`, ordered by address.
fn check_certificate(env: &Env, digest: &Hash<32>, signatures: &Vec<BytesN<65>>, set: &Vec<BytesN<20>>, required: u32) {
    if signatures.len() < required || signatures.len() > set.len() {
        fail(env, Error::InvalidCertificate);
    }
    let mut previous = [0u8; 20];
    for signature in signatures.iter() {
        let signer = recover(env, digest, &signature);
        if signer.to_array() <= previous || !set.contains(&signer) {
            fail(env, Error::InvalidCertificate);
        }
        previous = signer.to_array();
    }
}

fn check_validity(env: &Env, valid_until: u64, e: Error) {
    let now = env.ledger().timestamp();
    if now > valid_until || valid_until - now > MAX_VALIDITY {
        fail(env, e);
    }
}

fn strictly_ascending(env: &Env, set: &Vec<BytesN<20>>) {
    let mut previous = [0u8; 20];
    for a in set.iter() {
        if a.to_array() <= previous {
            fail(env, Error::InvalidConfiguration);
        }
        previous = a.to_array();
    }
}

/// A release record counts while it is paid, or queued under the current pause count. An unpaid record from before
/// the latest guardian pause is void.
fn record_counts(r: &BurnRecord, pause_count: u64) -> bool {
    r.paid || r.pause_count == pause_count
}

fn chain_ended(cfg: &Config, st: &State, now: u64) -> bool {
    st.pause_count == 0 || now >= st.paused_until + cfg.pause_cooldown
}

fn guardian_can_pause(cfg: &Config, st: &State, guardian: &BytesN<20>, now: u64) -> bool {
    cfg.guardians.contains(guardian)
        && now >= st.paused_until
        && now >= st.guardian_blocked_until
        && (chain_ended(cfg, st, now) || st.guardian_last_chain.get(guardian.clone()) != Some(st.pause_chain))
}

/// A transfer of the asset. A failure inside the asset contract (a revoked authorization, a missing trustline, a
/// short balance) is reported as this vault's `InvalidTransfer`, never under the asset contract's own error number,
/// which would read as another of this vault's errors. Either way the whole call reverts.
fn move_asset(env: &Env, asset: &token::TokenClient, from: &Address, to: &Address, stroops: i128) {
    if !matches!(asset.try_transfer(from, to, &stroops), Ok(Ok(()))) {
        fail(env, Error::InvalidTransfer);
    }
}

/// Moves `amount` units out of the backing: the recipient gets it less the release fee, which stays as an accrued
/// fee. The bucket and `total_locked` take the full burned amount.
fn pay(env: &Env, cfg: &Config, st: &mut State, recipient: &Address, amount: u64) -> u64 {
    let now = env.ledger().timestamp();
    let room = available(cfg, st, now);
    if amount > room {
        fail(env, Error::RateLimited);
    }
    if amount > st.total_locked {
        fail(env, Error::InsufficientBacking);
    }
    st.bucket = room - amount;
    st.bucket_updated_at = now;
    let fee = fee_of(amount, cfg.release_fee_bps);
    let paid = (amount - fee) as i128 * STROOPS_PER_UNIT;
    let vault = env.current_contract_address();
    let asset = token::TokenClient::new(env, &cfg.token);
    let before = asset.balance(&vault);
    if before < required_stroops(st) {
        fail(env, Error::InsufficientBacking);
    }
    st.total_locked -= amount;
    st.fees_accrued += fee;
    move_asset(env, &asset, &vault, recipient, paid);
    if asset.balance(&vault) + paid != before {
        fail(env, Error::InvalidTransfer);
    }
    fee
}

#[contract]
pub struct Vault;

#[contractimpl]
impl Vault {
    pub fn __constructor(env: Env, config: Config) {
        let c = &config;
        let vault = env.current_contract_address();
        let n = c.signers.len();
        let g = c.guardians.len();
        if c.deposit_fee_bps > MAX_FEE_BPS
            || c.release_fee_bps > MAX_FEE_BPS
            || c.fee_recipient == vault
            || c.fee_recipient == c.token
            || c.token == vault
            || c.cap == 0
            || c.window_limit == 0
            || c.window_limit > c.cap
            || c.window_seconds == 0
            || c.l2_min_burn == 0
            || c.min_deposit > c.window_limit
            || c.min_deposit < c.l2_min_burn
            || c.min_deposit - fee_of(c.min_deposit, c.deposit_fee_bps) < c.l2_min_burn
            || c.threshold < 2
            || c.threshold > n
            || n > MAX_SIGNERS
            || c.switch_threshold < c.threshold
            || c.switch_threshold > n
            || g > MAX_GUARDIANS
            || (g == 0 && (c.pause_duration != 0 || c.pause_cooldown != 0))
            || (g != 0
                && (c.pause_duration == 0 || c.pause_duration > MAX_PAUSE_DURATION || c.pause_cooldown < c.pause_duration))
            || c.release_delay > MAX_RELEASE_DELAY
            // After a chain of pauses the vault is open for `pause_cooldown`: a voided exit must fit in it twice over.
            || (g != 0 && c.release_delay > c.pause_cooldown / 2)
            || c.source_domain == c.native_domain
            || c.source_domain.to_array() == [0u8; 32]
            || c.native_domain.to_array() == [0u8; 32]
            || c.asset.to_array() == [0u8; 32]
        {
            fail(&env, Error::InvalidConfiguration);
        }
        strictly_ascending(&env, &c.signers);
        strictly_ascending(&env, &c.guardians);
        for guardian in c.guardians.iter() {
            if c.signers.contains(&guardian) {
                fail(&env, Error::InvalidConfiguration);
            }
        }
        if token::TokenClient::new(&env, &c.token).decimals() != TOKEN_DECIMALS {
            fail(&env, Error::InvalidConfiguration);
        }
        let network_id = env.ledger().network_id();
        let vault_id = contract_id(&env, &vault);
        let token_id = contract_id(&env, &c.token);
        let mut low = [0u8; 20];
        low.copy_from_slice(&vault_id.to_array()[12..]);
        let vault20 = BytesN::from_array(&env, &low);
        let route = Words::new(&env)
            .tag(TAG_ROUTE)
            .b32(&network_id)
            .b32(&c.source_domain)
            .b32(&c.native_domain)
            .b32(&c.asset)
            .b32(&token_id)
            .b32(&vault_id)
            .uint(6)
            .uint(c.cap)
            .sha256(&env)
            .to_bytes();
        // keccak256(abi.encode(MINT_CHAIN_TAG, sourceChainId, sourceVault, sourceRoute)) of BridgedStablecoinV3.
        let genesis =
            Words::new(&env).tag(TAG_MINT_CHAIN).b32(&network_id).addr20(&vault20).b32(&route).keccak(&env).to_bytes();
        let state = State {
            deposit_count: 0,
            total_locked: 0,
            fees_accrued: 0,
            deposit_head: genesis.clone(),
            control_nonce: 0,
            deposits_enabled: false,
            releases_enabled: false,
            bucket: c.window_limit,
            bucket_updated_at: env.ledger().timestamp(),
            paused_until: 0,
            pause_count: 0,
            guardian_blocked_until: 0,
            pause_chain: 0,
            guardian_last_chain: Map::new(&env),
        };
        env.storage().instance().set(&Key::Config, &config);
        env.storage().instance().set(&Key::Derived, &Derived { network_id, vault_id, vault20, route, genesis });
        save_state(&env, &state);
    }

    // ── views ──────────────────────────────────────────────────────────────────

    pub fn config(env: Env) -> Config {
        load_config(&env)
    }

    pub fn derived(env: Env) -> Derived {
        load_derived(&env)
    }

    pub fn state(env: Env) -> State {
        load_state(&env)
    }

    /// True while a guardian pause stops deposits and releases.
    pub fn paused(env: Env) -> bool {
        env.ledger().timestamp() < load_state(&env).paused_until
    }

    /// What the release bucket allows right now, in units.
    pub fn available_to_release(env: Env) -> u64 {
        available(&load_config(&env), &load_state(&env), env.ledger().timestamp())
    }

    /// The vault's balance against what its books need. `balance < required` means the asset was taken from the
    /// vault from outside (an issuer clawback): deposits, releases and the fee sweep then fail until it is whole.
    pub fn backing(env: Env) -> Backing {
        let cfg = load_config(&env);
        Backing {
            balance: token::TokenClient::new(&env, &cfg.token).balance(&env.current_contract_address()),
            required: required_stroops(&load_state(&env)),
        }
    }

    /// Deposit-chain head after `count` deposits (`count` 0: the genesis).
    pub fn chain_head_at(env: Env, count: u64) -> Option<BytesN<32>> {
        if count == 0 {
            return Some(load_derived(&env).genesis);
        }
        env.storage().persistent().get(&Key::Head(count))
    }

    pub fn burn_record(env: Env, nonce: u64) -> Option<BurnRecord> {
        env.storage().persistent().get(&Key::Nonce(nonce))
    }

    /// The burn nonce a burn id was released under, if any.
    pub fn released_burn(env: Env, burn: BytesN<32>) -> Option<u64> {
        env.storage().persistent().get(&Key::Burn(burn))
    }

    /// Where the burn `burn` of nonce `nonce` stands: 0 open (never released, or its queued release was voided by a
    /// pause: a certificate is accepted), 1 queued, 2 paid, 3 held (the nonce counts for another burn id, or the
    /// burn id counts under another nonce: no certificate for this pair is accepted now).
    pub fn burn_status(env: Env, nonce: u64, burn: BytesN<32>) -> u32 {
        let pause_count = load_state(&env).pause_count;
        let record: Option<BurnRecord> = env.storage().persistent().get(&Key::Nonce(nonce));
        if let Some(r) = record {
            if record_counts(&r, pause_count) {
                return if r.burn != burn {
                    3
                } else if r.paid {
                    2
                } else {
                    1
                };
            }
        }
        let by_burn: Option<u64> = env.storage().persistent().get(&Key::Burn(burn.clone()));
        if let Some(other) = by_burn {
            if other != nonce {
                let o: Option<BurnRecord> = env.storage().persistent().get(&Key::Nonce(other));
                if let Some(o) = o {
                    if o.burn == burn && record_counts(&o, pause_count) {
                        return 3;
                    }
                }
            }
        }
        0
    }

    pub fn pending(env: Env, id: BytesN<32>) -> Option<Pending> {
        env.storage().persistent().get(&Key::Pending(id))
    }

    /// The 20 bytes an L2 burn must name as its recipient to be paid to `recipient` here: the low 20 bytes of
    /// keccak256(bytes32("BLOCH-XLM-RECIPIENT-v1") ‖ strkey).
    pub fn recipient_commitment(env: Env, recipient: Address) -> BytesN<20> {
        let hash = address_hash(&env, TAG_RECIPIENT, &recipient).to_array();
        let mut out = [0u8; 20];
        out.copy_from_slice(&hash[12..]);
        BytesN::from_array(&env, &out)
    }

    /// The id of a deposit: its nonce in the top 8 bytes (the L2 token reads the mint's slot there), then the low
    /// 24 bytes of sha256 over the route, the nonce, the sender, the net amount and the L2 recipient.
    pub fn deposit_id(env: Env, nonce: u64, sender: Address, amount: u64, l2_recipient: BytesN<20>) -> BytesN<32> {
        let hash = Words::new(&env)
            .tag(TAG_DEPOSIT)
            .b32(&load_derived(&env).route)
            .uint(nonce)
            .b32(&address_hash(&env, TAG_SENDER, &sender))
            .uint(amount)
            .addr20(&l2_recipient)
            .sha256(&env)
            .to_array();
        let mut id = hash;
        id[..8].copy_from_slice(&nonce.to_be_bytes());
        BytesN::from_array(&env, &id)
    }

    pub fn release_id(env: Env, item: Release) -> BytesN<32> {
        Words::new(&env)
            .tag(TAG_RELEASE)
            .b32(&item.route)
            .uint(item.nonce)
            .b32(&address_hash(&env, TAG_RECIPIENT, &item.recipient))
            .uint(item.amount)
            .b32(&item.native_burn)
            .uint(item.mint_count)
            .uint(item.minted_total)
            .b32(&item.mint_head)
            .sha256(&env)
            .to_bytes()
    }

    /// The 32 bytes the committee signs for a release, as an Ethereum personal message (EIP-191). The same holds
    /// for every `*_digest` view below.
    pub fn release_digest(env: Env, item: Release, context: ReleaseContext) -> BytesN<32> {
        Self::release_hash(&env, &Self::release_id(env.clone(), item), &context).to_bytes()
    }

    pub fn control_digest(env: Env, deposits: bool, releases: bool, nonce: u64, valid_until: u64) -> BytesN<32> {
        Self::control_hash(&env, deposits, releases, nonce, valid_until).to_bytes()
    }

    pub fn pause_digest(env: Env, pause_count: u64, valid_until: u64) -> BytesN<32> {
        Self::counted_hash(&env, TAG_PAUSE, pause_count, valid_until).to_bytes()
    }

    pub fn unpause_digest(env: Env, pause_count: u64, valid_until: u64) -> BytesN<32> {
        Self::counted_hash(&env, TAG_UNPAUSE, pause_count, valid_until).to_bytes()
    }

    // ── deposits ───────────────────────────────────────────────────────────────

    /// Locks `amount` stroops of the asset from `from` and records a deposit for `l2_recipient` on the Bloch L2.
    /// The deposit is its net amount (less the deposit fee) in units; that is what the L2 token mints. There is no
    /// refund path, so a deposit the L2 token could never mint is refused here.
    pub fn deposit(env: Env, from: Address, amount: i128, l2_recipient: BytesN<20>) -> BytesN<32> {
        from.require_auth();
        let cfg = load_config(&env);
        let mut st = load_state(&env);
        let now = env.ledger().timestamp();
        if now < st.paused_until {
            fail(&env, Error::Paused);
        }
        if amount <= 0 || amount % STROOPS_PER_UNIT != 0 || amount / STROOPS_PER_UNIT > cfg.window_limit as i128 {
            fail(&env, Error::InvalidTransfer);
        }
        let units = (amount / STROOPS_PER_UNIT) as u64;
        let fee = fee_of(units, cfg.deposit_fee_bps);
        let net = units - fee;
        let vault = env.current_contract_address();
        if !st.deposits_enabled
            || units < cfg.min_deposit
            || l2_recipient.to_array() == [0u8; 20]
            || st.total_locked as u128 + net as u128 > cfg.cap as u128
            || st.deposit_count == u64::MAX
            || from == vault
        {
            fail(&env, Error::InvalidTransfer);
        }
        let asset = token::TokenClient::new(&env, &cfg.token);
        let before = asset.balance(&vault);
        if before < required_stroops(&st) {
            fail(&env, Error::InsufficientBacking);
        }
        move_asset(&env, &asset, &from, &vault, amount);
        if asset.balance(&vault) != before + amount {
            fail(&env, Error::InvalidTransfer);
        }
        let nonce = st.deposit_count;
        let id = Self::deposit_id(env.clone(), nonce, from.clone(), net, l2_recipient.clone());
        // keccak256(abi.encode(head, depositId, uint256(amount), recipient)): what BridgedStablecoinV3 computes on
        // the credit of this deposit.
        let head = Words::new(&env).b32(&st.deposit_head).b32(&id).uint(net).addr20(&l2_recipient).keccak(&env).to_bytes();
        st.deposit_count = nonce + 1;
        st.total_locked += net;
        st.fees_accrued += fee;
        st.deposit_head = head.clone();
        put(&env, &Key::Head(nonce + 1), &head);
        save_state(&env, &st);
        Deposited { id: id.clone(), nonce, sender: from, amount: net, fee, l2_recipient, head }.publish(&env);
        id
    }

    /// Pays every accrued fee to the fee recipient fixed at deployment. Anyone may call it; it never touches backing.
    pub fn sweep_fees(env: Env) -> u64 {
        let cfg = load_config(&env);
        let mut st = load_state(&env);
        let amount = st.fees_accrued;
        if amount == 0 {
            return 0;
        }
        let vault = env.current_contract_address();
        let asset = token::TokenClient::new(&env, &cfg.token);
        let before = asset.balance(&vault);
        if before < required_stroops(&st) {
            fail(&env, Error::InsufficientBacking);
        }
        let stroops = amount as i128 * STROOPS_PER_UNIT;
        st.fees_accrued = 0;
        move_asset(&env, &asset, &vault, &cfg.fee_recipient, stroops);
        if asset.balance(&vault) + stroops != before {
            fail(&env, Error::InvalidTransfer);
        }
        save_state(&env, &st);
        FeesSwept { recipient: cfg.fee_recipient, amount }.publish(&env);
        amount
    }

    // ── committee controls ─────────────────────────────────────────────────────

    /// `threshold` signers open or close deposits and releases. Both start closed.
    pub fn set_controls(
        env: Env,
        deposits: bool,
        releases: bool,
        nonce: u64,
        valid_until: u64,
        signatures: Vec<BytesN<65>>,
    ) {
        let cfg = load_config(&env);
        let mut st = load_state(&env);
        check_validity(&env, valid_until, Error::InvalidControls);
        if nonce != st.control_nonce
            || nonce == u64::MAX
            || (deposits == st.deposits_enabled && releases == st.releases_enabled)
        {
            fail(&env, Error::InvalidControls);
        }
        check_certificate(
            &env,
            &Self::control_hash(&env, deposits, releases, nonce, valid_until),
            &signatures,
            &cfg.signers,
            cfg.threshold,
        );
        st.control_nonce = nonce + 1;
        st.deposits_enabled = deposits;
        st.releases_enabled = releases;
        save_state(&env, &st);
        ControlsUpdated { nonce, deposits_enabled: deposits, releases_enabled: releases }.publish(&env);
    }

    // ── releases ───────────────────────────────────────────────────────────────

    /// Pays (or queues) a burn of the L2 token, certified by `threshold` signers under the vault's current pause
    /// count. One release per burn nonce and per burn id; a queued release that a guardian pause voided leaves its
    /// nonce open for one new certificate.
    pub fn release(env: Env, item: Release, context: ReleaseContext, signatures: Vec<BytesN<65>>) {
        let cfg = load_config(&env);
        let derived = load_derived(&env);
        let mut st = load_state(&env);
        let now = env.ledger().timestamp();
        if now < st.paused_until {
            fail(&env, Error::Paused);
        }
        if !st.releases_enabled {
            fail(&env, Error::InvalidRelease);
        }
        check_validity(&env, context.valid_until, Error::InvalidContext);
        if context.native_finalized_hash.to_array() == [0u8; 32] || context.pause_count != st.pause_count {
            fail(&env, Error::InvalidContext);
        }
        let vault = env.current_contract_address();
        if item.route != derived.route
            || item.amount == 0
            || item.amount > st.total_locked
            || item.amount > cfg.window_limit
            || item.recipient == vault
            || item.recipient == cfg.token
            || item.native_burn.to_array() == [0u8; 32]
        {
            fail(&env, Error::InvalidRelease);
        }
        // Provenance: the burn was made under this vault's deposit chain at its mint count.
        if item.mint_count == 0 || item.mint_count > st.deposit_count {
            fail(&env, Error::ProvenanceMismatch);
        }
        let head: Option<BytesN<32>> = env.storage().persistent().get(&Key::Head(item.mint_count));
        if head != Some(item.mint_head.clone()) {
            fail(&env, Error::ProvenanceMismatch);
        }
        // Replay: one release per burn nonce and per burn id. A record counts while it is paid or queued under the
        // current pause count; an unpaid record from before a pause is void.
        let counts = |r: &BurnRecord| record_counts(r, st.pause_count);
        let nonce_key = Key::Nonce(item.nonce);
        let burn_key = Key::Burn(item.native_burn.clone());
        let record: Option<BurnRecord> = env.storage().persistent().get(&nonce_key);
        if let Some(r) = &record {
            if counts(r) {
                fail(&env, Error::InvalidRelease);
            }
        }
        let by_burn: Option<u64> = env.storage().persistent().get(&burn_key);
        if let Some(other) = by_burn {
            if other != item.nonce {
                let o: Option<BurnRecord> = env.storage().persistent().get(&Key::Nonce(other));
                if let Some(o) = o {
                    if o.burn == item.native_burn && counts(&o) {
                        fail(&env, Error::InvalidRelease);
                    }
                }
            }
        }
        let id = Self::release_id(env.clone(), item.clone());
        check_certificate(&env, &Self::release_hash(&env, &id, &context), &signatures, &cfg.signers, cfg.threshold);
        if let Some(r) = &record {
            // The voided release of this nonce named another burn id (a forgery that took the nonce): forget it.
            if r.burn != item.native_burn {
                let old = Key::Burn(r.burn.clone());
                if env.storage().persistent().get(&old) == Some(item.nonce) {
                    env.storage().persistent().remove(&old);
                }
            }
        }
        put(&env, &burn_key, &item.nonce);
        if cfg.release_delay != 0 && item.amount > cfg.large_release_threshold {
            let ready_at = now + cfg.release_delay;
            put(
                &env,
                &nonce_key,
                &BurnRecord { burn: item.native_burn.clone(), pause_count: st.pause_count, paid: false },
            );
            put(
                &env,
                &Key::Pending(id.clone()),
                &Pending {
                    recipient: item.recipient.clone(),
                    amount: item.amount,
                    ready_at,
                    nonce: item.nonce,
                    pause_count: st.pause_count,
                },
            );
            save_state(&env, &st);
            ReleaseQueued {
                id,
                nonce: item.nonce,
                recipient: item.recipient,
                amount: item.amount,
                native_burn: item.native_burn,
                ready_at,
            }
            .publish(&env);
            return;
        }
        put(&env, &nonce_key, &BurnRecord { burn: item.native_burn.clone(), pause_count: st.pause_count, paid: true });
        let fee = pay(&env, &cfg, &mut st, &item.recipient, item.amount);
        save_state(&env, &st);
        Released {
            id,
            nonce: item.nonce,
            recipient: item.recipient,
            amount: item.amount,
            fee,
            native_burn: item.native_burn,
        }
        .publish(&env);
    }

    /// Anyone pays a queued release once its delay has passed, unless the vault is paused, the committee closed
    /// releases (it then stays queued), or a guardian paused the vault since it was queued (it is then void for
    /// good, whoever ended the pause: the burn is certified again and waits the delay again).
    pub fn execute_release(env: Env, id: BytesN<32>) {
        let cfg = load_config(&env);
        let mut st = load_state(&env);
        let key = Key::Pending(id.clone());
        let pending: Pending = match env.storage().persistent().get(&key) {
            Some(p) => p,
            None => fail(&env, Error::NotQueued),
        };
        let now = env.ledger().timestamp();
        if now < st.paused_until {
            fail(&env, Error::Paused);
        }
        if pending.pause_count != st.pause_count {
            fail(&env, Error::Voided);
        }
        if !st.releases_enabled {
            fail(&env, Error::InvalidRelease);
        }
        if now < pending.ready_at {
            fail(&env, Error::NotReady);
        }
        let nonce_key = Key::Nonce(pending.nonce);
        let mut record: BurnRecord = env.storage().persistent().get(&nonce_key).unwrap();
        if record.paid || record.pause_count != pending.pause_count {
            fail(&env, Error::Voided);
        }
        env.storage().persistent().remove(&key);
        record.paid = true;
        put(&env, &nonce_key, &record);
        let fee = pay(&env, &cfg, &mut st, &pending.recipient, pending.amount);
        save_state(&env, &st);
        Released {
            id,
            nonce: pending.nonce,
            recipient: pending.recipient,
            amount: pending.amount,
            fee,
            native_burn: record.burn,
        }
        .publish(&env);
    }

    // ── guardians ──────────────────────────────────────────────────────────────

    /// True if `guardian` could pause right now.
    pub fn guardian_can_pause(env: Env, guardian: BytesN<20>) -> bool {
        guardian_can_pause(&load_config(&env), &load_state(&env), &guardian, env.ledger().timestamp())
    }

    /// One guardian stops deposits and releases for `pause_duration`. The guardian signs `pause_digest` for the
    /// current `pause_count`; anyone may submit it. Not while paused, not within `pause_cooldown` of a committee
    /// unpause, and once per guardian in a chain of consecutive pauses.
    /// The pause raises `pause_count`, which voids every release certificate signed before it and every release
    /// still in the queue. That is the guardians' whole power: they move nothing, pay no one and change no limit.
    pub fn guardian_pause(env: Env, valid_until: u64, signature: BytesN<65>) {
        let cfg = load_config(&env);
        let mut st = load_state(&env);
        let now = env.ledger().timestamp();
        check_validity(&env, valid_until, Error::InvalidPause);
        let guardian = recover(&env, &Self::counted_hash(&env, TAG_PAUSE, st.pause_count, valid_until), &signature);
        if !cfg.guardians.contains(&guardian) {
            fail(&env, Error::NotGuardian);
        }
        if !guardian_can_pause(&cfg, &st, &guardian, now) {
            fail(&env, Error::InvalidPause);
        }
        if chain_ended(&cfg, &st, now) {
            st.pause_chain += 1;
        }
        st.guardian_last_chain.set(guardian.clone(), st.pause_chain);
        st.pause_count += 1;
        st.paused_until = now + cfg.pause_duration;
        save_state(&env, &st);
        GuardianPaused { guardian, pause_count: st.pause_count, paused_until: st.paused_until }.publish(&env);
    }

    /// `switch_threshold` signers end the current pause early; guardians then wait `pause_cooldown`. Nothing the
    /// pause voided comes back: `pause_count` stays.
    pub fn unpause(env: Env, pause_count: u64, valid_until: u64, signatures: Vec<BytesN<65>>) {
        let cfg = load_config(&env);
        let mut st = load_state(&env);
        let now = env.ledger().timestamp();
        if now >= st.paused_until || pause_count != st.pause_count {
            fail(&env, Error::InvalidPause);
        }
        check_validity(&env, valid_until, Error::InvalidPause);
        check_certificate(
            &env,
            &Self::counted_hash(&env, TAG_UNPAUSE, pause_count, valid_until),
            &signatures,
            &cfg.signers,
            cfg.switch_threshold,
        );
        st.paused_until = now;
        st.guardian_blocked_until = now + cfg.pause_cooldown;
        save_state(&env, &st);
        Unpaused { pause_count, guardian_blocked_until: st.guardian_blocked_until }.publish(&env);
    }
}

impl Vault {
    /// Every digest binds the network and this contract first.
    fn domain(env: &Env, tag: &[u8]) -> Words {
        let d = load_derived(env);
        Words::new(env).tag(tag).b32(&d.network_id).b32(&d.vault_id)
    }

    fn release_hash(env: &Env, id: &BytesN<32>, context: &ReleaseContext) -> Hash<32> {
        Self::domain(env, TAG_RELEASE_AUTH)
            .b32(id)
            .uint(context.valid_until)
            .uint(context.pause_count)
            .uint(context.native_finalized_number)
            .b32(&context.native_finalized_hash)
            .keccak(env)
    }

    fn control_hash(env: &Env, deposits: bool, releases: bool, nonce: u64, valid_until: u64) -> Hash<32> {
        Self::domain(env, TAG_CONTROLS)
            .b32(&load_derived(env).route)
            .uint(deposits as u64)
            .uint(releases as u64)
            .uint(nonce)
            .uint(valid_until)
            .keccak(env)
    }

    fn counted_hash(env: &Env, tag: &[u8], count: u64, valid_until: u64) -> Hash<32> {
        Self::domain(env, tag).b32(&load_derived(env).route).uint(count).uint(valid_until).keccak(env)
    }

}

#[cfg(test)]
mod test;
