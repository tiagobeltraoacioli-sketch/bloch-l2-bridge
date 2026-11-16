//! Unit and property tests of the Stellar source vault.
//!
//! Every hash the contract computes is computed here a second time, from the layout described in the comments of
//! `lib.rs` (32-byte words as Solidity's `abi.encode`), with `sha2` / `sha3` and plain byte vectors. The certificates
//! used by the tests are signed over these independent digests, so a divergence between the two implementations
//! fails nearly every test, and the pairing tests compare each value with the contract's views explicitly.
#![allow(clippy::too_many_arguments)]

extern crate std;

use super::*;
use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
use sha2::Digest as _;
use soroban_sdk::{
    testutils::{
        storage::{Instance as _, Persistent as _, Temporary as _},
        Address as _, Events as _, IssuerFlags, Ledger as _, StellarAssetIssuer,
    },
    token::{StellarAssetClient, TokenClient},
    Event as _, InvokeError,
};
use std::{
    format,
    panic::{catch_unwind, AssertUnwindSafe},
    string::String as StdString,
    vec,
    vec::Vec as StdVec,
};

// ── constants of the fixtures ──────────────────────────────────────────────────

/// Units (6 decimals) per whole coin.
const U: u64 = 1_000_000;
const T0: u64 = 1_800_000_000;
const SEQ0: u32 = 100_000;
const HOUR: u64 = 3_600;
const DAY: u64 = 86_400;
const PASSPHRASE: &[u8] = b"Test SDF Network ; September 2015";
const L2: [u8; 20] = [0x11; 20];

/// secp256k1 group order.
const ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xba, 0xae, 0xdc,
    0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

// ── independent hashing (second implementation) ────────────────────────────────

fn keccak(data: &[u8]) -> [u8; 32] {
    let mut h = sha3::Keccak256::new();
    h.update(data);
    h.finalize().into()
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = sha2::Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// A sequence of 32-byte words.
#[derive(Default)]
struct W(StdVec<u8>);

impl W {
    fn tag(mut self, tag: &str) -> Self {
        let mut w = [0u8; 32];
        w[..tag.len()].copy_from_slice(tag.as_bytes());
        self.0.extend_from_slice(&w);
        self
    }
    fn b32(mut self, v: &[u8; 32]) -> Self {
        self.0.extend_from_slice(v);
        self
    }
    fn u(mut self, v: u64) -> Self {
        self.0.extend_from_slice(&[0u8; 24]);
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }
    fn a20(mut self, v: &[u8; 20]) -> Self {
        self.0.extend_from_slice(&[0u8; 12]);
        self.0.extend_from_slice(v);
        self
    }
    fn raw(mut self, v: &[u8]) -> Self {
        self.0.extend_from_slice(v);
        self
    }
    fn keccak(self) -> [u8; 32] {
        keccak(&self.0)
    }
    fn sha256(self) -> [u8; 32] {
        sha256(&self.0)
    }
}

fn crc16_xmodem(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for b in data {
        crc ^= (*b as u16) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 { (crc << 1) ^ 0x1021 } else { crc << 1 };
        }
    }
    crc
}

/// Stellar strkey: base32(version ‖ 32-byte payload ‖ crc16-xmodem little endian), 56 characters.
fn strkey(version: u8, payload: &[u8; 32]) -> StdString {
    let mut raw = vec![version];
    raw.extend_from_slice(payload);
    let crc = crc16_xmodem(&raw);
    raw.extend_from_slice(&crc.to_le_bytes());
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = StdString::new();
    let (mut acc, mut bits) = (0u32, 0u32);
    for b in raw {
        acc = (acc << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(alphabet[((acc >> bits) & 31) as usize] as char);
        }
    }
    assert_eq!(bits, 0);
    out
}

/// (strkey, 32-byte payload) of an address, the strkey built by this file's encoder.
fn addr_parts(a: &Address) -> (StdString, [u8; 32]) {
    match a.to_payload().unwrap() {
        AddressPayload::ContractIdHash(h) => (strkey(2 << 3, &h.to_array()), h.to_array()),
        AddressPayload::AccountIdPublicKeyEd25519(k) => (strkey(6 << 3, &k.to_array()), k.to_array()),
    }
}

/// keccak256(bytes32(tag) ‖ strkey).
fn address_hash_x(tag: &str, a: &Address) -> [u8; 32] {
    W::default().tag(tag).raw(addr_parts(a).0.as_bytes()).keccak()
}

// ── keys and signatures ────────────────────────────────────────────────────────

#[derive(Clone)]
struct Key20 {
    sk: SigningKey,
    addr: [u8; 20],
}

fn eth_address(vk: &VerifyingKey) -> [u8; 20] {
    let point = vk.to_encoded_point(false);
    let hash = keccak(&point.as_bytes()[1..]);
    let mut out = [0u8; 20];
    out.copy_from_slice(&hash[12..]);
    out
}

/// A throwaway key from a small fixed scalar.
fn key(scalar: u64) -> Key20 {
    let mut b = [0u8; 32];
    b[24..].copy_from_slice(&scalar.to_be_bytes());
    let sk = SigningKey::from_slice(&b).unwrap();
    let addr = eth_address(sk.verifying_key());
    Key20 { sk, addr }
}

fn sorted_keys(scalars: core::ops::RangeInclusive<u64>) -> StdVec<Key20> {
    let mut keys: StdVec<Key20> = scalars.map(key).collect();
    keys.sort_by(|a, b| a.addr.cmp(&b.addr));
    keys
}

/// r ‖ s ‖ v, low s, v = 27 / 28.
/// keccak256("\x19Ethereum Signed Message:\n32" ‖ digest): what a key signs for the vault (EIP-191).
fn personal(digest: &[u8; 32]) -> [u8; 32] {
    let mut m = StdVec::from(&b"\x19Ethereum Signed Message:\n32"[..]);
    m.extend_from_slice(digest);
    keccak(&m)
}

/// A signature of `digest` as a personal message, as the committee's tools produce it.
fn sign(k: &Key20, digest: &[u8; 32]) -> [u8; 65] {
    sign_raw(k, &personal(digest))
}

/// Plain ECDSA over the 32 bytes given, low-s, v 27 or 28.
fn sign_raw(k: &Key20, digest: &[u8; 32]) -> [u8; 65] {
    let (sig, rec) = k.sk.sign_prehash_recoverable(digest).unwrap();
    let mut rec = rec.to_byte();
    let sig = match sig.normalize_s() {
        Some(low) => {
            rec ^= 1;
            low
        }
        None => sig,
    };
    assert!(rec < 2);
    let mut out = [0u8; 65];
    out[..64].copy_from_slice(&sig.to_bytes());
    out[64] = 27 + rec;
    assert!(out[32..64] <= HALF_ORDER[..]);
    out
}

/// The malleated twin of a signature: s' = n - s, v flipped. It recovers to the same key.
fn high_s_twin(sig: &[u8; 65]) -> [u8; 65] {
    let mut out = *sig;
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let d = ORDER[i] as i16 - sig[32 + i] as i16 - borrow;
        if d < 0 {
            out[32 + i] = (d + 256) as u8;
            borrow = 1;
        } else {
            out[32 + i] = d as u8;
            borrow = 0;
        }
    }
    assert_eq!(borrow, 0);
    out[64] = if sig[64] == 27 { 28 } else { 27 };
    out
}

/// True if `twin` is `sig` with s replaced by n - s and v flipped: under plain ECDSA both verify for the same key.
/// (k256 itself refuses to recover from a high s, so the relation is checked on the scalars.)
fn is_malleated_twin(sig: &[u8; 65], twin: &[u8; 65]) -> bool {
    let high = Signature::from_slice(&twin[..64]).unwrap();
    twin[32..64] > HALF_ORDER[..]
        && twin[..32] == sig[..32]
        && high.normalize_s().map(|low| low.to_bytes().to_vec()) == Some(sig[..64].to_vec())
        && twin[64] != sig[64]
        && (twin[64] == 27 || twin[64] == 28)
}

fn recover_x(digest: &[u8; 32], sig: &[u8; 65]) -> Option<[u8; 20]> {
    let s = Signature::from_slice(&sig[..64]).ok()?;
    let r = RecoveryId::from_byte(sig[64].checked_sub(27)?)?;
    VerifyingKey::recover_from_prehash(digest, &s, r).ok().map(|vk| eth_address(&vk))
}

// ── small helpers ──────────────────────────────────────────────────────────────

fn b32(env: &Env, v: &[u8; 32]) -> BytesN<32> {
    BytesN::from_array(env, v)
}

fn b20(env: &Env, v: &[u8; 20]) -> BytesN<20> {
    BytesN::from_array(env, v)
}

fn a20v(env: &Env, addrs: &[[u8; 20]]) -> Vec<BytesN<20>> {
    let mut v = Vec::new(env);
    for a in addrs {
        v.push_back(b20(env, a));
    }
    v
}

fn key_addrs(keys: &[Key20]) -> StdVec<[u8; 20]> {
    keys.iter().map(|k| k.addr).collect()
}

fn label(s: &str) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[..s.len()].copy_from_slice(s.as_bytes());
    w
}

fn fee_x(units: u64, bps: u32) -> u64 {
    (units as u128 * bps as u128 / 10_000) as u64
}

/// What a `try_` client method returns here (the contract's functions do not return `Result`, so the error is the
/// host's generic one).
type Tried<T, C> = Result<Result<T, C>, Result<soroban_sdk::Error, InvokeError>>;

/// The vault's own error of a refused call.
fn err_of<T: core::fmt::Debug, C: core::fmt::Debug>(r: Tried<T, C>) -> Error {
    match r {
        Err(Ok(e)) => Error::try_from(e).unwrap_or_else(|_| panic!("refused, but not with a vault error: {:?}", e)),
        other => panic!("expected a vault error, got {:?}", other),
    }
}

/// The raw error of a call refused by something other than the vault's own checks.
fn raw_err<T: core::fmt::Debug, C: core::fmt::Debug>(r: Tried<T, C>) -> soroban_sdk::Error {
    match r {
        Err(Ok(e)) => e,
        other => panic!("expected an error, got {:?}", other),
    }
}

/// Errors of the Stellar Asset Contract when it is called directly: `Error(Contract, #code)`. Through the vault they
/// never surface: any failure of an asset transfer is the vault's `InvalidTransfer`.
fn sac_error(code: u32) -> soroban_sdk::Error {
    soroban_sdk::Error::from_contract_error(code)
}
const SAC_OPERATION_NOT_SUPPORTED: u32 = 2;
const SAC_BALANCE_ERROR: u32 = 10;
const SAC_BALANCE_DEAUTHORIZED: u32 = 11;

fn panic_message(payload: std::boxed::Box<dyn core::any::Any + Send>) -> StdString {
    if let Some(s) = payload.downcast_ref::<StdString>() {
        s.clone()
    } else if let Some(s) = payload.downcast_ref::<&str>() {
        StdString::from(*s)
    } else {
        StdString::from("<non-string panic>")
    }
}

/// xorshift64*: a fixed-seed generator for the randomized tests.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn range(&mut self, lo: u64, hi: u64) -> u64 {
        lo + self.below(hi - lo + 1)
    }
}

/// A token whose only property is 6 decimals, for the constructor's decimals check.
#[contract]
pub struct SixDecimals;

#[contractimpl]
impl SixDecimals {
    pub fn decimals(_env: Env) -> u32 {
        6
    }
}

// ── fixture ────────────────────────────────────────────────────────────────────

/// Everything that exists before the vault is deployed.
struct Parts {
    env: Env,
    token: Address,
    issuer: StellarAssetIssuer,
    /// The address the vault will be registered at.
    vault: Address,
    fee_recipient: Address,
    signers: StdVec<Key20>,
    guardians: StdVec<Key20>,
}

fn parts_flags(flags: &[IssuerFlags]) -> Parts {
    let env = Env::default();
    env.ledger().with_mut(|l| {
        l.timestamp = T0;
        l.sequence_number = SEQ0;
        l.network_id = sha256(PASSPHRASE);
    });
    env.mock_all_auths();
    env.cost_estimate().budget().reset_unlimited();
    let admin = Address::generate(&env);
    let asset = env.register_stellar_asset_contract_v2(admin);
    for f in flags {
        asset.issuer().set_flag(*f);
    }
    Parts {
        token: asset.address(),
        issuer: asset.issuer(),
        vault: Address::generate(&env),
        fee_recipient: Address::generate(&env),
        signers: sorted_keys(1..=7),
        guardians: sorted_keys(101..=103),
        env,
    }
}

fn parts() -> Parts {
    parts_flags(&[])
}

/// The mainnet-shaped configuration: 7 signers (5 to release, 6 to switch), 3 guardians, 72 h pauses and cooldown,
/// cap 100,000 coins, 10,000 coins per day, minimum deposit 11 coins, L2 minimum burn 10 coins, 5 bps each way.
fn base_config(p: &Parts) -> Config {
    Config {
        token: p.token.clone(),
        source_domain: b32(&p.env, &label("stellar")),
        native_domain: b32(&p.env, &label("bloch-l2")),
        asset: b32(&p.env, &label("USDC")),
        cap: 100_000 * U,
        window_limit: 10_000 * U,
        window_seconds: DAY,
        min_deposit: 11 * U,
        l2_min_burn: 10 * U,
        signers: a20v(&p.env, &key_addrs(&p.signers)),
        threshold: 5,
        switch_threshold: 6,
        guardians: a20v(&p.env, &key_addrs(&p.guardians)),
        pause_duration: 72 * HOUR,
        pause_cooldown: 72 * HOUR,
        large_release_threshold: 0,
        release_delay: 0,
        fee_recipient: p.fee_recipient.clone(),
        deposit_fee_bps: 5,
        release_fee_bps: 5,
    }
}

struct Fx {
    env: Env,
    vault: Address,
    v: VaultClient<'static>,
    token: Address,
    tok: TokenClient<'static>,
    sac: StellarAssetClient<'static>,
    issuer: StellarAssetIssuer,
    fee_recipient: Address,
    signers: StdVec<Key20>,
    guardians: StdVec<Key20>,
    cfg: Config,
    net: [u8; 32],
    vault_id: [u8; 32],
    token_id: [u8; 32],
    route: [u8; 32],
}

fn attach(p: &Parts, cfg: &Config, vault: &Address) -> Fx {
    let net = p.env.ledger().network_id().to_array();
    let vault_id = addr_parts(vault).1;
    let token_id = addr_parts(&p.token).1;
    // sha256 over: tag, network id, source domain, native domain, asset, token id, vault id, 6 (decimals), cap.
    let route = W::default()
        .tag("BLOCH-XLM-ROUTE-v1")
        .b32(&net)
        .b32(&cfg.source_domain.to_array())
        .b32(&cfg.native_domain.to_array())
        .b32(&cfg.asset.to_array())
        .b32(&token_id)
        .b32(&vault_id)
        .u(6)
        .u(cfg.cap)
        .sha256();
    Fx {
        env: p.env.clone(),
        vault: vault.clone(),
        v: VaultClient::new(&p.env, vault),
        token: p.token.clone(),
        tok: TokenClient::new(&p.env, &p.token),
        sac: StellarAssetClient::new(&p.env, &p.token),
        issuer: p.issuer.clone(),
        fee_recipient: p.fee_recipient.clone(),
        signers: p.signers.clone(),
        guardians: p.guardians.clone(),
        cfg: cfg.clone(),
        net,
        vault_id,
        token_id,
        route,
    }
}

fn fx_parts(p: Parts, f: impl FnOnce(&mut Config, &Parts)) -> Fx {
    let mut cfg = base_config(&p);
    f(&mut cfg, &p);
    p.env.register_at(&p.vault, Vault, (cfg.clone(),));
    attach(&p, &cfg, &p.vault)
}

fn fx_with(f: impl FnOnce(&mut Config, &Parts)) -> Fx {
    fx_parts(parts(), f)
}

/// Mainnet-shaped vault, controls still closed.
fn fx() -> Fx {
    fx_with(|_, _| {})
}

/// Mainnet-shaped vault with deposits and releases open.
fn fx_open() -> Fx {
    let fx = fx();
    fx.controls(true, true);
    fx
}

/// Open vault holding one deposit of 5,000 coins.
fn fx_funded() -> Fx {
    let fx = fx_open();
    fx.dep(5_000 * U);
    fx
}

/// Open vault with a release queue: above 1,000 coins a release waits one hour. One deposit of 5,000 coins.
fn fx_queue() -> Fx {
    let fx = fx_with(|c, _| {
        c.release_delay = HOUR;
        c.large_release_threshold = 1_000 * U;
    });
    fx.controls(true, true);
    fx.dep(5_000 * U);
    fx
}

/// Open vault with short guardian periods, so that a signature (valid at most a day) outlives a pause.
fn fx_short_pauses(duration: u64, cooldown: u64) -> Fx {
    let fx = fx_with(|c, _| {
        c.pause_duration = duration;
        c.pause_cooldown = cooldown;
    });
    fx.controls(true, true);
    fx
}

/// The constructor must refuse the configuration `f` produces, with `InvalidConfiguration`.
fn ctor_refused(f: impl FnOnce(&mut Config, &Parts)) {
    let p = parts();
    let mut cfg = base_config(&p);
    f(&mut cfg, &p);
    let r = catch_unwind(AssertUnwindSafe(|| {
        p.env.register_at(&p.vault, Vault, (cfg,));
    }));
    let msg = panic_message(r.expect_err("the constructor accepted an invalid configuration"));
    assert!(msg.contains("Error(Contract, #1)"), "unexpected failure: {msg}");
}

impl Fx {
    fn now(&self) -> u64 {
        self.env.ledger().timestamp()
    }

    /// Moves the ledger close time forward, and the sequence at 5 s a ledger.
    fn advance(&self, seconds: u64) {
        self.env.ledger().with_mut(|l| {
            l.timestamp += seconds;
            l.sequence_number += (seconds / 5).max(1) as u32;
        });
    }

    /// A second deployment with the same configuration, in the same ledger.
    fn sibling(&self) -> Fx {
        let id = self.env.register(Vault, (self.cfg.clone(),));
        let p = Parts {
            env: self.env.clone(),
            token: self.token.clone(),
            issuer: self.issuer.clone(),
            vault: id.clone(),
            fee_recipient: self.fee_recipient.clone(),
            signers: self.signers.clone(),
            guardians: self.guardians.clone(),
        };
        attach(&p, &self.cfg, &id)
    }

    /// A new holder with `units` of the asset.
    fn user(&self, units: u64) -> Address {
        let a = Address::generate(&self.env);
        self.sac.mint(&a, &(units as i128 * 10));
        a
    }

    fn try_dep(&self, from: &Address, units: u64) -> Tried<BytesN<32>, soroban_sdk::ConversionError> {
        self.v.try_deposit(from, &(units as i128 * 10), &b20(&self.env, &L2))
    }

    /// A new holder deposits `units` (gross) for the default L2 recipient.
    fn dep(&self, units: u64) -> (Address, BytesN<32>) {
        let from = self.user(units);
        let id = self.v.deposit(&from, &(units as i128 * 10), &b20(&self.env, &L2));
        (from, id)
    }

    fn bal(&self, a: &Address) -> i128 {
        self.tok.balance(a)
    }

    // independent digests

    fn deposit_id_x(&self, nonce: u64, sender: &Address, net: u64, l2: &[u8; 20]) -> [u8; 32] {
        let mut id = W::default()
            .tag("BLOCH-XLM-DEPOSIT-v1")
            .b32(&self.route)
            .u(nonce)
            .b32(&address_hash_x("BLOCH-XLM-SENDER-v1", sender))
            .u(net)
            .a20(l2)
            .sha256();
        id[..8].copy_from_slice(&nonce.to_be_bytes());
        id
    }

    fn release_id_x(&self, i: &Release) -> [u8; 32] {
        W::default()
            .tag("BLOCH-XLM-RELEASE-v1")
            .b32(&i.route.to_array())
            .u(i.nonce)
            .b32(&address_hash_x("BLOCH-XLM-RECIPIENT-v1", &i.recipient))
            .u(i.amount)
            .b32(&i.native_burn.to_array())
            .u(i.mint_count)
            .u(i.minted_total)
            .b32(&i.mint_head.to_array())
            .sha256()
    }

    /// tag ‖ network id ‖ vault id: the start of every signed digest.
    fn domain_x(&self, tag: &str) -> W {
        W::default().tag(tag).b32(&self.net).b32(&self.vault_id)
    }

    fn release_digest_x(&self, i: &Release, c: &ReleaseContext) -> [u8; 32] {
        self.domain_x("BLOCH-XLM-RELEASE-AUTH-v1")
            .b32(&self.release_id_x(i))
            .u(c.valid_until)
            .u(c.pause_count)
            .u(c.native_finalized_number)
            .b32(&c.native_finalized_hash.to_array())
            .keccak()
    }

    fn control_digest_x(&self, deposits: bool, releases: bool, nonce: u64, valid_until: u64) -> [u8; 32] {
        self.domain_x("BLOCH-XLM-CONTROLS-v1")
            .b32(&self.route)
            .u(deposits as u64)
            .u(releases as u64)
            .u(nonce)
            .u(valid_until)
            .keccak()
    }

    fn pause_digest_x(&self, count: u64, valid_until: u64) -> [u8; 32] {
        self.domain_x("BLOCH-XLM-GUARDIAN-PAUSE-v1").b32(&self.route).u(count).u(valid_until).keccak()
    }

    fn unpause_digest_x(&self, count: u64, valid_until: u64) -> [u8; 32] {
        self.domain_x("BLOCH-XLM-UNPAUSE-v1").b32(&self.route).u(count).u(valid_until).keccak()
    }

    // certificates

    fn cert(&self, keys: &[&Key20], digest: &[u8; 32]) -> Vec<BytesN<65>> {
        let mut v = Vec::new(&self.env);
        for k in keys {
            v.push_back(BytesN::from_array(&self.env, &sign(k, digest)));
        }
        v
    }

    /// Signatures of the signers at these (address-ordered) positions.
    fn sigs(&self, idx: &[usize], digest: &[u8; 32]) -> Vec<BytesN<65>> {
        let keys: StdVec<&Key20> = idx.iter().map(|i| &self.signers[*i]).collect();
        self.cert(&keys, digest)
    }

    /// Signatures of the first `n` signers.
    fn first(&self, n: usize, digest: &[u8; 32]) -> Vec<BytesN<65>> {
        let idx: StdVec<usize> = (0..n).collect();
        self.sigs(&idx, digest)
    }

    fn gsigs(&self, idx: &[usize], digest: &[u8; 32]) -> Vec<BytesN<65>> {
        let keys: StdVec<&Key20> = idx.iter().map(|i| &self.guardians[*i]).collect();
        self.cert(&keys, digest)
    }

    fn try_controls(
        &self,
        deposits: bool,
        releases: bool,
        nonce: u64,
        valid_until: u64,
        n: usize,
    ) -> Tried<(), soroban_sdk::ConversionError> {
        let d = self.control_digest_x(deposits, releases, nonce, valid_until);
        self.v.try_set_controls(&deposits, &releases, &nonce, &valid_until, &self.first(n, &d))
    }

    fn controls(&self, deposits: bool, releases: bool) {
        let nonce = self.v.state().control_nonce;
        let valid_until = self.now() + 600;
        let d = self.control_digest_x(deposits, releases, nonce, valid_until);
        self.v.set_controls(&deposits, &releases, &nonce, &valid_until, &self.first(5, &d));
    }

    fn burn(&self, nonce: u64) -> BytesN<32> {
        b32(&self.env, &W::default().tag("test-burn").u(nonce).sha256())
    }

    /// A burn of `amount` under burn nonce `nonce`, stating the vault's current chain state.
    fn item(&self, nonce: u64, to: &Address, amount: u64) -> Release {
        let st = self.v.state();
        Release {
            route: b32(&self.env, &self.route),
            nonce,
            recipient: to.clone(),
            amount,
            native_burn: self.burn(nonce),
            mint_count: st.deposit_count,
            minted_total: st.total_locked,
            mint_head: st.deposit_head,
        }
    }

    fn ctx(&self) -> ReleaseContext {
        ReleaseContext {
            valid_until: self.now() + HOUR,
            pause_count: self.v.state().pause_count,
            native_finalized_number: 4_242,
            native_finalized_hash: b32(&self.env, &[0xab; 32]),
        }
    }

    /// A release certificate by the first `n` signers.
    fn rcert(&self, i: &Release, c: &ReleaseContext, n: usize) -> Vec<BytesN<65>> {
        self.first(n, &self.release_digest_x(i, c))
    }

    fn try_release_n(&self, i: &Release, c: &ReleaseContext, n: usize) -> Tried<(), soroban_sdk::ConversionError> {
        self.v.try_release(i, c, &self.rcert(i, c, n))
    }

    /// Certified by `threshold` signers under a fresh context.
    fn try_release(&self, i: &Release) -> Tried<(), soroban_sdk::ConversionError> {
        self.try_release_n(i, &self.ctx(), 5)
    }

    fn release(&self, i: &Release) {
        let c = self.ctx();
        self.v.release(i, &c, &self.rcert(i, &c, 5));
    }

    fn release_id(&self, i: &Release) -> BytesN<32> {
        b32(&self.env, &self.release_id_x(i))
    }

    fn try_pause(&self, guardian: &Key20) -> Tried<(), soroban_sdk::ConversionError> {
        let valid_until = self.now() + 600;
        let d = self.pause_digest_x(self.v.state().pause_count, valid_until);
        self.v.try_guardian_pause(&valid_until, &BytesN::from_array(&self.env, &sign(guardian, &d)))
    }

    fn pause(&self, g: usize) {
        self.try_pause(&self.guardians[g]).unwrap().unwrap();
    }

    fn try_unpause(&self, n: usize) -> Tried<(), soroban_sdk::ConversionError> {
        let count = self.v.state().pause_count;
        let valid_until = self.now() + 600;
        self.v.try_unpause(&count, &valid_until, &self.first(n, &self.unpause_digest_x(count, valid_until)))
    }

    /// The vault's own events of the last invocation.
    fn vault_events(&self) -> soroban_sdk::testutils::ContractEvents {
        self.env.events().all().filter_by_contract(&self.vault)
    }

    /// Books and balance agree: balance == (total_locked + fees_accrued) * 10.
    fn assert_whole(&self) {
        let st = self.v.state();
        assert_eq!(self.bal(&self.vault), (st.total_locked as i128 + st.fees_accrued as i128) * 10);
    }
}

// ── pairing: every hash, recomputed ────────────────────────────────────────────

#[test]
fn strkey_encoder_matches_sdk_address_strings() {
    let p = parts();
    for a in [p.vault.clone(), p.token.clone(), p.issuer.address(), Address::generate(&p.env)] {
        let (s, _) = addr_parts(&a);
        assert_eq!(s.len(), 56);
        assert_eq!(s, format!("{}", a.to_string()));
    }
    assert!(addr_parts(&p.vault).0.starts_with('C'));
    assert!(addr_parts(&p.issuer.address()).0.starts_with('G'));
}

#[test]
fn test_keys_recover_to_their_ethereum_addresses() {
    // Known vector: the private key 1 has the address 0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf.
    assert_eq!(
        key(1).addr,
        [
            0x7e, 0x5f, 0x45, 0x52, 0x09, 0x1a, 0x69, 0x12, 0x5d, 0x5d, 0xfc, 0xb7, 0xb8, 0xc2, 0x65, 0x90, 0x29, 0x39,
            0x5b, 0xdf
        ]
    );
    let d = keccak(b"digest");
    for k in sorted_keys(1..=7) {
        let s = sign(&k, &d);
        assert_eq!(recover_x(&personal(&d), &s), Some(k.addr));
        assert_eq!(recover_x(&d, &sign_raw(&k, &d)), Some(k.addr));
        assert!(is_malleated_twin(&s, &high_s_twin(&s)));
    }
}

#[test]
fn derived_values_match_independent_computation() {
    let fx = fx();
    let d = fx.v.derived();
    assert_eq!(d.network_id.to_array(), sha256(PASSPHRASE));
    assert_eq!(d.vault_id.to_array(), fx.vault_id);
    assert_eq!(d.vault20.to_array()[..], fx.vault_id[12..]);
    assert_eq!(d.route.to_array(), fx.route);
    let mut vault20 = [0u8; 20];
    vault20.copy_from_slice(&fx.vault_id[12..]);
    // keccak256(abi.encode(MINT_CHAIN_TAG, sourceChainId, sourceVault, sourceRoute)).
    let genesis = W::default().tag("BLOCH-USDT-MINT-CHAIN-v1").b32(&fx.net).a20(&vault20).b32(&fx.route).keccak();
    assert_eq!(d.genesis.to_array(), genesis);
    assert_eq!(fx.v.state().deposit_head.to_array(), genesis);
    assert_eq!(fx.v.chain_head_at(&0).unwrap().to_array(), genesis);
    assert_eq!(fx.v.chain_head_at(&1), None);
}

#[test]
fn route_binds_the_deployment_and_the_cap() {
    let fx = fx();
    let other = fx.sibling();
    assert_ne!(fx.v.derived().route, other.v.derived().route);
    assert_ne!(fx.v.derived().genesis, other.v.derived().genesis);
    let bigger = fx_with(|c, _| c.cap += 1);
    // Same addresses (both environments generate the same sequence), another cap.
    assert_eq!(bigger.vault_id, fx.vault_id);
    assert_eq!(bigger.token_id, fx.token_id);
    assert_ne!(bigger.v.derived().route, fx.v.derived().route);
    assert_eq!(bigger.v.derived().route.to_array(), bigger.route);
}

#[test]
fn deposit_ids_and_chain_heads_match_independent_computation() {
    let fx = fx_open();
    let mut head = fx.v.derived().genesis.to_array();
    let recipients = [[0x11u8; 20], [0x22; 20], [0xfe; 20]];
    let gross = [11 * U, 123_456_789, 10_000 * U];
    for n in 0..3u64 {
        let from = fx.user(gross[n as usize]);
        let l2 = recipients[n as usize];
        let id = fx.v.deposit(&from, &(gross[n as usize] as i128 * 10), &b20(&fx.env, &l2));
        let net = gross[n as usize] - fee_x(gross[n as usize], 5);
        let id_x = fx.deposit_id_x(n, &from, net, &l2);
        assert_eq!(id.to_array(), id_x);
        assert_eq!(id.to_array()[..8], n.to_be_bytes());
        assert_eq!(fx.v.deposit_id(&n, &from, &net, &b20(&fx.env, &l2)).to_array(), id_x);
        // keccak256(abi.encode(head, depositId, uint256(amount), recipient)).
        head = W::default().b32(&head).b32(&id_x).u(net).a20(&l2).keccak();
        assert_eq!(fx.v.state().deposit_head.to_array(), head);
        assert_eq!(fx.v.chain_head_at(&(n + 1)).unwrap().to_array(), head);
        assert_eq!(fx.v.state().deposit_count, n + 1);
    }
    assert_eq!(fx.v.chain_head_at(&4), None);
}

#[test]
fn recipient_commitment_matches_independent_computation() {
    let fx = fx();
    for a in [Address::generate(&fx.env), fx.issuer.address()] {
        let h = address_hash_x("BLOCH-XLM-RECIPIENT-v1", &a);
        assert_eq!(fx.v.recipient_commitment(&a).to_array()[..], h[12..]);
    }
}

#[test]
fn release_id_and_digest_match_independent_computation() {
    let fx = fx_funded();
    let to = Address::generate(&fx.env);
    let mut item = fx.item(7, &to, 1_234_567);
    item.minted_total = 99;
    let ctx = fx.ctx();
    assert_eq!(fx.v.release_id(&item).to_array(), fx.release_id_x(&item));
    assert_eq!(fx.v.release_digest(&item, &ctx).to_array(), fx.release_digest_x(&item, &ctx));
    // Every field moves the id.
    let base = fx.release_id_x(&item);
    let mut variants: StdVec<Release> = StdVec::new();
    for k in 0..8 {
        let mut i = item.clone();
        match k {
            0 => i.route = b32(&fx.env, &[1; 32]),
            1 => i.nonce += 1,
            2 => i.recipient = Address::generate(&fx.env),
            3 => i.amount += 1,
            4 => i.native_burn = b32(&fx.env, &[2; 32]),
            5 => i.mint_count += 1,
            6 => i.minted_total += 1,
            _ => i.mint_head = b32(&fx.env, &[3; 32]),
        }
        variants.push(i);
    }
    for i in variants {
        assert_ne!(fx.v.release_id(&i).to_array(), base);
        assert_eq!(fx.v.release_id(&i).to_array(), fx.release_id_x(&i));
    }
}

#[test]
fn control_pause_and_unpause_digests_match_independent_computation() {
    let fx = fx();
    let t = fx.now() + 77;
    for (d, r) in [(false, false), (true, false), (false, true), (true, true)] {
        assert_eq!(fx.v.control_digest(&d, &r, &3, &t).to_array(), fx.control_digest_x(d, r, 3, t));
    }
    assert_eq!(fx.v.pause_digest(&5, &t).to_array(), fx.pause_digest_x(5, t));
    assert_eq!(fx.v.unpause_digest(&5, &t).to_array(), fx.unpause_digest_x(5, t));
    assert_ne!(fx.v.pause_digest(&5, &t), fx.v.unpause_digest(&5, &t));
}

// ── 1. constructor ─────────────────────────────────────────────────────────────

macro_rules! ctor_refusals {
    ($($name:ident: $f:expr;)*) => {
        $(
            #[test]
            fn $name() {
                ctor_refused($f);
            }
        )*
    };
}

fn guardians_plus(p: &Parts, extra: [u8; 20]) -> Vec<BytesN<20>> {
    let mut v = vec![p.guardians[0].addr, p.guardians[1].addr, extra];
    v.sort();
    a20v(&p.env, &v)
}

ctor_refusals! {
    ctor_refuses_deposit_fee_above_30_bps: |c: &mut Config, _: &Parts| c.deposit_fee_bps = 31;
    ctor_refuses_release_fee_above_30_bps: |c: &mut Config, _: &Parts| c.release_fee_bps = 31;
    ctor_refuses_threshold_below_two: |c: &mut Config, _: &Parts| c.threshold = 1;
    ctor_refuses_threshold_above_signer_count: |c: &mut Config, _: &Parts| { c.threshold = 8; c.switch_threshold = 8; };
    ctor_refuses_switch_threshold_below_threshold: |c: &mut Config, _: &Parts| c.switch_threshold = 4;
    ctor_refuses_switch_threshold_above_signer_count: |c: &mut Config, _: &Parts| c.switch_threshold = 8;
    ctor_refuses_unsorted_signers: |c: &mut Config, p: &Parts| {
        let mut a = key_addrs(&p.signers);
        a.swap(2, 3);
        c.signers = a20v(&p.env, &a);
    };
    ctor_refuses_duplicate_signers: |c: &mut Config, p: &Parts| {
        let mut a = key_addrs(&p.signers);
        a[3] = a[2];
        c.signers = a20v(&p.env, &a);
    };
    ctor_refuses_zero_address_signer: |c: &mut Config, p: &Parts| {
        let mut a = key_addrs(&p.signers);
        a[0] = [0; 20];
        c.signers = a20v(&p.env, &a);
    };
    ctor_refuses_more_than_16_signers: |c: &mut Config, p: &Parts| {
        c.signers = a20v(&p.env, &key_addrs(&sorted_keys(1..=17)));
    };
    ctor_refuses_unsorted_guardians: |c: &mut Config, p: &Parts| {
        let mut a = key_addrs(&p.guardians);
        a.swap(0, 1);
        c.guardians = a20v(&p.env, &a);
    };
    ctor_refuses_duplicate_guardians: |c: &mut Config, p: &Parts| {
        let mut a = key_addrs(&p.guardians);
        a[2] = a[1];
        c.guardians = a20v(&p.env, &a);
    };
    ctor_refuses_guardian_that_is_a_signer: |c: &mut Config, p: &Parts| {
        c.guardians = guardians_plus(p, p.signers[3].addr);
    };
    ctor_refuses_more_than_7_guardians: |c: &mut Config, p: &Parts| {
        c.guardians = a20v(&p.env, &key_addrs(&sorted_keys(101..=108)));
    };
    ctor_refuses_guardians_with_zero_pause_duration: |c: &mut Config, _: &Parts| c.pause_duration = 0;
    ctor_refuses_pause_duration_above_14_days: |c: &mut Config, _: &Parts| {
        c.pause_duration = 14 * DAY + 1;
        c.pause_cooldown = 14 * DAY + 1;
    };
    ctor_refuses_cooldown_below_pause_duration: |c: &mut Config, _: &Parts| c.pause_cooldown = 72 * HOUR - 1;
    ctor_refuses_pause_duration_without_guardians: |c: &mut Config, p: &Parts| {
        c.guardians = Vec::new(&p.env);
        c.pause_cooldown = 0;
    };
    ctor_refuses_pause_cooldown_without_guardians: |c: &mut Config, p: &Parts| {
        c.guardians = Vec::new(&p.env);
        c.pause_duration = 0;
    };
    ctor_refuses_min_deposit_below_l2_min_burn: |c: &mut Config, _: &Parts| c.min_deposit = 10 * U - 1;
    // 10,004,000 less 5 bps (5,002) is 9,998,998: below the L2 minimum burn of 10,000,000.
    ctor_refuses_min_deposit_net_below_l2_min_burn: |c: &mut Config, _: &Parts| c.min_deposit = 10_004_000;
    ctor_refuses_min_deposit_above_window_limit: |c: &mut Config, _: &Parts| c.min_deposit = 10_000 * U + 1;
    ctor_refuses_zero_l2_min_burn: |c: &mut Config, _: &Parts| c.l2_min_burn = 0;
    ctor_refuses_window_limit_above_cap: |c: &mut Config, _: &Parts| c.window_limit = 100_000 * U + 1;
    ctor_refuses_zero_window_limit: |c: &mut Config, _: &Parts| c.window_limit = 0;
    ctor_refuses_zero_window_seconds: |c: &mut Config, _: &Parts| c.window_seconds = 0;
    ctor_refuses_zero_cap: |c: &mut Config, _: &Parts| c.cap = 0;
    ctor_refuses_release_delay_above_14_days: |c: &mut Config, _: &Parts| c.release_delay = 14 * DAY + 1;
    ctor_refuses_token_with_6_decimals: |c: &mut Config, p: &Parts| c.token = p.env.register(SixDecimals, ());
    ctor_refuses_fee_recipient_equal_to_vault: |c: &mut Config, p: &Parts| c.fee_recipient = p.vault.clone();
    ctor_refuses_fee_recipient_equal_to_token: |c: &mut Config, p: &Parts| c.fee_recipient = p.token.clone();
    ctor_refuses_token_equal_to_vault: |c: &mut Config, p: &Parts| c.token = p.vault.clone();
    ctor_refuses_equal_source_and_native_domain: |c: &mut Config, _: &Parts| c.native_domain = c.source_domain.clone();
    ctor_refuses_zero_source_domain: |c: &mut Config, p: &Parts| c.source_domain = b32(&p.env, &[0; 32]);
    ctor_refuses_zero_native_domain: |c: &mut Config, p: &Parts| c.native_domain = b32(&p.env, &[0; 32]);
    ctor_refuses_zero_asset_label: |c: &mut Config, p: &Parts| c.asset = b32(&p.env, &[0; 32]);
}

#[test]
fn ctor_accepts_mainnet_shaped_configuration() {
    let fx = fx();
    let c = fx.v.config();
    assert_eq!(c, fx.cfg);
    assert_eq!((c.signers.len(), c.threshold, c.switch_threshold, c.guardians.len()), (7, 5, 6, 3));
    assert_eq!((c.pause_duration, c.pause_cooldown), (259_200, 259_200));
    assert_eq!((c.cap, c.window_limit, c.window_seconds), (100_000_000_000, 10_000_000_000, 86_400));
    assert_eq!((c.min_deposit, c.l2_min_burn, c.deposit_fee_bps, c.release_fee_bps), (11_000_000, 10_000_000, 5, 5));
    let st = fx.v.state();
    assert_eq!((st.deposit_count, st.total_locked, st.fees_accrued, st.control_nonce), (0, 0, 0, 0));
    assert!(!st.deposits_enabled && !st.releases_enabled);
    assert_eq!((st.bucket, st.bucket_updated_at), (10_000_000_000, T0));
    assert_eq!((st.paused_until, st.pause_count, st.guardian_blocked_until, st.pause_chain), (0, 0, 0, 0));
    assert_eq!(st.guardian_last_chain.len(), 0);
    assert!(!fx.v.paused());
    assert_eq!(fx.v.available_to_release(), 10_000_000_000);
    assert_eq!(fx.v.backing(), Backing { balance: 0, required: 0 });
}

#[test]
fn ctor_accepts_boundary_values() {
    let fx = fx_with(|c, _| {
        c.deposit_fee_bps = 30;
        c.release_fee_bps = 30;
        c.release_delay = 7 * DAY;
        c.pause_duration = 14 * DAY;
        c.pause_cooldown = 14 * DAY;
        c.threshold = 2;
        c.switch_threshold = 7;
        // 10,030,091 less 30 bps (30,090) is 10,000,001.
        c.min_deposit = 10_030_091;
        c.window_limit = c.cap;
    });
    assert_eq!(fx.v.config().deposit_fee_bps, 30);
    // One unit less nets 9,999,999 at 30 bps... the smallest accepted gross minimum is the one whose net reaches 10.
    ctor_refused(|c, _| {
        c.deposit_fee_bps = 30;
        c.min_deposit = 10_030_089;
    });
}

#[test]
fn ctor_accepts_no_guardians_with_zero_durations() {
    let fx = fx_with(|c, p| {
        c.guardians = Vec::new(&p.env);
        c.pause_duration = 0;
        c.pause_cooldown = 0;
    });
    assert_eq!(fx.v.config().guardians.len(), 0);
    // Nobody can pause: any signature recovers to an address that is no guardian.
    assert_eq!(err_of(fx.try_pause(&fx.guardians[0])), Error::NotGuardian);
}

// ── 2. controls ────────────────────────────────────────────────────────────────

#[test]
fn controls_start_closed() {
    let fx = fx();
    let from = fx.user(100 * U);
    assert_eq!(err_of(fx.try_dep(&from, 100 * U)), Error::InvalidTransfer);
    let item = fx.item(1, &from, 1);
    assert_eq!(err_of(fx.try_release(&item)), Error::InvalidRelease);
}

#[test]
fn set_controls_opens_with_threshold_signatures() {
    let fx = fx();
    let t = fx.now() + 600;
    fx.try_controls(true, true, 0, t, 5).unwrap().unwrap();
    let ev = fx.vault_events();
    assert_eq!(ev, [ControlsUpdated { nonce: 0, deposits_enabled: true, releases_enabled: true }.to_xdr(&fx.env, &fx.vault)]);
    let st = fx.v.state();
    assert!(st.deposits_enabled && st.releases_enabled);
    assert_eq!(st.control_nonce, 1);
    fx.dep(100 * U);
}

#[test]
fn set_controls_accepts_all_signers_and_any_threshold_subset() {
    let fx = fx();
    let t = fx.now() + 600;
    let d = fx.control_digest_x(true, false, 0, t);
    fx.v.set_controls(&true, &false, &0, &t, &fx.first(7, &d));
    let d = fx.control_digest_x(true, true, 1, t);
    fx.v.set_controls(&true, &true, &1, &t, &fx.sigs(&[0, 2, 3, 5, 6], &d));
    assert_eq!(fx.v.state().control_nonce, 2);
}

#[test]
fn set_controls_can_open_one_side_only() {
    let fx = fx();
    fx.controls(true, false);
    let (from, _) = fx.dep(100 * U);
    assert_eq!(err_of(fx.try_release(&fx.item(1, &from, U))), Error::InvalidRelease);
    fx.controls(false, true);
    assert_eq!(err_of(fx.try_dep(&from, 0)), Error::InvalidTransfer);
    let other = fx.user(100 * U);
    assert_eq!(err_of(fx.try_dep(&other, 100 * U)), Error::InvalidTransfer);
    fx.release(&fx.item(1, &from, U));
}

#[test]
fn set_controls_refuses_fewer_than_threshold_signatures() {
    let fx = fx();
    assert_eq!(err_of(fx.try_controls(true, true, 0, fx.now() + 600, 4)), Error::InvalidCertificate);
    assert_eq!(fx.v.state().control_nonce, 0);
}

#[test]
fn set_controls_refuses_guardian_signatures() {
    let fx = fx();
    let t = fx.now() + 600;
    let d = fx.control_digest_x(true, true, 0, t);
    let r = fx.v.try_set_controls(&true, &true, &0, &t, &fx.gsigs(&[0, 1, 2], &d));
    assert_eq!(err_of(r), Error::InvalidCertificate);
    // Four signers and one guardian, ordered by address.
    let mut keys: StdVec<&Key20> = fx.signers[..4].iter().collect();
    keys.push(&fx.guardians[0]);
    keys.sort_by(|a, b| a.addr.cmp(&b.addr));
    let r = fx.v.try_set_controls(&true, &true, &0, &t, &fx.cert(&keys, &d));
    assert_eq!(err_of(r), Error::InvalidCertificate);
}

#[test]
fn set_controls_refuses_wrong_nonce() {
    let fx = fx();
    let t = fx.now() + 600;
    assert_eq!(err_of(fx.try_controls(true, true, 1, t, 5)), Error::InvalidControls);
    fx.controls(true, true);
    assert_eq!(err_of(fx.try_controls(false, false, 0, t, 5)), Error::InvalidControls);
    assert_eq!(err_of(fx.try_controls(false, false, 2, t, 5)), Error::InvalidControls);
    fx.try_controls(false, false, 1, t, 5).unwrap().unwrap();
}

#[test]
fn set_controls_refuses_no_change() {
    let fx = fx();
    let t = fx.now() + 600;
    assert_eq!(err_of(fx.try_controls(false, false, 0, t, 5)), Error::InvalidControls);
    fx.controls(true, false);
    assert_eq!(err_of(fx.try_controls(true, false, 1, t, 5)), Error::InvalidControls);
}

#[test]
fn set_controls_refuses_validity_outside_max_validity() {
    let fx = fx();
    let now = fx.now();
    assert_eq!(err_of(fx.try_controls(true, true, 0, now - 1, 5)), Error::InvalidControls);
    assert_eq!(err_of(fx.try_controls(true, true, 0, now + DAY + 1, 5)), Error::InvalidControls);
    // Both ends are inclusive.
    fx.try_controls(true, true, 0, now + DAY, 5).unwrap().unwrap();
    fx.try_controls(false, true, 1, now, 5).unwrap().unwrap();
}

#[test]
fn set_controls_refuses_expired_certificate() {
    let fx = fx();
    let t = fx.now() + 600;
    let d = fx.control_digest_x(true, true, 0, t);
    let cert = fx.first(5, &d);
    fx.advance(601);
    assert_eq!(err_of(fx.v.try_set_controls(&true, &true, &0, &t, &cert)), Error::InvalidControls);
}

#[test]
fn set_controls_refuses_replay_of_a_used_certificate() {
    let fx = fx();
    let t = fx.now() + 600;
    let d = fx.control_digest_x(true, true, 0, t);
    let cert = fx.first(5, &d);
    fx.v.set_controls(&true, &true, &0, &t, &cert);
    // Straight replay: the nonce moved (and nothing would change).
    assert_eq!(err_of(fx.v.try_set_controls(&true, &true, &0, &t, &cert)), Error::InvalidControls);
    // After the committee closed both again, the old opening certificate would be a change, but its nonce is spent.
    fx.controls(false, false);
    assert_eq!(err_of(fx.v.try_set_controls(&true, &true, &0, &t, &cert)), Error::InvalidControls);
    // Presenting the old signatures under the current nonce fails on the signatures.
    assert_eq!(err_of(fx.v.try_set_controls(&true, &true, &2, &t, &cert)), Error::InvalidCertificate);
    assert!(!fx.v.state().deposits_enabled);
}

#[test]
fn set_controls_refuses_certificate_of_another_instance() {
    let a = fx();
    let b = a.sibling();
    assert_eq!(b.v.config(), a.v.config());
    let t = a.now() + 600;
    let for_b = b.first(7, &b.control_digest_x(true, true, 0, t));
    assert_eq!(err_of(a.v.try_set_controls(&true, &true, &0, &t, &for_b)), Error::InvalidCertificate);
    assert!(!a.v.state().deposits_enabled);
    b.v.set_controls(&true, &true, &0, &t, &for_b);
    assert!(b.v.state().deposits_enabled);
}

#[test]
fn set_controls_refuses_certificate_signed_for_another_network() {
    let fx = fx();
    let t = fx.now() + 600;
    let d = W::default()
        .tag("BLOCH-XLM-CONTROLS-v1")
        .b32(&sha256(b"Public Global Stellar Network ; September 2015"))
        .b32(&fx.vault_id)
        .b32(&fx.route)
        .u(1)
        .u(1)
        .u(0)
        .u(t)
        .keccak();
    assert_eq!(err_of(fx.v.try_set_controls(&true, &true, &0, &t, &fx.first(7, &d))), Error::InvalidCertificate);
}

// ── 3. deposits ────────────────────────────────────────────────────────────────

#[test]
fn deposit_takes_fee_rounded_down_and_books_the_net() {
    let fx = fx_open();
    // (gross units, fee at 5 bps rounded down)
    let cases: [(u64, u64); 5] = [
        (11_000_000, 5_500),
        (11_001_999, 5_500),
        (11_002_000, 5_501),
        (123_456_789, 61_728),
        (10_000_000_000, 5_000_000),
    ];
    let (mut locked, mut fees) = (0u64, 0u64);
    for (gross, fee) in cases {
        let from = fx.user(gross + 3);
        fx.try_dep(&from, gross).unwrap().unwrap();
        locked += gross - fee;
        fees += fee;
        let st = fx.v.state();
        assert_eq!((st.total_locked, st.fees_accrued), (locked, fees));
        assert_eq!(fx.bal(&from), 30);
        assert_eq!(fx.bal(&fx.vault), (locked + fees) as i128 * 10);
        assert_eq!(fx.v.backing(), Backing { balance: (locked + fees) as i128 * 10, required: (locked + fees) as i128 * 10 });
    }
    assert_eq!(fx.v.state().deposit_count, 5);
}

#[test]
fn deposit_emits_event_with_all_fields() {
    let fx = fx_open();
    fx.dep(50 * U);
    let from = fx.user(123_456_789);
    let l2 = [0x77u8; 20];
    let head_before = fx.v.state().deposit_head.to_array();
    let id = fx.v.deposit(&from, &1_234_567_890, &b20(&fx.env, &l2));
    let ev = fx.vault_events();
    let net = 123_456_789 - 61_728;
    let id_x = fx.deposit_id_x(1, &from, net, &l2);
    let head = W::default().b32(&head_before).b32(&id_x).u(net).a20(&l2).keccak();
    assert_eq!(id.to_array(), id_x);
    let expected = Deposited {
        id: b32(&fx.env, &id_x),
        nonce: 1,
        sender: from.clone(),
        amount: net,
        fee: 61_728,
        l2_recipient: b20(&fx.env, &l2),
        head: b32(&fx.env, &head),
    };
    assert_eq!(ev, [expected.to_xdr(&fx.env, &fx.vault)]);
}

#[test]
fn deposit_accepts_exact_minimum_and_exact_window_limit() {
    let fx = fx_open();
    fx.dep(11 * U);
    fx.dep(10_000 * U);
    assert_eq!(fx.v.state().deposit_count, 2);
}

#[test]
fn deposit_refused_while_deposits_disabled() {
    let fx = fx();
    fx.controls(false, true);
    let from = fx.user(100 * U);
    assert_eq!(err_of(fx.try_dep(&from, 100 * U)), Error::InvalidTransfer);
    assert_eq!(fx.bal(&from), 1_000 * U as i128);
}

#[test]
fn deposit_refused_while_paused() {
    let fx = fx_open();
    fx.pause(0);
    let from = fx.user(100 * U);
    assert_eq!(err_of(fx.try_dep(&from, 100 * U)), Error::Paused);
    fx.advance(72 * HOUR - 1);
    assert_eq!(err_of(fx.try_dep(&from, 100 * U)), Error::Paused);
    fx.advance(1);
    fx.try_dep(&from, 100 * U).unwrap().unwrap();
}

#[test]
fn deposit_refused_below_minimum() {
    let fx = fx_open();
    let from = fx.user(100 * U);
    assert_eq!(err_of(fx.try_dep(&from, 11 * U - 1)), Error::InvalidTransfer);
    assert_eq!(fx.v.state().deposit_count, 0);
}

#[test]
fn deposit_refused_above_window_limit() {
    let fx = fx_open();
    let from = fx.user(20_000 * U);
    assert_eq!(err_of(fx.try_dep(&from, 10_000 * U + 1)), Error::InvalidTransfer);
}

#[test]
fn deposit_refused_when_not_a_multiple_of_ten_stroops() {
    let fx = fx_open();
    let from = fx.user(100 * U);
    for stroops in [500_000_001i128, 500_000_005, 500_000_009] {
        assert_eq!(err_of(fx.v.try_deposit(&from, &stroops, &b20(&fx.env, &L2))), Error::InvalidTransfer);
    }
    fx.v.deposit(&from, &500_000_010, &b20(&fx.env, &L2));
}

#[test]
fn deposit_refused_for_zero_or_negative_amount() {
    let fx = fx_open();
    let from = fx.user(100 * U);
    for stroops in [0i128, -10, -500_000_000, i128::MIN, i128::MAX - 7] {
        assert_eq!(err_of(fx.v.try_deposit(&from, &stroops, &b20(&fx.env, &L2))), Error::InvalidTransfer);
    }
}

#[test]
fn deposit_refused_for_zero_l2_recipient() {
    let fx = fx_open();
    let from = fx.user(100 * U);
    let r = fx.v.try_deposit(&from, &(100 * U as i128 * 10), &b20(&fx.env, &[0; 20]));
    assert_eq!(err_of(r), Error::InvalidTransfer);
}

#[test]
fn deposit_refused_over_cap_and_cap_can_be_filled_exactly() {
    let fx = fx_open();
    for _ in 0..10 {
        fx.dep(10_000 * U);
    }
    // Ten deposits of 10,000 net 9,995 each: 50 coins of room are left under the cap of 100,000.
    assert_eq!(fx.v.state().total_locked, 99_950 * U);
    let from = fx.user(200 * U);
    // 50,025,013 nets 50,000,001: one unit over.
    assert_eq!(err_of(fx.try_dep(&from, 50_025_013)), Error::InvalidTransfer);
    // 50,025,012 nets exactly 50,000,000.
    fx.try_dep(&from, 50_025_012).unwrap().unwrap();
    assert_eq!(fx.v.state().total_locked, fx.cfg.cap);
    assert_eq!(err_of(fx.try_dep(&from, 11 * U)), Error::InvalidTransfer);
    fx.assert_whole();
}

#[test]
fn deposit_refused_without_authorization_of_the_depositor() {
    let fx = fx_open();
    let from = fx.user(100 * U);
    // From here on nothing is authorized by anyone.
    fx.env.set_auths(&[]);
    let e = raw_err(fx.try_dep(&from, 100 * U));
    // The host's authorization failure, not a vault error.
    assert_eq!(
        e,
        soroban_sdk::Error::from_type_and_code(
            soroban_sdk::xdr::ScErrorType::Context,
            soroban_sdk::xdr::ScErrorCode::InvalidAction
        )
    );
    assert_eq!(fx.v.state().deposit_count, 0);
    assert_eq!(fx.bal(&from), 1_000 * U as i128);
    assert_eq!(fx.bal(&fx.vault), 0);
    // The same call with the depositor's authorization goes through.
    fx.env.mock_all_auths();
    fx.try_dep(&from, 100 * U).unwrap().unwrap();
}

#[test]
fn deposit_with_insufficient_balance_changes_nothing() {
    let fx = fx_open();
    let from = fx.user(50 * U);
    assert_eq!(err_of(fx.try_dep(&from, 51 * U)), Error::InvalidTransfer);
    assert_eq!(fx.v.state().deposit_count, 0);
    assert_eq!(fx.bal(&from), 500 * U as i128);
}

// ── 4. releases, instant path ──────────────────────────────────────────────────

#[test]
fn release_pays_amount_less_fee_and_updates_books() {
    let fx = fx_funded();
    let before = fx.v.state();
    assert_eq!((before.total_locked, before.fees_accrued), (4_997_500_000, 2_500_000));
    let to = Address::generate(&fx.env);
    let item = fx.item(1, &to, 1_234_567_891);
    let ctx = fx.ctx();
    fx.v.release(&item, &ctx, &fx.rcert(&item, &ctx, 5));
    let ev = fx.vault_events();
    // 5 bps of 1,234,567,891 is 617,283.9: fee 617,283.
    let fee = 617_283;
    assert_eq!(fx.bal(&to), (1_234_567_891 - fee) as i128 * 10);
    let st = fx.v.state();
    assert_eq!(st.total_locked, before.total_locked - 1_234_567_891);
    assert_eq!(st.fees_accrued, before.fees_accrued + fee);
    assert_eq!(st.bucket, 10_000_000_000 - 1_234_567_891);
    assert_eq!(st.bucket_updated_at, fx.now());
    fx.assert_whole();
    assert_eq!(
        fx.v.burn_record(&1),
        Some(BurnRecord { burn: item.native_burn.clone(), pause_count: 0, paid: true })
    );
    assert_eq!(fx.v.released_burn(&item.native_burn), Some(1));
    assert_eq!(fx.v.pending(&fx.release_id(&item)), None);
    let expected = Released {
        id: fx.release_id(&item),
        nonce: 1,
        recipient: to.clone(),
        amount: 1_234_567_891,
        fee,
        native_burn: item.native_burn.clone(),
    };
    assert_eq!(ev, [expected.to_xdr(&fx.env, &fx.vault)]);
}

#[test]
fn release_of_everything_empties_total_locked_and_keeps_fees() {
    let fx = fx_funded();
    let to = Address::generate(&fx.env);
    fx.release(&fx.item(1, &to, 4_997_500_000));
    let st = fx.v.state();
    assert_eq!(st.total_locked, 0);
    // 5 bps of 4,997,500,000 is 2,498,750.
    assert_eq!(st.fees_accrued, 2_500_000 + 2_498_750);
    assert_eq!(fx.bal(&fx.vault), st.fees_accrued as i128 * 10);
}

#[test]
fn release_accepts_an_older_chain_state_and_any_signer_subset() {
    let fx = fx_funded();
    let old = fx.v.state();
    fx.dep(100 * U);
    fx.dep(200 * U);
    let to = Address::generate(&fx.env);
    let mut item = fx.item(1, &to, U);
    item.mint_count = 1;
    item.mint_head = old.deposit_head;
    let ctx = fx.ctx();
    let d = fx.release_digest_x(&item, &ctx);
    fx.v.release(&item, &ctx, &fx.sigs(&[1, 2, 4, 5, 6], &d));
    let item = fx.item(2, &to, U);
    fx.v.release(&item, &ctx, &fx.first(7, &fx.release_digest_x(&item, &ctx)));
    assert_eq!(fx.bal(&to), 2 * (U as i128 - 500) * 10);
}

/// The call is refused with `e`, and neither the burn nor the books moved.
fn assert_release_refused(fx: &Fx, item: &Release, r: Tried<(), soroban_sdk::ConversionError>, e: Error) {
    let st = fx.v.state();
    assert_eq!(err_of(r), e);
    assert_eq!(fx.v.state(), st);
    assert_eq!(fx.v.burn_record(&item.nonce), None);
    assert_eq!(fx.v.released_burn(&item.native_burn), None);
    assert_eq!(fx.bal(&item.recipient), 0);
    fx.assert_whole();
}

#[test]
fn release_refused_for_wrong_route() {
    let fx = fx_funded();
    let other = fx.sibling();
    let to = Address::generate(&fx.env);
    let mut item = fx.item(1, &to, U);
    item.route = other.v.derived().route;
    assert_release_refused(&fx, &item, fx.try_release(&item), Error::InvalidRelease);
}

#[test]
fn release_refused_for_zero_amount() {
    let fx = fx_funded();
    let to = Address::generate(&fx.env);
    let item = fx.item(1, &to, 0);
    assert_release_refused(&fx, &item, fx.try_release(&item), Error::InvalidRelease);
}

#[test]
fn release_refused_for_amount_above_total_locked() {
    let fx = fx_funded();
    let to = Address::generate(&fx.env);
    let item = fx.item(1, &to, 4_997_500_001);
    assert_release_refused(&fx, &item, fx.try_release(&item), Error::InvalidRelease);
    fx.release(&fx.item(1, &to, 4_997_500_000));
}

#[test]
fn release_refused_to_the_vault_or_the_token() {
    let fx = fx_funded();
    for to in [fx.vault.clone(), fx.token.clone()] {
        let item = fx.item(1, &to, U);
        let st = fx.v.state();
        assert_eq!(err_of(fx.try_release(&item)), Error::InvalidRelease);
        assert_eq!(fx.v.state(), st);
    }
}

#[test]
fn release_refused_for_zero_burn_id() {
    let fx = fx_funded();
    let to = Address::generate(&fx.env);
    let mut item = fx.item(1, &to, U);
    item.native_burn = b32(&fx.env, &[0; 32]);
    assert_release_refused(&fx, &item, fx.try_release(&item), Error::InvalidRelease);
}

#[test]
fn release_refused_for_mint_count_zero() {
    let fx = fx_funded();
    let to = Address::generate(&fx.env);
    let mut item = fx.item(1, &to, U);
    item.mint_count = 0;
    item.mint_head = fx.v.derived().genesis;
    assert_release_refused(&fx, &item, fx.try_release(&item), Error::ProvenanceMismatch);
}

#[test]
fn release_refused_for_mint_count_above_deposit_count() {
    let fx = fx_funded();
    let to = Address::generate(&fx.env);
    let mut item = fx.item(1, &to, U);
    item.mint_count = 2;
    assert_release_refused(&fx, &item, fx.try_release(&item), Error::ProvenanceMismatch);
}

#[test]
fn release_refused_for_wrong_mint_head() {
    let fx = fx_funded();
    let first_head = fx.v.state().deposit_head;
    fx.dep(100 * U);
    let to = Address::generate(&fx.env);
    // A head no deposit produced.
    let mut item = fx.item(1, &to, U);
    item.mint_head = b32(&fx.env, &[0x99; 32]);
    assert_release_refused(&fx, &item, fx.try_release(&item), Error::ProvenanceMismatch);
    // A real head of this vault, stated at the wrong count.
    let mut item = fx.item(1, &to, U);
    item.mint_head = first_head;
    assert_release_refused(&fx, &item, fx.try_release(&item), Error::ProvenanceMismatch);
    // The head of another vault with the same deposits.
    let other = fx.sibling();
    other.controls(true, true);
    other.dep(5_000 * U);
    other.dep(100 * U);
    let mut item = fx.item(1, &to, U);
    item.mint_head = other.v.state().deposit_head;
    assert_release_refused(&fx, &item, fx.try_release(&item), Error::ProvenanceMismatch);
}

#[test]
fn release_refused_with_too_few_signatures() {
    let fx = fx_funded();
    let to = Address::generate(&fx.env);
    let item = fx.item(1, &to, U);
    assert_release_refused(&fx, &item, fx.try_release_n(&item, &fx.ctx(), 4), Error::InvalidCertificate);
    assert_release_refused(&fx, &item, fx.try_release_n(&item, &fx.ctx(), 0), Error::InvalidCertificate);
    fx.try_release_n(&item, &fx.ctx(), 5).unwrap().unwrap();
}

#[test]
fn release_refused_with_a_non_signer_signature() {
    let fx = fx_funded();
    let to = Address::generate(&fx.env);
    let item = fx.item(1, &to, U);
    let ctx = fx.ctx();
    let d = fx.release_digest_x(&item, &ctx);
    for outsider in [key(900), fx.guardians[0].clone()] {
        let mut keys: StdVec<&Key20> = fx.signers[..4].iter().collect();
        keys.push(&outsider);
        keys.sort_by(|a, b| a.addr.cmp(&b.addr));
        assert_release_refused(&fx, &item, fx.v.try_release(&item, &ctx, &fx.cert(&keys, &d)), Error::InvalidCertificate);
    }
    // Five valid signers plus an outsider is refused as well: every signature must be a member's.
    let outsider = key(901);
    let mut keys: StdVec<&Key20> = fx.signers[..5].iter().collect();
    keys.push(&outsider);
    keys.sort_by(|a, b| a.addr.cmp(&b.addr));
    assert_release_refused(&fx, &item, fx.v.try_release(&item, &ctx, &fx.cert(&keys, &d)), Error::InvalidCertificate);
}

#[test]
fn release_refused_with_a_duplicate_signer() {
    let fx = fx_funded();
    let to = Address::generate(&fx.env);
    let item = fx.item(1, &to, U);
    let ctx = fx.ctx();
    let d = fx.release_digest_x(&item, &ctx);
    for idx in [[0usize, 0, 1, 2, 3], [0, 1, 2, 3, 3], [0, 1, 1, 2, 3]] {
        assert_release_refused(&fx, &item, fx.v.try_release(&item, &ctx, &fx.sigs(&idx, &d)), Error::InvalidCertificate);
    }
}

#[test]
fn release_refused_with_unordered_signers() {
    let fx = fx_funded();
    let to = Address::generate(&fx.env);
    let item = fx.item(1, &to, U);
    let ctx = fx.ctx();
    let d = fx.release_digest_x(&item, &ctx);
    for idx in [[1usize, 0, 2, 3, 4], [0, 1, 2, 4, 3], [4, 3, 2, 1, 0]] {
        assert_release_refused(&fx, &item, fx.v.try_release(&item, &ctx, &fx.sigs(&idx, &d)), Error::InvalidCertificate);
    }
}

#[test]
fn release_refused_with_more_signatures_than_signers() {
    let fx = fx_funded();
    let to = Address::generate(&fx.env);
    let item = fx.item(1, &to, U);
    let ctx = fx.ctx();
    let d = fx.release_digest_x(&item, &ctx);
    let r = fx.v.try_release(&item, &ctx, &fx.sigs(&[0, 1, 2, 3, 4, 5, 6, 6], &d));
    assert_release_refused(&fx, &item, r, Error::InvalidCertificate);
}

#[test]
fn release_refused_with_high_s_signature() {
    let fx = fx_funded();
    let to = Address::generate(&fx.env);
    let item = fx.item(1, &to, U);
    let ctx = fx.ctx();
    let d = fx.release_digest_x(&item, &ctx);
    for position in [0usize, 2, 4] {
        let mut cert = Vec::new(&fx.env);
        for i in 0..5 {
            let s = sign(&fx.signers[i], &d);
            let s = if i == position {
                let twin = high_s_twin(&s);
                // The twin is a valid signature of the same key under plain ECDSA.
                assert!(is_malleated_twin(&s, &twin));
                twin
            } else {
                s
            };
            cert.push_back(BytesN::from_array(&fx.env, &s));
        }
        assert_release_refused(&fx, &item, fx.v.try_release(&item, &ctx, &cert), Error::InvalidCertificate);
    }
    fx.v.release(&item, &ctx, &fx.first(5, &d));
}

#[test]
fn release_refused_with_v_other_than_27_or_28() {
    let fx = fx_funded();
    let to = Address::generate(&fx.env);
    let item = fx.item(1, &to, U);
    let ctx = fx.ctx();
    let d = fx.release_digest_x(&item, &ctx);
    for delta in [27u8, 26, 254, 2] {
        // v - 27 (0 / 1), v - 26, v + 2 ... none is accepted.
        let mut cert = Vec::new(&fx.env);
        for i in 0..5 {
            let mut s = sign(&fx.signers[i], &d);
            if i == 1 {
                s[64] = s[64].wrapping_sub(delta);
                assert!(s[64] != 27 && s[64] != 28);
            }
            cert.push_back(BytesN::from_array(&fx.env, &s));
        }
        assert_release_refused(&fx, &item, fx.v.try_release(&item, &ctx, &cert), Error::InvalidCertificate);
    }
}

#[test]
fn release_refused_with_flipped_v() {
    let fx = fx_funded();
    let to = Address::generate(&fx.env);
    let item = fx.item(1, &to, U);
    let ctx = fx.ctx();
    let d = fx.release_digest_x(&item, &ctx);
    let mut cert = Vec::new(&fx.env);
    for i in 0..5 {
        let mut s = sign(&fx.signers[i], &d);
        if i == 0 {
            s[64] = if s[64] == 27 { 28 } else { 27 };
        }
        cert.push_back(BytesN::from_array(&fx.env, &s));
    }
    // The flipped signature recovers some other key (or none): never a pass.
    let st = fx.v.state();
    assert!(fx.v.try_release(&item, &ctx, &cert).is_err());
    assert_eq!(fx.v.state(), st);
    assert_eq!(fx.v.burn_record(&1), None);
}

#[test]
fn release_refused_with_unrecoverable_signature() {
    let fx = fx_funded();
    let to = Address::generate(&fx.env);
    let item = fx.item(1, &to, U);
    let ctx = fx.ctx();
    let d = fx.release_digest_x(&item, &ctx);
    let mut cert = fx.first(5, &d);
    // r = s = 0: the host's recovery itself fails. Whatever the error, nothing is paid or recorded.
    let mut zero = [0u8; 65];
    zero[64] = 27;
    cert.set(0, BytesN::from_array(&fx.env, &zero));
    let st = fx.v.state();
    let r = fx.v.try_release(&item, &ctx, &cert);
    assert!(r.is_err(), "{:?}", r);
    assert_eq!(fx.v.state(), st);
    assert_eq!(fx.v.burn_record(&1), None);
    assert_eq!(fx.bal(&to), 0);
}

#[test]
fn release_refused_when_a_signed_field_is_changed() {
    let fx = fx_funded();
    let to = Address::generate(&fx.env);
    let item = fx.item(1, &to, U);
    let ctx = fx.ctx();
    let cert = fx.rcert(&item, &ctx, 5);
    let mut more = item.clone();
    more.amount += 1;
    assert_release_refused(&fx, &more, fx.v.try_release(&more, &ctx, &cert), Error::InvalidCertificate);
    let mut thief = item.clone();
    thief.recipient = Address::generate(&fx.env);
    assert_release_refused(&fx, &thief, fx.v.try_release(&thief, &ctx, &cert), Error::InvalidCertificate);
    let mut total = item.clone();
    total.minted_total += 1;
    assert_release_refused(&fx, &total, fx.v.try_release(&total, &ctx, &cert), Error::InvalidCertificate);
    let mut c = ctx.clone();
    c.native_finalized_number += 1;
    assert_release_refused(&fx, &item, fx.v.try_release(&item, &c, &cert), Error::InvalidCertificate);
    let mut c = ctx.clone();
    c.native_finalized_hash = b32(&fx.env, &[0xac; 32]);
    assert_release_refused(&fx, &item, fx.v.try_release(&item, &c, &cert), Error::InvalidCertificate);
    let mut c = ctx.clone();
    c.valid_until += 1;
    assert_release_refused(&fx, &item, fx.v.try_release(&item, &c, &cert), Error::InvalidCertificate);
    fx.v.release(&item, &ctx, &cert);
}

#[test]
fn release_refused_after_valid_until() {
    let fx = fx_funded();
    let to = Address::generate(&fx.env);
    let item = fx.item(1, &to, U);
    let ctx = fx.ctx();
    let cert = fx.rcert(&item, &ctx, 5);
    fx.advance(HOUR);
    // valid_until itself is still inside.
    assert_eq!(fx.now(), ctx.valid_until);
    fx.advance(1);
    assert_release_refused(&fx, &item, fx.v.try_release(&item, &ctx, &cert), Error::InvalidContext);
}

#[test]
fn release_accepted_exactly_at_valid_until() {
    let fx = fx_funded();
    let to = Address::generate(&fx.env);
    let item = fx.item(1, &to, U);
    let ctx = fx.ctx();
    let cert = fx.rcert(&item, &ctx, 5);
    fx.advance(HOUR);
    fx.v.release(&item, &ctx, &cert);
}

#[test]
fn release_refused_when_valid_until_is_too_far_ahead() {
    let fx = fx_funded();
    let to = Address::generate(&fx.env);
    let item = fx.item(1, &to, U);
    let mut ctx = fx.ctx();
    ctx.valid_until = fx.now() + DAY + 1;
    let cert = fx.rcert(&item, &ctx, 5);
    assert_release_refused(&fx, &item, fx.v.try_release(&item, &ctx, &cert), Error::InvalidContext);
    // One second later the same certificate is within MAX_VALIDITY.
    fx.advance(1);
    fx.v.release(&item, &ctx, &cert);
}

#[test]
fn release_refused_for_zero_native_finalized_hash() {
    let fx = fx_funded();
    let to = Address::generate(&fx.env);
    let item = fx.item(1, &to, U);
    let mut ctx = fx.ctx();
    ctx.native_finalized_hash = b32(&fx.env, &[0; 32]);
    assert_release_refused(&fx, &item, fx.try_release_n(&item, &ctx, 5), Error::InvalidContext);
}

#[test]
fn release_refused_while_releases_disabled() {
    let fx = fx_funded();
    fx.controls(true, false);
    let to = Address::generate(&fx.env);
    let item = fx.item(1, &to, U);
    assert_release_refused(&fx, &item, fx.try_release(&item), Error::InvalidRelease);
    fx.controls(true, true);
    fx.release(&item);
}

#[test]
fn release_refused_while_paused() {
    let fx = fx_funded();
    let to = Address::generate(&fx.env);
    let item = fx.item(1, &to, U);
    fx.pause(1);
    assert_release_refused(&fx, &item, fx.try_release(&item), Error::Paused);
    fx.advance(72 * HOUR);
    fx.release(&item);
}

#[test]
fn release_refuses_replay_of_the_same_certificate() {
    let fx = fx_funded();
    let to = Address::generate(&fx.env);
    let item = fx.item(1, &to, U);
    let ctx = fx.ctx();
    let cert = fx.rcert(&item, &ctx, 5);
    fx.v.release(&item, &ctx, &cert);
    let st = fx.v.state();
    let paid = fx.bal(&to);
    assert_eq!(err_of(fx.v.try_release(&item, &ctx, &cert)), Error::InvalidRelease);
    // A fresh certificate of all seven signers for the same burn is refused as well.
    assert_eq!(err_of(fx.try_release_n(&item, &fx.ctx(), 7)), Error::InvalidRelease);
    assert_eq!(fx.v.state(), st);
    assert_eq!(fx.bal(&to), paid);
}

#[test]
fn release_refuses_same_nonce_with_another_burn_id() {
    let fx = fx_funded();
    let to = Address::generate(&fx.env);
    fx.release(&fx.item(1, &to, U));
    let mut item = fx.item(1, &to, U);
    item.native_burn = fx.burn(2);
    let st = fx.v.state();
    assert_eq!(err_of(fx.try_release(&item)), Error::InvalidRelease);
    assert_eq!(fx.v.state(), st);
    assert_eq!(fx.v.released_burn(&fx.burn(2)), None);
}

#[test]
fn release_refuses_same_burn_id_with_another_nonce() {
    let fx = fx_funded();
    let to = Address::generate(&fx.env);
    fx.release(&fx.item(1, &to, U));
    let mut item = fx.item(2, &to, U);
    item.native_burn = fx.burn(1);
    let st = fx.v.state();
    assert_eq!(err_of(fx.try_release(&item)), Error::InvalidRelease);
    assert_eq!(fx.v.state(), st);
    assert_eq!(fx.v.burn_record(&2), None);
}

#[test]
fn release_refuses_certificate_signed_for_another_network() {
    let fx = fx_funded();
    let to = Address::generate(&fx.env);
    let item = fx.item(1, &to, U);
    let ctx = fx.ctx();
    let d = W::default()
        .tag("BLOCH-XLM-RELEASE-AUTH-v1")
        .b32(&sha256(b"Public Global Stellar Network ; September 2015"))
        .b32(&fx.vault_id)
        .b32(&fx.release_id_x(&item))
        .u(ctx.valid_until)
        .u(ctx.native_finalized_number)
        .b32(&ctx.native_finalized_hash.to_array())
        .keccak();
    assert_ne!(d, fx.release_digest_x(&item, &ctx));
    assert_release_refused(&fx, &item, fx.v.try_release(&item, &ctx, &fx.first(7, &d)), Error::InvalidCertificate);
}

#[test]
fn release_refuses_certificate_of_another_network_deployment() {
    // The same deployment sequence on another network: same addresses, another network id.
    let a = fx_funded();
    let p = parts();
    p.env.ledger().with_mut(|l| l.network_id = sha256(b"Public Global Stellar Network ; September 2015"));
    let b = fx_parts(p, |_, _| {});
    assert_eq!(b.vault_id, a.vault_id);
    assert_ne!(b.net, a.net);
    assert_eq!(b.v.derived().network_id.to_array(), b.net);
    assert_eq!(b.v.derived().route.to_array(), b.route);
    assert_ne!(b.route, a.route);
    let to = Address::generate(&a.env);
    let item = a.item(1, &to, U);
    let ctx = a.ctx();
    // What the other network's vault would have its committee sign for this very item.
    let foreign = b.release_digest_x(&item, &ctx);
    assert_ne!(foreign, a.release_digest_x(&item, &ctx));
    assert_release_refused(&a, &item, a.v.try_release(&item, &ctx, &a.first(7, &foreign)), Error::InvalidCertificate);
}

#[test]
fn release_refuses_certificate_of_another_contract() {
    let a = fx_funded();
    let b = a.sibling();
    b.controls(true, true);
    b.dep(5_000 * U);
    let to = Address::generate(&a.env);
    // A release B's committee certified for B.
    let item_b = b.item(1, &to, U);
    let ctx = b.ctx();
    let cert_b = b.rcert(&item_b, &ctx, 7);
    assert_release_refused(&a, &item_b, a.v.try_release(&item_b, &ctx, &cert_b), Error::InvalidRelease);
    // The same burn restated with A's route and chain state, under B's signatures over B's digest of it.
    let item_a = a.item(1, &to, U);
    let d_b = b.release_digest_x(&item_a, &ctx);
    assert_eq!(d_b, b.v.release_digest(&item_a, &ctx).to_array());
    assert_release_refused(&a, &item_a, a.v.try_release(&item_a, &ctx, &b.first(7, &d_b)), Error::InvalidCertificate);
    b.v.release(&item_b, &ctx, &cert_b);
}

#[test]
fn release_to_the_issuer_account_keeps_the_books_whole() {
    let fx = fx_funded();
    // The only G... address these tests can build is the issuer's own account. A transfer to the issuer burns; the
    // vault's balance check accepts it and the books stay whole.
    let to = fx.issuer.address();
    let item = fx.item(1, &to, U);
    fx.release(&item);
    fx.assert_whole();
}

// ── 5. rate limit ──────────────────────────────────────────────────────────────

#[test]
fn bucket_drains_and_refills_continuously() {
    let fx = fx_open();
    fx.dep(10_000 * U);
    fx.dep(10_000 * U);
    fx.dep(10_000 * U);
    let to = Address::generate(&fx.env);
    assert_eq!(fx.v.available_to_release(), 10_000 * U);
    fx.release(&fx.item(1, &to, 10_000 * U));
    assert_eq!(fx.v.available_to_release(), 0);
    fx.advance(1);
    // 10,000,000,000 / 86,400 per second, rounded down.
    assert_eq!(fx.v.available_to_release(), 115_740);
    fx.advance(DAY / 4 - 1);
    assert_eq!(fx.v.available_to_release(), 2_500 * U);
    fx.advance(1);
    assert_eq!(fx.v.available_to_release(), 2_500_115_740);
    fx.release(&fx.item(2, &to, 2_500_115_740));
    assert_eq!(fx.v.available_to_release(), 0);
    assert_eq!(fx.v.state().bucket, 0);
    fx.advance(DAY / 2);
    assert_eq!(fx.v.available_to_release(), 5_000 * U);
    fx.release(&fx.item(3, &to, 1_000 * U));
    assert_eq!(fx.v.state().bucket, 4_000 * U);
    // The bucket never holds more than window_limit.
    fx.advance(10 * DAY);
    assert_eq!(fx.v.available_to_release(), 10_000 * U);
}

#[test]
fn release_above_the_bucket_is_rate_limited_and_consumes_nothing() {
    let fx = fx_open();
    fx.dep(10_000 * U);
    fx.dep(10_000 * U);
    let to = Address::generate(&fx.env);
    fx.release(&fx.item(1, &to, 10_000 * U));
    let other = Address::generate(&fx.env);
    let item = fx.item(2, &other, 115_741);
    let ctx = fx.ctx();
    let cert = fx.rcert(&item, &ctx, 5);
    assert_release_refused(&fx, &item, fx.v.try_release(&item, &ctx, &cert), Error::RateLimited);
    fx.advance(1);
    // 115,740 available: still one unit short.
    assert_release_refused(&fx, &item, fx.v.try_release(&item, &ctx, &cert), Error::RateLimited);
    fx.advance(1);
    // The very same certificate is good once the bucket allows it: the refusals consumed nothing.
    fx.v.release(&item, &ctx, &cert);
    assert_eq!(fx.v.burn_record(&2).unwrap().burn, item.native_burn);
}

#[test]
fn release_refused_above_window_limit() {
    let fx = fx_open();
    fx.dep(10_000 * U);
    fx.dep(10_000 * U);
    let to = Address::generate(&fx.env);
    // The bucket never holds more than window_limit, so such a release could never be paid: it is refused outright.
    let item = fx.item(1, &to, 10_000 * U + 1);
    assert_release_refused(&fx, &item, fx.try_release(&item), Error::InvalidRelease);
    fx.advance(30 * DAY);
    assert_release_refused(&fx, &item, fx.try_release_n(&item, &fx.ctx(), 7), Error::InvalidRelease);
    // Exactly window_limit is payable.
    fx.release(&fx.item(1, &to, 10_000 * U));
}

#[test]
fn rate_limit_bound_holds_over_every_interval_randomized() {
    let fx = fx_with(|c, _| c.cap = 1_000_000 * U);
    fx.controls(true, true);
    for _ in 0..40 {
        fx.dep(10_000 * U);
    }
    let w = fx.cfg.window_limit as u128;
    let secs = fx.cfg.window_seconds as u128;
    let to = Address::generate(&fx.env);
    let mut rng = Rng(0x00B1_0C4B_41D6_E001);
    let mut paid: StdVec<(u64, u64)> = StdVec::new();
    let (mut limited, mut nonce) = (0u32, 0u64);
    for _ in 0..400 {
        match rng.below(4) {
            0 => {}
            1 => fx.advance(rng.range(1, 600)),
            _ => fx.advance(rng.range(1, DAY / 6)),
        }
        let amount = match rng.below(8) {
            0 => rng.range(1, 1_000),
            1 => fx.v.available_to_release().max(1),
            2 => fx.v.available_to_release() + 1,
            _ => rng.range(1, 4_000 * U),
        };
        nonce += 1;
        let item = fx.item(nonce, &to, amount);
        let room = fx.v.available_to_release();
        let r = fx.try_release(&item);
        if amount <= room {
            r.unwrap().unwrap();
            paid.push((fx.now(), amount));
            assert_eq!(fx.v.available_to_release(), room - amount);
        } else {
            // Above window_limit a release is refused as such, whatever the bucket holds.
            let expected = if amount > fx.cfg.window_limit { Error::InvalidRelease } else { Error::RateLimited };
            assert_eq!(err_of(r), expected);
            limited += 1;
        }
    }
    assert!(paid.len() > 150, "only {} releases went through", paid.len());
    assert!(limited > 40, "only {} releases were rate limited", limited);
    // Over every interval [t_i, t_j]: released <= window_limit * (1 + T / window_seconds).
    let mut tightest = 0u128;
    for i in 0..paid.len() {
        let mut sum = 0u128;
        for j in i..paid.len() {
            sum += paid[j].1 as u128;
            let t = (paid[j].0 - paid[i].0) as u128;
            assert!(sum * secs <= w * (secs + t), "interval {i}..{j}: {sum} units in {t} s");
            tightest = tightest.max(sum * secs * 1_000 / (w * (secs + t)));
        }
    }
    // The bound is not slack in this run: some interval uses more than 99% of it.
    assert!(tightest > 990, "tightest interval used {tightest} per mille of the bound");
    let total: u128 = paid.iter().map(|p| p.1 as u128).sum();
    assert_eq!(fx.v.state().total_locked as u128, 40 * 9_995 * U as u128 - total);
    fx.assert_whole();
}

// ── 6. queue ───────────────────────────────────────────────────────────────────

#[test]
fn queue_release_at_threshold_pays_at_once() {
    let fx = fx_queue();
    let to = Address::generate(&fx.env);
    let item = fx.item(1, &to, 1_000 * U);
    fx.release(&item);
    assert_eq!(fx.bal(&to), (1_000 * U as i128 - 500_000) * 10);
    assert_eq!(fx.v.pending(&fx.release_id(&item)), None);
}

#[test]
fn queue_release_above_threshold_waits_and_then_pays() {
    let fx = fx_queue();
    let to = Address::generate(&fx.env);
    let item = fx.item(1, &to, 1_000 * U + 1);
    let id = fx.release_id(&item);
    let st = fx.v.state();
    fx.release(&item);
    let ev = fx.vault_events();
    let ready_at = fx.now() + HOUR;
    let queued = ReleaseQueued {
        id: id.clone(),
        nonce: 1,
        recipient: to.clone(),
        amount: 1_000 * U + 1,
        native_burn: item.native_burn.clone(),
        ready_at,
    };
    assert_eq!(ev, [queued.to_xdr(&fx.env, &fx.vault)]);
    // Queued: recorded, nothing paid, books and bucket untouched.
    assert_eq!(fx.v.pending(&id), Some(Pending { recipient: to.clone(), amount: 1_000 * U + 1, ready_at, nonce: 1, pause_count: 0 }));
    assert_eq!(fx.v.burn_record(&1), Some(BurnRecord { burn: item.native_burn.clone(), pause_count: 0, paid: false }));
    assert_eq!(fx.v.released_burn(&item.native_burn), Some(1));
    assert_eq!(fx.bal(&to), 0);
    assert_eq!(fx.v.state(), st);
    fx.advance(HOUR - 1);
    assert_eq!(err_of(fx.v.try_execute_release(&id)), Error::NotReady);
    fx.advance(1);
    fx.v.execute_release(&id);
    let ev = fx.vault_events();
    // 5 bps of 1,000,000,001 is 500,000.0005: fee 500,000.
    let released = Released {
        id: id.clone(),
        nonce: 1,
        recipient: to.clone(),
        amount: 1_000 * U + 1,
        fee: 500_000,
        native_burn: item.native_burn.clone(),
    };
    assert_eq!(ev, [released.to_xdr(&fx.env, &fx.vault)]);
    assert_eq!(fx.bal(&to), (1_000 * U as i128 + 1 - 500_000) * 10);
    let after = fx.v.state();
    assert_eq!(after.total_locked, st.total_locked - (1_000 * U + 1));
    assert_eq!(after.fees_accrued, st.fees_accrued + 500_000);
    assert_eq!(after.bucket, 10_000 * U - (1_000 * U + 1));
    assert_eq!(fx.v.pending(&id), None);
    fx.assert_whole();
    // Paid once.
    assert_eq!(err_of(fx.v.try_execute_release(&id)), Error::NotQueued);
    assert_eq!(err_of(fx.try_release(&item)), Error::InvalidRelease);
}

#[test]
fn queue_certificate_cannot_be_queued_twice() {
    let fx = fx_queue();
    let to = Address::generate(&fx.env);
    let item = fx.item(1, &to, 2_000 * U);
    let ctx = fx.ctx();
    let cert = fx.rcert(&item, &ctx, 5);
    fx.v.release(&item, &ctx, &cert);
    assert_eq!(err_of(fx.v.try_release(&item, &ctx, &cert)), Error::InvalidRelease);
    // Nor does a fresh certificate of all seven signers queue it again while it is queued.
    assert_eq!(err_of(fx.try_release_n(&item, &fx.ctx(), 7)), Error::InvalidRelease);
}

#[test]
fn queue_execute_refused_for_unknown_id() {
    let fx = fx_queue();
    assert_eq!(err_of(fx.v.try_execute_release(&b32(&fx.env, &[9; 32]))), Error::NotQueued);
    let to = Address::generate(&fx.env);
    // An instant release leaves nothing in the queue either.
    let item = fx.item(1, &to, U);
    fx.release(&item);
    assert_eq!(err_of(fx.v.try_execute_release(&fx.release_id(&item))), Error::NotQueued);
}

#[test]
fn queue_execute_is_rate_limited_like_any_release() {
    let fx = fx_queue();
    fx.dep(10_000 * U);
    let to = Address::generate(&fx.env);
    let item = fx.item(1, &to, 4_000 * U);
    let id = fx.release_id(&item);
    fx.release(&item);
    fx.advance(HOUR);
    // Drain the bucket with instant releases of 1,000 each.
    for n in 2..=8 {
        fx.release(&fx.item(n, &to, 1_000 * U));
    }
    assert!(fx.v.available_to_release() < 4_000 * U);
    assert_eq!(err_of(fx.v.try_execute_release(&id)), Error::RateLimited);
    assert!(fx.v.pending(&id).is_some());
    fx.advance(DAY);
    fx.v.execute_release(&id);
    fx.assert_whole();
}

/// The committee closing releases stops queued releases too: they stay queued and are paid once releases are open
/// again. Nothing is lost and nothing is paid meanwhile.
#[test]
fn queue_execute_refused_while_releases_are_closed() {
    let fx = fx_queue();
    let to = Address::generate(&fx.env);
    let item = fx.item(1, &to, 2_000 * U);
    let id = fx.release_id(&item);
    fx.release(&item);
    fx.controls(true, false);
    fx.advance(HOUR);
    let st = fx.v.state();
    assert_eq!(err_of(fx.v.try_execute_release(&id)), Error::InvalidRelease);
    assert_eq!(fx.v.state(), st);
    assert!(fx.v.pending(&id).is_some());
    assert_eq!(fx.bal(&to), 0);
    // A new certificate is refused as well.
    let other = fx.item(2, &to, 2_000 * U);
    assert_eq!(err_of(fx.try_release(&other)), Error::InvalidRelease);
    fx.controls(true, true);
    fx.v.execute_release(&id);
    assert_eq!(fx.bal(&to), (2_000 * U as i128 - 1_000_000) * 10);
    assert_eq!(err_of(fx.v.try_execute_release(&id)), Error::NotQueued);
    fx.assert_whole();
}

// ── 6b. a guardian pause voids; nothing else can be done to a release (reviewer 325: XLM-1, XLM-4) ────────────

/// R325-XLM-4. A pause does not merely hold a queued release: it voids it, for good, whoever ends the pause.
#[test]
fn pause_voids_queued_releases_and_no_unpause_revives_them() {
    for by_committee in [false, true] {
        let fx = fx_queue();
        let to = Address::generate(&fx.env);
        let item = fx.item(1, &to, 2_000 * U);
        let id = fx.release_id(&item);
        fx.release(&item);
        assert_eq!(fx.v.burn_status(&1, &item.native_burn), 1);
        fx.pause(0);
        // The queued release is dead from the pause on: its burn is open again.
        assert_eq!(fx.v.burn_status(&1, &item.native_burn), 0);
        fx.advance(2 * HOUR);
        assert_eq!(err_of(fx.v.try_execute_release(&id)), Error::Paused);
        if by_committee {
            fx.try_unpause(6).unwrap().unwrap();
        } else {
            fx.advance(72 * HOUR);
        }
        assert!(!fx.v.paused());
        let st = fx.v.state();
        assert_eq!(err_of(fx.v.try_execute_release(&id)), Error::Voided);
        fx.advance(30 * DAY);
        assert_eq!(err_of(fx.v.try_execute_release(&id)), Error::Voided);
        assert_eq!(fx.bal(&to), 0);
        assert_eq!(fx.v.state().total_locked, st.total_locked);
    }
}

/// R325-XLM-4. A certificate signed before a pause is dead after it, even when the pause is shorter than the
/// certificate's validity and whatever path the release would take.
#[test]
fn certificate_signed_before_a_pause_is_dead_after_it() {
    let fx = fx_short_pauses(HOUR, HOUR);
    fx.dep(5_000 * U);
    let to = Address::generate(&fx.env);
    let item = fx.item(1, &to, 100 * U);
    let mut ctx = fx.ctx();
    ctx.valid_until = fx.now() + DAY;
    assert_eq!(ctx.pause_count, 0);
    let cert = fx.rcert(&item, &ctx, 7);
    fx.pause(1);
    fx.advance(HOUR);
    assert!(!fx.v.paused() && fx.now() < ctx.valid_until);
    assert_release_refused(&fx, &item, fx.v.try_release(&item, &ctx, &cert), Error::InvalidContext);
    // Naming the new count without new signatures does not help: the count is signed.
    let mut relabelled = ctx.clone();
    relabelled.pause_count = 1;
    assert_release_refused(&fx, &item, fx.v.try_release(&item, &relabelled, &cert), Error::InvalidCertificate);
    // A certificate for a future count is refused as well.
    let mut ahead = fx.ctx();
    ahead.pause_count = 2;
    assert_release_refused(&fx, &item, fx.try_release_n(&item, &ahead, 7), Error::InvalidContext);
    // The committee signs again under the current count: paid.
    fx.release(&item);
    assert_eq!(fx.bal(&to), (100 * U as i128 - 50_000) * 10);
}

/// R325-XLM-1. A voided burn is not lost and needs nothing special: the ordinary threshold certifies it again, it
/// waits the delay again, and it is paid exactly once.
#[test]
fn voided_burn_is_certified_again_by_the_ordinary_threshold_and_paid_exactly_once() {
    let fx = fx_queue();
    let to = Address::generate(&fx.env);
    let item = fx.item(1, &to, 2_000 * U);
    let id = fx.release_id(&item);
    let ctx0 = fx.ctx();
    let cert0 = fx.rcert(&item, &ctx0, 5);
    fx.v.release(&item, &ctx0, &cert0);
    let st = fx.v.state();
    fx.pause(2);
    fx.try_unpause(6).unwrap().unwrap();
    // The same burn, the same five signers, the current pause count.
    let ctx1 = fx.ctx();
    assert_eq!(ctx1.pause_count, 1);
    let cert1 = fx.rcert(&item, &ctx1, 5);
    fx.v.release(&item, &ctx1, &cert1);
    assert_eq!(fx.release_id(&item), id);
    let ready_at = fx.now() + HOUR;
    assert_eq!(
        fx.v.pending(&id),
        Some(Pending { recipient: to.clone(), amount: 2_000 * U, ready_at, nonce: 1, pause_count: 1 })
    );
    assert_eq!(fx.v.burn_record(&1), Some(BurnRecord { burn: item.native_burn.clone(), pause_count: 1, paid: false }));
    // Once per pause: no second certificate while this one is queued.
    assert_eq!(err_of(fx.try_release_n(&item, &fx.ctx(), 7)), Error::InvalidRelease);
    // The delay runs again from the new certificate.
    fx.advance(HOUR - 1);
    assert_eq!(err_of(fx.v.try_execute_release(&id)), Error::NotReady);
    fx.advance(1);
    fx.v.execute_release(&id);
    let paid = (2_000 * U as i128 - 1_000_000) * 10;
    assert_eq!(fx.bal(&to), paid);
    assert_eq!(fx.v.state().total_locked, st.total_locked - 2_000 * U);
    assert_eq!(fx.v.burn_status(&1, &item.native_burn), 2);
    // Exactly once: the queue, both certificates, a fresh one of all seven, and the same burn under another nonce.
    assert_eq!(err_of(fx.v.try_execute_release(&id)), Error::NotQueued);
    assert_eq!(err_of(fx.v.try_release(&item, &ctx0, &cert0)), Error::InvalidContext);
    assert_eq!(err_of(fx.v.try_release(&item, &ctx1, &cert1)), Error::InvalidRelease);
    assert_eq!(err_of(fx.try_release_n(&item, &fx.ctx(), 7)), Error::InvalidRelease);
    let mut other = item.clone();
    other.nonce = 2;
    assert_eq!(err_of(fx.try_release_n(&other, &fx.ctx(), 7)), Error::InvalidRelease);
    // A later pause does not reopen a paid burn.
    fx.advance(80 * HOUR);
    fx.pause(0);
    fx.advance(72 * HOUR);
    assert_eq!(err_of(fx.try_release_n(&item, &fx.ctx(), 7)), Error::InvalidRelease);
    assert_eq!(fx.bal(&to), paid);
    fx.assert_whole();
}

/// A forged release that took a real burn's nonce is voided by a pause; the real burn of that nonce is then paid by
/// an ordinary certificate, and the forged burn id is forgotten.
#[test]
fn voided_forgery_leaves_its_nonce_to_the_real_burn() {
    let fx = fx_queue();
    let thief = Address::generate(&fx.env);
    let to = Address::generate(&fx.env);
    let mut forged = fx.item(1, &thief, 3_000 * U);
    forged.native_burn = fx.burn(99);
    let forged_id = fx.release_id(&forged);
    fx.release(&forged);
    // While the forgery is queued, the real burn of nonce 1 is held.
    let real = fx.item(1, &to, 1_500 * U);
    assert_eq!(err_of(fx.try_release(&real)), Error::InvalidRelease);
    assert_eq!(fx.v.burn_status(&1, &real.native_burn), 3);
    fx.pause(1);
    fx.try_unpause(6).unwrap().unwrap();
    assert_eq!(fx.v.burn_status(&1, &real.native_burn), 0);
    let id = fx.release_id(&real);
    fx.release(&real);
    assert_eq!(fx.v.released_burn(&forged.native_burn), None);
    assert_eq!(fx.v.released_burn(&real.native_burn), Some(1));
    // The forgery cannot come back for this nonce, with any number of signatures.
    assert_eq!(err_of(fx.try_release_n(&forged, &fx.ctx(), 7)), Error::InvalidRelease);
    assert_eq!(err_of(fx.v.try_execute_release(&forged_id)), Error::Voided);
    fx.advance(HOUR);
    assert_eq!(err_of(fx.v.try_execute_release(&forged_id)), Error::Voided);
    fx.v.execute_release(&id);
    assert_eq!(fx.bal(&to), (1_500 * U as i128 - 750_000) * 10);
    assert_eq!(fx.bal(&thief), 0);
    fx.assert_whole();
}

/// A forged release that named a REAL burn id under a nonce that is not that burn's: once voided, the real burn is
/// paid under its own nonce, and its id cannot be used a second time.
#[test]
fn voided_forgery_that_used_a_real_burn_id_does_not_lose_that_burn() {
    let fx = fx_queue();
    let to = Address::generate(&fx.env);
    let thief = Address::generate(&fx.env);
    let real = fx.item(7, &to, 1_200 * U);
    let mut forged = fx.item(3, &thief, 3_000 * U);
    forged.native_burn = real.native_burn.clone();
    fx.release(&forged);
    assert_eq!(err_of(fx.try_release(&real)), Error::InvalidRelease);
    assert_eq!(fx.v.burn_record(&7), None);
    fx.pause(0);
    fx.try_unpause(6).unwrap().unwrap();
    let id = fx.release_id(&real);
    fx.release(&real);
    assert_eq!(fx.v.released_burn(&real.native_burn), Some(7));
    // The forgery's nonce is open again, but not for the burn id that is now recorded under nonce 7.
    assert_eq!(err_of(fx.try_release_n(&forged, &fx.ctx(), 7)), Error::InvalidRelease);
    fx.advance(HOUR);
    fx.v.execute_release(&id);
    assert_eq!(fx.bal(&to), (1_200 * U as i128 - 600_000) * 10);
    assert_eq!(err_of(fx.try_release_n(&forged, &fx.ctx(), 7)), Error::InvalidRelease);
    // Nonce 3 is paid with its own burn by an ordinary certificate.
    let real3 = fx.item(3, &to, 10 * U);
    fx.release(&real3);
    assert_eq!(fx.bal(&to), (1_200 * U as i128 - 600_000) * 10 + (10 * U as i128 - 5_000) * 10);
    assert_eq!(fx.bal(&thief), 0);
    fx.assert_whole();
}

/// Reviewer 325, R325-XLM-1, the demonstration turned into a regression. With the proposed mainnet shape (every
/// release waits in the queue) two of the three guardian keys try to stop every one of 30 exits. All they have is
/// the pause: each of them once per chain, then the cooldown. Every exit is paid, with the ordinary 5 of 7 and
/// nothing done by hand; the two keys void two exits per chain and no more.
#[test]
fn r325_xlm1_two_guardian_keys_cannot_starve_exits() {
    let fx = fx_with(|c, _| {
        c.release_delay = 2 * HOUR;
        c.large_release_threshold = 0;
    });
    fx.controls(true, true);
    fx.dep(5_000 * U);
    let (mut voided, mut paid) = (0u32, 0u32);
    let start = fx.now();
    for nonce in 1..=30u64 {
        let to = Address::generate(&fx.env);
        let item = fx.item(nonce, &to, 20 * U);
        let id = fx.release_id(&item);
        loop {
            // Certified by five signers (again, after every void).
            fx.try_release_n(&item, &fx.ctx(), 5).unwrap().unwrap();
            // The two keys void it if either of them can pause.
            let hit = (0..2).any(|g| matches!(fx.try_pause(&fx.guardians[g]), Ok(Ok(()))));
            if !hit {
                break;
            }
            voided += 1;
            assert_eq!(err_of(fx.v.try_execute_release(&id)), Error::Paused);
            fx.advance(72 * HOUR);
            assert_eq!(err_of(fx.v.try_execute_release(&id)), Error::Voided);
        }
        fx.advance(2 * HOUR);
        fx.v.execute_release(&id);
        assert_eq!(fx.bal(&to), (20 * U as i128 - 10_000) * 10);
        paid += 1;
    }
    assert_eq!(paid, 30);
    assert!(voided < 30, "two guardians voided {voided} exits in a row with nothing to stop them");
    // One chain of two pauses, then 72 h in which they can do nothing: 30 exits of 2 h each fit in it.
    assert_eq!(voided, 2);
    assert_eq!(fx.now() - start, 2 * 72 * HOUR + 30 * 2 * HOUR);
    fx.assert_whole();
}

/// Guardians alone move nothing and change nothing: a pause leaves the configuration, the books and the balance as
/// they were, and guardian signatures open no release and end no pause.
#[test]
fn guardians_alone_cannot_move_funds_or_change_limits() {
    let fx = fx_queue();
    let to = Address::generate(&fx.env);
    let item = fx.item(1, &to, 2_000 * U);
    fx.release(&item);
    let (cfg, st, balance) = (fx.v.config(), fx.v.state(), fx.bal(&fx.vault));
    fx.pause(0);
    let after = fx.v.state();
    assert_eq!(fx.v.config(), cfg);
    assert_eq!(fx.bal(&fx.vault), balance);
    assert_eq!(
        (after.total_locked, after.fees_accrued, after.deposit_count, after.deposit_head.clone(), after.bucket),
        (st.total_locked, st.fees_accrued, st.deposit_count, st.deposit_head.clone(), st.bucket)
    );
    assert_eq!((after.deposits_enabled, after.releases_enabled, after.control_nonce), (true, true, st.control_nonce));
    // All three guardian keys sign an unpause and a release: neither is accepted.
    let count = after.pause_count;
    let t = fx.now() + 600;
    let by_guardians = fx.gsigs(&[0, 1, 2], &fx.unpause_digest_x(count, t));
    assert_eq!(err_of(fx.v.try_unpause(&count, &t, &by_guardians)), Error::InvalidCertificate);
    fx.try_unpause(6).unwrap().unwrap();
    let c = fx.ctx();
    let forged = fx.gsigs(&[0, 1, 2], &fx.release_digest_x(&item, &c));
    assert_eq!(err_of(fx.v.try_release(&item, &c, &forged)), Error::InvalidCertificate);
    assert_eq!(fx.bal(&to), 0);
    // The committee pays the burn; the guardians are blocked for the cooldown meanwhile.
    fx.release(&item);
    for g in 0..3 {
        assert_eq!(err_of(fx.try_pause(&fx.guardians[g])), Error::InvalidPause);
    }
    fx.advance(HOUR);
    fx.v.execute_release(&fx.release_id(&item));
    assert_eq!(fx.bal(&to), (2_000 * U as i128 - 1_000_000) * 10);
    assert_eq!(fx.v.config(), cfg);
    fx.assert_whole();
}

/// With `release_delay` 0 nothing is ever queued; a pause still voids every certificate not yet submitted.
#[test]
fn without_a_release_delay_a_pause_voids_unsubmitted_certificates_only() {
    let fx = fx_short_pauses(HOUR, HOUR);
    fx.dep(5_000 * U);
    assert_eq!(fx.cfg.release_delay, 0);
    let to = Address::generate(&fx.env);
    let paid = fx.item(1, &to, 500 * U);
    fx.release(&paid);
    assert_eq!(fx.v.pending(&fx.release_id(&paid)), None);
    let held = fx.item(2, &to, 500 * U);
    let mut ctx = fx.ctx();
    ctx.valid_until = fx.now() + DAY;
    let cert = fx.rcert(&held, &ctx, 5);
    fx.pause(0);
    fx.advance(HOUR);
    assert_eq!(fx.v.burn_status(&1, &paid.native_burn), 2);
    assert_eq!(err_of(fx.v.try_release(&held, &ctx, &cert)), Error::InvalidContext);
    assert_eq!(err_of(fx.try_release_n(&paid, &fx.ctx(), 7)), Error::InvalidRelease);
    fx.release(&held);
    assert_eq!(fx.bal(&to), 2 * (500 * U as i128 - 250_000) * 10);
}

/// R325-XLM-3. The committee and the guardians sign every digest as an Ethereum personal message. A signature over
/// the bare 32 bytes is not accepted anywhere.
#[test]
fn signatures_over_the_bare_digest_are_refused() {
    let fx = fx_funded();
    let to = Address::generate(&fx.env);
    let item = fx.item(1, &to, U);
    let ctx = fx.ctx();
    let d = fx.release_digest_x(&item, &ctx);
    let mut bare = Vec::new(&fx.env);
    for k in fx.signers.iter().take(7) {
        bare.push_back(BytesN::from_array(&fx.env, &sign_raw(k, &d)));
    }
    assert_release_refused(&fx, &item, fx.v.try_release(&item, &ctx, &bare), Error::InvalidCertificate);
    let t = fx.now() + 600;
    let bare_pause = BytesN::from_array(&fx.env, &sign_raw(&fx.guardians[0], &fx.pause_digest_x(0, t)));
    assert_eq!(err_of(fx.v.try_guardian_pause(&t, &bare_pause)), Error::NotGuardian);
    assert!(!fx.v.paused());
    // What is signed is exactly keccak256("\x19Ethereum Signed Message:\n32" ‖ digest).
    let mut cert = Vec::new(&fx.env);
    for k in fx.signers.iter().take(5) {
        cert.push_back(BytesN::from_array(&fx.env, &sign_raw(k, &personal(&d))));
    }
    fx.v.release(&item, &ctx, &cert);
    assert_eq!(fx.bal(&to), (U as i128 - 500) * 10);
}

/// After a chain of pauses the vault is open for `pause_cooldown`; a delay that does not fit in it twice is refused.
#[test]
fn ctor_refuses_a_release_delay_above_half_the_cooldown() {
    ctor_refused(|c, _| {
        c.release_delay = 36 * HOUR + 1;
        c.large_release_threshold = 0;
    });
    let ok = fx_with(|c, _| c.release_delay = 36 * HOUR);
    assert_eq!(ok.v.config().release_delay, 36 * HOUR);
    // Without guardians there is no pause to fit around.
    let free = fx_with(|c, p| {
        c.guardians = Vec::new(&p.env);
        c.pause_duration = 0;
        c.pause_cooldown = 0;
        c.release_delay = 14 * DAY;
    });
    assert_eq!(free.v.config().release_delay, 14 * DAY);
}

/// A release above `window_limit` could never be executed (the bucket never holds that much), so it is refused
/// before anything is recorded, on the queued path as on the instant one.
#[test]
fn queue_refuses_release_above_window_limit() {
    let fx = fx_queue();
    fx.dep(10_000 * U);
    fx.dep(10_000 * U);
    let to = Address::generate(&fx.env);
    let item = fx.item(1, &to, 10_000 * U + 1);
    let id = fx.release_id(&item);
    assert_release_refused(&fx, &item, fx.try_release(&item), Error::InvalidRelease);
    assert_release_refused(&fx, &item, fx.try_release_n(&item, &fx.ctx(), 7), Error::InvalidRelease);
    assert_eq!(fx.v.pending(&id), None);
    assert_eq!(err_of(fx.v.try_execute_release(&id)), Error::NotQueued);
    // A certificate above the limit for a voided nonce is refused too, and leaves that nonce open.
    let voided = fx.item(2, &to, 2_000 * U);
    fx.release(&voided);
    fx.pause(0);
    fx.try_unpause(6).unwrap().unwrap();
    let mut big = voided.clone();
    big.amount = 10_000 * U + 1;
    assert_eq!(err_of(fx.try_release_n(&big, &fx.ctx(), 7)), Error::InvalidRelease);
    assert_eq!(fx.v.burn_status(&2, &voided.native_burn), 0);
    // Exactly window_limit queues and is paid after the delay.
    let max = fx.item(1, &to, 10_000 * U);
    let max_id = fx.release_id(&max);
    fx.release(&max);
    assert!(fx.v.pending(&max_id).is_some());
    fx.advance(HOUR);
    fx.v.execute_release(&max_id);
    assert_eq!(fx.bal(&to), (10_000 * U as i128 - 5_000_000) * 10);
    fx.assert_whole();
}

// ── 7. guardians ───────────────────────────────────────────────────────────────

#[test]
fn guardian_one_signature_pauses_for_pause_duration() {
    let fx = fx_funded();
    assert!(fx.v.guardian_can_pause(&b20(&fx.env, &fx.guardians[0].addr)));
    fx.pause(0);
    let ev = fx.vault_events();
    let until = fx.now() + 72 * HOUR;
    let paused = GuardianPaused { guardian: b20(&fx.env, &fx.guardians[0].addr), pause_count: 1, paused_until: until };
    assert_eq!(ev, [paused.to_xdr(&fx.env, &fx.vault)]);
    let st = fx.v.state();
    assert_eq!((st.paused_until, st.pause_count, st.pause_chain, st.guardian_blocked_until), (until, 1, 1, 0));
    assert_eq!(st.guardian_last_chain.get(b20(&fx.env, &fx.guardians[0].addr)), Some(1));
    assert!(fx.v.paused());
    fx.advance(72 * HOUR - 1);
    assert!(fx.v.paused());
    fx.advance(1);
    assert!(!fx.v.paused());
    fx.dep(100 * U);
}

#[test]
fn guardian_pause_does_not_stop_the_fee_sweep_or_the_controls() {
    let fx = fx_funded();
    fx.pause(0);
    assert_eq!(fx.v.sweep_fees(), 2_500_000);
    fx.controls(false, false);
    assert!(!fx.v.state().deposits_enabled);
}

#[test]
fn guardian_pause_refused_for_non_guardian_signature() {
    let fx = fx_open();
    for k in [key(900), fx.signers[0].clone(), fx.signers[6].clone()] {
        assert_eq!(err_of(fx.try_pause(&k)), Error::NotGuardian);
    }
    assert_eq!(fx.v.state().pause_count, 0);
    assert!(!fx.v.guardian_can_pause(&b20(&fx.env, &fx.signers[0].addr)));
}

#[test]
fn guardian_pause_refused_with_high_s_or_bad_v() {
    let fx = fx_open();
    let t = fx.now() + 600;
    let s = sign(&fx.guardians[0], &fx.pause_digest_x(0, t));
    let twin = high_s_twin(&s);
    assert_eq!(err_of(fx.v.try_guardian_pause(&t, &BytesN::from_array(&fx.env, &twin))), Error::InvalidCertificate);
    let mut bad_v = s;
    bad_v[64] -= 27;
    assert_eq!(err_of(fx.v.try_guardian_pause(&t, &BytesN::from_array(&fx.env, &bad_v))), Error::InvalidCertificate);
    fx.v.guardian_pause(&t, &BytesN::from_array(&fx.env, &s));
}

#[test]
fn guardian_pause_refused_outside_validity() {
    let fx = fx_open();
    let now = fx.now();
    for t in [now - 1, now + DAY + 1] {
        let s = sign(&fx.guardians[0], &fx.pause_digest_x(0, t));
        assert_eq!(err_of(fx.v.try_guardian_pause(&t, &BytesN::from_array(&fx.env, &s))), Error::InvalidPause);
    }
    // A signature whose validity ran out.
    let t = now + 600;
    let s = sign(&fx.guardians[0], &fx.pause_digest_x(0, t));
    fx.advance(601);
    assert_eq!(err_of(fx.v.try_guardian_pause(&t, &BytesN::from_array(&fx.env, &s))), Error::InvalidPause);
}

#[test]
fn guardian_pause_signature_of_another_instance_is_no_guardian() {
    let a = fx_open();
    let b = a.sibling();
    let t = a.now() + 600;
    let s = BytesN::from_array(&a.env, &sign(&a.guardians[0], &b.pause_digest_x(0, t)));
    assert_eq!(err_of(a.v.try_guardian_pause(&t, &s)), Error::NotGuardian);
    b.v.guardian_pause(&t, &s);
    assert!(b.v.paused() && !a.v.paused());
}

#[test]
fn guardian_pause_signature_replay_fails_after_pause_count_moved() {
    // Short periods, so signatures (valid a day) outlive the pause.
    let fx = fx_short_pauses(HOUR, HOUR);
    let t = fx.now() + DAY;
    let sig = |g: usize, count: u64| BytesN::from_array(&fx.env, &sign(&fx.guardians[g], &fx.pause_digest_x(count, t)));
    let a0 = sig(0, 0);
    let b0 = sig(1, 0);
    fx.v.guardian_pause(&t, &a0);
    assert_eq!(fx.v.state().pause_count, 1);
    // During the pause and after it, both count-0 signatures now recover to some address that is no guardian.
    assert_eq!(err_of(fx.v.try_guardian_pause(&t, &a0)), Error::NotGuardian);
    assert_eq!(err_of(fx.v.try_guardian_pause(&t, &b0)), Error::NotGuardian);
    fx.advance(HOUR);
    assert!(!fx.v.paused());
    assert_eq!(err_of(fx.v.try_guardian_pause(&t, &a0)), Error::NotGuardian);
    assert_eq!(err_of(fx.v.try_guardian_pause(&t, &b0)), Error::NotGuardian);
    // Even after the chain ended, when guardian A may pause again, the old signature is dead.
    fx.advance(HOUR);
    assert!(fx.v.guardian_can_pause(&b20(&fx.env, &fx.guardians[0].addr)));
    assert_eq!(err_of(fx.v.try_guardian_pause(&t, &a0)), Error::NotGuardian);
    fx.v.guardian_pause(&t, &sig(0, 1));
    assert_eq!(fx.v.state().pause_count, 2);
}

#[test]
fn guardian_cannot_pause_while_paused() {
    let fx = fx_open();
    fx.pause(0);
    for g in 0..3 {
        assert!(!fx.v.guardian_can_pause(&b20(&fx.env, &fx.guardians[g].addr)));
        assert_eq!(err_of(fx.try_pause(&fx.guardians[g])), Error::InvalidPause);
    }
    fx.advance(72 * HOUR - 1);
    assert_eq!(err_of(fx.try_pause(&fx.guardians[1])), Error::InvalidPause);
    assert_eq!(fx.v.state().pause_count, 1);
}

/// The chain rule with three guardians: each pauses once per chain, a chain is at most three pauses, then the
/// cooldown must pass.
fn check_chain_rule(duration: u64, cooldown: u64) {
    let fx = fx_short_pauses(duration, cooldown);
    let can = |g: usize| fx.v.guardian_can_pause(&b20(&fx.env, &fx.guardians[g].addr));
    let t0 = fx.now();
    fx.pause(0);
    assert_eq!(fx.v.state().pause_chain, 1);
    fx.advance(duration);
    // A cannot pause twice in one chain; B renews at expiry.
    assert!(!can(0) && can(1) && can(2));
    assert_eq!(err_of(fx.try_pause(&fx.guardians[0])), Error::InvalidPause);
    fx.pause(1);
    fx.advance(duration);
    assert!(!can(0) && !can(1) && can(2));
    assert_eq!(err_of(fx.try_pause(&fx.guardians[0])), Error::InvalidPause);
    assert_eq!(err_of(fx.try_pause(&fx.guardians[1])), Error::InvalidPause);
    fx.pause(2);
    let st = fx.v.state();
    assert_eq!((st.pause_count, st.pause_chain, st.paused_until), (3, 1, t0 + 3 * duration));
    fx.advance(duration);
    // Three pauses made the chain; now the vault is open and nobody can pause until the cooldown has passed.
    assert_eq!(fx.now(), t0 + 3 * duration);
    assert!(!fx.v.paused());
    for g in 0..3 {
        assert!(!can(g));
        assert_eq!(err_of(fx.try_pause(&fx.guardians[g])), Error::InvalidPause);
    }
    fx.dep(100 * U);
    fx.advance(cooldown - 1);
    for g in 0..3 {
        assert_eq!(err_of(fx.try_pause(&fx.guardians[g])), Error::InvalidPause);
    }
    assert!(!fx.v.paused());
    fx.advance(1);
    assert!(can(0) && can(1) && can(2));
    fx.pause(0);
    let st = fx.v.state();
    assert_eq!((st.pause_count, st.pause_chain), (4, 2));
    // In the new chain A is spent again, B is not.
    fx.advance(duration);
    assert!(!can(0) && can(1));
}

#[test]
fn guardian_chain_rule_with_mainnet_periods() {
    check_chain_rule(72 * HOUR, 72 * HOUR);
}

#[test]
fn guardian_chain_rule_with_cooldown_longer_than_pause() {
    check_chain_rule(HOUR, 5 * HOUR);
}

#[test]
fn guardian_chain_is_kept_by_a_late_renewal_within_cooldown() {
    let fx = fx_short_pauses(HOUR, 5 * HOUR);
    fx.pause(0);
    // B pauses well after A's pause expired but before the cooldown passed: still the same chain.
    fx.advance(HOUR + 4 * HOUR);
    fx.pause(1);
    assert_eq!(fx.v.state().pause_chain, 1);
    fx.advance(HOUR);
    assert_eq!(err_of(fx.try_pause(&fx.guardians[0])), Error::InvalidPause);
    // After a full cooldown with no pause the chain ends and A may start the next one.
    fx.advance(5 * HOUR);
    fx.pause(0);
    assert_eq!(fx.v.state().pause_chain, 2);
}

#[test]
fn unpause_needs_switch_threshold() {
    let fx = fx_funded();
    fx.pause(0);
    fx.advance(HOUR);
    assert_eq!(err_of(fx.try_unpause(5)), Error::InvalidCertificate);
    assert!(fx.v.paused());
    fx.try_unpause(6).unwrap().unwrap();
    let ev = fx.vault_events();
    let blocked = fx.now() + 72 * HOUR;
    assert_eq!(ev, [Unpaused { pause_count: 1, guardian_blocked_until: blocked }.to_xdr(&fx.env, &fx.vault)]);
    assert!(!fx.v.paused());
    let st = fx.v.state();
    assert_eq!((st.paused_until, st.guardian_blocked_until, st.pause_count), (fx.now(), blocked, 1));
    fx.dep(100 * U);
    let to = Address::generate(&fx.env);
    fx.release(&fx.item(1, &to, U));
}

#[test]
fn unpause_blocks_guardians_for_pause_cooldown() {
    let fx = fx_open();
    fx.pause(0);
    fx.advance(HOUR);
    fx.try_unpause(7).unwrap().unwrap();
    for g in 0..3 {
        assert!(!fx.v.guardian_can_pause(&b20(&fx.env, &fx.guardians[g].addr)));
        assert_eq!(err_of(fx.try_pause(&fx.guardians[g])), Error::InvalidPause);
    }
    fx.advance(72 * HOUR - 1);
    assert_eq!(err_of(fx.try_pause(&fx.guardians[1])), Error::InvalidPause);
    fx.advance(1);
    // The block is over and so is the chain: even the guardian that paused may pause again.
    fx.pause(0);
    assert_eq!(fx.v.state().pause_chain, 2);
}

#[test]
fn unpause_refused_when_not_paused_or_for_another_pause_count() {
    let fx = fx_open();
    assert_eq!(err_of(fx.try_unpause(7)), Error::InvalidPause);
    fx.pause(0);
    let t = fx.now() + 600;
    for count in [0u64, 2] {
        let cert = fx.first(7, &fx.unpause_digest_x(count, t));
        assert_eq!(err_of(fx.v.try_unpause(&count, &t, &cert)), Error::InvalidPause);
    }
    // The right count under signatures made for another count.
    let cert = fx.first(7, &fx.unpause_digest_x(0, t));
    assert_eq!(err_of(fx.v.try_unpause(&1, &t, &cert)), Error::InvalidCertificate);
    fx.advance(72 * HOUR);
    assert_eq!(err_of(fx.try_unpause(7)), Error::InvalidPause);
}

#[test]
fn unpause_certificate_cannot_be_replayed_on_a_later_pause() {
    let fx = fx_short_pauses(HOUR, HOUR);
    fx.pause(0);
    let t = fx.now() + DAY;
    let cert = fx.first(6, &fx.unpause_digest_x(1, t));
    fx.v.unpause(&1, &t, &cert);
    assert_eq!(err_of(fx.v.try_unpause(&1, &t, &cert)), Error::InvalidPause);
    fx.advance(HOUR);
    fx.pause(1);
    assert!(fx.v.paused());
    assert_eq!(err_of(fx.v.try_unpause(&1, &t, &cert)), Error::InvalidPause);
    assert_eq!(err_of(fx.v.try_unpause(&2, &t, &cert)), Error::InvalidCertificate);
    assert!(fx.v.paused());
}

#[test]
fn unpause_refused_with_guardian_signatures_or_pause_digest() {
    let fx = fx_open();
    fx.pause(0);
    let t = fx.now() + 600;
    let d = fx.unpause_digest_x(1, t);
    assert_eq!(err_of(fx.v.try_unpause(&1, &t, &fx.gsigs(&[0, 1, 2], &d))), Error::InvalidCertificate);
    // Signers signing the pause digest of the same count is not an unpause.
    let cert = fx.first(7, &fx.pause_digest_x(1, t));
    assert_eq!(err_of(fx.v.try_unpause(&1, &t, &cert)), Error::InvalidCertificate);
    for bad in [fx.now() - 1, fx.now() + DAY + 1] {
        let cert = fx.first(7, &fx.unpause_digest_x(1, bad));
        assert_eq!(err_of(fx.v.try_unpause(&1, &bad, &cert)), Error::InvalidPause);
    }
}

// ── 8. fees ────────────────────────────────────────────────────────────────────

#[test]
fn sweep_pays_exactly_the_accrued_fees_and_leaves_the_backing() {
    let fx = fx_funded();
    let to = Address::generate(&fx.env);
    fx.release(&fx.item(1, &to, 1_000 * U));
    let st = fx.v.state();
    assert_eq!(st.fees_accrued, 2_500_000 + 500_000);
    let stranger_balance_before = fx.bal(&fx.fee_recipient);
    assert_eq!(fx.v.sweep_fees(), 3_000_000);
    let ev = fx.vault_events();
    assert_eq!(ev, [FeesSwept { recipient: fx.fee_recipient.clone(), amount: 3_000_000 }.to_xdr(&fx.env, &fx.vault)]);
    assert_eq!(fx.bal(&fx.fee_recipient) - stranger_balance_before, 30_000_000);
    let after = fx.v.state();
    assert_eq!(after.fees_accrued, 0);
    assert_eq!(after.total_locked, st.total_locked);
    assert_eq!(after.bucket, st.bucket);
    assert_eq!(fx.bal(&fx.vault), st.total_locked as i128 * 10);
    assert_eq!(fx.v.backing(), Backing { balance: st.total_locked as i128 * 10, required: st.total_locked as i128 * 10 });
}

#[test]
fn sweep_with_zero_fees_returns_zero() {
    let fx = fx_open();
    assert_eq!(fx.v.sweep_fees(), 0);
    assert_eq!(fx.vault_events().events().len(), 0);
    fx.dep(100 * U);
    assert_eq!(fx.v.sweep_fees(), 50_000);
    assert_eq!(fx.v.sweep_fees(), 0);
    assert_eq!(fx.bal(&fx.fee_recipient), 500_000);
    fx.assert_whole();
}

#[test]
fn sweep_needs_no_authorization() {
    let fx = fx_funded();
    fx.env.set_auths(&[]);
    assert_eq!(fx.v.sweep_fees(), 2_500_000);
    assert_eq!(fx.bal(&fx.fee_recipient), 25_000_000);
}

#[test]
fn sweep_never_pays_a_donation_or_the_backing() {
    let fx = fx_funded();
    // Somebody sends the asset straight to the vault: it is in no book.
    let donor = fx.user(77 * U);
    fx.tok.transfer(&donor, &fx.vault, &(77 * U as i128 * 10));
    assert_eq!(fx.v.sweep_fees(), 2_500_000);
    assert_eq!(fx.bal(&fx.fee_recipient), 25_000_000);
    let b = fx.v.backing();
    assert_eq!(b.balance - b.required, 77 * U as i128 * 10);
    assert_eq!(b.required, fx.v.state().total_locked as i128 * 10);
}

// ── 9. issuer powers ───────────────────────────────────────────────────────────

fn fx_issuer(flags: &[IssuerFlags]) -> Fx {
    let fx = fx_parts(parts_flags(flags), |_, _| {});
    fx.controls(true, true);
    fx
}

#[test]
fn issuer_deauthorizing_the_vault_blocks_deposit_and_release_and_consumes_nothing() {
    let fx = fx_issuer(&[IssuerFlags::RevocableFlag, IssuerFlags::ClawbackEnabledFlag]);
    fx.dep(5_000 * U);
    let to = Address::generate(&fx.env);
    let item = fx.item(1, &to, 1_000 * U);
    let mut ctx = fx.ctx();
    ctx.valid_until = fx.now() + DAY;
    let cert = fx.rcert(&item, &ctx, 5);
    let from = fx.user(100 * U);

    fx.sac.set_authorized(&fx.vault, &false);
    assert!(!fx.sac.authorized(&fx.vault));
    let st = fx.v.state();
    // Each fails inside the asset contract (balance deauthorized); the vault reports it as its own InvalidTransfer
    // and the whole call is undone.
    assert_eq!(err_of(fx.try_dep(&from, 100 * U)), Error::InvalidTransfer);
    assert_eq!(err_of(fx.v.try_release(&item, &ctx, &cert)), Error::InvalidTransfer);
    assert_eq!(err_of(fx.v.try_sweep_fees()), Error::InvalidTransfer);
    assert_eq!(fx.v.state(), st);
    assert_eq!(fx.v.burn_record(&1), None);
    assert_eq!(fx.v.released_burn(&item.native_burn), None);
    assert_eq!(fx.bal(&from), 1_000 * U as i128);
    assert_eq!(fx.bal(&to), 0);
    assert_eq!(fx.v.backing(), Backing { balance: 50_000 * U as i128, required: 50_000 * U as i128 });

    fx.advance(HOUR);
    fx.sac.set_authorized(&fx.vault, &true);
    // The very same certificate: its nonce was not consumed by the failed attempt.
    fx.v.release(&item, &ctx, &cert);
    assert_eq!(fx.bal(&to), (1_000 * U as i128 - 500_000) * 10);
    fx.try_dep(&from, 100 * U).unwrap().unwrap();
    assert_eq!(fx.v.sweep_fees(), 2_500_000 + 500_000 + 50_000);
    fx.assert_whole();
}

#[test]
fn issuer_clawback_stops_deposit_release_and_sweep_until_made_whole() {
    let fx = fx_issuer(&[IssuerFlags::RevocableFlag, IssuerFlags::ClawbackEnabledFlag]);
    fx.dep(5_000 * U);
    let to = Address::generate(&fx.env);
    let item = fx.item(1, &to, 1_000 * U);
    let mut ctx = fx.ctx();
    ctx.valid_until = fx.now() + DAY;
    let cert = fx.rcert(&item, &ctx, 5);
    let from = fx.user(100 * U);

    // The issuer takes one unit (10 stroops) out of the vault.
    fx.sac.clawback(&fx.vault, &10);
    let b = fx.v.backing();
    assert_eq!((b.balance, b.required), (50_000 * U as i128 - 10, 50_000 * U as i128));
    let st = fx.v.state();
    assert_eq!(err_of(fx.try_dep(&from, 100 * U)), Error::InsufficientBacking);
    assert_eq!(err_of(fx.v.try_release(&item, &ctx, &cert)), Error::InsufficientBacking);
    assert_eq!(err_of(fx.v.try_sweep_fees()), Error::InsufficientBacking);
    assert_eq!(fx.v.state(), st);
    assert_eq!(fx.v.burn_record(&1), None);
    assert_eq!(fx.bal(&from), 1_000 * U as i128);
    assert_eq!(fx.bal(&to), 0);
    assert_eq!(fx.bal(&fx.fee_recipient), 0);

    // A large clawback behaves the same.
    fx.sac.clawback(&fx.vault, &(4_000 * U as i128 * 10));
    assert_eq!(err_of(fx.v.try_release(&item, &ctx, &cert)), Error::InsufficientBacking);
    assert_eq!(fx.v.state(), st);

    // One stroop short of whole is still short.
    fx.sac.mint(&fx.vault, &(4_000 * U as i128 * 10 + 9));
    assert_eq!(err_of(fx.v.try_sweep_fees()), Error::InsufficientBacking);
    fx.sac.mint(&fx.vault, &1);
    assert_eq!(fx.v.backing(), Backing { balance: 50_000 * U as i128, required: 50_000 * U as i128 });
    fx.v.release(&item, &ctx, &cert);
    fx.try_dep(&from, 100 * U).unwrap().unwrap();
    assert_eq!(fx.v.sweep_fees(), 2_500_000 + 500_000 + 50_000);
    assert_eq!(fx.bal(&to), (1_000 * U as i128 - 500_000) * 10);
    fx.assert_whole();
}

#[test]
fn issuer_clawback_stops_a_queued_release_too() {
    let p = parts_flags(&[IssuerFlags::RevocableFlag, IssuerFlags::ClawbackEnabledFlag]);
    let fx = fx_parts(p, |c, _| {
        c.release_delay = HOUR;
        c.large_release_threshold = 1_000 * U;
    });
    fx.controls(true, true);
    fx.dep(5_000 * U);
    let to = Address::generate(&fx.env);
    let item = fx.item(1, &to, 2_000 * U);
    let id = fx.release_id(&item);
    fx.release(&item);
    fx.sac.clawback(&fx.vault, &10);
    fx.advance(HOUR);
    assert_eq!(err_of(fx.v.try_execute_release(&id)), Error::InsufficientBacking);
    assert!(fx.v.pending(&id).is_some());
    fx.sac.mint(&fx.vault, &10);
    fx.v.execute_release(&id);
    fx.assert_whole();
}

#[test]
fn issuer_clawback_flag_enabled_after_the_vault_balance_exists() {
    // No flag while the vault's balance entry is created.
    let fx = fx_issuer(&[]);
    fx.dep(5_000 * U);
    fx.issuer.set_flag(IssuerFlags::RevocableFlag);
    fx.issuer.set_flag(IssuerFlags::ClawbackEnabledFlag);
    // What the SDK's asset contract does: the clawback bit is fixed on a balance when it is created, so the vault's
    // balance, created before the flag, cannot be clawed back (asset error 10).
    assert_eq!(fx.sac.try_clawback(&fx.vault, &10), Err(Ok(sac_error(SAC_BALANCE_ERROR))));
    assert_eq!(fx.bal(&fx.vault), 50_000 * U as i128);
    fx.assert_whole();
    // A holder whose balance is created after the flag was enabled can be clawed back.
    let late = fx.user(10 * U);
    fx.sac.clawback(&late, &10);
    assert_eq!(fx.bal(&late), 10 * U as i128 * 10 - 10);
    // Deauthorization is different: it reads the issuer's revocable flag at the time of the call, so the flag set
    // late does reach the old balance and freezes the vault.
    fx.sac.set_authorized(&fx.vault, &false);
    let from = fx.user(100 * U);
    assert_eq!(err_of(fx.try_dep(&from, 100 * U)), Error::InvalidTransfer);
    let to = Address::generate(&fx.env);
    assert_eq!(err_of(fx.try_release(&fx.item(1, &to, U))), Error::InvalidTransfer);
    assert_eq!(fx.v.burn_record(&1), None);
    fx.sac.set_authorized(&fx.vault, &true);
    fx.release(&fx.item(1, &to, U));
    fx.assert_whole();
}

#[test]
fn issuer_without_revocable_flag_cannot_deauthorize_or_claw_back() {
    let fx = fx_issuer(&[]);
    fx.dep(5_000 * U);
    assert_eq!(fx.sac.try_set_authorized(&fx.vault, &false), Err(Ok(sac_error(SAC_OPERATION_NOT_SUPPORTED))));
    assert_eq!(fx.sac.try_clawback(&fx.vault, &10), Err(Ok(sac_error(SAC_BALANCE_ERROR))));
    fx.assert_whole();
}

#[test]
fn issuer_auth_required_vault_must_be_authorized_before_the_first_deposit() {
    let fx = fx_issuer(&[IssuerFlags::RequiredFlag, IssuerFlags::RevocableFlag]);
    let from = Address::generate(&fx.env);
    // With the issuer's auth-required flag every new balance starts unauthorized, the vault's included.
    assert_eq!(fx.sac.try_mint(&from, &(100 * U as i128 * 10)), Err(Ok(sac_error(SAC_BALANCE_DEAUTHORIZED))));
    fx.sac.set_authorized(&from, &true);
    fx.sac.mint(&from, &(100 * U as i128 * 10));
    assert_eq!(err_of(fx.try_dep(&from, 100 * U)), Error::InvalidTransfer);
    assert_eq!(fx.v.state().deposit_count, 0);
    fx.sac.set_authorized(&fx.vault, &true);
    fx.try_dep(&from, 100 * U).unwrap().unwrap();
    // A release to a recipient the issuer has not authorized fails in the asset and consumes nothing.
    let to = Address::generate(&fx.env);
    let item = fx.item(1, &to, U);
    let mut ctx = fx.ctx();
    ctx.valid_until = fx.now() + DAY;
    let cert = fx.rcert(&item, &ctx, 5);
    assert_eq!(err_of(fx.v.try_release(&item, &ctx, &cert)), Error::InvalidTransfer);
    assert_eq!(fx.v.burn_record(&1), None);
    fx.sac.set_authorized(&to, &true);
    fx.v.release(&item, &ctx, &cert);
    fx.assert_whole();
}

// ── 10. storage and archival ───────────────────────────────────────────────────

#[test]
fn storage_records_are_written_with_at_least_record_ttl() {
    let fx = fx_funded();
    let to = Address::generate(&fx.env);
    let item = fx.item(1, &to, U);
    fx.release(&item);
    let max = fx.env.as_contract(&fx.vault, || fx.env.storage().max_ttl());
    // The test ledger's maximum (6,311,999) is above both constants, so neither is capped here.
    assert!(max >= INSTANCE_TTL);
    let record_ttl = RECORD_TTL.min(max);
    let (nonce_ttl, burn_ttl, head_ttl, instance_ttl) = fx.env.as_contract(&fx.vault, || {
        (
            fx.env.storage().persistent().get_ttl(&Key::Nonce(1)),
            fx.env.storage().persistent().get_ttl(&Key::Burn(item.native_burn.clone())),
            fx.env.storage().persistent().get_ttl(&Key::Head(1)),
            fx.env.storage().instance().get_ttl(),
        )
    });
    assert!(nonce_ttl >= record_ttl);
    assert!(burn_ttl >= record_ttl);
    assert!(head_ttl >= record_ttl);
    assert!(instance_ttl >= INSTANCE_TTL.min(max) / 2);
    assert!(instance_ttl >= record_ttl);
    // Exactly, in this run (all written in the current ledger).
    assert_eq!((nonce_ttl, burn_ttl, head_ttl, instance_ttl), (RECORD_TTL, RECORD_TTL, RECORD_TTL, INSTANCE_TTL));
}

#[test]
fn storage_queue_records_get_record_ttl_and_instance_is_extended() {
    let fx = fx_queue();
    let to = Address::generate(&fx.env);
    let item = fx.item(1, &to, 2_000 * U);
    let id = fx.release_id(&item);
    fx.release(&item);
    let ttl = |k: Key| fx.env.as_contract(&fx.vault, || fx.env.storage().persistent().get_ttl(&k));
    assert_eq!(ttl(Key::Pending(id.clone())), RECORD_TTL);
    // Later, the execution rewrites the nonce record (now paid) with a fresh TTL.
    fx.env.ledger().with_mut(|l| l.sequence_number += 1_000);
    assert_eq!(ttl(Key::Nonce(1)), RECORD_TTL - 1_000);
    fx.advance(HOUR);
    fx.v.execute_release(&id);
    assert_eq!(ttl(Key::Nonce(1)), RECORD_TTL);
    // The instance is extended back to INSTANCE_TTL once it has fallen below half of it.
    let instance = || fx.env.as_contract(&fx.vault, || fx.env.storage().instance().get_ttl());
    fx.env.ledger().with_mut(|l| l.sequence_number += INSTANCE_TTL / 2);
    assert!(instance() < INSTANCE_TTL / 2);
    fx.v.sweep_fees();
    assert_eq!(instance(), INSTANCE_TTL);
}

#[test]
fn storage_uses_no_temporary_entries() {
    let fx = fx_queue();
    let to = Address::generate(&fx.env);
    fx.release(&fx.item(1, &to, U));
    let queued = fx.item(2, &to, 2_000 * U);
    fx.release(&queued);
    fx.pause(0);
    fx.try_unpause(6).unwrap().unwrap();
    fx.release(&queued);
    fx.v.sweep_fees();
    // The test host lists the entries of every contract here (the asset's balances are persistent entries too), so
    // no contract in this run, the asset included, wrote a temporary entry.
    let (temporary, present) = fx.env.as_contract(&fx.vault, || {
        let p = fx.env.storage().persistent();
        let present = p.has(&Key::Head(1))
            && p.has(&Key::Nonce(1))
            && p.has(&Key::Burn(fx.burn(1)))
            && p.has(&Key::Nonce(2))
            && p.has(&Key::Burn(fx.burn(2)))
            && p.has(&Key::Pending(fx.release_id(&queued)));
        let t = fx.env.storage().temporary();
        let in_temporary = t.has(&Key::Head(1)) || t.has(&Key::Nonce(1)) || t.has(&Key::Nonce(2)) || t.has(&Key::State);
        assert!(!in_temporary);
        (t.all().len(), present)
    });
    assert_eq!(temporary, 0);
    assert!(present);
}

/// What the SDK 29 test host does with a persistent entry whose TTL ended: it restores it by itself. Once the ledger
/// sequence is past the entry's live-until ledger, the entry is served again as if restored in the current ledger
/// (its TTL reads as the minimum persistent TTL less one, 4,095), with no error, no panic and no explicit restore
/// step. So an archived-and-missing record cannot be produced here; what is asserted is the required property: with
/// the record's TTL over, neither the old certificate nor a fresh one for the same burn is ever paid.
#[test]
fn storage_replay_after_the_record_ttl_never_succeeds() {
    let fx = fx_funded();
    let to = Address::generate(&fx.env);
    let item = fx.item(1, &to, U);
    let mut ctx = fx.ctx();
    ctx.valid_until = fx.now() + DAY;
    let cert = fx.rcert(&item, &ctx, 5);
    fx.v.release(&item, &ctx, &cert);
    let paid = fx.bal(&to);
    let st = fx.v.state();
    let nonce_ttl = fx.env.as_contract(&fx.vault, || fx.env.storage().persistent().get_ttl(&Key::Nonce(1)));
    // Only the sequence moves: the close time stays, so the certificate itself is still within its validity and the
    // replay records are the only thing between it and a second payment.
    fx.env.ledger().with_mut(|l| l.sequence_number += nonce_ttl + 1);
    // The entry's live-until ledger is now in the past, and the host reports it as just restored.
    let ttl = catch_unwind(AssertUnwindSafe(|| {
        fx.env.as_contract(&fx.vault, || fx.env.storage().persistent().get_ttl(&Key::Nonce(1)))
    }));
    assert_eq!(ttl.ok(), Some(4_095));
    // The old certificate.
    let r = catch_unwind(AssertUnwindSafe(|| fx.v.try_release(&item, &ctx, &cert)));
    assert!(!matches!(r, Ok(Ok(_))), "the replay was accepted");
    // In this host it is an ordinary refusal: the expired record is read as restored.
    assert_eq!(err_of(r.unwrap()), Error::InvalidRelease);
    // A fresh certificate of the whole committee for the same nonce and burn.
    let r = catch_unwind(AssertUnwindSafe(|| fx.try_release_n(&item, &ctx, 7)));
    assert!(!matches!(r, Ok(Ok(_))), "the re-certified replay was accepted");
    assert_eq!(err_of(r.unwrap()), Error::InvalidRelease);
    // Same nonce under another burn id, same burn id under another nonce.
    let mut other_burn = item.clone();
    other_burn.native_burn = fx.burn(2);
    assert_eq!(err_of(fx.try_release_n(&other_burn, &ctx, 7)), Error::InvalidRelease);
    let mut other_nonce = item.clone();
    other_nonce.nonce = 2;
    assert_eq!(err_of(fx.try_release_n(&other_nonce, &ctx, 7)), Error::InvalidRelease);
    assert_eq!(fx.bal(&to), paid);
    assert_eq!(fx.v.state(), st);
    assert_eq!(fx.v.burn_record(&1), Some(BurnRecord { burn: item.native_burn.clone(), pause_count: 0, paid: true }));
    assert_eq!(fx.v.released_burn(&item.native_burn), Some(1));
    // A new burn is still paid, and its records are written with a full TTL.
    fx.release(&fx.item(3, &to, U));
    assert_eq!(fx.env.as_contract(&fx.vault, || fx.env.storage().persistent().get_ttl(&Key::Nonce(3))), RECORD_TTL);
}

// ── 11. books invariant under a randomized sequence ────────────────────────────

#[test]
fn books_invariant_holds_under_randomized_operations() {
    let fx = fx_open();
    let mut rng = Rng(0x0BAD_5EED_2026_1116);
    let users: StdVec<Address> = (0..3).map(|_| fx.user(2_000_000 * U)).collect();
    let recipients: StdVec<Address> = (0..3).map(|_| Address::generate(&fx.env)).collect();
    let (mut locked, mut fees) = (0u64, 0u64);
    let (mut sum_net, mut sum_released, mut swept) = (0u128, 0u128, 0u128);
    let mut nonce = 0u64;
    let mut count = [0u32; 8];
    for step in 0..400 {
        let paused = fx.v.paused();
        match rng.below(20) {
            0..=6 => {
                let from = &users[rng.below(3) as usize];
                let units = match rng.below(10) {
                    0 => rng.range(1, 11 * U - 1),
                    1 => 10_000 * U + rng.range(1, 1_000),
                    _ => rng.range(11 * U, 10_000 * U),
                };
                let stroops = units as i128 * 10 + if rng.below(12) == 0 { 3 } else { 0 };
                let r = fx.v.try_deposit(from, &stroops, &b20(&fx.env, &[step as u8 | 1; 20]));
                let net = units - fee_x(units, 5);
                let ok = !paused
                    && stroops % 10 == 0
                    && units >= 11 * U
                    && units <= 10_000 * U
                    && locked + net <= fx.cfg.cap;
                assert_eq!(r.is_ok(), ok, "step {step}: deposit of {stroops} stroops: {:?}", r);
                if ok {
                    locked += net;
                    fees += units - net;
                    sum_net += net as u128;
                    count[0] += 1;
                } else {
                    count[1] += 1;
                }
            }
            7..=12 => {
                let room = fx.v.available_to_release();
                let amount = match rng.below(8) {
                    0 => locked + rng.range(1, 1_000),
                    1 => room + 1,
                    2 => rng.range(1, 100),
                    _ => rng.range(1, room.min(locked).max(1)),
                };
                nonce += 1;
                let to = &recipients[rng.below(3) as usize];
                let before = fx.bal(to);
                let item = fx.item(nonce, to, amount);
                let r = fx.try_release(&item);
                let ok = !paused && amount <= locked && amount <= room && item.mint_count > 0;
                assert_eq!(r.is_ok(), ok, "step {step}: release of {amount}: {:?}", r);
                if ok {
                    let fee = fee_x(amount, 5);
                    locked -= amount;
                    fees += fee;
                    sum_released += amount as u128;
                    assert_eq!(fx.bal(to) - before, (amount - fee) as i128 * 10);
                    count[2] += 1;
                } else {
                    assert_eq!(fx.bal(to), before);
                    count[3] += 1;
                }
            }
            13 | 14 => {
                let got = fx.v.sweep_fees();
                assert_eq!(got, fees, "step {step}");
                swept += got as u128;
                fees = 0;
                count[4] += 1;
            }
            15 => {
                let g = rng.below(3) as usize;
                let can = fx.v.guardian_can_pause(&b20(&fx.env, &fx.guardians[g].addr));
                let r = fx.try_pause(&fx.guardians[g]);
                assert_eq!(r.is_ok(), can, "step {step}: pause: {:?}", r);
                if can {
                    count[5] += 1;
                }
            }
            16 => {
                let r = fx.try_unpause(6);
                assert_eq!(r.is_ok(), paused, "step {step}: unpause: {:?}", r);
                if paused {
                    count[6] += 1;
                }
            }
            _ => {
                fx.advance(rng.range(1, 30 * HOUR));
                count[7] += 1;
            }
        }
        let st = fx.v.state();
        assert_eq!((st.total_locked, st.fees_accrued), (locked, fees), "step {step}");
        assert_eq!(fx.bal(&fx.vault), (locked as i128 + fees as i128) * 10, "step {step}");
        assert!(st.total_locked <= fx.cfg.cap);
        assert_eq!(sum_net - sum_released, st.total_locked as u128, "step {step}");
        assert!(st.bucket <= fx.cfg.window_limit);
        let b = fx.v.backing();
        assert_eq!(b.balance, b.required);
    }
    assert_eq!(fx.bal(&fx.fee_recipient), swept as i128 * 10);
    let out: i128 = recipients.iter().map(|r| fx.bal(r)).sum();
    let held: i128 = users.iter().map(|u| fx.bal(u)).sum();
    // Nothing is created or lost: what the users put in is in the vault, with the recipients or with the fee recipient.
    assert_eq!(3 * 2_000_000 * U as i128 * 10 - held, fx.bal(&fx.vault) + out + swept as i128 * 10);
    assert!(count[0] > 40 && count[2] > 40 && count[4] > 10 && count[5] > 2 && count[6] > 0, "{:?}", count);
}
