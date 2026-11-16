//! Hashing in the exact byte layouts of the Ethereum vault (`ProvenanceSourceVault`) and of the L2 token
//! (`BridgedStablecoinV3`): Solidity `abi.encode` of static types is a run of 32-byte big-endian words, so every
//! identifier and digest below is the one the EVM contracts and the existing signer tooling compute, with Solana
//! identities mapped to 20-byte values (`id20`).

use solana_keccak_hasher as keccak;
use solana_sha256_hasher as sha256;

pub type Word = [u8; 32];
pub type Addr20 = [u8; 20];

/// `bytes32("...")` as Solidity writes a short string literal: the bytes, right-padded with zeros.
pub const fn tag(text: &[u8]) -> Word {
    assert!(text.len() <= 32);
    let mut w = [0u8; 32];
    let mut i = 0;
    while i < text.len() {
        w[i] = text[i];
        i += 1;
    }
    w
}

pub const ROUTE_TAG: Word = tag(b"BLOCH-USDT-ROUTE-v1");
pub const DEPOSIT_TAG: Word = tag(b"BLOCH-USDT-DEPOSIT-v2");
pub const RELEASE_TAG: Word = tag(b"BLOCH-USDT-RELEASE-v2");
pub const RELEASE_AUTH_TAG: Word = tag(b"BLOCH-USDT-RELEASE-AUTH-v2");
pub const CONTROLS_TAG: Word = tag(b"BLOCH-USDT-CONTROLS-v1");
pub const UNPAUSE_TAG: Word = tag(b"BLOCH-USDT-UNPAUSE-v1");
pub const MINT_CHAIN_TAG: Word = tag(b"BLOCH-USDT-MINT-CHAIN-v1");
/// Solana only: a guardian authorizes its pause with its secp256k1 key instead of sending the transaction.
pub const GUARDIAN_PAUSE_TAG: Word = tag(b"BLOCH-SVM-GUARDIAN-PAUSE-v1");

/// Domain tags of the 20-byte identities (`id20`).
pub const ID_VAULT: &[u8] = b"BLOCH-SVM-VAULT-ID-v1";
pub const ID_MINT: &[u8] = b"BLOCH-SVM-MINT-ID-v1";
pub const ID_ACCOUNT: &[u8] = b"BLOCH-SVM-ACCOUNT-ID-v1";
pub const CONFIG_TAG: &[u8] = b"BLOCH-SVM-VAULT-CONFIG-v1";

/// "\x19Ethereum Signed Message:\n32": what `cast wallet sign` (EIP-191) puts before a 32-byte hash.
pub const EIP191_PREFIX: [u8; 28] = *b"\x19Ethereum Signed Message:\n32";
/// The message a secp256k1 instruction must carry: the prefix and the 32-byte authorization.
pub const SIGNED_MESSAGE_LEN: usize = 60;

pub fn word_u64(v: u64) -> Word {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&v.to_be_bytes());
    w
}

pub fn word_bool(v: bool) -> Word {
    word_u64(v as u64)
}

pub fn word_addr(a: &Addr20) -> Word {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(a);
    w
}

pub fn keccak_words(words: &[&[u8]]) -> Word {
    keccak::hashv(words).to_bytes()
}

pub fn sha256_words(words: &[&[u8]]) -> Word {
    sha256::hashv(words).to_bytes()
}

/// The 20-byte identity of a Solana value in EVM-shaped messages: the last 20 bytes of
/// keccak256(domain || part0 || part1 ...). The Ethereum address rule applied to a tagged preimage.
pub fn id20(domain: &[u8], parts: &[&[u8]]) -> Addr20 {
    let mut h = keccak::Hasher::default();
    h.hash(domain);
    for p in parts {
        h.hash(p);
    }
    let full = h.result().to_bytes();
    let mut out = [0u8; 20];
    out.copy_from_slice(&full[12..]);
    out
}

/// `ProvenanceSourceVault.routeId()` with `token` = id20 of the mint and `address(this)` = id20 of the vault.
pub fn route_id(source_domain: &Word, native_domain: &Word, native_asset: &Word, mint20: &Addr20, vault20: &Addr20, cap: u64) -> Word {
    sha256_words(&[
        &ROUTE_TAG,
        source_domain,
        native_domain,
        native_asset,
        &word_addr(mint20),
        &word_addr(vault20),
        &word_u64(6),
        &word_u64(cap),
    ])
}

/// `ProvenanceSourceVault.mintChainGenesis()`; `BridgedStablecoinV3` starts its `mintHead` from the same value.
pub fn mint_chain_genesis(chain_id: &Word, vault20: &Addr20, route: &Word) -> Word {
    keccak_words(&[&MINT_CHAIN_TAG, chain_id, &word_addr(vault20), route])
}

/// `ProvenanceSourceVault.depositId(...)`: the nonce in the top 8 bytes, the low 24 bytes of the sha256 below.
pub fn deposit_id(route: &Word, nonce: u64, sender20: &Addr20, net: u64, l2_recipient: &Addr20) -> Word {
    let h = sha256_words(&[
        &DEPOSIT_TAG,
        route,
        &word_u64(nonce),
        &word_addr(sender20),
        &word_u64(net),
        &word_addr(l2_recipient),
    ]);
    let mut id = h;
    id[..8].copy_from_slice(&nonce.to_be_bytes());
    id
}

/// One step of the deposit chain: keccak256(abi.encode(head, id, uint256(net), l2Recipient)).
pub fn chain_step(head: &Word, id: &Word, net: u64, l2_recipient: &Addr20) -> Word {
    keccak_words(&[head, id, &word_u64(net), &word_addr(l2_recipient)])
}

pub struct ReleaseItem {
    pub route: Word,
    pub nonce: u64,
    pub recipient: Addr20,
    pub amount: u64,
    pub native_burn: Word,
    pub mint_count: u64,
    pub minted_total: u64,
    pub mint_head: Word,
}

pub struct ReleaseContext {
    pub valid_until: u64,
    pub source_anchor_slot: u64,
    pub source_anchor_hash: Word,
    pub native_finalized_number: u64,
    pub native_finalized_hash: Word,
}

/// `ProvenanceSourceVault.releaseId(item)`.
pub fn release_id(item: &ReleaseItem) -> Word {
    sha256_words(&[
        &RELEASE_TAG,
        &item.route,
        &word_u64(item.nonce),
        &word_addr(&item.recipient),
        &word_u64(item.amount),
        &item.native_burn,
        &word_u64(item.mint_count),
        &word_u64(item.minted_total),
        &item.mint_head,
    ])
}

/// The 32-byte authorization under `releaseDigest`: the signed digest is keccak256(EIP191_PREFIX || this).
pub fn release_authorization(chain_id: &Word, vault20: &Addr20, id: &Word, context: &ReleaseContext) -> Word {
    keccak_words(&[
        &RELEASE_AUTH_TAG,
        chain_id,
        &word_addr(vault20),
        id,
        &word_u64(context.valid_until),
        &word_u64(context.source_anchor_slot),
        &context.source_anchor_hash,
        &word_u64(context.native_finalized_number),
        &context.native_finalized_hash,
    ])
}

/// Authorization under `controlDigest`.
pub fn controls_authorization(chain_id: &Word, vault20: &Addr20, route: &Word, deposits: bool, releases: bool, nonce: u64, valid_until: u64) -> Word {
    keccak_words(&[
        &CONTROLS_TAG,
        chain_id,
        &word_addr(vault20),
        route,
        &word_bool(deposits),
        &word_bool(releases),
        &word_u64(nonce),
        &word_u64(valid_until),
    ])
}

/// Authorization under `unpauseDigest`.
pub fn unpause_authorization(chain_id: &Word, vault20: &Addr20, route: &Word, count: u64, valid_until: u64) -> Word {
    keccak_words(&[&UNPAUSE_TAG, chain_id, &word_addr(vault20), route, &word_u64(count), &word_u64(valid_until)])
}

/// Authorization of a guardian pause: bound to the pause it starts (`count` = pauseCount + 1), so it is used once.
pub fn guardian_pause_authorization(chain_id: &Word, vault20: &Addr20, route: &Word, count: u64, valid_until: u64) -> Word {
    keccak_words(&[&GUARDIAN_PAUSE_TAG, chain_id, &word_addr(vault20), route, &word_u64(count), &word_u64(valid_until)])
}

/// The EIP-191 digest of an authorization (what the keys sign; the secp256k1 program computes it from the message).
pub fn eip191_digest(authorization: &Word) -> Word {
    keccak_words(&[&EIP191_PREFIX, authorization])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tags_are_right_padded() {
        assert_eq!(&ROUTE_TAG[..19], b"BLOCH-USDT-ROUTE-v1");
        assert!(ROUTE_TAG[19..].iter().all(|b| *b == 0));
    }

    #[test]
    fn deposit_id_carries_its_nonce() {
        let id = deposit_id(&[7u8; 32], 0x0102030405060708, &[1u8; 20], 5, &[2u8; 20]);
        assert_eq!(&id[..8], &[1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn keccak_is_ethereum_keccak() {
        // keccak256("") = c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
        assert_eq!(keccak_words(&[])[..4], [0xc5, 0xd2, 0x46, 0x01]);
    }
}
