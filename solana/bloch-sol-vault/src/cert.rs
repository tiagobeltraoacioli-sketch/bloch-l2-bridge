//! Committee certificates: a threshold of secp256k1 signatures, verified by the native secp256k1 program in the
//! instruction placed immediately before ours, and bound to our instruction here.
//!
//! The native program only proves "these signatures recover to these addresses over these bytes, wherever the
//! offsets point". Everything that makes that proof OURS is checked below:
//!
//! 1. Our instruction runs at the top level of the transaction (not through a CPI), so "the instruction before the
//!    current one" is a statement about our own position.
//! 2. The instructions sysvar is the real one (`load_*_checked` compare its address).
//! 3. The previous instruction's program id is the native secp256k1 program and it takes no accounts.
//! 4. Its data has exactly one canonical layout for `n` signatures (below), with no spare byte, so every byte the
//!    native program verified is a byte we read:
//!
//!    ```text
//!    [0]                      n
//!    [1 .. 1+11n]             n offset structures
//!    [1+11n .. 1+96n]         n entries of: signature (64) | recovery id (1) | Ethereum address (20)
//!    [1+96n .. 1+96n+60]      the message: "\x19Ethereum Signed Message:\n32" | authorization (32)
//!    ```
//!
//! 5. Every offset structure points into that same instruction (all three instruction indexes equal its index)
//!    at exactly the canonical positions, with message size 60: the native program cannot have verified bytes that
//!    live in another instruction or at another offset.
//! 6. The message is the prefix followed by the authorization this program computed from its own state and from
//!    this instruction's arguments.
//! 7. The addresses are members of the set, strictly ascending (so distinct), and at least `required` of them.

use crate::abi::{Addr20, Word, EIP191_PREFIX, SIGNED_MESSAGE_LEN};
use crate::error::VaultError;
use solana_program::{
    account_info::AccountInfo,
    instruction::{get_stack_height, TRANSACTION_LEVEL_STACK_HEIGHT},
    program_error::ProgramError,
    pubkey::Pubkey,
    sysvar::instructions::{load_current_index_checked, load_instruction_at_checked},
};

pub const SECP256K1_PROGRAM_ID: Pubkey = solana_program::pubkey!("KeccakSecp256k11111111111111111111111111111");

const OFFSETS_LEN: usize = 11;
const ENTRY_LEN: usize = 64 + 1 + 20;

/// The data length of the canonical secp256k1 instruction for `n` signatures.
pub const fn canonical_len(n: usize) -> usize {
    1 + (OFFSETS_LEN + ENTRY_LEN) * n + SIGNED_MESSAGE_LEN
}

fn le16(b: &[u8]) -> usize {
    u16::from_le_bytes([b[0], b[1]]) as usize
}

/// Checks the certificate and returns a bit per member of `set` that signed.
pub fn check_certificate(
    instructions_sysvar: &AccountInfo,
    authorization: &Word,
    set: &[Addr20],
    required: usize,
) -> Result<u32, ProgramError> {
    if get_stack_height() != TRANSACTION_LEVEL_STACK_HEIGHT {
        return Err(VaultError::NotTopLevel.into());
    }
    let current = load_current_index_checked(instructions_sysvar)? as usize;
    if current == 0 || current - 1 > u8::MAX as usize {
        return Err(VaultError::InvalidCertificate.into());
    }
    let secp_index = current - 1;
    let ix = load_instruction_at_checked(secp_index, instructions_sysvar)?;
    if ix.program_id != SECP256K1_PROGRAM_ID || !ix.accounts.is_empty() {
        return Err(VaultError::InvalidCertificate.into());
    }
    check_secp_data(&ix.data, secp_index as u8, authorization, set, required)
}

/// The pure part of the check, on the bytes of the secp256k1 instruction at index `secp_index`.
pub fn check_secp_data(
    data: &[u8],
    secp_index: u8,
    authorization: &Word,
    set: &[Addr20],
    required: usize,
) -> Result<u32, ProgramError> {
    let bad = || ProgramError::from(VaultError::InvalidCertificate);
    if data.is_empty() || required == 0 || set.len() > 32 {
        return Err(bad());
    }
    let n = data[0] as usize;
    if n < required || n > set.len() || data.len() != canonical_len(n) {
        return Err(bad());
    }
    let entries_at = 1 + OFFSETS_LEN * n;
    let message_at = 1 + (OFFSETS_LEN + ENTRY_LEN) * n;
    let message = &data[message_at..];
    if message[..EIP191_PREFIX.len()] != EIP191_PREFIX || message[EIP191_PREFIX.len()..] != authorization[..] {
        return Err(bad());
    }
    let mut signed: u32 = 0;
    let mut previous = [0u8; 20];
    for i in 0..n {
        let o = &data[1 + OFFSETS_LEN * i..1 + OFFSETS_LEN * (i + 1)];
        let entry_at = entries_at + ENTRY_LEN * i;
        // signature_offset u16, signature_instruction_index u8, eth_address_offset u16,
        // eth_address_instruction_index u8, message_data_offset u16, message_data_size u16,
        // message_instruction_index u8
        if le16(&o[0..2]) != entry_at
            || o[2] != secp_index
            || le16(&o[3..5]) != entry_at + 65
            || o[5] != secp_index
            || le16(&o[6..8]) != message_at
            || le16(&o[8..10]) != SIGNED_MESSAGE_LEN
            || o[10] != secp_index
        {
            return Err(bad());
        }
        let address: Addr20 = data[entry_at + 65..entry_at + 85].try_into().unwrap();
        if address <= previous {
            return Err(bad());
        }
        previous = address;
        match set.iter().position(|member| *member == address) {
            Some(index) => signed |= 1 << index,
            None => return Err(bad()),
        }
    }
    Ok(signed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build(n: usize, index: u8, addresses: &[Addr20], authorization: &Word) -> Vec<u8> {
        let mut d = vec![0u8; canonical_len(n)];
        d[0] = n as u8;
        let entries_at = 1 + 11 * n;
        let message_at = 1 + 96 * n;
        for i in 0..n {
            let o = 1 + 11 * i;
            let e = entries_at + 85 * i;
            d[o..o + 2].copy_from_slice(&(e as u16).to_le_bytes());
            d[o + 2] = index;
            d[o + 3..o + 5].copy_from_slice(&((e + 65) as u16).to_le_bytes());
            d[o + 5] = index;
            d[o + 6..o + 8].copy_from_slice(&(message_at as u16).to_le_bytes());
            d[o + 8..o + 10].copy_from_slice(&60u16.to_le_bytes());
            d[o + 10] = index;
            d[e + 65..e + 85].copy_from_slice(&addresses[i]);
        }
        d[message_at..message_at + 28].copy_from_slice(&EIP191_PREFIX);
        d[message_at + 28..].copy_from_slice(authorization);
        d
    }

    fn set() -> Vec<Addr20> {
        (1u8..=7).map(|i| [i; 20]).collect()
    }

    #[test]
    fn accepts_the_canonical_layout() {
        let auth = [9u8; 32];
        let d = build(5, 3, &set()[..5], &auth);
        assert_eq!(check_secp_data(&d, 3, &auth, &set(), 5).unwrap(), 0b11111);
    }

    #[test]
    fn refuses_every_single_byte_change_of_the_structure() {
        let auth = [9u8; 32];
        let good = build(5, 3, &set()[..5], &auth);
        let entries_at = 1 + 11 * 5;
        for at in 0..good.len() {
            // Signature and recovery-id bytes are the native program's business: it has already verified them.
            let in_entries = at >= entries_at && at < 1 + 96 * 5;
            if in_entries && (at - entries_at) % 85 < 65 {
                continue;
            }
            let mut d = good.clone();
            d[at] ^= 1;
            assert!(check_secp_data(&d, 3, &auth, &set(), 5).is_err(), "byte {at} is not bound");
        }
    }

    #[test]
    fn refuses_other_instruction_indexes_lengths_orders_and_counts() {
        let auth = [9u8; 32];
        let s = set();
        let d = build(5, 3, &s[..5], &auth);
        assert!(check_secp_data(&d, 2, &auth, &s, 5).is_err());
        assert!(check_secp_data(&d, 3, &[8u8; 32], &s, 5).is_err());
        assert!(check_secp_data(&d, 3, &auth, &s, 6).is_err());
        let mut longer = d.clone();
        longer.push(0);
        assert!(check_secp_data(&longer, 3, &auth, &s, 5).is_err());
        assert!(check_secp_data(&d[..d.len() - 1], 3, &auth, &s, 5).is_err());
        let swapped = [s[1], s[0], s[2], s[3], s[4]];
        assert!(check_secp_data(&build(5, 3, &swapped, &auth), 3, &auth, &s, 5).is_err());
        let repeated = [s[0], s[0], s[2], s[3], s[4]];
        assert!(check_secp_data(&build(5, 3, &repeated, &auth), 3, &auth, &s, 5).is_err());
        let stranger = [s[0], s[1], s[2], s[3], [0xee; 20]];
        assert!(check_secp_data(&build(5, 3, &stranger, &auth), 3, &auth, &s, 5).is_err());
        assert!(check_secp_data(&build(4, 3, &s[..4], &auth), 3, &auth, &s, 5).is_err());
        assert!(check_secp_data(&[0u8], 3, &auth, &s, 5).is_err());
        assert!(check_secp_data(&[], 3, &auth, &s, 5).is_err());
    }
}
