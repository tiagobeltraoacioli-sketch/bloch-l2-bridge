//! TEST ONLY. Two behaviours, chosen by the first data byte:
//! - 0xC1: relay. Accounts: the target program, then the target's accounts. Calls the target by CPI with the
//!   rest of the data and the given accounts (the same signer and writable flags).
//! - anything else: succeeds and does nothing (a program that accepts any bytes, e.g. bytes shaped like a
//!   secp256k1 instruction).
use solana_program::{
    account_info::AccountInfo,
    entrypoint::ProgramResult,
    instruction::{AccountMeta, Instruction},
    program::invoke,
    program_error::ProgramError,
    pubkey::Pubkey,
};

solana_program::entrypoint!(process_instruction);

pub fn process_instruction(_program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    if data.first() != Some(&0xC1) {
        return Ok(());
    }
    let (target, rest) = accounts.split_first().ok_or(ProgramError::NotEnoughAccountKeys)?;
    let metas = rest
        .iter()
        .map(|a| AccountMeta { pubkey: *a.key, is_signer: a.is_signer, is_writable: a.is_writable })
        .collect();
    invoke(&Instruction { program_id: *target.key, accounts: metas, data: data[1..].to_vec() }, accounts)
}
