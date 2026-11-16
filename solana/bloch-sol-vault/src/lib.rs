//! Bloch bridge vault on Solana (`bUSDC.sol`). UNAUDITED. Not for deployment.
//!
//! The Solana port of `ProvenanceSourceVault` (contracts/usdt/ProvenanceSourceVault.sol) in its launch
//! configuration (provenance mode 1, committee mode): a program-owned classic SPL token account holds the
//! deposits; a release is paid only on a threshold of the committee's secp256k1 signatures over the same digest
//! the Ethereum vault uses; limits, signers, guardians, fees and the fee recipient are fixed at initialization;
//! guardians can only pause. The program has no owner, no setter and no instruction that changes a limit, and it
//! refuses to initialize a vault while the program itself is upgradeable.
//!
//! Specification, every difference from the Ethereum vault and the reasons: docs/SOLANA-VAULT.md.

pub mod abi;
pub mod cert;
pub mod error;
pub mod processor;
pub mod state;

#[cfg(not(feature = "no-entrypoint"))]
solana_program::entrypoint!(process_instruction);

pub fn process_instruction(
    program_id: &solana_program::pubkey::Pubkey,
    accounts: &[solana_program::account_info::AccountInfo],
    data: &[u8],
) -> solana_program::entrypoint::ProgramResult {
    processor::process(program_id, accounts, data)
}
