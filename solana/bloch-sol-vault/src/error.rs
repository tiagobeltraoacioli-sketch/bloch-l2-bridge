use solana_program::program_error::ProgramError;

/// Custom error codes (`ProgramError::Custom(code)`); the numbers are part of the interface the tools read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum VaultError {
    InvalidConfiguration = 100,
    InvalidAccount = 101,
    InvalidTransfer = 102,
    InvalidRelease = 103,
    InvalidCertificate = 104,
    InvalidControls = 105,
    InsufficientBacking = 106,
    InvalidContext = 107,
    RateLimited = 108,
    NotGuardian = 109,
    InvalidPause = 110,
    Paused = 111,
    ProvenanceMismatch = 112,
    NotApproved = 113,
    NotReady = 114,
    AlreadyReleased = 115,
    Voided = 116,
    NotTopLevel = 117,
    ProgramUpgradeable = 118,
    WrongRecipient = 119,
    Expired = 120,
}

impl From<VaultError> for ProgramError {
    fn from(e: VaultError) -> Self {
        ProgramError::Custom(e as u32)
    }
}
