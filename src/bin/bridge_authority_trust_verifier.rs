//! Exact trust-anchor verifier for observation-only authority intake.

use bloch_l2_bridge::authority_trust_intake::{verify_trust_intake, TrustIntake};
use std::io::{self, Read};

const MAX_REQUEST_BYTES: u64 = 128 * 1024;

fn word(value: &str) -> Result<[u8; 32], String> {
    let value = value.strip_prefix("0x").ok_or("compiled anchor lacks 0x")?;
    if value.len() != 64
        || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
        || value.bytes().any(|byte| byte.is_ascii_uppercase())
    {
        return Err("invalid compiled trust anchor digest".into());
    }
    let mut output = [0_u8; 32];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| "invalid compiled trust anchor digest")?;
    }
    if !output.iter().any(|byte| *byte != 0) || output.windows(2).all(|pair| pair[0] == pair[1]) {
        return Err("placeholder compiled trust anchor digest".into());
    }
    Ok(output)
}

fn run() -> Result<(), String> {
    let compiled = option_env!("BLOCH_BRIDGE_AUTHORITY_TRUST_ANCHOR_SHA256")
        .ok_or("authority trust anchor was not compiled into this verifier")?;
    let expected = word(compiled)?;
    let mut input = Vec::new();
    io::stdin()
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut input)
        .map_err(|error| error.to_string())?;
    if input.is_empty() || input.len() > MAX_REQUEST_BYTES as usize {
        return Err("invalid authority trust intake size".into());
    }
    let intake: TrustIntake = serde_json::from_slice(&input).map_err(|error| error.to_string())?;
    let commitment = verify_trust_intake(&intake, &expected)?;
    println!(
        "0x{}",
        commitment
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    Ok(())
}

fn main() {
    if run().is_err() {
        std::process::exit(1);
    }
}
