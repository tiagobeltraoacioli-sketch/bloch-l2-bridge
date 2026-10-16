//! Minimal bounded verifier for one public Ed25519 signature.

use ring::signature::{UnparsedPublicKey, ED25519};
use std::{
    env,
    io::{self, Read},
};

const MAX_MESSAGE_BYTES: u64 = 128 * 1024;

fn bytes<const N: usize>(value: &str) -> Result<[u8; N], ()> {
    let value = value.strip_prefix("0x").ok_or(())?;
    if value.len() != N * 2
        || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
        || value.bytes().any(|byte| byte.is_ascii_uppercase())
    {
        return Err(());
    }
    let mut output = [0_u8; N];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).map_err(|_| ())?;
    }
    if !output.iter().any(|byte| *byte != 0) || output.windows(2).all(|pair| pair[0] == pair[1]) {
        return Err(());
    }
    Ok(output)
}

fn run() -> Result<(), ()> {
    let arguments: Vec<_> = env::args().skip(1).collect();
    if arguments.len() != 2 {
        return Err(());
    }
    let public_key = bytes::<32>(&arguments[0])?;
    let signature = bytes::<64>(&arguments[1])?;
    let mut message = Vec::new();
    io::stdin()
        .take(MAX_MESSAGE_BYTES + 1)
        .read_to_end(&mut message)
        .map_err(|_| ())?;
    if message.is_empty() || message.len() > MAX_MESSAGE_BYTES as usize {
        return Err(());
    }
    UnparsedPublicKey::new(&ED25519, public_key)
        .verify(&message, &signature)
        .map_err(|_| ())
}

fn main() {
    if run().is_err() {
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_inputs_are_strict_canonical_and_non_placeholder() {
        assert_eq!(bytes::<2>("0x01fe"), Ok([1, 254]));
        for invalid in ["01fe", "0x01FE", "0x0000", "0x1111", "0x01"] {
            assert!(bytes::<2>(invalid).is_err());
        }
    }
}
