//! Exact-package verifier for a separately reviewed bridge readiness request.
//!
//! The accepted request commitment is compiled into the executable. An unset,
//! malformed, or placeholder commitment makes the binary unusable. This keeps
//! the generic repository build fail-closed and prevents this verifier from
//! becoming a digest echo or accepting a package selected at runtime.

use sha2::{Digest, Sha256};
use std::{
    fmt::Write as _,
    io::{self, Read},
};

const REQUEST_DOMAIN: &[u8] = b"BLOCH-BRIDGE-ACTIVATION-READINESS-v2\0";
const MAX_REQUEST_BYTES: u64 = 128 * 1024;
const EXPECTED_COMMITMENT: Option<&str> = option_env!("BLOCH_BRIDGE_READINESS_COMMITMENT_SHA256");

fn commitment(value: Option<&str>) -> Result<[u8; 32], String> {
    let value = value.ok_or("readiness commitment was not embedded at build time")?;
    let value = value
        .strip_prefix("0x")
        .ok_or("readiness commitment lacks 0x prefix")?;
    if value.len() != 64
        || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
        || value.bytes().any(|byte| byte.is_ascii_uppercase())
    {
        return Err("readiness commitment must be a lowercase SHA-256 digest".into());
    }
    let mut result = [0; 32];
    for (index, slot) in result.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| "invalid readiness commitment")?;
    }
    if !result.iter().any(|byte| *byte != 0) || result.windows(2).all(|pair| pair[0] == pair[1]) {
        return Err("placeholder readiness commitment refused".into());
    }
    Ok(result)
}

fn verify_request(request: &[u8], expected: Option<&str>) -> Result<[u8; 32], String> {
    if request.len() > MAX_REQUEST_BYTES as usize || !request.starts_with(REQUEST_DOMAIN) {
        return Err("invalid readiness request framing".into());
    }
    let bundle: serde_json::Value = serde_json::from_slice(&request[REQUEST_DOMAIN.len()..])
        .map_err(|_| "invalid readiness bundle")?;
    if bundle
        .as_object()
        .and_then(|object| object.get("schema"))
        .and_then(serde_json::Value::as_str)
        != Some("postern.bridge-activation-readiness.v2")
    {
        return Err("unsupported readiness bundle".into());
    }
    let actual: [u8; 32] = Sha256::digest(request).into();
    if actual != commitment(expected)? {
        return Err("readiness request commitment mismatch".into());
    }
    Ok(actual)
}

fn lowercase_hex(value: &[u8]) -> String {
    let mut encoded = String::with_capacity(value.len() * 2);
    for byte in value {
        write!(&mut encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    encoded
}

fn run() -> Result<(), String> {
    if std::env::args_os().len() != 1 {
        return Err("readiness verifier accepts no runtime configuration".into());
    }
    let mut request = Vec::new();
    io::stdin()
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut request)
        .map_err(|error| error.to_string())?;
    let digest = verify_request(&request, EXPECTED_COMMITMENT)?;
    println!("{}", lowercase_hex(&digest));
    Ok(())
}

fn main() {
    if run().is_err() {
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> Vec<u8> {
        [
            REQUEST_DOMAIN,
            br#"{"schema":"postern.bridge-activation-readiness.v2"}"#,
        ]
        .concat()
    }

    fn digest(value: &[u8]) -> String {
        format!("0x{:x}", Sha256::digest(value))
    }

    #[test]
    fn only_the_embedded_exact_request_is_accepted() {
        let request = request();
        let expected = digest(&request);
        assert_eq!(
            verify_request(&request, Some(&expected)).unwrap(),
            <[u8; 32]>::from(Sha256::digest(&request))
        );

        let mut substituted = request;
        substituted.push(b' ');
        assert!(verify_request(&substituted, Some(&expected)).is_err());
    }

    #[test]
    fn unset_malformed_and_placeholder_commitments_fail_closed() {
        let request = request();
        for expected in [
            None,
            Some("00"),
            Some("0x00"),
            Some("0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            Some("0x1111111111111111111111111111111111111111111111111111111111111111"),
        ] {
            assert!(verify_request(&request, expected).is_err());
        }
    }

    #[test]
    fn framing_and_size_are_enforced_before_acceptance() {
        let wrong_domain = b"BLOCH-BRIDGE-ACTIVATION-READINESS-v1\0{}";
        assert!(verify_request(wrong_domain, Some(&digest(wrong_domain))).is_err());

        let oversized = vec![b'x'; MAX_REQUEST_BYTES as usize + 1];
        assert!(verify_request(&oversized, Some(&digest(&oversized))).is_err());

        let wrong_schema = [REQUEST_DOMAIN, br#"{"schema":"other"}"#].concat();
        assert!(verify_request(&wrong_schema, Some(&digest(&wrong_schema))).is_err());
    }
}
