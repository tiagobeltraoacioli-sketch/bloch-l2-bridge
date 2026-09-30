//! Offline fixed-build vault configuration and initial storage proof verifier.
use bloch_l2_bridge::{
    ethereum_deployment_vault::{verify_request, MAX_REQUEST_BYTES},
    hex,
};
use sha2::{Digest, Sha256};
use std::io::{self, Read};

fn main() {
    std::panic::set_hook(Box::new(|_| {}));
    let mut request = Vec::new();
    if std::env::args_os().len() != 1
        || io::stdin()
            .take(MAX_REQUEST_BYTES as u64 + 1)
            .read_to_end(&mut request)
            .is_err()
        || verify_request(&request).is_err()
    {
        eprintln!("Ethereum deployment vault refused");
        std::process::exit(1);
    }
    println!("{}", hex::encode(&Sha256::digest(&request)));
}
