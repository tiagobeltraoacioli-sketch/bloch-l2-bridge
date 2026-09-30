//! Read-only bounded transaction/receipt inclusion, not finality authentication.
use bloch_l2_bridge::{
    ethereum_deployment_inclusion::{verify_request, MAX_REQUEST_BYTES},
    hex,
};
use sha2::{Digest, Sha256};
use std::io::{self, Read};

fn main() {
    // Never echo untrusted proof nodes through a dependency's panic hook.
    std::panic::set_hook(Box::new(|_| {}));
    let mut request = Vec::new();
    if std::env::args_os().len() != 1
        || io::stdin()
            .take(MAX_REQUEST_BYTES as u64 + 1)
            .read_to_end(&mut request)
            .is_err()
        || verify_request(&request).is_err()
    {
        eprintln!("Ethereum deployment inclusion refused");
        std::process::exit(1);
    }
    println!("{}", hex::encode(&Sha256::digest(&request)));
}
