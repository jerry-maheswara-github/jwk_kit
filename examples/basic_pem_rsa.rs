use jwk_kit::error::JwkError;
use jwk_kit::cryptography::rsa::generate_rsa_keypair_pem;
use std::fs::write;

fn main() -> Result<(), JwkError> {
    let (private_pem, public_pem) = generate_rsa_keypair_pem(2048)?;

    write("./examples/rsa/rsa-access-private.pem", &private_pem)
        .map_err(|_| JwkError::PemWriteError)?;
    println!("Private key saved to rsa-access-private.pem:\n{}", private_pem);

    write("./examples/rsa/rsa-access-public.pem", &public_pem)
        .map_err(|_| JwkError::PemWriteError)?;
    println!("Public key saved to rsa-access-public.pem:\n{}", public_pem);

    Ok(())
}
