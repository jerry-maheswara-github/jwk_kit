use jwk_kit::error::JwkError;
use jwk_kit::generator::ecdsa::generate_es256_keypair_pem;
use std::fs::write;

fn main() -> Result<(), JwkError> {
    let (private_pem, public_pem) = generate_es256_keypair_pem()?;

    write("./examples/ecdsa/ecdsa-access-private.pem", &private_pem)
        .map_err(|_| JwkError::PemWriteError)?;
    println!("Private key saved to ecdsa-access-private.pem:\n{}", private_pem);

    write("./examples/ecdsa/ecdsa-access-public.pem", &public_pem)
        .map_err(|_| JwkError::PemWriteError)?;
    println!("Public key saved to ecdsa-access-public.pem:\n{}", public_pem);

    Ok(())
}
