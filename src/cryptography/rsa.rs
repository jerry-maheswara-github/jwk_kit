use rsa::rand_core::OsRng;
use rsa::{
    pkcs8::{EncodePrivateKey, EncodePublicKey},
    RsaPrivateKey, RsaPublicKey,
};
use crate::error::JwkError;

/// Generate a new RSA keypair in PKCS#8 PEM format.
///
/// Returns a tuple of `(private_pem, public_pem)`
pub fn generate_rsa_keypair_pem(bits: usize) -> Result<(String, String), JwkError> {
    let mut rng = OsRng;

    let private_key = RsaPrivateKey::new(&mut rng, bits)
        .map_err(|_| JwkError::KeyGenerationFailed)?;

    let public_key: RsaPublicKey = private_key.to_public_key();

    let private_pem = private_key
        .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
        .map(|pem| pem.to_string())
        .map_err(|_| JwkError::KeyGenerationFailed)?;

    let public_pem = public_key
        .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
        .map_err(|_| JwkError::KeyGenerationFailed)?;

    Ok((private_pem, public_pem))
}
