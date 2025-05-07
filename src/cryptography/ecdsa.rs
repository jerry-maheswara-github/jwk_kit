use crate::error::JwkError;
use p256::ecdsa::SigningKey;
use p256::elliptic_curve::rand_core::OsRng;
use p256::pkcs8::{EncodePrivateKey, EncodePublicKey};

/// Generate a new ECDSA (ES256) keypair in PKCS#8 PEM format.
///
/// Returns a tuple of `(private_pem, public_pem)`
pub fn generate_es256_keypair_pem() -> Result<(String, String), JwkError> {
    let signing_key = SigningKey::random(&mut OsRng);

    let private_pem = signing_key
        .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
        .map(|pem| pem.to_string())
        .map_err(|_| JwkError::KeyGenerationFailed)?;

    let verify_key = signing_key.verifying_key();

    let public_pem = verify_key
        .to_public_key_pem(p256::pkcs8::LineEnding::LF)
        .map(|pem| pem.to_string())
        .map_err(|_| JwkError::KeyGenerationFailed)?;

    Ok((private_pem, public_pem))
}
