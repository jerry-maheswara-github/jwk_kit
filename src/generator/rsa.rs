use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rsa::rand_core::OsRng;
use rsa::{
    pkcs8::{EncodePrivateKey, EncodePublicKey},
    RsaPrivateKey, RsaPublicKey,
};
use rsa::pkcs8::DecodePublicKey;
use rsa::traits::PublicKeyParts;
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

/// # extract_rsa_n_e
///
/// Extracts the RSA modulus (`n`) and exponent (`e`) from an RSA key in JWK format.
/// This function assumes the key is an RSA key and retrieves the necessary components
/// for signing or verification operations.
///
/// ## Parameters:
/// - `pem_data`: The `pem_data` object representing the RSA key.
///
/// ## Returns:
/// - `Result<(String, String), JwkError>`: A tuple containing the modulus (`n`) and exponent (`e`).
///   Returns an error if the JWK is not valid or does not contain the required components.
pub fn extract_rsa_n_e(pem_data: &str) -> Result<(String, String), JwkError> {
    let public_key = RsaPublicKey::from_public_key_pem(&pem_data)
        .map_err(|_| JwkError::MissingRsaParams)?;

    let n = public_key.n().to_bytes_be();
    let e = public_key.e().to_bytes_be();

    if n.is_empty() || e.is_empty() {
        return Err(JwkError::MissingRsaParams);
    }

    let n_b64 = URL_SAFE_NO_PAD.encode(n);
    let e_b64 = URL_SAFE_NO_PAD.encode(e);

    Ok((n_b64, e_b64))
}