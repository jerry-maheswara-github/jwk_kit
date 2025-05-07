use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use crate::error::JwkError;
use p256::ecdsa::SigningKey;
use p256::elliptic_curve::rand_core::OsRng;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::pkcs8::{DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use p256::PublicKey;

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


/// # extract_es256_coordinates
///
/// Extracts the elliptic curve coordinates (`x` and `y`) from an EC (Elliptic Curve) key
/// in JWK format, specifically for the ES256 algorithm (P-256 curve).
/// This function assumes the key is an EC key and retrieves the necessary components
/// for further processing.
///
/// ## Parameters:
/// - `pem_data`: The `pem_data` object representing the EC key.
///
/// ## Returns:
/// - `Result<(String, String), JwkError>`: A tuple containing the `x` and `y` coordinates.
///   Returns an error if the JWK is not valid or does not contain the required components.
pub fn extract_es256_coordinates(pem_data: &str) -> Result<(String, String), JwkError> {
    let public_key = PublicKey::from_public_key_pem(&pem_data)
        .map_err(|_| JwkError::MissingEcParams)?;

    let encoded_point = public_key.to_encoded_point(false);
    let x = encoded_point.x().ok_or(JwkError::MissingEcX)?;
    let y = encoded_point.y().ok_or(JwkError::MissingEcY)?;

    let x_b64 = URL_SAFE_NO_PAD.encode(x);
    let y_b64 = URL_SAFE_NO_PAD.encode(y);

    Ok((x_b64, y_b64))
}
