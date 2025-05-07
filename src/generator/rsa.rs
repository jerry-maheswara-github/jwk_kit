use base64::{
    Engine,
    engine::general_purpose::URL_SAFE_NO_PAD
};
use crate::error::JwkError;
use rsa::{
    pkcs8::DecodePublicKey,
    rand_core::OsRng,
    traits::PublicKeyParts,
    pkcs8::{EncodePrivateKey, EncodePublicKey},
    RsaPrivateKey, RsaPublicKey,
};

/// Generates a new RSA key pair with the specified key size and returns it in PEM format.
///
/// This function creates a fresh RSA key pair of the given bit length (e.g., 2048 or 4096 bits),
/// and returns both the private and public keys as PEM-encoded strings.
/// These keys can then be used for JWT signing, TLS, or converted into JWK format.
///
/// # Parameters
/// - `bits`: The desired size of the RSA key in bits. Common values are 2048 or 4096.
///
/// # Returns
/// A `Result` containing a tuple of `(private_key_pem, public_key_pem)` as `String`s on success,
/// or a `JwkError` on failure. The keys are returned in PEM format and are ready to be stored,
/// used directly, or converted into a JWK.
///
/// # Errors
/// Returns a `JwkError` if:
/// - Key generation fails.
/// - The keys cannot be serialized to PEM format.
///
/// # Example
/// ```rust
/// use jwk_kit::generator::rsa::generate_rsa_keypair_pem;
/// match generate_rsa_keypair_pem(2048) {
///     Ok((private_pem, public_pem)) => {
///         println!("Private Key:\n{}", private_pem);
///         println!("Public Key:\n{}", public_pem);
///     },
///     Err(e) => {
///         eprintln!("RSA key generation failed: {:?}", e);
///     },
/// }
/// ```
///
/// # Note
/// To convert the generated public key to a JWK, you can use [`extract_rsa_n_e`].
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

/// Extracts the modulus (N) and exponent (E) from a PEM-encoded RSA key.
///
/// This function takes a PEM-encoded RSA key (either public or private) and extracts
/// the modulus (N) and exponent (E), which are essential components of an RSA public key
/// as part of the JWK (JSON Web Key) representation.
///
/// # Parameters
/// - `pem_data`: A string slice containing the PEM-encoded RSA key (can be either public or private key).
///
/// # Returns
/// A `Result` containing a tuple with the modulus (`N`) and exponent (`E`) as `String`s in case of success,
/// or a `JwkError` in case of failure. The modulus and exponent are returned as base64url-encoded strings,
/// which is the standard format for JWKs.
///
/// # Errors
/// This function returns a `JwkError` if:
/// - The input PEM data is not a valid RSA key.
/// - The key does not contain valid RSA modulus and exponent values.
/// - Any other error occurs while extracting the modulus and exponent.
///
/// # Example
/// ```rust
/// use jwk_kit::generator::rsa::extract_rsa_n_e;
/// let pem_data = "-----BEGIN PUBLIC KEY-----\n...";  // PEM-encoded RSA public key
/// match extract_rsa_n_e(pem_data) {
///     Ok((n, e)) => {
///         println!("Modulus (N): {}, Exponent (E): {}", n, e);
///     },
///     Err(e) => {
///         eprintln!("Failed to extract N and E: {:?}", e);
///     },
/// }
/// ```
///
/// # Note
/// This function is useful for extracting the public key components for RSA keys,
/// particularly when generating a JWK for use in web-based authentication systems (e.g., JWT, OAuth).
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