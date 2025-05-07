use std::fs;
use jwk_kit::generator::ecdsa::extract_es256_coordinates;
use jwk_kit::generator::rsa::extract_rsa_n_e;
use jwk_kit::jwk::{create_jwks, JwkBuilder};
use jwk_kit::error::JwkError;

fn main() -> Result<(), JwkError> {
    // --- EC KEY ---
    let ec_path = "./examples/ecdsa/ecdsa-rsa-access-public.pem";
    let ec_pem_data = fs::read_to_string(ec_path).map_err(|_| JwkError::MissingEcParams)?;

    let (x, y) = extract_es256_coordinates(&ec_pem_data)?;
    let ec_jwk = JwkBuilder::new("EC")
        .set_key_use("sig")
        .set_algorithm("ES256")
        .set_key_id("ecdsa-key-1")
        .set_curve_type("P-256")
        .set_x_coordinate(&x)
        .set_y_coordinate(&y)
        .build()?;

    // --- RSA KEY ---
    let rsa_path = "./examples/rsa/rsa-access-public.pem";
    let rsa_pem_data = fs::read_to_string(rsa_path).map_err(|_| JwkError::MissingRsaParams)?;

    let (n_b64, e_b64) = extract_rsa_n_e(&rsa_pem_data)?;
    let rsa_jwk = JwkBuilder::new("RSA")
        .set_key_use("sig")
        .set_algorithm("RS256")
        .set_key_id("rsa-key-1")
        .set_modulus(&n_b64)
        .set_exponent(&e_b64)
        .build()?;

    // --- Combine into JWKS ---
    let jwks = create_jwks(vec![ec_jwk, rsa_jwk]);

    let jwks_json = serde_json::to_string_pretty(&jwks)
        .map_err(|_| JwkError::UnsupportedKeyType("serialization failed".into()))?;

    println!("JWKS:\n{}", jwks_json);

    Ok(())
}
