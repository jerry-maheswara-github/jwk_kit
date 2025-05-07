use std::fs;
use jwk_kit::error::JwkError;
use jwk_kit::jwk::{create_jwks, extract_es256_coordinates, extract_rsa_n_e, JwkBuilder};

fn main() -> Result<(), JwkError> {
    // --- EC KEY ---
    let ec_path = "./examples/ecdsa/ecdsa-rsa-access-public.pem";
    let ec_pem_data = fs::read_to_string(ec_path).map_err(|_| JwkError::MissingEcParams)?;

    let (x, y) = extract_es256_coordinates(&ec_pem_data)?;
    let ec_jwk = JwkBuilder::new("EC")
        .use_("sig")
        .alg("ES256")
        .kid("ecdsa-key-1")
        .crv("P-256")
        .x(&x)
        .y(&y)
        .build()?;

    // --- RSA KEY ---
    let rsa_path = "./examples/rsa/rsa-access-public.pem";
    let rsa_pem_data = fs::read_to_string(rsa_path).map_err(|_| JwkError::MissingRsaParams)?;

    let (n_b64, e_b64) = extract_rsa_n_e(&rsa_pem_data)?;
    let rsa_jwk = JwkBuilder::new("RSA")
        .use_("sig")
        .alg("RS256")
        .kid("rsa-key-1")
        .n(&n_b64)
        .e(&e_b64)
        .build()?;

    // --- Combine into JWKS ---
    let jwks = create_jwks(vec![ec_jwk, rsa_jwk]);

    let jwks_json = serde_json::to_string_pretty(&jwks)
        .map_err(|_| JwkError::UnsupportedKeyType("serialization failed".into()))?;

    println!("JWKS:\n{}", jwks_json);

    Ok(())
}
