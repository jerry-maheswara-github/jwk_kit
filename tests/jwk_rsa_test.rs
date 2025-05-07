#[cfg(test)]
mod tests {
    use jwk_kit::jwk::JwkBuilder;
    use jwk_kit::error::JwkError;

    #[test]
    fn test_valid_rsa_jwk() {
        let jwk = JwkBuilder::new("RSA")
            .set_key_use("sig")
            .set_algorithm("RS256")
            .set_key_id("rsa-key-1")
            .set_modulus("rsa_modulus_base64")
            .set_exponent("AQAB")
            .build()
            .expect("Should build valid RSA JWK");

        assert_eq!(jwk.kty, "RSA");
        assert_eq!(jwk.n.unwrap(), "rsa_modulus_base64");
    }

    #[test]
    fn test_invalid_rsa_missing_e() {
        let err = JwkBuilder::new("RSA")
            .set_modulus("modulus_only")
            .build()
            .expect_err("Missing 'e' should cause error");

        assert_eq!(err, JwkError::MissingRsaParams);
    }
}
