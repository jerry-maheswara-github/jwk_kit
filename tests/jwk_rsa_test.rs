#[cfg(test)]
mod tests {
    use jwk_kit::jwk::JwkBuilder;
    use jwk_kit::error::JwkError;

    #[test]
    fn test_valid_rsa_jwk() {
        let jwk = JwkBuilder::new("RSA")
            .use_("sig")
            .alg("RS256")
            .kid("rsa-key-1")
            .n("rsa_modulus_base64")
            .e("AQAB")
            .build()
            .expect("Should build valid RSA JWK");

        assert_eq!(jwk.kty, "RSA");
        assert_eq!(jwk.n.unwrap(), "rsa_modulus_base64");
    }

    #[test]
    fn test_invalid_rsa_missing_e() {
        let err = JwkBuilder::new("RSA")
            .n("modulus_only")
            .build()
            .expect_err("Missing 'e' should cause error");

        assert_eq!(err, JwkError::MissingRsaParams);
    }
}
