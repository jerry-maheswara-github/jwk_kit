#[cfg(test)]
mod tests {
    use jwk_kit::jwk::JwkBuilder;
    use jwk_kit::error::JwkError; // ⬅ pastikan import error enum-nya

    #[test]
    fn test_valid_ec_jwk() {
        let jwk = JwkBuilder::new("EC")
            .use_("sig")
            .alg("ES256")
            .kid("ecdsa-key-1")
            .crv("P-256")
            .x("x_base64")
            .y("y_base64")
            .build()
            .expect("Should build valid EC JWK");

        assert_eq!(jwk.kty, "EC");
        assert_eq!(jwk.crv.unwrap(), "P-256");
    }

    #[test]
    fn test_invalid_ec_missing_coords() {
        let err = JwkBuilder::new("EC")
            .crv("P-256")
            .x("x_value")
            .build()
            .expect_err("Missing 'y' should cause error");

        assert_eq!(err, JwkError::MissingEcParams);
    }
}
