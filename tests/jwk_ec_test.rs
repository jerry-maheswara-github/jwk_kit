#[cfg(test)]
mod tests {
    use jwk_kit::jwk::JwkBuilder;
    use jwk_kit::error::JwkError; // ⬅ pastikan import error enum-nya

    #[test]
    fn test_valid_ec_jwk() {
        let jwk = JwkBuilder::new("EC")
            .set_key_use("sig")
            .set_algorithm("ES256")
            .set_key_id("ecdsa-key-1")
            .set_curve_type("P-256")
            .set_x_coordinate("x_base64")
            .set_y_coordinate("y_base64")
            .build()
            .expect("Should build valid EC JWK");

        assert_eq!(jwk.kty, "EC");
        assert_eq!(jwk.crv.unwrap(), "P-256");
    }

    #[test]
    fn test_invalid_ec_missing_coords() {
        let err = JwkBuilder::new("EC")
            .set_curve_type("P-256")
            .set_x_coordinate("x_value")
            .build()
            .expect_err("Missing 'y' should cause error");

        assert_eq!(err, JwkError::MissingEcParams);
    }
}
