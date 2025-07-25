#[cfg(test)]
mod tests {
    use jwk_kit::jwk::JwkBuilder;
    use jwk_kit::error::JwkError;

    #[test]
    fn test_build_valid_rsa_jwk() {
        let jwk = JwkBuilder::new("RSA")
            .set_modulus("some-modulus")
            .set_exponent("some-exponent")
            .set_algorithm("RS256")
            .set_key_id("key-id")
            .build();

        assert!(jwk.is_ok());

        let jwk = jwk.unwrap();
        assert_eq!(jwk.kty, "RSA");
        assert_eq!(jwk.alg.as_deref(), Some("RS256"));
        assert_eq!(jwk.n.as_deref(), Some("some-modulus"));
        assert_eq!(jwk.e.as_deref(), Some("some-exponent"));
    }

    #[test]
    fn test_build_rsa_missing_params() {
        let result = JwkBuilder::new("RSA")
            .set_exponent("some-exponent")
            .build();

        assert!(matches!(result, Err(JwkError::MissingRsaParams)));
    }

    #[test]
    fn test_build_valid_ec_jwk() {
        let jwk = JwkBuilder::new("EC")
            .set_curve_type("P-256")
            .set_x_coordinate("x-coordinate")
            .set_y_coordinate("y-coordinate")
            .set_algorithm("ES256")
            .build();

        assert!(jwk.is_ok());

        let jwk = jwk.unwrap();
        assert_eq!(jwk.kty, "EC");
        assert_eq!(jwk.crv.as_deref(), Some("P-256"));
        assert_eq!(jwk.x.as_deref(), Some("x-coordinate"));
        assert_eq!(jwk.y.as_deref(), Some("y-coordinate"));
    }

    #[test]
    fn test_build_ec_missing_params() {
        let result = JwkBuilder::new("EC")
            .set_x_coordinate("x-coordinate")
            .set_y_coordinate("y-coordinate")
            .build();

        assert!(matches!(result, Err(JwkError::MissingEcParams)));
    }

    #[test]
    fn test_build_unsupported_key_type() {
        let result = JwkBuilder::new("OCT")
            .build();

        match result {
            Err(JwkError::UnsupportedKeyType(kty)) => assert_eq!(kty, "OCT"),
            _ => panic!("Expected UnsupportedKeyType error with 'OCT'"),
        }

    }
}
