#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;
    use jwk_kit::error::JwkError;
    use jwk_kit::generator::ecdsa::extract_es256_coordinates;
    use jwk_kit::generator::rsa::extract_rsa_n_e;

    #[test]
    fn test_extract_es256_coordinates_success() {
        let path = "./examples/ecdsa/ecdsa-access-public.pem";
        assert!(Path::new(path).exists(), "Missing test key file: {}", path);

        let pem_data = fs::read_to_string(path).expect("Failed to read EC PEM file");
        let result = extract_es256_coordinates(&pem_data);
        assert!(result.is_ok(), "Expected Ok, got {:?}", result);

        let (x, y) = result.unwrap();
        assert!(!x.is_empty(), "x should not be empty");
        assert!(!y.is_empty(), "y should not be empty");
    }

    #[test]
    fn test_extract_es256_coordinates_fail() {
        let path = "./examples/ecdsa/ecdsa-invalid.pem";
        assert!(Path::new(path).exists(), "Missing test key file: {}", path);

        let pem_data = fs::read_to_string(path).expect("Failed to read invalid EC PEM");
        let result = extract_es256_coordinates(&pem_data);
        assert_eq!(result.unwrap_err(), JwkError::MissingEcParams);
    }

    #[test]
    fn test_extract_rsa_n_e_success() {
        let path = "./examples/rsa/rsa-access-public.pem";
        assert!(Path::new(path).exists(), "Missing test key file: {}", path);

        let pem_data = fs::read_to_string(path).expect("Failed to read RSA PEM file");
        let result = extract_rsa_n_e(&pem_data);
        assert!(result.is_ok(), "Expected Ok, got {:?}", result);

        let (n, e) = result.unwrap();
        assert!(!n.is_empty(), "modulus (n) should not be empty");
        assert!(!e.is_empty(), "exponent (e) should not be empty");
    }

    #[test]
    fn test_extract_rsa_n_e_fail() {
        let path = "./examples/rsa/rsa-invalid.pem";
        assert!(Path::new(path).exists(), "Missing test key file: {}", path);

        let pem_data = fs::read_to_string(path).expect("Failed to read invalid RSA PEM");
        let result = extract_rsa_n_e(&pem_data);
        assert_eq!(result.unwrap_err(), JwkError::MissingRsaParams);
    }
}
