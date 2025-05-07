use jwk_kit::generator::rsa::generate_rsa_keypair_pem;
use jwk_kit::generator::ecdsa::generate_es256_keypair_pem;

#[test]
fn test_generate_rsa_keypair_pem() {
    let (private_pem, public_pem) = generate_rsa_keypair_pem(2048)
        .expect("RSA keypair generation should succeed");

    assert!(private_pem.contains("BEGIN PRIVATE KEY"));
    assert!(public_pem.contains("BEGIN PUBLIC KEY"));
    assert!(!private_pem.is_empty());
    assert!(!public_pem.is_empty());
}

#[test]
fn test_generate_es256_keypair_pem() {
    let (private_pem, public_pem) = generate_es256_keypair_pem()
        .expect("ES256 keypair generation should succeed");

    assert!(private_pem.contains("BEGIN PRIVATE KEY"));
    assert!(public_pem.contains("BEGIN PUBLIC KEY"));
    assert!(!private_pem.is_empty());
    assert!(!public_pem.is_empty());
}
