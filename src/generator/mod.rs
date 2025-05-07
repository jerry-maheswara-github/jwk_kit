/// # Generating and parsing ECDSA (Elliptic Curve Digital Signature Algorithm) keys
///
/// This module provides functions for generating and parsing ECDSA (Elliptic Curve Digital Signature Algorithm) keys,
/// specifically for the ES256 curve (P-256). It supports key pair generation, as well as serializing and parsing keys
/// in various formats, including JWK (JSON Web Key) format.
///
/// ## Key functionalities:
/// - Generate ES256 (P-256) ECDSA key pairs.
/// - Parse and extract key parameters from ECDSA keys (e.g., curve parameters, private and public keys).
/// - Convert ECDSA keys to JWK format for integration with JWT-based applications.
pub mod ecdsa;

/// # Generating and parsing RSA key pairs
///
/// This module provides functions for generating and parsing RSA key pairs, specifically supporting key sizes of 2048 and 4096 bits.
/// It includes functionality for serializing and parsing keys in PEM (PKCS#8) format and converting them to JWK format for use in JWT-based applications.
///
/// ## Key functionalities:
/// - Generate RSA key pairs (supports 2048 and 4096 bits).
/// - Parse RSA keys, extracting key components such as modulus (n) and exponent (e).
/// - Convert RSA keys to JWK format for use in signing and verification operations.
/// - Export RSA keys in PEM format (PKCS#8).
pub mod rsa;
