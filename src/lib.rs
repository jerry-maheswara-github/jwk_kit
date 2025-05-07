//! # 🔐 jwk-kit
//!
//! **A modern, lightweight, and developer-friendly Rust library for managing JSON Web Keys (JWKs).**
//!
//! `jwk-kit` simplifies working with JSON Web Keys (JWK) in Rust by offering a clean, efficient API for key generation, serialization, and conversion.  
//! 
//! Ideal for developers building secure APIs, implementing OAuth2, JWT, or other web-based authentication mechanisms.
//!
//! Whether you're managing a JWKS endpoint or handling tokens in your auth layer, `jwk-kit` helps you stay compliant, secure, and productive.
//! 
//! ---
//!
//! ## ✨ Features
//!
//! - Generate RSA key pairs (2048/4096 bits)
//! - Generate ES256 (P-256) key pairs
//! - Easy key generation and conversion to standard-compliant JWK format.
//! - Base64URL-safe encoding (no padding)
//! - Export keys in PEM (PKCS#8) format
//! - Built with ergonomics in mind—minimal boilerplate, maximum clarity.
//! - Fully compliant with [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517)
//!
//! ---
//!
//! ## 🔧 Installation
//!
//! Add this to your `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! jwk-kit = "0.1.0"
//! ```
//! 
//! ---
//! 
//! ## 🚀 Usage Example
//!
//! ```rust
//! use jwk_kit::generator::rsa::{extract_rsa_n_e, generate_rsa_keypair_pem};
//! use jwk_kit::generator::ecdsa::{extract_es256_coordinates, generate_es256_keypair_pem};
//! use jwk_kit::jwk::{create_jwks, JwkBuilder};
//! use jwk_kit::error::JwkError;
//! 
//! fn main() -> Result<(), JwkError> {
//!     let (private_pem, public_pem) = generate_rsa_keypair_pem(2048)?;
//!     println!("RSA Private Key:\n{}", private_pem);
//!     println!("RSA Public Key:\n{}", public_pem);
//! 
//!     let (n_b64, e_b64) = extract_rsa_n_e(&public_pem)?;
//!     let rsa_jwk = JwkBuilder::new("RSA")
//!         .use_("sig")
//!         .alg("RS256")
//!         .kid("rsa-key-1")
//!         .n(&n_b64)
//!         .e(&e_b64)
//!         .build()?;
//! 
//!     let (private_pem, public_pem) = generate_es256_keypair_pem()?;
//!     println!("ECDSA Private Key:\n{}", private_pem);
//!     println!("ECDSA Public Key:\n{}", public_pem);
//!     
//!     let (x, y) = extract_es256_coordinates(&public_pem)?;
//!     let ec_jwk = JwkBuilder::new("EC")
//!         .use_("sig")
//!         .alg("ES256")
//!         .kid("ecdsa-key-1")
//!         .crv("P-256")
//!         .x(&x)
//!         .y(&y)
//!         .build()?;
//! 
//!     let jwks = create_jwks(vec![rsa_jwk, ec_jwk]);
//! 
//!     let jwks_json = serde_json::to_string_pretty(&jwks)
//!         .map_err(|_| JwkError::UnsupportedKeyType("serialization failed".into()))?;
//! 
//!     println!("JWKS:\n{}", jwks_json);
//! 
//!     Ok(())
//! }
//! ```
//!
//! ---
//!
//! ## 📜 License
//! 
//! This project is licensed under the Apache 2.0 License. See the [LICENSE](https://www.apache.org/licenses/LICENSE-2.0.txt) for details.
//!
//! ---
//!
//! ## 📚 Related Specifications
//!
//! - [RFC 7517 - JSON Web Key (JWK)](https://datatracker.ietf.org/doc/html/rfc7517)
//! - [RFC 7518 - JSON Web Algorithms (JWA)](https://datatracker.ietf.org/doc/html/rfc7518)
//!
//! ---
//!
//! ## 🧑‍💻 Author
//!
//! Created and maintained by [Jerry Maheswara](https://github.com/jerry-maheswara-github).  
//! Feel free to reach out for suggestions, issues, or improvements!
//!
//! ---
//!
//! ## ❤️ Built with Love in Rust
//!
//! This project is built with ❤️ using **Rust** — a systems programming language that is safe, fast, and concurrent. Rust is the perfect choice for building reliable and efficient applications.
//!
//! ---
//!
//! ## 👋 Contributing
//!
//! Pull requests, issues, and feedback are welcome!  
//! If you find this crate useful, give it a ⭐ and share it with others in the Rust community.
//!
//! ---
//! 

/// # jwk
///
/// This module contains helpers for serializing and deserializing JSON Web Keys (JWK) and
/// JSON Web Key Sets (JWKS). It provides functions to convert cryptographic keys to the JWK format
/// and handle the serialization for use in applications that require JWKs.
///
/// ## Key functionalities:
/// - Convert RSA and ECDSA (ES256) keys to JWK format.
/// - Serialize and deserialize JWKS (JSON Web Key Sets).
pub mod jwk;

/// # error
///
/// This module defines the error handling for the `jwk_kit` crate. It contains the `JwkError` enum,
/// which is used across the crate to provide detailed error messages for various cryptographic and
/// JWK-related operations.
///
/// ## Key functionalities:
/// - Handle errors related to JWK generation, parsing, and conversion.
/// - Provide error types for invalid key formats, invalid operations, etc.
pub mod error;

/// # generator
///
/// This module is responsible for key generation and parsing for various cryptographic algorithms,
/// including RSA and ECDSA (ES256). It provides the core functions for generating key pairs, parsing
/// keys, and converting them to PEM format or JWK format.
///
/// ## Key functionalities:
/// - RSA keypair generation and parsing (supports 2048/4096-bit RSA).
/// - ECDSA keypair generation and parsing (supports P-256 for ES256).
/// - Functions for exporting keys to PEM (PKCS#8) format.
pub mod generator;
