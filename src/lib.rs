//! # 🌐 jwk_kit
//!
//! **A lightweight, developer-friendly Rust library for handling JSON Web Keys (JWK)**  
//! 
//! jwk_kit is a lightweight, developer-friendly Rust library designed for handling JSON Web Keys (JWK). 
//! It provides a simple and efficient way to generate, manage, and serialize cryptographic keys in the JWK format, 
//! which is commonly used for securing APIs, OAuth2, JWT, and other web-based authentication protocols.
//! 
//! This library supports RSA and ECDSA (specifically ES256 with the P-256 curve) key generation and conversion to the standard JWK format. 
//! With jwk_kit, you can easily create and manage cryptographic keys, export them to PEM format, 
//! and ensure that your application is fully compliant with the JWK and JWKS standards.
//!
//! ---
//!
//! ## ✨ Features
//!
//! - ✅ Generate RSA key pairs (2048/4096 bits)
//! - ✅ Generate ES256 (P-256) key pairs
//! - ✅ Convert keys to JWK format
//! - ✅ Base64URL-safe encoding (no padding)
//! - ✅ Export keys in PEM (PKCS#8) format
//! - ✅ Fully compliant with [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517)
//!
//! ---
//!
//! ## 🔧 Installation
//!
//! Add this to your `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! jwk_kit = "0.1.0"
//! ```
//! ---
//! 
//! ## 🚀 Usage Example
//!
//! ```rust
//! use jwk_kit::generator::rsa::generate_rsa_keypair_pem;
//! use jwk_kit::jwk::extract_rsa_n_e;
//! 
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let (private_pem, public_pem) = generate_rsa_keypair_pem(2048)?;
//!     println!("Private Key:\n{}", private_pem);
//!     println!("Public Key:\n{}", public_pem);
//! 
//!     let (n, e) = extract_rsa_n_e(&public_pem)?;
//!     println!("RSA modulus (n): \n{}", n);
//!     println!("RSA exponent (e): \n{}", e);
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
//! Created by **[Jerry Maheswara]**  
//! Built with ❤️ and Rust 🦀  

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
