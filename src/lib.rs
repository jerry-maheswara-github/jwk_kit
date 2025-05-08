//! # 🔐 A Rust Library for JSON Web Keys (JWK)
//!
//! ## 📚 Overview
//!
//! `jwk_kit` is a lightweight and modern Rust library for working with JSON Web Keys (JWK).
//! It makes it easy to generate, manage, and serialize cryptographic keys in the JWK format.
//!
//! Designed with developers in mind, it offers a clean API and serves as a convenient
//! alternative to the `openssl` command-line tool, enabling direct integration into Rust apps.
//!
//! Whether you're managing a JWKS endpoint or handling tokens in your auth system,
//! `jwk_kit` helps you stay secure, standards-compliant, and efficient.

//! ---
//!
//! ## 🆚 Why Use `jwk_kit` Over `openssl` CLI?
//!
//! `openssl` is powerful but often needs external calls or manual steps.
//! In contrast, `jwk_kit` offers a native Rust API to automate and embed
//! key generation and JWK conversion directly into your application.
//!
//! ### 📌 Example:
//!
//! Instead of using the `openssl` CLI commands to generate RSA keys:
//!
//! ```bash
//! openssl genpkey -algorithm RSA -out access-private.pem -pkeyopt rsa_keygen_bits:2048
//! openssl rsa -pubout -in access-private.pem -out access-public.pem
//!
//! openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ec-access-private.pem
//! openssl ec -in ec-access-private.pem -pubout -out ec-access-public.pem
//! ```
//!
//! With `jwk_kit`, you can generate and manage keys entirely within your Rust app—no need for shell commands.
//! Unlike CLI-based solutions that require external tools to convert keys to JWK,
//! `jwk_kit` handles generation, management, and conversion natively,
//! streamlining your workflow and removing external dependencies.
//! 
//! ---
//! 
//! ## ✨ Features
//!
//! - **Native Rust API** — No need for external shell commands or subprocess management.
//! - **Key Generation and Management** — Easily generate RSA (2048/4096 bits) and ES256 (P-256) key pairs, and convert them into JWK format.
//! - **Base64URL-safe encoding** (no padding) and export keys in PEM (PKCS#8) format.
//! - **Web Standards Integration** — Ideal for use with JSON Web Tokens (JWT), OAuth2, and OpenID Connect.
//! - **Testing and Dynamic Key Rotation** — Useful for key management in secure applications, including key rotation for compliance.
//! - **Lightweight and Ergonomic** — Minimal dependencies, built with ergonomics in mind, and simple to use in your Rust projects.
//! - **Compliant with RFC 7517** — Fully compliant with the [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517) specification for JSON Web Keys (JWK).
//!
//! ---
//!
//! ## 🔧 Installation
//!
//! Add this to your `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! jwk_kit = "0.1.1"
//! ```
//! 
//! ---
//! 
//! ## 🚀 Quick Start
//! 
//! ```rust
//! use jwk_kit::generator::rsa::{extract_rsa_n_e, generate_rsa_keypair_pem};
//! use jwk_kit::generator::ecdsa::{extract_es256_coordinates, generate_es256_keypair_pem};
//! use jwk_kit::jwk::{create_jwks, JwkBuilder};
//! use jwk_kit::error::JwkError;
//! use std::fs::{write, File};
//!
//! fn main() -> Result<(), JwkError> {
//!     // Generate an RSA key pair (private and public keys) with a 2048-bit modulus
//!     let (private_pem, public_pem) = generate_rsa_keypair_pem(2048)?;
//!     println!("RSA Private Key:\n{}", private_pem);
//!     println!("RSA Public Key:\n{}", public_pem);
//!
//!     // Save the RSA private key to a file named rsa-access-private.pem
//!     write("./examples/rsa/rsa-access-private.pem", &private_pem)
//!         .map_err(|_| JwkError::PemWriteError)?;
//!     println!("Private key saved to rsa-access-private.pem:\n{}", private_pem);
//!
//!     // Save the RSA public key to a file named rsa-access-public.pem
//!     write("./examples/rsa/rsa-access-public.pem", &public_pem)
//!         .map_err(|_| JwkError::PemWriteError)?;
//!     println!("Public key saved to rsa-access-public.pem:\n{}", public_pem);
//!
//!     // Extract the RSA modulus (n) and exponent (e) from the public key in PEM format
//!     let (n_b64, e_b64) = extract_rsa_n_e(&public_pem)?;
//!
//!     // Build a JWK (JSON Web Key) for the RSA key using the modulus and exponent
//!     let rsa_jwk = JwkBuilder::new("RSA")
//!         .set_key_use("sig") 
//!         .set_algorithm("RS256") 
//!         .set_key_id("rsa-key-1") 
//!         .set_modulus(&n_b64) 
//!         .set_exponent(&e_b64) 
//!         .build()?;
//!
//!     // ----------------------------------
//!     // Generate an ECDSA key pair (private and public keys) for ES256 (P-256 curve)
//!     let (private_pem, public_pem) = generate_es256_keypair_pem()?;
//!     println!("ECDSA Private Key:\n{}", private_pem);
//!     println!("ECDSA Public Key:\n{}", public_pem);
//!     
//!     // Save the ECDSA private key to a file named ecdsa-access-private.pem
//!     write("./examples/ecdsa/ecdsa-access-private.pem", &private_pem)
//!         .map_err(|_| JwkError::PemWriteError)?;
//!     println!("Private key saved to ecdsa-access-private.pem:\n{}", private_pem);
//! 
//!     // Save the ECDSA public key to a file named ecdsa-access-public.pem
//!     write("./examples/ecdsa/ecdsa-access-public.pem", &public_pem)
//!         .map_err(|_| JwkError::PemWriteError)?;
//!     println!("Public key saved to ecdsa-access-public.pem:\n{}", public_pem);
//! 
//!     // Extract the EC curve coordinates (x, y) from the public key in PEM format
//!     let (x, y) = extract_es256_coordinates(&public_pem)?;
//!
//!     // Build a JWK for the ECDSA key using the curve type (P-256) and coordinates (x, y)
//!     let ec_jwk = JwkBuilder::new("EC")
//!         .set_key_use("sig") 
//!         .set_algorithm("ES256") 
//!         .set_key_id("ecdsa-key-1") 
//!         .set_curve_type("P-256")  
//!         .set_x_coordinate(&x) 
//!         .set_y_coordinate(&y) 
//!         .build()?;
//! 
//!     // ----------------------------------
//!     // Create a JSON Web Key Set (JWKS) containing both the RSA and ECDSA keys
//!     let jwks = create_jwks(vec![rsa_jwk, ec_jwk]);
//!
//!     // Serialize the JWKS to a JSON string
//!     let jwks_json = serde_json::to_string_pretty(&jwks)
//!         .map_err(|_| JwkError::UnsupportedKeyType("serialization failed".into()))?;
//!
//!     // Print the JWKS (with RSA and ECDSA keys) in a readable format,
//!     // or write it to `jwks.json` using `std::fs::write`.
//!     println!("jwks.json \n{}", jwks_json);
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
//!
//! ## 🧑‍💻 Author
//!
//! Created and maintained by [Jerry Maheswara](https://github.com/jerry-maheswara-github)
//!
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
//! ## 🌍 Specification Compliance
//!
//! `jwk_kit` is designed to be fully compliant with the following IETF specifications:
//!
//! - [RFC 7517 - JSON Web Key (JWK)](https://datatracker.ietf.org/doc/html/rfc7517):
//!   Defines a JSON-based data structure for representing cryptographic keys, including both public and private key information.
//!
//! - [RFC 7518 - JSON Web Algorithms (JWA)](https://datatracker.ietf.org/doc/html/rfc7518):
//!   Specifies cryptographic algorithms and identifiers for use with JWKs, JWTs, and related technologies.
//!
//! These specifications ensure interoperability across different languages, platforms, and identity systems.
//! The key generation, encoding, and serialization behaviors of `jwk_kit` are aligned with the structures and field requirements outlined in these RFCs.
//!
//! For deeper integration or troubleshooting, reviewing these documents can be highly beneficial.
//!
//! ---

/// # Contains helpers for serializing and deserializing
///
/// This module contains helpers for serializing and deserializing JSON Web Keys (JWK) and
/// JSON Web Key Sets (JWKS). It provides functions to convert cryptographic keys to the JWK format
/// and handle the serialization for use in applications that require JWKs.
///
/// ## Key functionalities:
/// - Convert RSA and ECDSA (ES256) keys to JWK format.
/// - Serialize and deserialize JWKS (JSON Web Key Sets).
pub mod jwk;

/// # Defines the error handling
///
/// This module defines the error handling for the `jwk_kit` crate. It contains the `JwkError` enum,
/// which is used across the crate to provide detailed error messages for various cryptographic and
/// JWK-related operations.
///
/// ## Key functionalities:
/// - Handle errors related to JWK generation, parsing, and conversion.
/// - Provide error types for invalid key formats, invalid operations, etc.
pub mod error;

/// # Responsible for key generation
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
