use crate::error::JwkError;
use serde::{Deserialize, Serialize};

/// # Representing a JSON Web Key (JWK)
///
/// A struct representing a JSON Web Key (JWK). The `Jwk` struct holds the various components
/// of a cryptographic key in a format that can be easily serialized into a JWK.
///
/// ## Key fields:
/// - `kty` (Key Type): The type of the key (e.g., RSA, EC).
/// - `alg` (Algorithm): The algorithm used with the key (e.g., RS256, ES256).
/// - `use` (Key Use): The intended use of the key, such as "sig" for signing or "enc" for encryption.
/// - `kid` (Key ID): An identifier for the key, useful for key rotation and lookup.
/// - `n`, `e` (RSA-specific): The RSA modulus and exponent components, if the key type is RSA.
/// - `x`, `y` (ECDSA-specific): The elliptic curve coordinates, if the key type is EC (P-256 for ES256).
/// - `d` (Private key): The private key component, typically used for signing.
#[derive(Debug, Serialize, Deserialize)]
pub struct Jwk {
    pub kty: String,

    #[serde(rename = "use", skip_serializing_if = "Option::is_none")]
    pub use_: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub n: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub e: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub d: Option<String>,
}

/// Represents a JSON Web Key Set (JWKS).
///
/// The `Jwks` struct is a container for multiple `Jwk` objects, following the structure
/// defined in [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517). It is commonly
/// used to publish a set of public keys (e.g., in a JWKS endpoint `http://www.your-domain.com/.well-known/jwks.json`) for use in verifying
/// JSON Web Tokens (JWTs) and other cryptographic operations.
///
/// This struct can be serialized to and deserialized from JSON using Serde, making it easy
/// to expose or consume JWKS-compliant key sets in web applications.
#[derive(Debug, Serialize, Deserialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

/// # A builder for constructing a JSON Web Key (JWK).
///
/// A builder struct to facilitate the creation of a `Jwk`. The builder pattern is used
/// to construct a `Jwk` with various optional parameters that can be set during the process.
///
/// ## Key functionalities:
/// - Provides a fluent interface for setting each field in a `Jwk`.
/// - Allows setting the key type (`kty`), algorithm (`alg`), key use (`use_`), key ID (`kid`), and key-specific values
///   for both RSA and ECDSA keys.
/// - Ensures that a complete and valid JWK is created.
pub struct JwkBuilder {
    kty: String,
    use_: Option<String>,
    alg: Option<String>,
    kid: Option<String>,
    n: Option<String>,
    e: Option<String>,
    crv: Option<String>,
    x: Option<String>,
    y: Option<String>,
    d: Option<String>,
}

impl JwkBuilder {
    pub fn new(kty: &str) -> Self {
        Self {
            kty: kty.to_string(),
            use_: None,
            alg: None,
            kid: None,
            n: None,
            e: None,
            crv: None,
            x: None,
            y: None,
            d: None,
        }
    }

    pub fn set_key_use(&mut self, value: &str) -> &mut Self {
        self.use_ = Some(value.to_string());
        self
    }

    pub fn set_algorithm(&mut self, value: &str) -> &mut Self {
        self.alg = Some(value.to_string());
        self
    }

    pub fn set_key_id(&mut self, value: &str) -> &mut Self {
        self.kid = Some(value.to_string());
        self
    }

    pub fn set_modulus(&mut self, value: &str) -> &mut Self {
        self.n = Some(value.to_string());
        self
    }

    pub fn set_exponent(&mut self, value: &str) -> &mut Self {
        self.e = Some(value.to_string());
        self
    }

    pub fn set_curve_type(&mut self, value: &str) -> &mut Self {
        self.crv = Some(value.to_string());
        self
    }

    pub fn set_x_coordinate(&mut self, value: &str) -> &mut Self {
        self.x = Some(value.to_string());
        self
    }

    pub fn set_y_coordinate(&mut self, value: &str) -> &mut Self {
        self.y = Some(value.to_string());
        self
    }

    pub fn set_private_key(&mut self, value: &str) -> &mut Self {
        self.d = Some(value.to_string());
        self
    }

    // Update build method to take a reference to `self`
    pub fn build(&self) -> Result<Jwk, JwkError> {
        match self.kty.as_str() {
            "RSA" => {
                if self.n.is_none() || self.e.is_none() {
                    return Err(JwkError::MissingRsaParams);
                }
            }
            "EC" => {
                if self.crv.is_none() || self.x.is_none() || self.y.is_none() {
                    return Err(JwkError::MissingEcParams);
                }
            }
            _ => return Err(JwkError::UnsupportedKeyType(self.kty.clone())),
        }

        Ok(Jwk {
            kty: self.kty.clone(),
            use_: self.use_.clone(),
            alg: self.alg.clone(),
            kid: self.kid.clone(),
            n: self.n.clone(),
            e: self.e.clone(),
            crv: self.crv.clone(),
            x: self.x.clone(),
            y: self.y.clone(),
            d: self.d.clone(),
        })
    }
}

/// # Creates a JSON Web Key Set (JWKS) from a collection of individual JWKs.
///
/// Creates a new `Jwks` (JSON Web Key Set) from a list of `Jwk` objects. This function
/// aggregates individual keys into a set that can be serialized and shared in JWKS format.
///
/// ## Parameters:
/// - `keys`: A vector of `Jwk` objects to be included in the key set.
///
/// ## Returns:
/// - `Jwks`: A `Jwks` struct containing the provided keys.
pub fn create_jwks(keys: Vec<Jwk>) -> Jwks {
    Jwks { keys }
}
