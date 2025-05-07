use crate::error::JwkError;
use serde::{Deserialize, Serialize};

/// # Jwk
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

/// # Jwks
///
/// A struct representing a JSON Web Key Set (JWKS). A JWKS is a collection of `Jwk` objects,
/// allowing for the management and exchange of multiple keys in a single document.
///
/// ## Key fields:
/// - `keys`: A vector containing multiple `Jwk` objects. Each object represents an individual key
///   within the key set.
#[derive(Debug, Serialize, Deserialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

/// # JwkBuilder
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
    /// Creates a new builder instance for a `Jwk` with the specified key type.
    ///
    /// ## Parameters:
    /// - `kty`: The type of key (e.g., "RSA", "EC").
    ///
    /// ## Returns:
    /// - `JwkBuilder`: A new instance of `JwkBuilder`.
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

    /// Sets the `use` field (key use) for the JWK.
    pub fn use_(mut self, value: &str) -> Self {
        self.use_ = Some(value.to_string());
        self
    }

    /// Sets the `alg` field (algorithm) for the JWK.
    pub fn alg(mut self, value: &str) -> Self {
        self.alg = Some(value.to_string());
        self
    }

    /// Sets the `kid` field (key ID) for the JWK.
    pub fn kid(mut self, value: &str) -> Self {
        self.kid = Some(value.to_string());
        self
    }

    /// Sets the `n` field (RSA modulus) for the JWK.
    pub fn n(mut self, value: &str) -> Self {
        self.n = Some(value.to_string());
        self
    }

    /// Sets the `e` field (RSA exponent) for the JWK.
    pub fn e(mut self, value: &str) -> Self {
        self.e = Some(value.to_string());
        self
    }

    /// Sets the `crv` field (curve type) for EC keys.
    pub fn crv(mut self, value: &str) -> Self {
        self.crv = Some(value.to_string());
        self
    }

    /// Sets the `x` field (EC x-coordinate) for the JWK.
    pub fn x(mut self, value: &str) -> Self {
        self.x = Some(value.to_string());
        self
    }

    /// Sets the `y` field (EC y-coordinate) for the JWK.
    pub fn y(mut self, value: &str) -> Self {
        self.y = Some(value.to_string());
        self
    }

    /// Sets the `d` field (private key) for the JWK.
    pub fn d(mut self, value: &str) -> Self {
        self.d = Some(value.to_string());
        self
    }

    /// Builds and returns the `Jwk` struct.
    /// This function checks if all required parameters are provided based on the key type.
    pub fn build(self) -> Result<Jwk, JwkError> {
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
            kty: self.kty,
            use_: self.use_,
            alg: self.alg,
            kid: self.kid,
            n: self.n,
            e: self.e,
            crv: self.crv,
            x: self.x,
            y: self.y,
            d: self.d,
        })
    }
}



/// # create_jwks
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
