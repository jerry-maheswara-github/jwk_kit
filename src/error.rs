
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum JwkError {
    #[error("Missing required RSA parameters: 'n' (modulus) and/or 'e' (exponent)")]
    MissingRsaParams,

    #[error("Missing required EC parameters: 'crv' (curve), 'x', and/or 'y' (coordinates)")]
    MissingEcParams,

    #[error("Missing EC coordinate 'x' (public key X component is required)")]
    MissingEcX,

    #[error("Missing EC coordinate 'y' (public key Y component is required)")]
    MissingEcY,

    #[error("Unsupported key type: {0}. Only 'RSA' and 'EC' are supported")]
    UnsupportedKeyType(String),

    #[error("RSA key generation failed (internal error or RNG failure)")]
    KeyGenerationFailed,

    #[error("Failed to read PEM data from file or input")]
    PemReadError,
    
    #[error("Failed to write PEM data to file")]
    PemWriteError,

    #[error("Failed to parse RSA public key from PEM")]
    RsaParseError,

    #[error("Failed to parse EC public key from PEM")]
    EcParseError,

    #[error("Failed to encode data as base64url")]
    Base64EncodingError,

    #[error("Invalid or unsupported curve type: {0}")]
    UnsupportedCurve(String),

}