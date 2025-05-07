use crate::error::JwkError;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use p256::{elliptic_curve::sec1::ToEncodedPoint, pkcs8::DecodePublicKey, PublicKey};
use rsa::{traits::PublicKeyParts, RsaPublicKey};
use serde::{Deserialize, Serialize};

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

#[derive(Debug, Serialize, Deserialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

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

    pub fn use_(mut self, value: &str) -> Self {
        self.use_ = Some(value.to_string());
        self
    }

    pub fn alg(mut self, value: &str) -> Self {
        self.alg = Some(value.to_string());
        self
    }

    pub fn kid(mut self, value: &str) -> Self {
        self.kid = Some(value.to_string());
        self
    }

    pub fn n(mut self, value: &str) -> Self {
        self.n = Some(value.to_string());
        self
    }

    pub fn e(mut self, value: &str) -> Self {
        self.e = Some(value.to_string());
        self
    }

    pub fn crv(mut self, value: &str) -> Self {
        self.crv = Some(value.to_string());
        self
    }

    pub fn x(mut self, value: &str) -> Self {
        self.x = Some(value.to_string());
        self
    }

    pub fn y(mut self, value: &str) -> Self {
        self.y = Some(value.to_string());
        self
    }

    pub fn d(mut self, value: &str) -> Self {
        self.d = Some(value.to_string());
        self
    }

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

pub fn extract_es256_coordinates(pem_data: &str) -> Result<(String, String), JwkError> {
    let public_key = PublicKey::from_public_key_pem(&pem_data)
        .map_err(|_| JwkError::MissingEcParams)?;

    let encoded_point = public_key.to_encoded_point(false);
    let x = encoded_point.x().ok_or(JwkError::MissingEcX)?;
    let y = encoded_point.y().ok_or(JwkError::MissingEcY)?;

    let x_b64 = URL_SAFE_NO_PAD.encode(x);
    let y_b64 = URL_SAFE_NO_PAD.encode(y);

    Ok((x_b64, y_b64))
}

pub fn extract_rsa_n_e(pem_data: &str) -> Result<(String, String), JwkError> {
    let public_key = RsaPublicKey::from_public_key_pem(&pem_data)
        .map_err(|_| JwkError::MissingRsaParams)?;

    let n = public_key.n().to_bytes_be();
    let e = public_key.e().to_bytes_be();

    if n.is_empty() || e.is_empty() {
        return Err(JwkError::MissingRsaParams);
    }

    let n_b64 = URL_SAFE_NO_PAD.encode(n);
    let e_b64 = URL_SAFE_NO_PAD.encode(e);

    Ok((n_b64, e_b64))
}

pub fn create_jwks(keys: Vec<Jwk>) -> Jwks {
    Jwks { keys }
}

