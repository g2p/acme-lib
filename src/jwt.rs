use serde::{Deserialize, Serialize};

use crate::acc::AcmeKey;

#[derive(Debug, Serialize, Deserialize, Default)]
pub(crate) struct JwsProtectedExtra {
    url: String,
    nonce: String,
}

pub(crate) struct JwsProtected(pub(crate) biscuit::jws::Header<JwsProtectedExtra>);

impl JwsProtected {
    pub(crate) fn new_jwk(
        jwk: biscuit::jwk::JWK<biscuit::Empty>,
        url: &str,
        nonce: String,
    ) -> Self {
        let private = JwsProtectedExtra {
            url: url.into(),
            nonce,
        };
        let registered = biscuit::jws::RegisteredHeader {
            algorithm: biscuit::jwa::SignatureAlgorithm::ES256,
            web_key: Some(serde_json::to_string(&jwk).unwrap()),
            media_type: None,
            ..Default::default()
        };
        Self(biscuit::jws::Header {
            registered,
            private,
        })
    }
    pub(crate) fn new_kid(kid: &str, url: &str, nonce: String) -> Self {
        let private = JwsProtectedExtra {
            url: url.into(),
            nonce,
        };
        let registered = biscuit::jws::RegisteredHeader {
            algorithm: biscuit::jwa::SignatureAlgorithm::ES256,
            key_id: Some(kid.into()),
            media_type: None,
            ..Default::default()
        };
        Self(biscuit::jws::Header {
            registered,
            private,
        })
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub(crate) struct Jwk {
    alg: String,
    crv: String,
    kty: String,
    #[serde(rename = "use")]
    _use: String,
    x: String,
    y: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
// LEXICAL ORDER OF FIELDS MATTER!
pub(crate) struct JwkThumb {
    crv: String,
    kty: String,
    x: String,
    y: String,
}

impl From<&AcmeKey> for biscuit::jwk::JWK<biscuit::Empty> {
    fn from(a: &AcmeKey) -> Self {
        //let mut ctx = openssl::bn::BigNumContext::new().expect("BigNumContext");
        // TODO: build x and y (pub coords) from pkcs8, possibly through d (the priv coord)
        let p8 = a.to_pkcs8();
        let template = include_bytes!("ecPublicKey_p256_pkcs8_v1_template.der");
        // Ensure the ring generator didn't change
        assert_eq!(&p8[..0x24], &template[..0x24]);
        assert_eq!(&p8[0x44..0x49], &template[0x24..]);
        assert_eq!(p8[0x49], 4);
        assert_eq!(p8.len(), 0x8a);
        // Since the rest of the structure has been fully checked (including with ring
        // when instantiating AcmeKey), we can do things like this
        // r will be from 0x24 to 0x44
        //let r = &p8[0x24..0x44];
        // x will be from 0x4a to 0x6a
        let x = &p8[0x4a..0x6a];
        // y will be from 0x6a to 0x8a
        let y = &p8[0x6a..0x8a];
        let common = biscuit::jwk::CommonParameters {
            algorithm: Some(biscuit::jwa::Algorithm::Signature(
                biscuit::jwa::SignatureAlgorithm::ES256,
            )),
            ..Default::default()
        };
        let algorithm = biscuit::jwk::AlgorithmParameters::EllipticCurve(
            biscuit::jwk::EllipticCurveKeyParameters {
                key_type: biscuit::jwk::EllipticCurveKeyType::EC,
                curve: biscuit::jwk::EllipticCurve::P256,
                x: x.to_vec(),
                y: y.to_vec(),
                ..Default::default()
            },
        );
        biscuit::jwk::JWK {
            common,
            algorithm,
            additional: Default::default(),
        }
    }
}

impl From<&Jwk> for JwkThumb {
    fn from(a: &Jwk) -> Self {
        JwkThumb {
            crv: a.crv.clone(),
            kty: a.kty.clone(),
            x: a.x.clone(),
            y: a.y.clone(),
        }
    }
}
