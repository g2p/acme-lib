use std::sync::Arc;

use ring::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};

use crate::Result;

pub(crate) struct AcmeKey {
    //keypair: EcdsaKeyPair,
    pub(crate) jws_secret: biscuit::jws::Secret,
    pkcs8: Box<[u8]>,
    /// set once we contacted the ACME API to figure out the key id
    key_id: Option<String>,
}

impl std::fmt::Debug for AcmeKey {
    /// Implemented manually, because jws_secret does not implement Debug
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AcmeKey")
            .field("key_id", &self.key_id)
            .finish()
    }
}

impl AcmeKey {
    pub(crate) fn new(rng: &dyn ring::rand::SecureRandom) -> Result<Self> {
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, rng)?;
        Self::from_pkcs8(pkcs8.as_ref())
    }

    pub(crate) fn from_pkcs8(pkcs8: &[u8]) -> Result<Self> {
        let keypair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8)?;
        let pkcs8 = Box::from(pkcs8);
        let jws_secret = biscuit::jws::Secret::EcdsaKeyPair(Arc::new(keypair));
        Ok(Self {
            //keypair,
            jws_secret,
            pkcs8,
            key_id: None,
        })
    }

    pub(crate) fn to_pkcs8(&self) -> &[u8] {
        &self.pkcs8
    }

    pub(crate) fn key_id(&self) -> &str {
        self.key_id.as_ref().unwrap()
    }

    pub(crate) fn set_key_id(&mut self, kid: String) {
        self.key_id = Some(kid)
    }
}
