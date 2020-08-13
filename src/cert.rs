use crate::Result;

pub(crate) fn create_csr_der(key: &rcgen::KeyPair, domains: &[&str]) -> Result<Vec<u8>> {
    let domains: Vec<String> = domains.iter().map(|d| str::to_owned(d)).collect();
    let mut params = rcgen::CertificateParams::new(domains);
    // Work around the lack of clone / to_owned
    let key = rcgen::KeyPair::from_pem(&key.serialize_pem())?;
    params.key_pair = Some(key);
    let cert = rcgen::Certificate::from_params(params)?;
    Ok(cert.serialize_request_der()?)
}

pub fn create_p256_key() -> Result<rcgen::KeyPair> {
    Ok(rcgen::KeyPair::generate(&rcgen::PKCS_ECDSA_P256_SHA256)?)
}

pub fn create_p384_key() -> Result<rcgen::KeyPair> {
    Ok(rcgen::KeyPair::generate(&rcgen::PKCS_ECDSA_P384_SHA384)?)
}

/*
/// Encapsulated certificate and private key.
struct Certificate(rustls::CertifiedKey);

impl Certificate {
    pub(crate) fn new(private_key: String, certificate: String) -> Self {
        rustls::CertifiedKey::new()
    }

    /// The PEM encoded private key.
    pub fn private_key(&self) -> &str {
        &self.private_key
    }

    /// The private key as DER.
    pub fn private_key_der(&self) -> Vec<u8> {
        let pkey = PKey::private_key_from_pem(self.private_key.as_bytes()).expect("from_pem");
        pkey.private_key_to_der().expect("private_key_to_der")
    }

    /// The PEM encoded issued certificate.
    pub fn certificate(&self) -> &str {
        &self.certificate
    }

    /// The issued certificate as DER.
    pub fn certificate_der(&self) -> Vec<u8> {
        let x509 = X509::from_pem(self.certificate.as_bytes()).expect("from_pem");
        x509.to_der().expect("to_der")
    }

}
*/
