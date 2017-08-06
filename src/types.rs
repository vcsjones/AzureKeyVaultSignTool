use std::env::VarError;

pub enum SignaturePadding {
    PkcsV15,
    PSS
}

#[derive(Debug, PartialEq, Eq)]
pub enum DigestAlgorithm {
    MD5,
    SHA1,
    SHA256,
    SHA384,
    SHA512
}

pub enum SignatureAlgorithm {
    RSA(DigestAlgorithm, SignaturePadding),
    ECDSA(DigestAlgorithm)
}

#[repr(u32)]
#[derive(Debug, PartialEq, Eq)]
pub enum SigningError {
    MissingCredentials(VarError),
    InvalidDigestAlgorithm
}