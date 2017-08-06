pub enum PCertContext{}

use ::types::DigestAlgorithm;

#[repr(C)]
pub struct CryptoApiBlob {
    pub cb_data : u32,
    pub pb_data : *mut u8
}

#[repr(u32)]
#[derive(Debug, PartialEq, Eq)]
pub enum AlgId {
    Md5 = 0x8003,
    Sha1 = 0x8004,
    Sha256 = 0x800C,
    Sha384 = 0x800D,
    Sha512 = 0x800E,
}

pub trait ToDigestAlgorithm {
    fn to_algorithm(self) -> Option<DigestAlgorithm>;
}

impl ToDigestAlgorithm for AlgId {
    fn to_algorithm(self) -> Option<DigestAlgorithm> {
        match self {
            AlgId::Md5 => Some(DigestAlgorithm::MD5),
            AlgId::Sha1 => Some(DigestAlgorithm::SHA1),
            AlgId::Sha256 => Some(DigestAlgorithm::SHA256),
            AlgId::Sha384 => Some(DigestAlgorithm::SHA384),
            AlgId::Sha512 => Some(DigestAlgorithm::SHA512)
        }
    }
}
