use std::env::VarError;

#[repr(C)]
pub struct CryptoApiBlob {
    pub cb_data : u32,
    pub pb_data : *mut u8
}

pub enum PCertContext{}

#[repr(u32)]
#[derive(Debug, PartialEq, Eq)]
pub enum AlgId {
    Md5 = 0x8003,
    Sha1 = 0x8004,
    Sha256 = 0x800C,
    Sha384 = 0x800D,
    Sha512 = 0x800E,
}

#[repr(u32)]
#[derive(Debug, PartialEq, Eq)]
pub enum SigningError {
    MissingCredentials(VarError)
}