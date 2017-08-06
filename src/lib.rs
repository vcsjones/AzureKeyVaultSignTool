extern crate serde;
extern crate winapi;

mod types;

use std::{env, slice};
use types::*;
use winapi::winerror::*;
use winapi::wincrypt::*;


#[no_mangle]
#[allow(non_snake_case)]
#[allow(unused_variables)]
pub extern "system" fn AuthenticodeDigestSign(
    p_signer_cert: *mut CERT_CONTEXT,
    p_metadata_blob: *mut CRYPTOAPI_BLOB,
    digest_alg_id: ALG_ID,
    p_to_be_signed_digest: *mut u8,
    to_be_signed_digest_size : u32,
    p_signed_digest: *mut CRYPTOAPI_BLOB
    ) -> HRESULT {
        let digest_size : usize = to_be_signed_digest_size as usize;
        let digest = unsafe { slice::from_raw_parts(p_to_be_signed_digest, digest_size) }.to_vec();
        return match perform_authenticode_sign(p_signer_cert, digest_alg_id, &digest) {
            Ok(_) => S_OK,
            Err(SigningError::MissingCredentials(_)) => 0x80070056u32 as HRESULT,
            Err(SigningError::InvalidDigestAlgorithm) => NTE_BAD_ALGID
        };
}

#[allow(unused_variables)]
fn perform_authenticode_sign(
    p_signer_cert: *mut CERT_CONTEXT,
    digest_alg_id: ALG_ID,
    digest : &Vec<u8>) -> Result<(), SigningError> {
        let key_vault_url = try!(env::var("AZURE_KEY_VAULT_URL").map_err(SigningError::MissingCredentials));
        let key_vault_token = try!(env::var("AZURE_KEY_VAULT_TOKEN").map_err(SigningError::MissingCredentials));
        let key_vault_certificate = try!(env::var("AZURE_KEY_VAULT_CERTIFICATE").map_err(SigningError::MissingCredentials));
        let digest_algorithm = match digest_alg_id.to_algorithm() {
            Some(x) => x,
            None => return Result::Err(SigningError::InvalidDigestAlgorithm)
        };

        let signature_algorithm = SignatureAlgorithm::RSA(digest_algorithm, SignaturePadding::PkcsV15);
        return Result::Ok(());
}

pub trait ToDigestAlgorithm {
    fn to_algorithm(self) -> Option<DigestAlgorithm>;
}

impl ToDigestAlgorithm for ALG_ID {
    fn to_algorithm(self) -> Option<DigestAlgorithm> {
        match self {
            CALG_MD5 => Some(DigestAlgorithm::MD5),
            CALG_SHA1 => Some(DigestAlgorithm::SHA1),
            CALG_SHA_256 => Some(DigestAlgorithm::SHA256),
            CALG_SHA_384 => Some(DigestAlgorithm::SHA384),
            CALG_SHA_512 => Some(DigestAlgorithm::SHA512),
            _ => None
        }
    }
}