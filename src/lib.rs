extern crate serde;
extern crate winapi;

mod types;
mod azure;
use std::{env, slice};
use types::*;
use winapi::winerror::*;
use winapi::wincrypt::*;
use azure::*;


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
        let certificate = match unsafe { p_signer_cert.as_ref() } {
            Some(cert) => cert,
            None => return E_INVALIDARG
        };
        return match perform_authenticode_sign(certificate, digest_alg_id, &digest) {
            Ok(_) => S_OK,
            Err(SigningError::MissingCredentials(_)) => 0x80070056u32 as HRESULT,
            Err(SigningError::InvalidDigestAlgorithm) => NTE_BAD_ALGID,
            Err(_) => E_FAIL
        };
}

#[allow(unused_variables)]
fn perform_authenticode_sign(
    signer_cert: &CERT_CONTEXT,
    digest_alg_id: ALG_ID,
    digest : &Vec<u8>) -> Result<(), SigningError> {
        let key_vault_url = try!(env::var("AZURE_KEY_VAULT_URL").map_err(SigningError::MissingCredentials));
        let key_vault_client_id = try!(env::var("AZURE_KEY_VAULT_CLIENT_ID").map_err(SigningError::MissingCredentials));
        let key_vault_client_secret = try!(env::var("AZURE_KEY_VAULT_CLIENT_SECRET").map_err(SigningError::MissingCredentials));
        let credentials = azure::AzureCredentials {
            client_id : key_vault_client_id,
            client_secret : key_vault_client_secret
        };
        let key_vault_certificate = try!(env::var("AZURE_KEY_VAULT_CERTIFICATE").map_err(SigningError::MissingCredentials));
        let digest_algorithm = match digest_alg_id.to_algorithm() {
            Some(x) => x,
            None => return Result::Err(SigningError::InvalidDigestAlgorithm)
        };
        let signature_algorithm = SignatureAlgorithm::RSA(digest_algorithm, SignaturePadding::PkcsV15);

        let azure_state = create_azure_state();
        let azure_certificate = try!(get_key_vault_certificate(&key_vault_certificate, &azure_state).map_err(SigningError::AzureError));
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