extern crate serde;

mod win32;
mod types;

use std::{env, slice};
use types::*;
use win32::*;


#[no_mangle]
#[allow(non_snake_case)]
#[allow(unused_variables)]
pub extern "system" fn AuthenticodeDigestSign(
    p_signer_cert: *mut PCertContext,
    p_metadata_blob: *mut CryptoApiBlob,
    digest_alg_id: AlgId,
    p_to_be_signed_digest: *mut u8,
    to_be_signed_digest_size : u32,
    p_signed_digest: *mut CryptoApiBlob
    ) -> u32 {
        let digest_size : usize = to_be_signed_digest_size as usize;
        let digest = unsafe { slice::from_raw_parts(p_to_be_signed_digest, digest_size) }.to_vec();
        return match perform_authenticode_sign(p_signer_cert, digest_alg_id, &digest) {
            Ok(_) => 0u32,
            Err(SigningError::MissingCredentials(_)) => 0x8007052Eu32,
            Err(SigningError::InvalidDigestAlgorithm) => 0x80090008u32
        };
}

#[allow(unused_variables)]
fn perform_authenticode_sign(
    p_signer_cert: *mut PCertContext,
    digest_alg_id: AlgId,
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