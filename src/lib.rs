mod types;
use std::{env, slice};
use types::*;

macro_rules! cred {
    ($string:expr) => {
        match env::var($string) {
            Ok(value) => value,
            Err(err) => return Err(SigningError::MissingCredentials)
        };
    };
}

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
            Err(SigningError::MissingCredentials) => 0x8007052Eu32
        };
}

#[allow(unused_variables)]
fn perform_authenticode_sign(
    p_signer_cert: *mut PCertContext,
    digest_alg_id: AlgId,
    digest : &Vec<u8>) -> Result<(), SigningError> {
        let key_vault_url = cred!("AZURE_KEY_VAULT_URL");
        let key_vault_token = cred!("AZURE_KEY_VAULT_TOKEN");
        let key_vault_certificate = cred!("AZURE_KEY_VAULT_CERTIFICATE");
        return Result::Ok(());
}