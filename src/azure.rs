use std::io::{self, Write, Error};
use futures::{Future, Stream};
use hyper::{Client, Uri};
use tokio_core::reactor::Core;
use std::str::FromStr;

static API_VERSION: &'static str = "2016-10-01";

#[derive(Debug, PartialEq, Eq)]
pub enum AzureError {
    IoError,
    InvalidConfiguration
}

#[derive(Debug)]
pub struct AzureCredentials {
    pub client_id : String,
    pub client_secret : String
}

#[derive(Debug)]
pub struct AzureClient<'a> {
    token : Option<String>,
    vault_url : String,
    credentials : &'a AzureCredentials
}

impl<'a> AzureClient<'a> {
    fn set_token(&mut self, token : String) {
        self.token = Some(token);
    }

    pub fn new(azure_credentials : &'a AzureCredentials, key_vault_url : String) -> AzureClient<'a> {
        AzureClient {
            token : None,
            credentials : azure_credentials,
            vault_url : key_vault_url
        }
    }

    pub fn get_key_vault_certificate(&mut self, certificate_name : &String) -> Result<(), AzureError>  {
        let mut core = Core::new().map_err(|_| AzureError::IoError)?;
        let client = Client::new(&core.handle());
        let vault_uri = Uri::from_str(&self.vault_url).map_err(|_| AzureError::InvalidConfiguration)?;
        let vault_host = vault_uri.authority().ok_or(AzureError::InvalidConfiguration)?;
        let raw_host = format!("https://{}/certificates/{}/?api-version={}", vault_host, certificate_name, API_VERSION);
        let certificate_uri = Uri::from_str(&raw_host).map_err(|_| AzureError::InvalidConfiguration)?;
        client.get(certificate_uri).map(|res| {
            
        });
        return Result::Ok(());
    }

    pub fn get_key_vault_key_for_certificate(&mut self, certificate : ()) -> Result<(), AzureError> {
        return Result::Ok(());
    }

    fn azure_authenticate() -> Result<(), AzureError> {
        return Result::Ok(());
    }
}