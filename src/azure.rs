use std::cell::Cell;

#[derive(Debug, PartialEq, Eq)]
pub enum AzureError {
}

pub struct AzureCredentials {
    pub client_id : String,
    pub client_secret : String
}

pub struct AzureState {
    token : Cell<Option<String>>,
    use_counter : Cell<i32>
}

pub fn create_azure_state() -> AzureState {
    return AzureState {
        token : Cell::new(None),
        use_counter : Cell::new(0)
    }
}

pub fn get_key_vault_certificate(certificate_name : &String, state : &AzureState) -> Result<(), AzureError>  {
    state.use_counter.set(state.use_counter.get() + 1);
    return Result::Ok(());
}