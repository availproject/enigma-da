use crate::error::AppError;
use dashmap::DashMap;

pub struct KeyStore {
    public_keys: DashMap<u32, Vec<u8>>,
    private_keys: DashMap<u32, Vec<u8>>,
}

impl KeyStore {
    pub fn new() -> Self {
        Self {
            public_keys: DashMap::new(),
            private_keys: DashMap::new(),
        }
    }

    pub async fn store_keys(
        &self,
        app_id: u32,
        public_key: &[u8],
        private_key: &[u8],
    ) -> Result<(), AppError> {
        if public_key.is_empty() || private_key.is_empty() {
            return Err(AppError::InvalidKey("Keys cannot be empty".into()));
        }
        self.public_keys.insert(app_id, public_key.to_vec());
        self.private_keys.insert(app_id, private_key.to_vec());
        Ok(())
    }

    pub async fn get_public_key(&self, app_id: u32) -> Result<Vec<u8>, AppError> {
        self.public_keys
            .get(&app_id)
            .map(|v| v.clone())
            .ok_or(AppError::KeyNotFound(app_id))
    }
}