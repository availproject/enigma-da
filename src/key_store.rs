use crate::error::AppError;
use sled::{Db, IVec};

pub struct KeyStore {
    db: Db,
}

impl KeyStore {
    pub fn new(path: &str) -> Result<Self, AppError> {
        let db = sled::open(path).map_err(|e| AppError::Database(e.to_string()))?;
        Ok(Self { db })
    }

    pub fn store_keys(
        &self,
        app_id: u32,
        public_key: &[u8],
        private_key: &[u8],
    ) -> Result<(), AppError> {
        if public_key.is_empty() || private_key.is_empty() {
            return Err(AppError::InvalidKey("Keys cannot be empty".into()));
        }

        let pub_key_key = format!("pub:{app_id}");
        let priv_key_key = format!("priv:{app_id}");

        self.db
            .insert(pub_key_key.as_bytes(), public_key)
            .map_err(|e| AppError::Database(e.to_string()))?;

        // we won't be storing private keys in production, but for testing purposes
        self.db
            .insert(priv_key_key.as_bytes(), private_key)
            .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(())
    }

    pub fn get_public_key(&self, app_id: u32) -> Result<Vec<u8>, AppError> {
        let pub_key_key = format!("pub:{app_id}");
        match self.db.get(pub_key_key.as_bytes()) {
            Ok(Some(ivec)) => Ok(ivec.to_vec()),
            Ok(None) => Err(AppError::KeyNotFound(app_id)),
            Err(e) => Err(AppError::Database(e.to_string())),
        }
    }

    pub fn get_private_key(&self, app_id: u32) -> Result<Vec<u8>, AppError> {
       let key = format!("priv:{app_id}");
        match self.db.get(key.as_bytes()) {
            Ok(Some(ivec)) => Ok(ivec.to_vec()),
            Ok(None) => Err(AppError::KeyNotFound(app_id)),
            Err(e) => Err(AppError::Database(e.to_string())),
    }
}
}
