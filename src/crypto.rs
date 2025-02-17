use secp256k1::{Secp256k1, SecretKey, PublicKey};
use rand::{rngs::OsRng, RngCore};
use crate::error::AppError;

pub fn generate_keypair() -> Result<(Vec<u8>, Vec<u8>), AppError> {
    let secp = Secp256k1::new();
    let mut rng = OsRng;
    
    // Generate random 32-byte private key
    let mut private_key = [0u8; 32];
    rng.try_fill_bytes(&mut private_key);
    
    let secret_key = SecretKey::from_slice(&private_key)
        .map_err(|e| AppError::KeyGenerationError(e.to_string()))?;
        
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    
    Ok((
        public_key.serialize().to_vec(),
        private_key.to_vec(),
    ))
}