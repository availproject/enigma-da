use keys::{
    interface::{SchemeError, Serializable},
    key_generator::KeyGenerator,
    keystore::KeyStore,
};
use log::{error, info};
use std::fs;
use std::{collections::HashMap, fmt::Debug, fs::File, io::Write, path::PathBuf};

use theta_proto::new_schemes::ThresholdScheme;
use thiserror::Error;

#[derive(Error)]
pub enum Error {
    #[error("file error: {0}")]
    File(#[from] std::io::Error),
    #[error("threshold error: {0}")]
    Threshold(#[from] SchemeError),
    #[error("serde error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("error: {0}")]
    String(String),
}

impl Debug for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::File(arg0) => f.debug_tuple("File").field(arg0).finish(),
            Self::Threshold(arg0) => f.debug_tuple("Threshold").field(arg0).finish(),
            Self::Serde(arg0) => f.debug_tuple("Serde").field(arg0).finish(),
            Self::String(arg0) => f.write_str(&arg0),
        }
    }
}
pub fn keygen(
    k: u16,
    n: u16,
    a: &str,
    dir: &str,
    new: bool,
    app_id: u32,
) -> Result<Vec<u8>, Error> {
    // let parts = a.split(',');
    let mut keys = HashMap::new();
    let mut rng = rand::thread_rng();

    if k > n {
        return Err(Error::Threshold(SchemeError::InvalidParams(Some(
            "Threshold parameter must not exceed number of parties".into(),
        ))));
    }

    if fs::create_dir_all(dir).is_err() {
        error!("Error: could not create directory");
        return Err(Error::Threshold(SchemeError::IOError));
    }

    if new {
        let _ = fs::remove_dir_all(dir.to_owned() + "/pub");
    }

    if fs::create_dir_all(dir.to_owned() + "/pub/").is_err() {
        error!("Error: could not create directory");
        return Err(Error::Threshold(SchemeError::IOError));
    }

    info!("Generating keys...");

    let scheme_str = a.trim();
    if scheme_str.is_empty() {
        println!("Invalid format of argument 'subjects'");
        return Err(Error::Threshold(SchemeError::InvalidParams(None)));
    }

    let scheme = ThresholdScheme::from_str_name(scheme_str);
    if scheme.is_none() {
        println!("Invalid scheme '{}' selected", scheme_str);
        return Err(Error::Threshold(SchemeError::InvalidParams(None)));
    }

    info!("Generating {}...", scheme_str);

    let name = String::from(scheme_str);

    let key = KeyGenerator::generate_keys(n as u8, k as u8, &mut rng, &scheme.unwrap(), app_id)
        .expect("Error generating keys");

    // Extraction of the public key and creation of a .pub file
    let pubkey = key[0].get_public_key();
    let publickey = pubkey.to_bytes().unwrap();
    let public_key = pubkey.get_pk().serialize().to_vec();
    println!("public_key_length_fromlib{}", public_key.len());

    let file = File::create(format!(
        "{}/pub/{}_{}.pub",
        dir,
        scheme_str,
        key[0].get_app_id()
    ));
    if let Err(e) = file.unwrap().write_all(&publickey) {
        error!("Error storing public key: {}", e.to_string());
        return Err(Error::Threshold(SchemeError::IOError));
    }

    keys.insert(name.clone(), key);

    for node_id in 0..n {
        // Define the name of the key file based on the node
        let keyfile = format!("{}/node{:?}.keystore", dir, node_id + 1);
        let mut kc = KeyStore::new();

        if !new {
            let _ = kc.load(&PathBuf::from(keyfile.clone()));
        }
        // each value in keys is a vector of secret key share (related to the same pk) that needs to be distributed among the right key file (parties)
        for k in keys.clone() {
            let _ = kc.insert_private_key(k.1[node_id as usize].clone());
        }

        // Here the information about the keys of a specific party are actually being written on file
        // TODO: eventually here there could be a protocol for an online phase to send the information to the nodes but in encrypted format.
        let _ = kc.to_file(&keyfile);

        info!("Created {}", keyfile);
    }

    info!("Keys successfully generated.");
    return Ok(public_key);
}
