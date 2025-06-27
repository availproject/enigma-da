use clap::Parser;
use k256::ProjectivePoint;
use keys::{
    interface::{SchemeError, Serializable},
    key_generator::KeyGenerator,
    keys::{PrivateKeyShare, PublicKey},
    keystore::KeyStore,
};
use log::{error, info};
use std::fs;
use std::{
    collections::HashMap,
    fmt::Debug,
    fs::File,
    io::{Read, Write},
    path::PathBuf,
};
use terminal_menu::{TerminalMenuItem, button, label, menu, mut_menu, run};
use theta_proto::{
    new_schemes::{ThresholdOperation, ThresholdScheme},
    protocol_types::{KeyRequest, threshold_crypto_library_client::ThresholdCryptoLibraryClient},
};
use thiserror::Error;
use utils::thetacli::cli::*;

#[derive(Error)]
enum Error {
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

#[tokio::main]
async fn main() -> Result<(), Error> {
    let args = ThetaCliArgs::parse();

    match args.command {
        Commands::Keygen(key_gen_args) => {
            return keygen(
                key_gen_args.k,
                key_gen_args.n,
                &key_gen_args.subjects,
                &key_gen_args.output,
                key_gen_args.new,
            );
        }
    
        Commands::Keystore(keystore_args) => {
            return keystore(
                &keystore_args.action,
                &keystore_args.keystore,
                keystore_args.address,
                keystore_args.new,
                keystore_args.input,
            )
            .await;
        }
    }
}

fn keygen(k: u16, n: u16, a: &str, dir: &str, new: bool) -> Result<(), Error> {
    let mut parts = a.split(',');
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

    let mut default_key_set: Vec<String>;

    info!("Generating keys...");

    // if a == "all" {
    //     default_key_set = generate_valid_scheme_group_pairs();
    //     default_key_set = vec![default_key_set.join(",")];
    //     let str_list = default_key_set[0].as_str();
    //     parts = str_list.split(',');
    // }

    for part in parts {
        let scheme_str = part;
        if scheme_str.is_empty() {
            println!("Invalid format of argument 'subjects'");
            return Err(Error::Threshold(SchemeError::InvalidParams(None)));
        }

        let scheme = ThresholdScheme::from_str_name(scheme_str);
        if scheme.is_none() {
            println!("Invalid scheme '{}' selected", scheme_str);
            return Err(Error::Threshold(SchemeError::InvalidParams(None)));
        }

        info!("Generating {}...", part);

        // Creation of the id (name) given to a certain key. For now the name is based on scheme_group info.
        let mut name = String::from(scheme_str);

        let key = KeyGenerator::generate_keys(n as u8, k as u8, &mut rng, &scheme.unwrap())
            .expect("Error generating keys");

        // Extraction of the public key and creation of a .pub file
        let pubkey = key[0].get_public_key().to_bytes().unwrap();
        let file = File::create(format!("{}/pub/{}_{}.pub", dir, part, key[0].get_app_id()));
        if let Err(e) = file.unwrap().write_all(&pubkey) {
            error!("Error storing public key: {}", e.to_string());
            return Err(Error::Threshold(SchemeError::IOError));
        }

        keys.insert(name.clone(), key);
    }

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
        // TODO: eventually here there could be a protocol for an online phase to send the information to the Thetacrypt instances.
        let _ = kc.to_file(&keyfile);

        info!("Created {}", keyfile);
    }

    info!("Keys successfully generated.");
    return Ok(());
}


// fn generate_valid_scheme_group_pairs() -> Vec<String> {
//     let mut scheme_group_vec: Vec<String> = Vec::new();
//     let mut i: i32 = 0;
//     loop {
//         let scheme = match ThresholdScheme::from_i32(i) {
//             Some(scheme) => scheme,
//             None => break,
//         };

//         let new_scheme = String::from(scheme.as_str_name());
//         scheme_group_vec.push(new_scheme);


//         i += 1;
//     }
//     return scheme_group_vec;
// }

fn load_key(
    key_path: Option<String>,
    keystore_path: Option<String>,
    key_id: Option<String>,
    operation: ThresholdOperation,
) -> Result<PublicKey, Error> {
    let key;

    if key_path.is_some() {
        let contents = fs::read(key_path.unwrap());

        if let Err(e) = contents {
            error!("Error reading public key: {}", e.to_string());
            return Err(Error::Threshold(SchemeError::DeserializationFailed));
        }

        let tmp = PublicKey::from_bytes(&contents.unwrap());

        if let Err(e) = tmp {
            error!("Error reading public key: {}", e.to_string());
            return Err(Error::Threshold(SchemeError::DeserializationFailed));
        }

        key = tmp.unwrap();
    } else if keystore_path.is_some() {
        let keystore = KeyStore::from_file(&PathBuf::from(keystore_path.unwrap()));

        if keystore.is_err() {}

        let keystore = keystore.unwrap();

        if key_id.is_none() {
            let entries;

            match operation {
                ThresholdOperation::Encryption => {
                    entries = keystore.get_encryption_keys();
                }
            }

            let mut key_menu_items: Vec<TerminalMenuItem> =
                entries.iter().map(|x| button(x.to_string())).collect();
            key_menu_items.insert(0, label("Select Key:"));
            let key_menu = menu(key_menu_items);

            run(&key_menu);
            {
                let km = mut_menu(&key_menu);
                let tmp = entries
                    .iter()
                    .find(|k| km.selected_item_name().contains(&k.id));

                if tmp.is_none() {
                    error!("Error importing key");
                    return Err(Error::String(String::from("Error loading public key")));
                }

                key = tmp.unwrap().pk.clone();
            }
        } else {
            let tmp = keystore.get_key_by_id(&key_id.unwrap());

            if let Err(e) = tmp {
                error!("Error loading public key: {}", e.to_string());
                return Err(Error::Threshold(SchemeError::DeserializationFailed));
            }

            key = tmp.unwrap().pk;
        }
    } else {
        error!("Either pubkey or keystore need to be specified");
        return Err(Error::String(String::from(
            "Either pubkey or keystore need to be specified",
        )));
    }

    return Ok(key);
}

async fn keystore(
    action: &str,
    keystore_path: &str,
    address: Option<String>,
    new: bool,
    input: Option<String>,
) -> Result<(), Error> {
    match action {
        "ls" => {
            let tmp = KeyStore::from_file(&PathBuf::from(keystore_path));

            if tmp.is_err() {
                println!("Error reading key store!");
                return Err(Error::String(format!("Error reading key store!")));
            }

            let keystore = tmp.unwrap();

            println!("{}", keystore.to_string());
        }
        "fetch" => {
            if address.is_none() {
                println!("No node address specified");
                return Err(Error::String(String::from("No node address specified")));
            }

            let mut keystore;

            if !new {
                let tmp = KeyStore::from_file(&PathBuf::from(keystore_path));

                if tmp.is_err() {
                    println!("Error reading key store!");
                    return Err(Error::String(format!("Error reading key store!")));
                }

                keystore = tmp.unwrap();
            } else {
                keystore = KeyStore::new();
            }

            let address = address.unwrap();
            let connection = ThresholdCryptoLibraryClient::connect(address.clone()).await;
            if connection.is_err() {
                return Err(Error::String(format!("Could not connect to {}", address)));
            }

            let response = connection.unwrap().get_public_keys(KeyRequest {}).await;

            if response.is_err() {
                println!("Error fetching public keys!");
                return Err(Error::String(format!("Error fetching public keys!")));
            }

            let response = response.unwrap();
            let keys = &response.get_ref().keys;
            if let Err(e) = keystore.import_public_keys(keys) {
                return Err(Error::String(e));
            }

            if keystore.to_file(keystore_path).is_err() {
                println!("Error storing keys to keychain");
                return Err(Error::String(format!("Error storing keys to keychain")));
            }

            println!("Successfully imported keys from server");
        }
        "add" => {
            if input.is_none() {
                return Err(Error::String(String::from("No input key file provided")));
            }

            let key_file = fs::read(input.unwrap());

            if key_file.is_err() {
                return Err(Error::String(String::from("Error reading input key file")));
            }

            let tmp = KeyStore::from_file(&PathBuf::from(keystore_path));

            if tmp.is_err() {
                println!("Error reading key store!");
                return Err(Error::String(format!("Error reading key store!")));
            }

            let mut keystore = tmp.unwrap();
            let bytes = key_file.unwrap();

            let pk = PublicKey::from_bytes(&bytes);
            let mut key_type = "public";

            if pk.is_err() {
                let sk = PrivateKeyShare::from_bytes(&bytes);
                if sk.is_err() {
                    return Err(Error::String(String::from("Invalid key file")));
                }

                if let Err(e) = keystore.insert_private_key(sk.unwrap()) {
                    return Err(Error::String(e.to_string()));
                }

                key_type = "secret";
            } else {
                if let Err(e) = keystore.insert_public_key(pk.unwrap()) {
                    return Err(Error::String(e.to_string()));
                }
            }

            if let Err(e) = keystore.to_file(keystore_path) {
                return Err(Error::String(e.to_string()));
            }

            println!("Successfully added {} key to keystore", key_type);
        }
        _ => {
            println!("Invalid action. Valid actions are: ls, add, fetch");
        }
    }

    Ok(())
}
