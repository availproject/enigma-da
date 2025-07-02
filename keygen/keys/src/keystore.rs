use super::KeyStoreError;
use super::keys::{PrivateKeyShare, PublicKey};
use crate::scheme_types_imp::SchemeDetails;
use log::error;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct KeyEntry {
    pub id: u32,
    pub(crate) is_default: bool,
    pub sk: Option<PrivateKeyShare>,
    pub pk: PublicKey,
}

impl KeyEntry {
    pub fn to_string(&self) -> String {
        let mut postfix = String::from("");
        if self.sk.is_some() {
            postfix.push_str("<sk>");
        }

        let mut default_string = String::from("");
        if self.is_default {
            default_string.push_str("\t(default)");
        }

        format!(
            "{} {} {} {}",
            &self.id,
            self.pk.get_scheme().as_str_name(),
            postfix,
            default_string
        )
    }
}

#[derive(PartialEq, Eq, Debug)]
pub struct KeyStore {
    key_entries: HashMap<u32, KeyEntry>,
    filename: Option<PathBuf>,
}

#[derive(Serialize, Deserialize)]
struct SerializedKeyEntry {
    pub id: u32,
    pub key_type: String,
    pub scheme: String,
    pub operation: String,
    pub key: String,
}

impl From<Vec<SerializedKeyEntry>> for KeyStore {
    fn from(value: Vec<SerializedKeyEntry>) -> Self {
        let mut kc = Self::new();

        for entry in value {
            match entry.key_type.as_str() {
                "secret" => {
                    let key = PrivateKeyShare::from_pem(&entry.key);
                    if key.is_err() {
                        error!(
                            "Error deserializing private key share: {}",
                            key.unwrap_err().to_string()
                        );
                        continue;
                    }
                    let key = key.unwrap();
                    let id = kc.insert_private_key(key.clone());
                    if id.is_err() {
                        error!("Error inserting private key: {}", id.unwrap_err());
                    }
                }
                _ => {
                    let key = PublicKey::from_pem(&entry.key);
                    if key.is_err() {
                        error!(
                            "Error deserializing public key: {}",
                            key.unwrap_err().to_string()
                        );
                        continue;
                    }
                    let id = kc.insert_public_key(key.unwrap());

                    if id.is_err() {
                        error!("Error inserting public key: {}", id.unwrap_err());
                    }
                }
            }
        }

        kc
    }
}

impl KeyStore {
    pub fn new() -> Self {
        KeyStore {
            key_entries: HashMap::new(),
            filename: Option::None,
        }
    }

    pub fn load(&mut self, filename: &PathBuf) -> std::io::Result<()> {
        let key_chain_str = fs::read_to_string(filename)?;
        let ks: Vec<SerializedKeyEntry> = serde_json::from_str(&key_chain_str)?;
        let k: KeyStore = ks.into();
        self.key_entries = k.key_entries;
        self.filename = Some(filename.clone());
        Ok(())
    }

    pub fn from_str(key_chain_str: String) -> std::io::Result<Self> {
        let ks: Vec<SerializedKeyEntry> = serde_json::from_str(&key_chain_str)?;
        let k: KeyStore = ks.into();
        Ok(k)
    }

    pub fn from_file(filename: &PathBuf) -> std::io::Result<Self> {
        let key_chain_str = fs::read_to_string(filename)?;
        Self::from_str(key_chain_str)
    }

    pub fn to_file(&self, filename: &str) -> std::io::Result<()> {
        let mut keys = Vec::new();

        for (id, key) in &self.key_entries {
            keys.push(SerializedKeyEntry {
                id: id.clone(),
                key_type: match key.sk.is_some() {
                    true => String::from("secret"),
                    false => String::from("public"),
                },
                // group: key.pk.get_group().as_str_name().to_string(),
                scheme: key.pk.get_scheme().as_str_name().to_string(),
                operation: key.pk.get_operation().as_str_name().to_string(),
                key: match key.sk.is_some() {
                    true => key.sk.as_ref().unwrap().pem().unwrap(),
                    false => key.pk.pem().unwrap(),
                },
            });
        }

        let serialized = serde_json::to_string(&keys).unwrap();
        fs::write(filename, serialized)?;

        Ok(())
    }
    //will change this func to import_public_key from the keyresponse
    // pub fn import_public_keys(&mut self, public_keys: &[PublicKeyEntry]) -> Result<(), String> {
    //     for entry in public_keys {
    //         let key = PublicKey::from_bytes(&entry.key);
    //         if key.is_ok() {
    //             let id = self.insert_public_key(key.unwrap());
    //             if let Err(e) = id {
    //                 println!("Error: {}", e.to_string());
    //                 continue;
    //             }

    //             debug!("Imported public key {}", id.unwrap());
    //         } else {
    //             return Err(format!("Error: {}", key.unwrap_err().to_string()));
    //         }
    //     }

    //     Ok(())
    // }

    //insert privatekeyshare to a keystore
    pub fn insert_private_key(&mut self, key: PrivateKeyShare) -> Result<u32, KeyStoreError> {
        let app_id = key.clone().get_app_id().clone();

        if self
            .key_entries
            .iter()
            .any(|e| *e.0 == app_id && e.1.sk.is_some())
        {
            return Err(KeyStoreError::DuplicateEntry(app_id.clone()));
        }

        let operation = key.get_scheme().get_operation();
        let matching_keys: Vec<(&u32, &mut KeyEntry)> = self
            .key_entries
            .iter_mut()
            .filter(|e| {
                e.1.sk.is_some()
                    && e.1.sk.as_ref().unwrap().get_scheme().get_operation() == operation
            })
            .collect();

        let mut is_default = true;
        for _k in matching_keys {
            _k.1.is_default = false;
            is_default = false;
        }

        let entry = self.key_entries.get(&app_id);
        if entry.is_some() {
            self.key_entries.remove_entry(&app_id);
        }

        self.key_entries.insert(app_id, KeyEntry {
            id: app_id.clone(),
            is_default,
            pk: key.get_public_key(),
            sk: Some(key),
        });

        Ok(app_id)
    }

    pub fn insert_public_key(&mut self, key: PublicKey) -> Result<u32, KeyStoreError> {
        let app_id = key.get_app_id();

        if self.key_entries.iter().any(|e| e.0.eq(&app_id)) {
            return Err(KeyStoreError::DuplicateEntry(app_id.clone()));
        }

        let operation = key.get_scheme().get_operation();
        let is_default = !self
            .key_entries
            .iter()
            .any(|e| e.1.pk.get_scheme().get_operation() == operation);

        self.key_entries.insert(app_id.clone(), KeyEntry {
            id: app_id.clone(),
            is_default,
            sk: None,
            pk: key,
        });
        Ok(app_id)
    }

    // Return the matching key with the given app_id, or an error if no key with app_id exists.
    pub fn get_key_by_id(&self, id: &u32) -> Result<KeyEntry, KeyStoreError> {
        if self.key_entries.contains_key(id) == false {
            error!("No entry for id {}", &id);
            return Err(KeyStoreError::IdNotFound(*id));
        }

        return Ok(self.key_entries.get(id).unwrap().clone());
    }
}
