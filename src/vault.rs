use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng, AeadCore},
    Aes256Gcm, Nonce
};
use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Argon2
};

#[derive(Serialize, Deserialize, Debug)]
pub struct VaultEntry {
    pub service: String,
    pub username: String,
    pub encrypted_password: Vec<u8>,
    pub nonce: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Vault {
    pub entries: HashMap<String, VaultEntry>,
}

pub enum VaultError {
    EncryptionError,
    DecryptionError,
    KeyDerivationError,
}

impl Vault {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Derives a 32-byte key from a master password
    pub fn derive_key(master_password: &str) -> [u8; 32] {
        let salt = SaltString::from_b64("SGVsbG9Xb3JsZDEyMw").unwrap(); // In a real app, use a random salt
        let argon2 = Argon2::default();
        let hash = argon2.hash_password(master_password.as_bytes(), &salt).unwrap();
        let mut key = [0u8; 32];
        key.copy_from_slice(&hash.hash.unwrap().as_bytes()[..32]);
        key
    }

    pub fn encrypt_password(password: &str, key: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
        let cipher = Aes256Gcm::new(key.into());
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng); 
        let ciphertext = cipher.encrypt(&nonce, password.as_bytes()).expect("encryption failure!");
        (ciphertext, nonce.to_vec())
    }

    pub fn decrypt_password(ciphertext: &[u8], nonce: &[u8], key: &[u8; 32]) -> String {
        let cipher = Aes256Gcm::new(key.into());
        let nonce = Nonce::from_slice(nonce);
        let plaintext = cipher.decrypt(nonce, ciphertext).expect("decryption failure!");
        String::from_utf8(plaintext).expect("Invalid UTF-8")
    }

    pub fn add_entry(&mut self, entry: VaultEntry) {
        self.entries.insert(entry.service.clone(), entry);
    }
}
