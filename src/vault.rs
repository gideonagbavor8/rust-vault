use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
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

#[derive(Debug)]
#[allow(dead_code)]
pub enum VaultError {

    EncryptionError,
    DecryptionError,
    KeyDerivationError,
    IoError(String),
    SerializationError(String),
}

impl Vault {
    /// Creates a new, empty Vault.
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Derives a 32-byte key from a master password
    pub fn derive_key(master_password: &str) -> Result<[u8; 32], VaultError> {
        let salt = SaltString::from_b64("SGVsbG9Xb3JsZDEyMw").map_err(|_| VaultError::KeyDerivationError)?;
        let argon2 = Argon2::default();
        let hash = argon2.hash_password(master_password.as_bytes(), &salt).map_err(|_| VaultError::KeyDerivationError)?;
        
        let mut key = [0u8; 32];
        key.copy_from_slice(&hash.hash.unwrap().as_bytes()[..32]);
        Ok(key)
    }

    /// Encrypts a plaintext password using AES-256-GCM and a derived 32-byte key.
    /// Returns a tuple containing the encrypted bytes and the randomly generated nonce.
    pub fn encrypt_password(password: &str, key: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>), VaultError> {
        let cipher = Aes256Gcm::new(key.into());
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng); 
        let ciphertext = cipher.encrypt(&nonce, password.as_bytes()).map_err(|_| VaultError::EncryptionError)?;
        Ok((ciphertext, nonce.to_vec()))
    }

    /// Decrypts a ciphertext using AES-256-GCM, the derived key, and the specific nonce used during encryption.
    /// Returns the decrypted plaintext password as a UTF-8 String.
    pub fn decrypt_password(ciphertext: &[u8], nonce: &[u8], key: &[u8; 32]) -> Result<String, VaultError> {
        let cipher = Aes256Gcm::new(key.into());
        let nonce = Nonce::from_slice(nonce);
        let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|_| VaultError::DecryptionError)?;
        String::from_utf8(plaintext).map_err(|_| VaultError::DecryptionError)
    }

    /// Adds a new VaultEntry into the local HashMap memory.
    pub fn add_entry(&mut self, entry: VaultEntry) {
        self.entries.insert(entry.service.clone(), entry);
    }

    /// Serializes the entire Vault struct into JSON format and writes it to the specified file path.
    pub fn save_to_file(&self, path: &str) -> Result<(), VaultError> {
        let json = serde_json::to_string(self)
            .map_err(|e| VaultError::SerializationError(e.to_string()))?;
        fs::write(path, json)
            .map_err(|e| VaultError::IoError(e.to_string()))?;
        Ok(())
    }

    /// Loads and deserializes a Vault struct from a JSON file. If the file does not exist,
    /// it returns a new, empty Vault instead of failing.
    pub fn load_from_file(path: &str) -> Result<Self, VaultError> {
        if !Path::new(path).exists() {
            return Ok(Vault::new());
        }
        let json = fs::read_to_string(path)
            .map_err(|e| VaultError::IoError(e.to_string()))?;
        let vault: Vault = serde_json::from_str(&json)
            .map_err(|e| VaultError::SerializationError(e.to_string()))?;
        Ok(vault)
    }
}
