mod generator;
mod vault;

use generator::{generate_password, PasswordConfig};
use vault::{Vault, VaultEntry};

fn main() {
    println!("--- Secure Password Generator & Vault ---");

    // 1. Setup Password Configuration
    let config = PasswordConfig {
        length: 16,
        use_symbols: true,
        use_numbers: true,
    };

    // 2. Generate a password
    let password = generate_password(&config);
    println!("Generated Password: {}", password);

    // 3. Setup Encryption (Master Password)
    let master_pwd = "my_super_secret_master_password";
    let key = Vault::derive_key(master_pwd);

    // 4. Encrypt the generated password
    let (encrypted_data, nonce) = Vault::encrypt_password(&password, &key);

    // 5. Initialize the Vault and add entry
    let mut my_vault = Vault::new();
    let entry = VaultEntry {
        service: String::from("GitHub"),
        username: String::from("gideonagbavor8"),
        encrypted_password: encrypted_data,
        nonce: nonce,
    };

    my_vault.add_entry(entry);
    println!("Stored encrypted entry for GitHub.");

    // 6. Verify by Decrypting
    let github_entry = my_vault.entries.get("GitHub").unwrap();
    let decrypted = Vault::decrypt_password(
        &github_entry.encrypted_password, 
        &github_entry.nonce, 
        &key
    );

    println!("Decrypted Password: {}", decrypted);
    assert_eq!(password, decrypted);
    println!("Verification successful! The passwords match.");
    println!("--- Process Complete ---");
}
