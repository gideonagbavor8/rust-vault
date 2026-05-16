mod generator;
mod vault;

use clap::{Parser, Subcommand};
use generator::{generate_password, PasswordConfig};
use vault::{Vault, VaultEntry};
use std::io::{self, Write};

/// Prompts the user with a custom message and securely reads a single line from standard input.
/// Returns the input as a trimmed String.
fn read_master_password(prompt: &str) -> String {
    print!("{}", prompt);
    io::stdout().flush().unwrap();
    let mut password = String::new();
    io::stdin().read_line(&mut password).unwrap();
    password.trim().to_string()
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new password and save it
    Generate {
        /// Name of the service (e.g., GitHub)
        service: String,
        /// Your username for the service
        username: String,
        /// Length of the password
        #[arg(short, long, default_value_t = 16)]
        length: usize,
    },
    /// Retrieve a password from the vault
    Retrieve {
        /// Name of the service
        service: String,
    },
}

/// The main entry point of the application. Parses CLI arguments using `clap` and delegates 
/// to the appropriate Command variant (Generate or Retrieve). Handles all major application flow and error reporting.
fn main() {
    let cli = Cli::parse();
    let vault_path = "vault.json";

    match cli.command {
        Commands::Generate { service, username, length } => {
            let config = PasswordConfig {
                length,
                use_symbols: true,
                use_numbers: true,
            };
            
            let password = generate_password(&config);
            println!("Generated a secure password for {}.", service);

            let master_pwd = read_master_password("Enter your master password: ");

            let key = match Vault::derive_key(&master_pwd) {
                Ok(k) => k,
                Err(e) => {
                    eprintln!("Error deriving key: {:?}", e);
                    return;
                }
            };

            let (encrypted_data, nonce) = match Vault::encrypt_password(&password, &key) {
                Ok(data) => data,
                Err(e) => {
                    eprintln!("Error encrypting password: {:?}", e);
                    return;
                }
            };

            let mut vault = match Vault::load_from_file(vault_path) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("Error loading vault: {:?}", e);
                    return;
                }
            };

            let entry = VaultEntry {
                service: service.clone(),
                username,
                encrypted_password: encrypted_data,
                nonce,
            };

            vault.add_entry(entry);
            if let Err(e) = vault.save_to_file(vault_path) {
                eprintln!("Error saving vault: {:?}", e);
                return;
            }

            println!("Successfully encrypted and saved to vault!");
        }
        Commands::Retrieve { service } => {
            let vault = match Vault::load_from_file(vault_path) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("Error loading vault: {:?}", e);
                    return;
                }
            };

            let entry = match vault.entries.get(&service) {
                Some(e) => e,
                None => {
                    eprintln!("Service '{}' not found in vault.", service);
                    return;
                }
            };

            let master_pwd = read_master_password("Enter your master password: ");

            let key = match Vault::derive_key(&master_pwd) {
                Ok(k) => k,
                Err(e) => {
                    eprintln!("Error deriving key: {:?}", e);
                    return;
                }
            };

            let decrypted = match Vault::decrypt_password(&entry.encrypted_password, &entry.nonce, &key) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("Error decrypting password. You may have typed the wrong master password. ({:?})", e);
                    return;
                }
            };

            println!("--- {} Credentials ---", service);
            println!("Username: {}", entry.username);
            println!("Password: {}", decrypted);
        }
    }
}
