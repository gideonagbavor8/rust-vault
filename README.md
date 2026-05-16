# Overview

As a software engineer expanding my backend and systems programming skills, I am working on building secure, memory-safe applications. My goal for this project was to learn the Rust programming language by implementing a practical cryptographic tool.

This software is a Secure Password Generator and Vault CLI. It demonstrates how to generate cryptographically strong passwords, securely derive 256-bit keys from a master password using Argon2, and encrypt the data using AES-GCM encryption before storing it in a local vault.

I wrote this software to familiarize myself with Rust's strict ownership model, error handling (Result and Option enums), and integrating external crates for cryptography and serialization.

[Software Demo Video](https://www.loom.com/share/d2514ce97935438c85ad8d361f4eed12)

# Development Environment

I used Visual Studio Code with the rust-analyzer extension for development. The project is managed and built using Cargo, Rust's package manager.

This software is written entirely in **Rust**. It utilizes several external libraries (crates):
* **`rand`**: For secure random number and character generation.
* **`argon2`**: For key derivation from the master password.
* **`aes-gcm`**: For authenticated symmetric encryption.
* **`serde` & `serde_json`**: For defining data structures and serialization.

# Useful Websites

* [The Rust Programming Language Book](https://doc.rust-lang.org/book/)
* [Rust Standard Library Documentation](https://doc.rust-lang.org/std/)
* [docs.rs - aes-gcm](https://docs.rs/aes-gcm/latest/aes_gcm/)
* [docs.rs - argon2](https://docs.rs/argon2/latest/argon2/)
