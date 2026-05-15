use rand::{thread_rng, Rng};

pub struct PasswordConfig {
    pub length: usize,
    pub use_symbols: bool,
    pub use_numbers: bool,
}

/// Generates a cryptographically strong password.
/// Returns a String (owned) to avoid lifetime/borrow issues.
pub fn generate_password(config: &PasswordConfig) -> String {
    let mut rng = thread_rng();
    
    // We start with alphanumeric characters
    let mut charset: Vec<char> = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
        .chars()
        .collect();

    if config.use_numbers {
        charset.extend("0123456789".chars());
    }

    if config.use_symbols {
        charset.extend("!@#$%^&*()_+-=[]{}|;:,.<>?".chars());
    }

    // Generate the password by picking random indices from the charset
    let password: String = (0..config.length)
        .map(|_| {
            let idx = rng.gen_range(0..charset.len());
            charset[idx]
        })
        .collect();

    password // Ownership of this String is returned to the caller
}
