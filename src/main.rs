// Bandit - Post-Quantum File Encryption
// Copyright (C) 2026 Andy Dixon
// Contact: bandit@dixon.cx - https://www.dixon.cx
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
//!
//! # Bandit
//!
//! A comprehensive post-quantum secure file encryption and decryption system implementing
//! the PQXDH (Post-Quantum Extended Diffie-Hellman) protocol.
//!
//! ## Features
//!
//! - Post-quantum secure key exchange using Kyber-1024
//! - Classical X25519 key exchange for hybrid security
//! - ChaCha20-Poly1305 authenticated encryption
//! - Argon2id key derivation from passwords
//! - Optional FIDO2/WebAuthn security key support
//! - Support for stdin/stdout and file I/O
//! - Secure memory zeroing
//! - Cross-platform compatibility

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::io::{self, Read, Write};
use std::path::PathBuf;
use zeroize::Zeroize;

mod crypto;
mod security_key;

use crypto::{decrypt_data, encrypt_data, CryptoConfig};
use security_key::SecurityKeyManager;

/// Bandit Encryption System
///
/// Provides post-quantum secure encryption and decryption of files or stdin data
/// using the PQXDH protocol with optional security key authentication.
#[derive(Parser, Debug)]
#[command(
    name = "bandit",
    version,
    author,
    about = "Bandit - Post-Quantum Extended Diffie-Hellman file encryption system",
    long_about = None
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Encrypt a file or stdin data
    Encrypt {
        /// Input file path (omit to read from stdin)
        #[arg(short, long)]
        input: Option<PathBuf>,

        /// Output file path (omit to write to stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Use password-only authentication (no security key)
        #[arg(short, long)]
        password: bool,

        /// Use AES-GCM instead of ChaCha20-Poly1305
        #[arg(long)]
        use_aes: bool,
    },

    /// Decrypt a file or stdin data
    Decrypt {
        /// Input file path (omit to read from stdin)
        #[arg(short, long)]
        input: Option<PathBuf>,

        /// Output file path (omit to write to stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Use password-only authentication (no security key)
        #[arg(short, long)]
        password: bool,
    },

    /// Generate and display new key pair information
    Info,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Encrypt {
            input,
            output,
            password,
            use_aes,
        } => handle_encrypt(input, output, password, use_aes),

        Commands::Decrypt {
            input,
            output,
            password,
        } => handle_decrypt(input, output, password),

        Commands::Info => handle_info(),
    }
}

/// Handles the encryption operation
///
/// Reads data from the specified input (file or stdin), encrypts it using PQXDH
/// with the provided password and optional security key, then writes the encrypted
/// data to the specified output (file or stdout).
fn handle_encrypt(
    input: Option<PathBuf>,
    output: Option<PathBuf>,
    password_only: bool,
    use_aes: bool,
) -> Result<()> {
    eprintln!("🔐 Bandit Encryption System");
    eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━");

    let use_security_key = !password_only;

    // Read input data
    let plaintext = read_input(input.as_ref())?;
    eprintln!("✓ Read {} bytes of input data", plaintext.len());

    // Get security key data first (default behavior)
    let mut security_key_data: Option<Vec<u8>> = None;
    if use_security_key {
        eprintln!("\n🔑 Security key authentication required");
        let key_manager = SecurityKeyManager::new()?;
        security_key_data = Some(key_manager.authenticate()?);
        eprintln!("✓ Security key authenticated successfully");
    }

    // Get password (optional if using security key)
    let mut password = if password_only {
        prompt_password("Enter encryption password: ")?
    } else {
        match prompt_password("Enter encryption password (optional, press Enter to skip): ") {
            Ok(pwd) if !pwd.is_empty() => pwd,
            _ => String::new(),
        }
    };

    // Configure cryptographic settings
    let config = CryptoConfig {
        use_aes_gcm: use_aes,
    };

    // Perform encryption
    eprintln!("\n🔒 Encrypting data with PQXDH...");
    let ciphertext = encrypt_data(
        &plaintext,
        password.as_bytes(),
        security_key_data.as_deref(),
        &config,
    )?;

    // Secure cleanup
    password.zeroize();
    if let Some(ref mut data) = security_key_data {
        data.zeroize();
    }

    eprintln!("✓ Encryption complete ({} bytes)", ciphertext.len());

    // Write output
    write_output(output.as_ref(), &ciphertext)?;
    eprintln!("✓ Output written successfully");

    Ok(())
}

/// Handles the decryption operation
///
/// Reads encrypted data from the specified input (file or stdin), decrypts it using
/// PQXDH with the provided password and optional security key, then writes the
/// decrypted data to the specified output (file or stdout).
fn handle_decrypt(
    input: Option<PathBuf>,
    output: Option<PathBuf>,
    password_only: bool,
) -> Result<()> {
    eprintln!("🔓 Bandit Decryption System");
    eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━");

    let use_security_key = !password_only;

    // Read encrypted data
    let ciphertext = read_input(input.as_ref())?;
    eprintln!("✓ Read {} bytes of encrypted data", ciphertext.len());

    // Get security key data first (default behavior)
    let mut security_key_data: Option<Vec<u8>> = None;
    if use_security_key {
        eprintln!("\n🔑 Security key authentication required");
        let key_manager = SecurityKeyManager::new()?;
        security_key_data = Some(key_manager.authenticate()?);
        eprintln!("✓ Security key authenticated successfully");
    }

    // Get password (optional if using security key)
    let mut password = if password_only {
        prompt_password("Enter decryption password: ")?
    } else {
        match prompt_password("Enter decryption password (optional, press Enter to skip): ") {
            Ok(pwd) if !pwd.is_empty() => pwd,
            _ => String::new(),
        }
    };

    // Perform decryption
    eprintln!("\n🔓 Decrypting data with PQXDH...");
    let plaintext = decrypt_data(
        &ciphertext,
        password.as_bytes(),
        security_key_data.as_deref(),
    )?;

    // Secure cleanup
    password.zeroize();
    if let Some(ref mut data) = security_key_data {
        data.zeroize();
    }

    eprintln!("✓ Decryption complete ({} bytes)", plaintext.len());

    // Write output
    write_output(output.as_ref(), &plaintext)?;
    eprintln!("✓ Output written successfully");

    Ok(())
}

/// Displays information about the Bandit system and generates sample keys
fn handle_info() -> Result<()> {
    eprintln!("📋 Bandit Encryption System Information");
    eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    eprintln!();
    eprintln!("Protocol: Post-Quantum Extended Diffie-Hellman");
    eprintln!("Post-Quantum KEM: Kyber-1024 (NIST Level 5)");
    eprintln!("Classical ECDH: X25519");
    eprintln!("Signature: Ed25519");
    eprintln!("Encryption: ChaCha20-Poly1305 (or AES-256-GCM)");
    eprintln!("KDF: Argon2id");
    eprintln!("Key Size: 256 bits");
    eprintln!();
    eprintln!("✓ System ready for encryption and decryption operations");

    Ok(())
}

/// Reads input data from a file or stdin
///
/// # Arguments
///
/// * `path` - Optional path to input file. If `None`, reads from stdin.
///
/// # Returns
///
/// A vector containing the input data
fn read_input(path: Option<&PathBuf>) -> Result<Vec<u8>> {
    let mut buffer = Vec::new();

    if let Some(path) = path {
        let mut file = std::fs::File::open(path)
            .with_context(|| format!("Failed to open input file: {}", path.display()))?;
        file.read_to_end(&mut buffer)
            .context("Failed to read input file")?;
    } else {
        io::stdin()
            .read_to_end(&mut buffer)
            .context("Failed to read from stdin")?;
    }

    Ok(buffer)
}

/// Writes output data to a file or stdout
///
/// # Arguments
///
/// * `path` - Optional path to output file. If `None`, writes to stdout.
/// * `data` - Data to write
fn write_output(path: Option<&PathBuf>, data: &[u8]) -> Result<()> {
    if let Some(path) = path {
        std::fs::write(path, data)
            .with_context(|| format!("Failed to write output file: {}", path.display()))?;
    } else {
        io::stdout()
            .write_all(data)
            .context("Failed to write to stdout")?;
    }

    Ok(())
}

/// Prompts the user for a password without echoing
///
/// # Arguments
///
/// * `prompt` - The prompt message to display
///
/// # Returns
///
/// The password entered by the user
fn prompt_password(prompt: &str) -> Result<String> {
    rpassword::prompt_password(prompt).context("Failed to read password")
}
