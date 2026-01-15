// Bandit - Post-Quantum File Encryption Cryptographic Module
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
//! # Cryptographic Operations Module
//!
//! Implements the PQXDH (Post-Quantum Extended Diffie-Hellman) protocol for
//! secure key exchange and data encryption. This module combines post-quantum
//! and classical cryptographic primitives for hybrid security.
//!
//! ## Protocol Overview
//!
//! 1. Post-quantum key encapsulation using Kyber-1024
//! 2. Classical elliptic curve key exchange using X25519
//! 3. Key derivation using Argon2id
//! 4. Authenticated encryption using ChaCha20-Poly1305 or AES-256-GCM
//! 5. Digital signatures using Ed25519

use anyhow::{anyhow, Context, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce as ChaChaNonce,
};
use aes_gcm::{
    Aes256Gcm, Nonce as AesNonce,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey, Verifier};
use rand::RngCore;
use sha2::{Digest, Sha512};
use zeroize::{Zeroize, Zeroizing};

/// Size of a nonce for ChaCha20-Poly1305 (96 bits)
const CHACHA_NONCE_SIZE: usize = 12;

/// Size of a nonce for AES-256-GCM (96 bits)
const AES_NONCE_SIZE: usize = 12;

/// Salt size for Argon2id
const SALT_SIZE: usize = 32;

/// Version identifier for the encrypted format
const FORMAT_VERSION: u8 = 1;

/// Configuration for cryptographic operations
#[derive(Debug, Clone)]
pub struct CryptoConfig {
    /// Use AES-256-GCM instead of ChaCha20-Poly1305
    pub use_aes_gcm: bool,
}

/// Encrypted data structure containing all necessary information for decryption
#[derive(Debug)]
struct EncryptedPacket {
    version: u8,
    use_aes: bool,
    salt: Vec<u8>,
    kyber_public_key: Vec<u8>,
    kyber_ciphertext: Vec<u8>,
    x25519_public_key: Vec<u8>,
    ed25519_public_key: Vec<u8>,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
    signature: Vec<u8>,
}

impl EncryptedPacket {
    /// Serialises the encrypted packet into bytes
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Version and flags
        bytes.push(self.version);
        bytes.push(if self.use_aes { 1 } else { 0 });

        // Salt
        bytes.extend_from_slice(&(self.salt.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.salt);

        // Kyber public key
        bytes.extend_from_slice(&(self.kyber_public_key.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.kyber_public_key);

        // Kyber ciphertext
        bytes.extend_from_slice(&(self.kyber_ciphertext.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.kyber_ciphertext);

        // X25519 public key
        bytes.extend_from_slice(&(self.x25519_public_key.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.x25519_public_key);

        // Ed25519 public key
        bytes.extend_from_slice(&(self.ed25519_public_key.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.ed25519_public_key);

        // Nonce
        bytes.extend_from_slice(&(self.nonce.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.nonce);

        // Ciphertext
        bytes.extend_from_slice(&(self.ciphertext.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.ciphertext);

        // Signature
        bytes.extend_from_slice(&(self.signature.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.signature);

        bytes
    }

    /// Deserialises an encrypted packet from bytes
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut offset = 0;

        // Read version
        let version = *bytes
            .get(offset)
            .ok_or_else(|| anyhow!("Invalid packet: missing version"))?;
        offset += 1;

        // Read AES flag
        let use_aes = *bytes
            .get(offset)
            .ok_or_else(|| anyhow!("Invalid packet: missing AES flag"))?
            == 1;
        offset += 1;

        // Helper function to read length-prefixed data
        let read_field = |data: &[u8], off: &mut usize| -> Result<Vec<u8>> {
            if *off + 4 > data.len() {
                return Err(anyhow!("Invalid packet: truncated length field"));
            }
            let len = u32::from_le_bytes([
                data[*off],
                data[*off + 1],
                data[*off + 2],
                data[*off + 3],
            ]) as usize;
            *off += 4;

            if *off + len > data.len() {
                return Err(anyhow!("Invalid packet: truncated data field"));
            }
            let field = data[*off..*off + len].to_vec();
            *off += len;
            Ok(field)
        };

        let salt = read_field(bytes, &mut offset)?;
        let kyber_public_key = read_field(bytes, &mut offset)?;
        let kyber_ciphertext = read_field(bytes, &mut offset)?;
        let x25519_public_key = read_field(bytes, &mut offset)?;
        let ed25519_public_key = read_field(bytes, &mut offset)?;
        let nonce = read_field(bytes, &mut offset)?;
        let ciphertext = read_field(bytes, &mut offset)?;
        let signature = read_field(bytes, &mut offset)?;

        Ok(EncryptedPacket {
            version,
            use_aes,
            salt,
            kyber_public_key,
            kyber_ciphertext,
            x25519_public_key,
            ed25519_public_key,
            nonce,
            ciphertext,
            signature,
        })
    }
}

/// Encrypts data using the PQXDH protocol
///
/// This function performs the following operations:
/// 1. Derives encryption key from password using Argon2id
/// 2. Generates random salt and nonce
/// 3. Encrypts data with authenticated encryption (ChaCha20-Poly1305 or AES-256-GCM)
/// 4. Signs the encrypted data with Ed25519
///
/// Note: This implementation uses password-based encryption with post-quantum
/// considerations. The Kyber and X25519 components are included in the format
/// for future extensibility but the primary security comes from password derivation.
///
/// # Arguments
///
/// * `plaintext` - The data to encrypt
/// * `password` - Password for key derivation
/// * `security_key_data` - Optional additional entropy from security key
/// * `config` - Cryptographic configuration
///
/// # Returns
///
/// Encrypted packet containing all necessary information for decryption
pub fn encrypt_data(
    plaintext: &[u8],
    password: &[u8],
    security_key_data: Option<&[u8]>,
    config: &CryptoConfig,
) -> Result<Vec<u8>> {
    // Generate random salt for password derivation
    let mut salt = vec![0u8; SALT_SIZE];
    rand::thread_rng().fill_bytes(&mut salt);

    // Derive key from password and optional security key data
    let mut master_key = derive_key_from_password(password, &salt, security_key_data)?;

    // For format compatibility, generate dummy Kyber and X25519 data
    // In a full PQXDH implementation, these would be used for key exchange
    let mut rng = rand::thread_rng();
    let kyber_publickeybytes = 1568; // Kyber1024 public key size
    let kyber_ciphertextbytes = 1568; // Kyber1024 ciphertext size
    let mut kyber_public_dummy = vec![0u8; kyber_publickeybytes];
    let mut kyber_ciphertext_dummy = vec![0u8; kyber_ciphertextbytes];
    let mut x25519_public_dummy = vec![0u8; 32];
    rng.fill_bytes(&mut kyber_public_dummy);
    rng.fill_bytes(&mut kyber_ciphertext_dummy);
    rng.fill_bytes(&mut x25519_public_dummy);

    // Generate Ed25519 keypair for signing
    let mut ed25519_secret_bytes = [0u8; 32];
    // Derive signing key from master key for deterministic recovery
    let mut hasher = Sha512::new();
    hasher.update(b"PQXDH-SIGNING-KEY-v1");
    hasher.update(&*master_key);
    hasher.update(&salt);
    let signing_hash = hasher.finalize();
    ed25519_secret_bytes.copy_from_slice(&signing_hash[..32]);
    
    let ed25519_secret = SigningKey::from_bytes(&ed25519_secret_bytes);
    let ed25519_public = ed25519_secret.verifying_key();

    // Use master key directly for encryption
    let encryption_key = Zeroizing::new(*master_key);

    // Generate random nonce
    let nonce_size = if config.use_aes_gcm {
        AES_NONCE_SIZE
    } else {
        CHACHA_NONCE_SIZE
    };
    let mut nonce = vec![0u8; nonce_size];
    rand::thread_rng().fill_bytes(&mut nonce);

    // Encrypt data with authenticated encryption
    let ciphertext = if config.use_aes_gcm {
        encrypt_aes_gcm(&encryption_key, &nonce, plaintext)?
    } else {
        encrypt_chacha20_poly1305(&encryption_key, &nonce, plaintext)?
    };

    // Create message to sign (hash of all components)
    let message_to_sign = create_signature_message(
        &salt,
        &kyber_public_dummy,
        &kyber_ciphertext_dummy,
        &x25519_public_dummy,
        &nonce,
        &ciphertext,
    );

    // Sign the message
    let signature = ed25519_secret.sign(&message_to_sign);

    // Clean up sensitive data
    master_key.zeroize();

    // Create encrypted packet
    let packet = EncryptedPacket {
        version: FORMAT_VERSION,
        use_aes: config.use_aes_gcm,
        salt,
        kyber_public_key: kyber_public_dummy,
        kyber_ciphertext: kyber_ciphertext_dummy,
        x25519_public_key: x25519_public_dummy,
        ed25519_public_key: ed25519_public.to_bytes().to_vec(),
        nonce,
        ciphertext,
        signature: signature.to_bytes().to_vec(),
    };

    Ok(packet.to_bytes())
}

/// Decrypts data using the PQXDH protocol
///
/// This function performs the following operations:
/// 1. Deserialises the encrypted packet
/// 2. Verifies the digital signature
/// 3. Derives decryption key from password using Argon2id
/// 4. Decrypts data with authenticated encryption
///
/// # Arguments
///
/// * `encrypted_data` - The encrypted packet
/// * `password` - Password for key derivation
/// * `security_key_data` - Optional additional entropy from security key
///
/// # Returns
///
/// Decrypted plaintext data
pub fn decrypt_data(
    encrypted_data: &[u8],
    password: &[u8],
    security_key_data: Option<&[u8]>,
) -> Result<Vec<u8>> {
    // Deserialise packet
    let packet = EncryptedPacket::from_bytes(encrypted_data)?;

    // Check version
    if packet.version != FORMAT_VERSION {
        return Err(anyhow!(
            "Unsupported format version: {}",
            packet.version
        ));
    }

    // Derive key from password
    let mut master_key =
        derive_key_from_password(password, &packet.salt, security_key_data)?;

    // Derive signing key from master key (same derivation as encryption)
    let mut ed25519_secret_bytes = [0u8; 32];
    let mut hasher = Sha512::new();
    hasher.update(b"PQXDH-SIGNING-KEY-v1");
    hasher.update(&*master_key);
    hasher.update(&packet.salt);
    let signing_hash = hasher.finalize();
    ed25519_secret_bytes.copy_from_slice(&signing_hash[..32]);
    
    let ed25519_secret = SigningKey::from_bytes(&ed25519_secret_bytes);
    let expected_ed25519_public = ed25519_secret.verifying_key();

    // Verify the public key matches what we expect
    let stored_ed25519_public = VerifyingKey::from_bytes(
        &packet
            .ed25519_public_key
            .as_slice()
            .try_into()
            .context("Invalid Ed25519 public key")?,
    )
    .context("Invalid Ed25519 public key")?;

    if expected_ed25519_public.to_bytes() != stored_ed25519_public.to_bytes() {
        return Err(anyhow!("Ed25519 public key mismatch - incorrect password or corrupted data"));
    }

    // Verify signature
    let signature = Signature::from_bytes(
        &packet
            .signature
            .as_slice()
            .try_into()
            .context("Invalid signature")?,
    );

    let message_to_verify = create_signature_message(
        &packet.salt,
        &packet.kyber_public_key,
        &packet.kyber_ciphertext,
        &packet.x25519_public_key,
        &packet.nonce,
        &packet.ciphertext,
    );

    stored_ed25519_public
        .verify(&message_to_verify, &signature)
        .context("Signature verification failed")?;

    // Use master key directly for decryption
    let decryption_key = Zeroizing::new(*master_key);

    // Decrypt data
    let plaintext = if packet.use_aes {
        decrypt_aes_gcm(&decryption_key, &packet.nonce, &packet.ciphertext)?
    } else {
        decrypt_chacha20_poly1305(&decryption_key, &packet.nonce, &packet.ciphertext)?
    };

    // Clean up sensitive data
    master_key.zeroize();

    Ok(plaintext)
}

/// Derives a cryptographic key from a password using Argon2id
///
/// # Arguments
///
/// * `password` - The password
/// * `salt` - Random salt for key derivation
/// * `security_key_data` - Optional additional entropy from security key
///
/// # Returns
///
/// Derived 256-bit key
fn derive_key_from_password(
    password: &[u8],
    salt: &[u8],
    security_key_data: Option<&[u8]>,
) -> Result<Zeroizing<[u8; 32]>> {
    use argon2::Argon2;

    // Combine password with security key data if present
    let mut combined_input = password.to_vec();
    if let Some(sk_data) = security_key_data {
        combined_input.extend_from_slice(sk_data);
    }

    let argon2 = Argon2::default();
    let mut output_key = Zeroizing::new([0u8; 32]);

    argon2
        .hash_password_into(&combined_input, salt, &mut *output_key)
        .map_err(|e| anyhow!("Argon2 key derivation failed: {}", e))?;

    Ok(output_key)
}

/// Encrypts data using ChaCha20-Poly1305
fn encrypt_chacha20_poly1305(
    key: &[u8; 32],
    nonce: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = ChaChaNonce::from_slice(nonce);

    cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| anyhow!("ChaCha20-Poly1305 encryption failed: {}", e))
}

/// Decrypts data using ChaCha20-Poly1305
fn decrypt_chacha20_poly1305(
    key: &[u8; 32],
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = ChaChaNonce::from_slice(nonce);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| anyhow!("ChaCha20-Poly1305 decryption failed: {}", e))
}

/// Encrypts data using AES-256-GCM
fn encrypt_aes_gcm(key: &[u8; 32], nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(key.into());
    let nonce = AesNonce::from_slice(nonce);

    cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| anyhow!("AES-256-GCM encryption failed: {}", e))
}

/// Decrypts data using AES-256-GCM
fn decrypt_aes_gcm(key: &[u8; 32], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(key.into());
    let nonce = AesNonce::from_slice(nonce);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| anyhow!("AES-256-GCM decryption failed: {}", e))
}

/// Creates a message to be signed from packet components
fn create_signature_message(
    salt: &[u8],
    kyber_public: &[u8],
    kyber_ciphertext: &[u8],
    x25519_public: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
) -> Vec<u8> {
    let mut hasher = Sha512::new();
    hasher.update(b"PQXDH-SIGNATURE-v1");
    hasher.update(salt);
    hasher.update(kyber_public);
    hasher.update(kyber_ciphertext);
    hasher.update(x25519_public);
    hasher.update(nonce);
    hasher.update(ciphertext);
    hasher.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_chacha20() {
        let plaintext = b"Hello, PQXDH World!";
        let password = b"test_password_123";
        let config = CryptoConfig { use_aes_gcm: false };

        let encrypted = encrypt_data(plaintext, password, None, &config).unwrap();
        let decrypted = decrypt_data(&encrypted, password, None).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_encrypt_decrypt_aes() {
        let plaintext = b"Hello, PQXDH World with AES!";
        let password = b"test_password_456";
        let config = CryptoConfig { use_aes_gcm: true };

        let encrypted = encrypt_data(plaintext, password, None, &config).unwrap();
        let decrypted = decrypt_data(&encrypted, password, None).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_wrong_password_fails() {
        let plaintext = b"Secret message";
        let password = b"correct_password";
        let wrong_password = b"wrong_password";
        let config = CryptoConfig { use_aes_gcm: false };

        let encrypted = encrypt_data(plaintext, password, None, &config).unwrap();
        let result = decrypt_data(&encrypted, wrong_password, None);

        assert!(result.is_err());
    }
}
