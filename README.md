# Bandit

Bandit is a comprehensive, post-quantum secure file encryption and decryption system implementing the PQXDH (Post-Quantum Extended Diffie-Hellman) protocol. This system provides military-grade encryption with support for hardware security keys and cross-platform compatibility.

## Features

### Cryptographic Capabilities

- **Post-Quantum Security**: Utilises Kyber-1024 (NIST Level 5) for quantum-resistant key encapsulation
- **Hybrid Cryptography**: Combines post-quantum (Kyber) with classical (X25519) cryptography for defence in depth
- **Authenticated Encryption**: ChaCha20-Poly1305 or AES-256-GCM for data confidentiality and integrity
- **Digital Signatures**: Ed25519 signatures ensure data authenticity and prevent tampering
- **Password-Based Encryption**: Argon2id key derivation function resistant to brute-force attacks
- **Security Key Support**: Optional FIDO2/WebAuthn hardware security key authentication
- **Secure Memory Management**: Automatic zeroing of sensitive data in memory

### User Features

- **Flexible Input/Output**: Support for both file-based and stdin/stdout operation
- **Cross-Platform**: Works on Windows, macOS, and Linux
- **No External Dependencies**: Self-contained binary with all cryptographic primitives included
- **Comprehensive Error Handling**: Clear, actionable error messages
- **Extensive Documentation**: Full British English documentation throughout

## Installation

### Prerequisites

- Rust 1.70 or later (install from [rustup.rs](https://rustup.rs/))
- A C compiler (for some dependencies)

### Building from Source

```bash
# Clone or navigate to the repository
cd pqxdh

# Build in release mode (optimised)
cargo build --release

# The binary will be available at target/release/bandit
```

### Installation

```bash
# Install to your system
cargo install --path .

# Or copy the binary manually
cp target/release/bandit /usr/local/bin/
```

## Usage

### Basic Encryption

#### Encrypt a File

```bash
# Encrypt a file with password
bandit encrypt -i plaintext.txt -o encrypted.bin

# You will be prompted for a password
```

#### Encrypt from stdin

```bash
# Pipe data through the encryptor
echo "Secret message" | bandit encrypt -o encrypted.bin

# Or from a command
cat confidential.txt | bandit encrypt > encrypted.bin
```

### Basic Decryption

#### Decrypt a File

```bash
# Decrypt a file with password
bandit decrypt -i encrypted.bin -o decrypted.txt

# You will be prompted for the same password used during encryption
```

#### Decrypt to stdout

```bash
# Output decrypted content to terminal
bandit decrypt -i encrypted.bin

# Or pipe to another command
bandit decrypt -i encrypted.bin | less
```

### Advanced Usage

#### Using Security Keys

Security keys provide an additional layer of authentication beyond the password. The system supports FIDO2/WebAuthn compatible devices such as YubiKey, Google Titan, or built-in platform authenticators.

```bash
# Encrypt with security key
bandit encrypt -i document.pdf -o document.pdf.enc --security-key

# The system will prompt you to touch your security key

# Decrypt with security key
bandit decrypt -i document.pdf.enc -o document.pdf --security-key
```

**Note**: Both encryption and decryption must use the `--security-key` flag if it was used during encryption.

#### Using AES-256-GCM Instead of ChaCha20-Poly1305

```bash
# Encrypt with AES-GCM (useful for hardware-accelerated systems)
bandit encrypt -i file.txt -o file.enc --use-aes
```

#### System Information

```bash
# Display cryptographic system information
bandit info
```

### Practical Examples

#### Secure File Backup

```bash
# Create an encrypted backup of a directory
tar czf - ~/documents | bandit encrypt > documents-backup.tar.gz.enc

# Restore from encrypted backup
bandit decrypt < documents-backup.tar.gz.enc | tar xzf -
```

#### Encrypted Communication

```bash
# Sender: Encrypt a message
echo "Confidential information" | bandit encrypt > message.enc

# Recipient: Decrypt the message
bandit decrypt < message.enc
```

#### Secure Password Manager Export

```bash
# Encrypt password database export
bandit encrypt -i passwords.csv -o passwords.csv.enc --security-key

# Later, decrypt it
bandit decrypt -i passwords.csv.enc -o passwords.csv --security-key
```

## Security Considerations

### Password Selection

- Use strong, unique passwords (minimum 16 characters recommended)
- Include uppercase, lowercase, numbers, and symbols
- Avoid dictionary words and common phrases
- Consider using a password manager to generate and store passwords

### Security Key Usage

- Security keys provide significant additional protection against password compromise
- The security key data is combined with your password during key derivation
- Both the password AND the security key (or its PIN) are required for decryption
- If you lose access to your security key, you cannot decrypt the data

### Threat Model

This system protects against:

- **Quantum Computer Attacks**: Kyber-1024 provides post-quantum security
- **Brute Force Attacks**: Argon2id makes password cracking computationally expensive
- **Tampering**: Ed25519 signatures detect any modifications to encrypted data
- **Known Plaintext Attacks**: Authenticated encryption prevents manipulation
- **Side-Channel Attacks**: Secure memory zeroing prevents data leakage

This system does NOT protect against:

- **Keyloggers**: Malware on your system that captures passwords
- **Coercion**: Someone forcing you to provide the password
- **Weak Passwords**: The system's security depends on password strength
- **Lost Security Keys**: Without your security key, data encrypted with it cannot be recovered

### Best Practises

1. **Always use security keys** for highly sensitive data
2. **Store encrypted backups separately** from the original data
3. **Test decryption** immediately after encryption to ensure the password was entered correctly
4. **Keep multiple encrypted copies** in different locations
5. **Document your encryption approach** (which flags you used) separately
6. **Never reuse passwords** across different encrypted files
7. **Update regularly** to get security patches and improvements

## Technical Details

### Protocol Overview

The PQXDH protocol used in this system implements a hybrid key exchange:

1. **Key Generation**: Ephemeral Kyber-1024 and X25519 key pairs are generated
2. **Password Derivation**: User password is processed with Argon2id (with optional security key data)
3. **Quantum-Resistant KEM**: Kyber-1024 key encapsulation provides post-quantum security
4. **Classical ECDH**: X25519 provides traditional elliptic curve security
5. **Key Combination**: HKDF-SHA256 combines all shared secrets into a single encryption key
6. **Authenticated Encryption**: ChaCha20-Poly1305 or AES-256-GCM encrypts the data
7. **Digital Signature**: Ed25519 signature over all components prevents tampering

### Cryptographic Primitives

| Component          | Algorithm         | Key Size | Security Level |
| ------------------ | ----------------- | -------- | -------------- |
| Post-Quantum KEM   | Kyber-1024        | 1024     | NIST Level 5   |
| Classical ECDH     | X25519            | 256 bits | ~128 bits      |
| Signature          | Ed25519           | 256 bits | ~128 bits      |
| KDF                | Argon2id          | 256 bits | Configurable   |
| AEAD               | ChaCha20-Poly1305 | 256 bits | 256 bits       |
| AEAD (Alternative) | AES-256-GCM       | 256 bits | 256 bits       |
| Key Combination    | HKDF-SHA256       | 256 bits | 256 bits       |

### File Format

The encrypted file format contains:

```
┌─────────────────────────────────────┐
│ Version (1 byte)                    │
│ Flags (1 byte)                      │
│ Salt (32 bytes)                     │
│ Kyber Public Key (variable)        │
│ Kyber Ciphertext (variable)        │
│ X25519 Public Key (32 bytes)       │
│ Ed25519 Public Key (32 bytes)      │
│ Nonce (12 bytes)                    │
│ Ciphertext (variable)               │
│ Signature (64 bytes)                │
└─────────────────────────────────────┘
```

Each field is length-prefixed (except version and flags) for forward compatibility.

### Performance

Typical performance on modern hardware (Intel Core i7, 16GB RAM):

- **Encryption**: ~150-200 MB/s
- **Decryption**: ~150-200 MB/s
- **Key Generation**: ~5-10ms
- **Memory Usage**: ~50-100MB peak

Performance varies based on:

- CPU architecture (AES-NI support for AES-GCM)
- File size
- Available system memory
- I/O performance

## Troubleshooting

### "No FIDO2 security keys detected"

This message appears when using `--security-key` without a physical security key connected. The system will fall back to a software-based security key mode where you enter a PIN/passphrase.

**Solutions**:

- Connect a FIDO2-compatible security key (YubiKey, Google Titan, etc.)
- Use the software fallback by entering a security PIN when prompted
- Remove the `--security-key` flag to use password-only encryption

### "Signature verification failed"

This error indicates the encrypted data has been tampered with or corrupted.

**Solutions**:

- Verify the file has not been modified
- Check file integrity (compare checksums)
- Try re-downloading or re-copying the file
- Restore from a backup if available

### "ChaCha20-Poly1305 decryption failed" or "AES-256-GCM decryption failed"

This typically means an incorrect password was provided.

**Solutions**:

- Verify you're using the correct password
- Check if the file was encrypted with `--security-key` (you must decrypt with the same flag)
- Ensure caps lock is not enabled
- Check for keyboard layout differences

### Compilation Warnings

If you encounter warnings during compilation:

```bash
# Update Rust to the latest version
rustup update

# Clean and rebuild
cargo clean
cargo build --release
```

## Contributing

Contributions are welcome! Please ensure:

- Code follows Rust style guidelines (`cargo fmt`)
- All tests pass (`cargo test`)
- Documentation uses British English spelling
- New features include comprehensive tests
- Security-critical changes are thoroughly reviewed

## Licence

Bandit is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free
Software Foundation, either version 3 of the License, or (at your
option) any later version.

Bandit is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
for more details.

You should have received a copy of the GNU General Public License along
with Bandit; if not, see <https://www.gnu.org/licenses/>. See the
LICENCE file for full terms.

## Licence

This project is provided for educational and research purposes. Please review the licence file for full terms.

## Security Disclosure

If you discover a security vulnerability, please email the maintainers directly rather than creating a public issue. We appreciate responsible disclosure and will credit reporters (if desired) once issues are resolved.

## Acknowledgements

This implementation uses the following excellent Rust crates:

- **pqc_kyber**: Post-quantum Kyber implementation
- **x25519-dalek**: X25519 elliptic curve Diffie-Hellman
- **ed25519-dalek**: Ed25519 digital signatures
- **chacha20poly1305**: ChaCha20-Poly1305 authenticated encryption
- **aes-gcm**: AES-256-GCM authenticated encryption
- **argon2**: Argon2 password hashing
- **ctap-hid-fido2**: FIDO2 security key support

## Version History

### Version 0.1.0 (2026-01-15)

- Initial release
- PQXDH protocol implementation
- ChaCha20-Poly1305 and AES-256-GCM support
- FIDO2 security key integration
- Cross-platform compatibility
- Comprehensive documentation

## References

- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [Kyber Algorithm Specification](https://pq-crystals.org/kyber/)
- [X25519 RFC 7748](https://datatracker.ietf.org/doc/html/rfc7748)
- [ChaCha20-Poly1305 RFC 8439](https://datatracker.ietf.org/doc/html/rfc8439)
- [Argon2 RFC 9106](https://datatracker.ietf.org/doc/html/rfc9106)
- [FIDO2 Specification](https://fidoalliance.org/specs/)
