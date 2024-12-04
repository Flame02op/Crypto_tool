# Cryptography Tool

This tool provides various cryptographic functionalities including key generation, encryption, decryption, hashing, digital signatures, and more.

## Symmetric Cryptography

This type of cryptography uses a shared key (known to both sender and receiver) and thus the name symmetric cryptography.

### DES: Data Encryption Standard

- Key length: 56 bits.
- Block cipher with block size of 64 bits.
- Initially, the key consists of 64 bits. However, before the DES process even begins, every 8th bit is discarded to produce a 56-bit key.

### AES: Advanced Encryption Standard

- AES is a Block Cipher.
- The key size can be 128/192/256 bits.
- Encrypts data in blocks of 128 bits each.
- Works on bytes instead of bits (as in the case of DES), thus it takes 128 bits or 16 bytes of plaintext as input and generates 16 bytes of ciphered text.

#### Encryption
- Treats each block of 128-bits or 16 bytes as a 4-byte x 4-byte grid.

## Asymmetric Cryptography

This type of cryptography uses a pair of keys (public and private) for encryption and decryption, and for digital signatures.

### RSA: Rivest-Shamir-Adleman

- Key length: Typically 2048 or 4096 bits.
- Used for secure data transmission.
- Can be used for both encryption and digital signatures.

### ECDSA: Elliptic Curve Digital Signature Algorithm

- Based on elliptic curve cryptography.
- Provides the same level of security as RSA but with smaller key sizes.
- Commonly used for digital signatures.

### Ed25519

- High-speed, high-security signatures.
- Based on the Edwards-curve Digital Signature Algorithm (EdDSA).
- Provides fast signing and verification.

## Hashing

Hashing is used to ensure data integrity by producing a fixed-size hash value from input data.

### SHA: Secure Hash Algorithm

- SHA-256, SHA-384, SHA-512 are commonly used.
- Produces a fixed-size hash value (e.g., 256 bits for SHA-256).

### CRC: Cyclic Redundancy Check

- Used for error-checking in data transmission.
- Produces a fixed-size checksum based on the input data.

## Digital Signatures

Digital signatures provide authentication and integrity for messages.

### RSA Signatures

- Uses RSA keys for signing and verification.
- Commonly used for secure communications.

### ECDSA Signatures

- Uses elliptic curve cryptography for signing and verification.
- Provides strong security with smaller key sizes.

### Ed25519 Signatures

- Uses EdDSA for fast and secure signatures.
- Suitable for high-performance applications.

## Message Authentication Codes (MACs)

MACs provide data integrity and authenticity using a symmetric key.

### HMAC: Hash-based Message Authentication Code

- Uses a cryptographic hash function and a secret key.
- Commonly used for data integrity checks.

### CMAC: Cipher-based Message Authentication Code

- Uses a block cipher (e.g., AES) and a secret key.
- Provides data integrity and authenticity.

## Random Number Generation

Random numbers are used for key generation, nonces, and other cryptographic operations.

### Generating Random Bytes

- Uses a secure random number generator to produce random bytes.
- Commonly used for generating cryptographic keys.

## Key Management

Key management involves generating, storing, and converting cryptographic keys.

### Key Generation

- Generates symmetric and asymmetric keys.
- Supports AES, RSA, ECDSA, and Ed25519 key generation.

### Key Conversion

- Converts keys between different formats (e.g., PEM to HEX).
- Supports both symmetric and asymmetric keys.

## Usage

To use this tool, follow the instructions provided in the `setup_env.bat` script to create a virtual environment and install the necessary dependencies. Then, run the tool using the provided GUI or command-line interface.

```bash
# Create and activate the virtual environment
call setup_env.bat

# Run the tool
python GUI/crypto_gui.py
```