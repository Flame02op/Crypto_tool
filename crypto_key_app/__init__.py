# A tool with user interface for performing below cryptographic operations
# 1. Encryption/Decryption (Support various AES standards) -> AES CBC and AES CTR
# 2. CMAC Generation/Verification (Support various standards)
# 3. Signature Verification/Generation (Support various algorithms like RSA, ECDSA, etc) -> RSA and ECDSA
# 4. Key format conversion (hex to pem, pem to hex, etc)
# 5. Random Number Generation
# 6. Hash Calculation/Verification (support all types)
# 7. CRC Calculation/Verification (support all types)
# 8. Key Generation/Verification


# AES -> symmetrical (public key)

# For RSA Support below
# RSASSA-PSS
# SHA256withRSA
# sha512WithRSA
# md5WithRSA

# For Ecdsa
# SECP256r1
# Secp256k1
# Secp128r1

# RSA-OAEP (Optimal Asymmetric Encryption Padding): While primarily used for encryption,
# RSA-OAEP can also be used in signature schemes.

# RSA-PSS (Probabilistic Signature Scheme): This is a more modern and secure variant of RSA signatures.
# It uses a probabilistic padding scheme, making it more resistant to certain types of cryptographic attacks.

# RSA-PKCS#1 v1.5: This is the original RSA signature scheme defined in PKCS#1 v1.5.
# It uses a specific padding scheme for the message before signing.




# Testing:

# TAB 1
# Key generation for all types (Done)
# key conversions for all types (Done)
# signature generation and verification for all types (Done)
# generate and update hash for all types (Done)
# signature for long messages for all types (Done)

# TAB2
# Encryption and decryption for all types
# generate and verify hash for all types

# TAB3
# CMAC generation and verification
# CRC generation and verification
# Random bytes generation

# TAB4
# Update description
# Update user manual