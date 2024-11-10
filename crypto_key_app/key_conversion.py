from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519

# Define key format mappings
keyFormat = {
    "private_key": {
        "RSA": rsa.RSAPrivateKey,
        "ECDSA": ec.EllipticCurvePrivateKey,
        "ED25519": ed25519.Ed25519PrivateKey
    },
    "public_key": {
        "RSA": rsa.RSAPublicKey,
        "ECDSA": ec.EllipticCurvePublicKey,
        "ED25519": ed25519.Ed25519PublicKey
    }
}
# To do : check if DER support is needed
# PEM (Privacy-Enhanced Mail): This is a text-based encoding that wraps binary data in a base64 encoding and includes header and footer markers such as -----BEGIN PRIVATE KEY----- and -----END PRIVATE KEY-----.
# PEM is often used when transferring keys as plain text files.

# DER (Distinguished Encoding Rules): This is a binary format for data structures, more compact than PEM, and does not include the base64 encoding or the header/footer markers.
# DER-encoded keys are purely binary and are often used in certificates or when keys need to be processed in a more machine-efficient way.

# Determine the key type and format (e.g., RSA, ECDSA, ED25519)
def determine_key_format(key):
    for key_type, formats in keyFormat.items():
        for format_name, format_class in formats.items():
            if isinstance(key, format_class):
                return format_name, key_type
    raise ValueError("Invalid or unsupported key format")

# Convert a PEM key to a hexadecimal string
def pem_to_hex(pem_key):
    key_format, key_type = determine_key_format(pem_key)

    if key_type == "private_key":
        pem_bytes = pem_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8 if key_format != "RSA" else serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
    elif key_type == "public_key":
        pem_bytes = pem_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    else:
        raise ValueError("Unsupported key type for conversion to hex")

    return pem_bytes.hex()

# Convert a hexadecimal string to a PEM key object
def hex_to_pem(hex_key):
    try:
        # Convert the hex string back to PEM bytes
        pem_bytes = bytes.fromhex(hex_key)

        # Attempt to load the key as a private or public key
        try:
            key = serialization.load_pem_private_key(
                pem_bytes,
                password=None
            )
        except (ValueError, TypeError):
            # If not a private key, try loading it as a public key
            try:
                key = serialization.load_pem_public_key(pem_bytes)
            except ValueError as e:
                raise ValueError("Invalid key data: unable to parse as a valid private or public key") from e
        
        return key

    except ValueError as e:
        raise ValueError("Invalid hexadecimal string: could not decode") from e
