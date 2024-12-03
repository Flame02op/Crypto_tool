from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
import base64

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
    },
    "Symmetric" : bytes
}
# To do : check if DER support is needed
# PEM (Privacy-Enhanced Mail): This is a text-based encoding that wraps binary data in a base64 encoding and includes header and footer markers such as -----BEGIN PRIVATE KEY----- and -----END PRIVATE KEY-----.
# PEM is often used when transferring keys as plain text files.

# DER (Distinguished Encoding Rules): This is a binary format for data structures, more compact than PEM, and does not include the base64 encoding or the header/footer markers.
# DER-encoded keys are purely binary and are often used in certificates or when keys need to be processed in a more machine-efficient way.

# Determine the key type and format (e.g., RSA, ECDSA, ED25519)
def determine_key_format(key):
    for key_type, formats in keyFormat.items():
        if isinstance(formats, dict):
            for format_name, format_class in formats.items():
                if isinstance(key, format_class):
                    return format_name, key_type
        else:
            if isinstance(key, formats):
                return key_type, key_type
    raise ValueError("Invalid or unsupported key format")

# Convert a PEM key to a hexadecimal string
def pem_to_hex(pem_key):
    try:
        key_format, key_type = determine_key_format(pem_key)

        if key_type == "private_key":
            pem_bytes = pem_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8 if key_format != "RSA" else serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
            return ("Success", pem_bytes.hex())
        elif key_type == "public_key":
            pem_bytes = pem_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            return ("Success", pem_bytes.hex())
        elif key_type == "Symmetric":
            pem_key = pem_key.replace("-----BEGIN AES KEY-----\n", "").replace("\n-----END AES KEY-----", "")
            hex_key = base64.b64decode(pem_key)
            return ("Success", hex_key)
        else:
            raise ValueError("Unsupported key type for conversion to hex")
        
    except Exception as e:
        return ("Error", str(e))

# Convert a hexadecimal string to a PEM key object
def hex_to_pem(hex_key):
    try:
        # Convert the hex string back to bytes
        key_bytes = bytes.fromhex(hex_key)
        
        # Attempt to load the key as a private key
        try:
            key = serialization.load_pem_private_key(key_bytes, password=None)
            return ("Success", key, "private_key")
        except (ValueError, TypeError):
            pass
        
        # Attempt to load the key as a public key
        try:
            key = serialization.load_pem_public_key(key_bytes)
            return ("Success", key, "public_key")
        except (ValueError, TypeError):
            pass
        
        # Attempt to load the key as a symmetric key (AES)
        try:
            pem_key = base64.b64encode(key_bytes).decode('utf-8')
            pem_key = f"-----BEGIN AES KEY-----\n{pem_key}\n-----END AES KEY-----"
            return ("Success", pem_key, "symmetric_key")
        except Exception as e:
            return ("Failure", "Invalid key data: unable to parse as a valid private, public, or symmetric key")
        
    except ValueError:
        return ("Failure", "Invalid hexadecimal string: could not decode")
    except Exception as e:
        return ("Error", str(e))


