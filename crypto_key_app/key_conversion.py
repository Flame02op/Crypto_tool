from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
import key_management as keys

# Convert PEM key to hex
def pem_to_hex(pem_key):
    if isinstance(pem_key, rsa.RSAPrivateKey):
        pem_bytes = pem_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        return pem_bytes.hex()
    elif isinstance(pem_key, rsa.RSAPublicKey):
        pem_bytes = pem_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem_bytes.hex()
    else:
        raise ValueError("Can only convert RSA private or public keys to hex")


# Convert hex back to PEM
def hex_to_pem(hex_key):
    try:
        pem_bytes = bytes.fromhex(hex_key)
        return pem_bytes
    except ValueError:
        raise ValueError("Invalid hexadecimal string")
    
