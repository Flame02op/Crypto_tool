from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# Convert PEM key to hex
def pem_to_hex(pem_key):
    if isinstance(pem_key, rsa.RSAPrivateKey):
        pem_bytes = pem_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        return pem_bytes.hex()
    else:
        print("Can only convert secret keys to hex")

# Convert hex back to PEM
def hex_to_pem(hex_key):
    pem_bytes = bytes.fromhex(hex_key)
    return pem_bytes