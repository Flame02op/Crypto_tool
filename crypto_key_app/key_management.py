from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

key_size= {'256' : 1024, '512' : 2048}
 
def generate_rsa_key_pair(size):
    if str(size) in key_size:
        size = key_size[str(size)]

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=int(size)
    )
    public_key = private_key.public_key()
    return private_key, public_key


def show_rsa_key_pair(private_key, public_key):
    # Serialize private key to PEM format
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()  
    )
    
    # Serialize public key to PEM format
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    print("Private Key:\n", private_pem.decode('utf-8'))
    print("Public Key:\n", public_pem.decode('utf-8'))

