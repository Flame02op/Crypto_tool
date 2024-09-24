from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

curves = {
    'secp192r1' : ec.SECP192R1,
    'secp256r1' : ec.SECP256R1,
    'secp384r1' : ec.SECP384R1,
    'secp521r1' : ec.SECP521R1,
    'secp256k1' : ec.SECP256K1
}

keySize= {'256' : 1024, '512' : 2048}
 
def generate_rsa_key_pair(key_size):
    if str(key_size) in keySize:
        key_size = keySize[str(key_size)]
    else:
        if int(key_size) < '256' :
            raise ValueError("Keys with size less than 1024 bits or 256 bytes are generally considered to be unsecured.")
        else:
            raise ValueError(f"Key with given size {key_size} Bytes is not supported")

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=int(key_size)
    )
    public_key = private_key.public_key()
    return private_key, public_key


def generate_ecdsa_key_pair(curve = 'secp256r1'):
    if curve not in curves:
        raise ValueError(f"The given algorithm is not supported : '{curve}'. Please select a valid algorithm secp128r1/secp256r1/secp256k1")
    private_key = ec.generate_private_key(curves[curve]())
    public_key = private_key.public_key()
    return private_key, public_key


def show_key_pair(private_key, public_key):
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
