from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import ed25519
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
        if int(key_size) < 256 :
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


def generate_ed25519_key_pair():
    private_key = ed25519.Ed25519PrivateKey.generate()
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

def load_key(key_type, file_path):
        # Ensure the key type is valid
    if key_type not in {'RSA', 'ECDSA', 'ED25519'}:
        raise ValueError("Invalid key type. Use 'RSA', 'ECDSA', or 'ED25519'.")

    try:
        # Read the key file
        with open(file_path, 'rb') as key_file:
            key_data = key_file.read()

        # Attempt to load the key
        try:
            # Try loading as PEM first
            key = serialization.load_pem_private_key(key_data, password=None)
        except ValueError:
            try:
                key = serialization.load_pem_public_key(key_data)
            except ValueError:
                # If PEM fails, try DER
                try:
                    key = serialization.load_der_private_key(key_data, password=None)
                except ValueError:
                    key = serialization.load_der_public_key(key_data)

        # Validate that the loaded key matches the expected type
        if key_type == 'RSA' and not isinstance(key, (rsa.RSAPrivateKey, rsa.RSAPublicKey)):
            raise ValueError("Loaded key is not of type RSA.")
        elif key_type == 'ECDSA' and not isinstance(key, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)):
            raise ValueError("Loaded key is not of type ECDSA.")
        elif key_type == 'ED25519' and not isinstance(key, (ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey)):
            raise ValueError("Loaded key is not of type ED25519.")

        return key

    except FileNotFoundError:
        raise ValueError(f"File not found: {file_path}")
    except Exception as e:
        raise ValueError(f"An error occurred while loading the key: {e}")
