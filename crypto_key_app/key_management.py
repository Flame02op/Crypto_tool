from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
import base64

curves = {
    'secp192r1' : ec.SECP192R1,
    'secp256r1' : ec.SECP256R1,
    'secp384r1' : ec.SECP384R1,
    'secp521r1' : ec.SECP521R1,
    'secp256k1' : ec.SECP256K1
}

keySize= {'128' : 1024, '256' : 2048, '512' : 4096, '1024' : 8192}

def validate_key(key_type, key):
    if key_type == 'RSA' and not isinstance(key, (rsa.RSAPrivateKey, rsa.RSAPublicKey)):
        return ("Failure", "Loaded key is not of type RSA.")
    elif key_type == 'ECDSA' and not isinstance(key, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)):
        return ("Failure", "Loaded key is not of type ECDSA.")
    elif key_type == 'ED25519' and not isinstance(key, (ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey)):
        return ("Failure", "Loaded key is not of type ED25519.")
    return ("Success", "Key validated")
 
def generate_rsa_key_pair(key_size):
    try:
        if str(key_size) in keySize:
            key_size = keySize[str(key_size)]
        else:
            if int(key_size) < 128 :
                raise ValueError("Keys with size less than 1024 bits or 128 bytes are generally considered to be unsecured.")
            else:
                raise ValueError(f"Key with given size {key_size} Bytes is not supported")

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=int(key_size)
        )
        public_key = private_key.public_key()
        return ("Success", private_key, public_key)
    except Exception as e:
        return ("Error", str(e), "")


def generate_ecdsa_key_pair(curve = 'secp256r1'):
    try:
        if curve.lower() not in curves:
            raise ValueError(f"The given algorithm is not supported : '{curve}'. Please select a valid algorithm secp128r1/secp256r1/secp256k1")
        private_key = ec.generate_private_key(curves[curve.lower()]())
        public_key = private_key.public_key()
        return ("Success", private_key, public_key)
    except Exception as e:
        return ("Error", str(e), "")


def generate_ed25519_key_pair():
    try:
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        return ("Success", private_key, public_key)
    except Exception as e:
        return ("Error", str(e), "")
    
def show_key_pair(private_key, public_key):
        # Determine the key type
    if isinstance(private_key, rsa.RSAPrivateKey):
        private_format = serialization.PrivateFormat.TraditionalOpenSSL
    elif isinstance(private_key, (ec.EllipticCurvePrivateKey, ed25519.Ed25519PrivateKey)):
        private_format = serialization.PrivateFormat.PKCS8
    else:
        raise ValueError("Unsupported key type")

    # Serialize private key to PEM format
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=private_format,
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
                # Unsure whether to implement the support for DER
                try:
                    key = serialization.load_der_private_key(key_data, password=None)
                except ValueError:
                    key = serialization.load_der_public_key(key_data)

        retVal = validate_key(key_type, key)
        if retVal[0] == "Success":
            return ("Success", key)
        else:
            return retVal

    except Exception as e:
        return ("Error", str(e))
    
def load_symmetric_key(file_path):
    try:
        with open(file_path, 'r') as key_file:
            lines = key_file.readlines()

        # Ensure the PEM headers are present
        if not ((lines[0].strip() == "-----BEGIN SYMMETRIC KEY-----" and
                lines[-1].strip() == "-----END SYMMETRIC KEY-----") or (lines[0].strip() == "-----BEGIN AES KEY-----" and
                lines[-1].strip() == "-----END AES KEY-----")):
            raise ValueError("Invalid PEM format: Missing BEGIN/END KEY headers.")
        key = ''.join(lines[1:-1]).strip()
        # key = base64.b64decode(key)
        return ("Success", key)
    except Exception as e:
        print("Failed to load symmetric key:", str(e))
        return None

def save_private_key(key_type, private_key, conversion = False):
    try:
        if key_type == "RSA" or key_type == "ECDSA":
            # Serialize RSA or ECDSA keys to PEM format
            pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        elif conversion:
            # For Ed25519 keys, handle the PEM conversion properly
            pem_content = private_key.decode("utf-8")
            pem_key = pem_content.replace("-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----", "").strip()
            pem_key = base64.b64decode(pem_key)
            if len(pem_key) > 32:
                ed25519_private_key = pem_key[-32:]  # get the 32-byte key
            try:
                private_key = ed25519.Ed25519PrivateKey.from_private_bytes(ed25519_private_key)
                pem = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
            except AttributeError as e:
                raise AttributeError("Error loading private key:", str(e))
        else:
            pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        with open(f"./Temp/Keys/{key_type.lower()}_private_key.pem", 'wb') as key_file:
            key_file.write(pem)

    except Exception as e:
        raise Exception("An error occurred:", str(e))

def save_public_key(key_type, public_key):
    try:
        if isinstance(public_key, bytes) and key_type == "ED25519":
            # Deserialize the public key from raw bytes
            pem_content = public_key.decode("utf-8")
            pem_key = pem_content.replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "").strip()
            pem_key = base64.b64decode(pem_key)
            if len(pem_key) > 32:
                pem_key = pem_key[-32:]
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(pem_key)

        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        with open(f"./Temp/Keys/{key_type.lower()}_public_key.pem", 'wb') as key_file:
            key_file.write(pem)
    except Exception as e:
        print("An error occurred", str(e))


