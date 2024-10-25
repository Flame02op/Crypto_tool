from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

def validate_message(message):
    if not isinstance(message, (bytes, bytearray)):
        raise ValueError("Message must be of type bytes or bytearray.")
    return True

def generate_ed25519_signature(private_key, message):
    if validate_message(message):
        return private_key.sign(message)

def verify_ed25519_signature(public_key, message, signature):
    if validate_message(message):
        try:
            public_key.verify(signature, message)
            return True
        except InvalidSignature:
            return False
