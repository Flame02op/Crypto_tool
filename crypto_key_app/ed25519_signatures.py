from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

def validate_message(message):
    if not isinstance(message, (bytes, bytearray)):
        raise ValueError("Message must be of type bytes or bytearray.")
    return True

def generate_ed25519_signature(private_key, message):
    try:
        if validate_message(message):
            return ("success", private_key.sign(message))
    except Exception as e:
        return("Error", str(e))


def verify_ed25519_signature(public_key, message, signature):
    try:
        if validate_message(message):
            try:
                public_key.verify(signature, message)
                return ("Success", "Signature Verified")
            except InvalidSignature:
                return ("Failure", "Invalid Signature")
    except Exception as e:
        return ("Error", str(e))