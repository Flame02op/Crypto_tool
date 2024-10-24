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
        

# if __name__ == "__main__":
#     private_key, public_key = generate_ed25519_key_pair()
#     message = b"Hello, World!"
#     signature = generate_ed25519_signature(private_key, message)
    
#     # Verify the correct signature
#     is_valid = verify_ed25519_signature(public_key, message, signature)
#     print(f"Signature valid: {is_valid}")
    
#     # Verify with a tampered message
#     tampered_message = b"Hello, Universe!"
#     is_valid = verify_ed25519_signature(public_key, tampered_message, signature)
#     print(f"Signature valid for tampered message: {is_valid}")
    
#     # Verify with a tampered signature
#     tampered_signature = signature[:-1] + b'\x00'
#     is_valid = verify_ed25519_signature(public_key, message, tampered_signature)
#     print(f"Signature valid for tampered signature: {is_valid}")