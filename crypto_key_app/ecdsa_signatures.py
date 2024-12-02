from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

signature_schemes = {
    "sha256": hashes.SHA256,
    "sha384": hashes.SHA384,
    "sha512": hashes.SHA512,
    "md5": hashes.MD5,
}

def validate_hash_algorithm(selected_hash):
    if selected_hash not in signature_schemes:
        raise ValueError("Please select a valid signing scheme: sha256/sha384/sha512/md5")
    return True

def validate_message(message):
    if not isinstance(message, (bytes, bytearray)):
        raise ValueError("Message must be of type bytes or bytearray.")

def generate_hash_longMessage(selected_hash='sha256'):
    try:
        validate_hash_algorithm(selected_hash)
        return ("Success", hashes.Hash(signature_schemes[selected_hash]()))
    except Exception as e:
        return ("Error", str(e))

def update_hash_longMessage(hasher, message_block):
    try:
        if not hasattr(hasher, "update"):
            raise ValueError("Invalid hasher object, please create a new hasher object")
        validate_message(message_block)
        hasher.update(message_block)
        return ("Success", "Hasher Updated")
    except Exception as e:
        return ("Error", str(e))

def generate_ecdsa_signature_longMessage(private_key, hasher, selected_hash='sha256'):
    try:
        validate_hash_algorithm(selected_hash)
        if not hasattr(hasher, "finalize"):
            raise ValueError("Invalid hasher object, please create a new hasher object")
        digest = hasher.finalize()
        signature = private_key.sign(digest, ECDSA(signature_schemes[selected_hash]()))
        return ("Success", signature)
    except Exception as e:
        return ("Error", str(e))

def verify_ecdsa_signature_longMessage(public_key, hasher, signature, selected_hash='sha256'):
    try:
        validate_hash_algorithm(selected_hash)
        if not hasattr(hasher, "finalize"):
            raise ValueError("Invalid hasher object, please create a new hasher object")
        digest = hasher.finalize()
        public_key.verify(signature, digest, ECDSA(signature_schemes[selected_hash]()))
        return ("Success", "Signature verified")
    except InvalidSignature:
        return ("Failure", "Invalid Signature")
    except Exception as e:
        return ("Error", str(e))

def generate_ecdsa_signature(private_key, message, selected_hash='sha256'):
    try:
        validate_hash_algorithm(selected_hash)
        validate_message(message)
        signature = private_key.sign(message, ECDSA(signature_schemes[selected_hash]()))
        return ("Success", signature)
    except Exception as e:
        return ("Error", str(e))

def verify_ecdsa_signature(public_key, message, signature, selected_hash='sha256'):
    try:
        validate_hash_algorithm(selected_hash)
        validate_message(message)
        public_key.verify(signature, message, ECDSA(signature_schemes[selected_hash]()))
        return ("Success", "Signature verified")
    except InvalidSignature:
        return ("Failure", "Invalid Signature")
    except Exception as e:
        return ("Error", str(e))
