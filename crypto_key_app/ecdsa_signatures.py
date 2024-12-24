from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
import pickle

signature_schemes = {
    "SHA256"        : hashes.SHA256,
    "SHA384"        : hashes.SHA384,
    "SHA512"        : hashes.SHA512,
    "MD5"           : hashes.MD5,
    "SHA3-256"      : hashes.SHA3_256,
    "SHA3-384"      : hashes.SHA3_384,
    "SHA3-512"      : hashes.SHA3_512,
    'blake2b'       : hashes.BLAKE2b,
    'blake2s'       : hashes.BLAKE2s,
    "raise_invalid" : "Please select a valid signing scheme: sha256/sha384/sha512"
}

def validate_hash_algorithm(selected_hash):
    if selected_hash not in signature_schemes:
        raise ValueError("Please select a valid signing scheme: sha256/sha384/sha512/md5")
    return True

def validate_message(message):
    if not isinstance(message, (bytes, bytearray)):
        raise ValueError("Message must be of type bytes or bytearray.")
    return True

def generate_hash_longMessage(selected_hash, filepath = None):
    try:
        if validate_hash_algorithm(selected_hash):
            hasher_obj = hashes.Hash(signature_schemes[selected_hash]())
            if filepath:
                with open("./Temp/Sign/Hasher.hash", "wb") as fout:
                    # Serialize the state of the hasher
                    state = hasher_obj.copy().finalize()
                    pickle.dump((selected_hash, state), fout)
                return ("Success", "Hasher generated successfully")
            else:
                return hasher_obj
    except Exception as e:
        return("Error", str(e))

def update_hash_longMessage(hasher_obj, message_block, selected_hash=None, filepath=None):
    try:
        if not hasattr(hasher_obj, "update"):
            raise ValueError("Invalid hasher object, please create a hasher object")
        if validate_message(message_block):
            hasher_obj.update(message_block)
            if filepath and selected_hash:
                with open(filepath, "wb") as fout:
                    state = hasher_obj.copy().finalize()
                    pickle.dump((selected_hash, state), fout)
            return ("Success", "Hasher Updated")
    except Exception as e:
        return ("Error", str(e))

def generate_ecdsa_signature_longMessage(private_key, hasher, selected_hash='sha256'):
    try:
        if validate_hash_algorithm(selected_hash):
            if not hasattr(hasher, "finalize"):
                raise ValueError("Invalid hasher object, please create a new hasher object")
            digest = hasher.finalize()
            signature = private_key.sign(digest, ECDSA(signature_schemes[selected_hash]()))
            return ("Success", signature)
    except Exception as e:
        return ("Error", str(e))

def verify_ecdsa_signature_longMessage(public_key, hasher, signature, selected_hash='sha256'):
    try:
        if validate_hash_algorithm(selected_hash):
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
        if validate_hash_algorithm(selected_hash) and validate_message(message):
            signature = private_key.sign(message, ECDSA(signature_schemes[selected_hash]()))
            return ("Success", signature)
    except Exception as e:
        return ("Error", str(e))

def verify_ecdsa_signature(public_key, message, signature, selected_hash='sha256'):
    try:
        if validate_hash_algorithm(selected_hash) and validate_message(message):
            public_key.verify(signature, message, ECDSA(signature_schemes[selected_hash]()))
            return ("Success", "Signature verified")
    except InvalidSignature:
        return ("Failure", "Invalid Signature")
    except Exception as e:
        return ("Error", str(e))
