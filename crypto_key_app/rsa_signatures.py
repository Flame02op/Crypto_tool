from cryptography.hazmat.primitives.asymmetric import padding, utils
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
import pickle
signature_schemes ={
    "SHA256"         : hashes.SHA256,
    "SHA384"         : hashes.SHA384,
    "SHA512"         : hashes.SHA512,
    "MD5"            : hashes.MD5,
    "SHA3-256"       : hashes.SHA3_256,
    "SHA3-384"       : hashes.SHA3_384,
    "SHA3-512"       : hashes.SHA3_512,
    'blake2b'        : hashes.BLAKE2b,
    'blake2s'        : hashes.BLAKE2s,
    "raise_invalid"  : "Please select a valid hash algorithm"
}

def validate_hash_algorithm(selected_hash):
    if selected_hash not in signature_schemes:
        return ValueError(signature_schemes["raise_invalid"])
    return True

def validate_message(message):
    if not isinstance(message, (bytes, bytearray)):
        raise ValueError("Message must be of type bytes or bytearray.")
    return True

def generate_hash_longMessage(selected_hash, filepath=None):
    if validate_hash_algorithm(selected_hash):
        try:
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
    else:
        return ("Error", str(signature_schemes["raise_invalid"]))

def update_hash_longMessage(hasher_obj, message_block, selected_hash=None, filepath=None):
    try:
        if not hasattr(hasher_obj, "update"):
            raise ValueError("Invalid hasher object, please create a hasher object with generate_hash_longmessage")
        if validate_message(message_block):
            hasher_obj.update(message_block)
            if filepath and selected_hash:
                print("Updating Hasher")
                with open(filepath, "wb") as fout:
                    state = hasher_obj.copy().finalize()
                    pickle.dump((selected_hash, state), fout)
                return ("Success", "Hasher Updated")
    except Exception as e:
        return ("Error", str(e))
    

def generate_rsa_signature_longMessage(private_key, hasher, selected_hash='sha256'):
    try:
        if validate_hash_algorithm(selected_hash):
            if not hasattr(hasher, "finalize"):
                raise ValueError("Invalid hasher object, please create a hasher object with generate_hash_longmessage")
            
            digest = hasher.finalize()
            return ("Success", 
                    private_key.sign(
                    digest,
                    padding.PSS(
                        mgf=padding.MGF1(signature_schemes[selected_hash]()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    utils.Prehashed(signature_schemes[selected_hash]())
                )
            )
    except Exception as e:
        return("Error", str(e))


def verify_rsa_signature_longMessage(public_key, hasher, signature, selected_hash='sha256'):
    try:
        if validate_hash_algorithm(selected_hash):
            if not hasattr(hasher, "finalize"):
                raise ValueError("Invalid hasher object, please create a hasher object with generate_hash_longmessage")

            digest = hasher.finalize()
            public_key.verify(
                signature,
                digest,
                padding.PSS(
                    mgf=padding.MGF1(signature_schemes[selected_hash]()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                utils.Prehashed(signature_schemes[selected_hash]())
            )
            print("sign verified")
            return("Success", "Signature Verified")
    except InvalidSignature:
        return("Failure", "Invalid Signature")
    except Exception as e:
        return("Error", str(e))


def generate_rsa_signature(private_key, message, selected_hash='sha256'):
    try:
        if validate_hash_algorithm(selected_hash) and validate_message(message):
            return ("Success", 
                    private_key.sign(
                    message,
                    padding.PSS(
                        mgf=padding.MGF1(signature_schemes[selected_hash]()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    signature_schemes[selected_hash]()
                )
            )
    except Exception as e:
        return("Error", str(e))

def verify_rsa_signature(public_key, message, signature, selected_hash='sha256'):
    try:
        if validate_hash_algorithm(selected_hash) and validate_message(message):
            public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(signature_schemes[selected_hash]()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                signature_schemes[selected_hash]()
            )
            print("sign verified")
            return("Success", "Signature verified")            
    except InvalidSignature:
        return("Failure", "Invalid Signature")
    except Exception as e:
        return("Error", str(e))



