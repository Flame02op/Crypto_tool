from cryptography.hazmat.primitives.asymmetric import padding, utils
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA

signature_schemes ={
    "sha256"        : hashes.SHA256,
    "sha384"        : hashes.SHA384,
    "sha512"        : hashes.SHA512,
    "md5"           : hashes.MD5,
    "raise_invalid" : "Please select a valid signing scheme sha256/sha384/sha512/md5"
}

def validate_hash_algorithm(selected_hash):
    if selected_hash not in signature_schemes:
        raise ValueError(signature_schemes["raise_invalid"])
    return True

def validate_message(message):
    if not isinstance(message, (bytes, bytearray)):
        raise ValueError("Message must be of type bytes or bytearray.")
    return True

def generate_hash_longMessage(selected_hash='sha256'):
    if validate_hash_algorithm(selected_hash):
        return hashes.Hash(signature_schemes[selected_hash]())

def update_hash_longMessage(hasher, message_block):
    if not hasattr(hasher, "update"):
        raise ValueError("Invalid hasher object, please create a hasher object with generate_hash_longmessage")
    if validate_message(message_block):
        hasher.update(message_block)

def generate_rsa_signature_longMessage(private_key, hasher, selected_hash='sha256'):
    if validate_hash_algorithm(selected_hash):
        if not hasattr(hasher, "finalize"):
            raise ValueError("Invalid hasher object, please create a hasher object with generate_hash_longmessage")
        
        digest = hasher.finalize()
        return private_key.sign(
            digest,
            padding.PSS(
                mgf=padding.MGF1(signature_schemes[selected_hash]()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            utils.Prehashed(signature_schemes[selected_hash]())
        )

def verify_rsa_signature_longMessage(public_key, hasher, signature, selected_hash='sha256'):
    if validate_hash_algorithm(selected_hash):
        if not hasattr(hasher, "finalize"):
            raise ValueError("Invalid hasher object, please create a hasher object with generate_hash_longmessage")
        try:
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
        except InvalidSignature as invalidSign:
            print("Signature is invalid")
            return None

def generate_rsa_signature(private_key, message, selected_hash='sha256'):
    if validate_hash_algorithm(selected_hash) and validate_message(message):
        return private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(signature_schemes[selected_hash]()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            signature_schemes[selected_hash]()
        )

def verify_rsa_signature(public_key, message, signature, selected_hash='sha256'):
    if validate_hash_algorithm(selected_hash) and validate_message(message):
        try:
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
        except InvalidSignature as invalidSign:
            print("Signature is invalid")
            return None
