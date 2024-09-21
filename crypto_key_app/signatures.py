from cryptography.hazmat.primitives.asymmetric import padding, utils
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

signature_schemes ={
    "sha256"        : hashes.SHA256,
    "sha512"        : hashes.SHA512,
    "md5"           : hashes.MD5,
    "raise_invalid" : "Please select a valid signing scheme sha256/sha512/md5"
}

def generate_hash_longData(chosen_hash='sha256'):
    if chosen_hash not in signature_schemes:
        raise ValueError(signature_schemes["raise_invalid"])
    return hashes.Hash(signature_schemes[chosen_hash]())

def update_hash_longData(hasher, data_block):
    if not hasattr(hasher, "update"):
        raise ValueError("Invalid hasher object, please create a hasher object with generate_hash_longData")
    hasher.update(data_block)

def generate_rsa_signature_longData(private_key, hasher, chosen_hash='sha256'):
    if chosen_hash not in signature_schemes:
        raise ValueError(signature_schemes["raise_invalid"])
    if not hasattr(hasher, "finalize"):
        raise ValueError("Invalid hasher object, please create a hasher object with generate_hash_longData")
    
    digest = hasher.finalize()
    return private_key.sign(
        digest,
        padding.PSS(
            mgf=padding.MGF1(signature_schemes[chosen_hash]()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        utils.Prehashed(signature_schemes[chosen_hash]())
    )

def verify_rsa_signature_longData(public_key, hasher, signature, chosen_hash='sha256'):
    if chosen_hash not in signature_schemes:
        raise ValueError(signature_schemes["raise_invalid"])
    if not hasattr(hasher, "finalize"):
        raise ValueError("Invalid hasher object, please create a hasher object with generate_hash_longData")
    try:
        digest = hasher.finalize()
        public_key.verify(
            signature,
            digest,
            padding.PSS(
                mgf=padding.MGF1(signature_schemes[chosen_hash]()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            utils.Prehashed(signature_schemes[chosen_hash]())
        )
        print("sign verified")
    except InvalidSignature as invalidSign:
        print("Signature is invalid")
        return None

def generate_rsa_signature(private_key, message, chosen_hash='sha256'):
    if chosen_hash not in signature_schemes:
        raise ValueError(signature_schemes["raise_invalid"])
    
    return private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(signature_schemes[chosen_hash]()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        signature_schemes[chosen_hash]()
    )

def verify_rsa_signature(public_key, message, signature, chosen_hash='sha256'):
    if chosen_hash not in signature_schemes:
        raise ValueError(signature_schemes["raise_invalid"])

    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(signature_schemes[chosen_hash]()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            signature_schemes[chosen_hash]()
        )
        print("sign verified")
    except InvalidSignature as invalidSign:
        print("Signature is invalid")
        return None