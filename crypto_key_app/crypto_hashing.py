# This code is slightly slow when working with complex data as it uses the rust library at the
# backend. Thus it is an overkill for hashing when we have the hashlib library. But to maintain
# consistency across the tool, this code can be used.
from cryptography.hazmat.primitives import hashes

secure_algorithms = {
    'sha256'   : hashes.SHA256,
    'sha384'   : hashes.SHA3_384,
    'sha512'   : hashes.SHA512,
    'sha3_256' : hashes.SHA3_256,
    'sha3_384' : hashes.SHA3_384,
    'sha3_512' : hashes.SHA3_512,
    'blake2b'  : hashes.BLAKE2b,
    'blake2s'  : hashes.BLAKE2s,
    
}

# Deprecated due to collision attacks
non_secure_algorithms ={
    'md5'    : hashes.MD5,
    'sha224' : hashes.SHA224,
    'sha1'   : hashes.SHA1
}

def calculate_hash(data, algorithm='sha256'):

    if algorithm in secure_algorithms:
        hash_obj = hashes.Hash(secure_algorithms[algorithm]())
    elif algorithm in non_secure_algorithms:
        if input(f"The algorithm '{algorithm}' is not recommended for security reasons, do you still want to proceed? Enter yes or no : ").lower() == "yes": 
            hash_obj = hashes.Hash(non_secure_algorithms[algorithm]())
        else:
            return None
    else:
        raise ValueError("Unsupported algorithm")
    hash_obj.update(data)
    return hash_obj.finalize()

def verify_hash(data, expected_hash, algorithm='sha256'):
    if algorithm in secure_algorithms:
        hash_obj = hashes.Hash(secure_algorithms[algorithm]())
    elif algorithm in non_secure_algorithms:
        hash_obj = hashes.Hash(non_secure_algorithms[algorithm]())
    hash_obj.update(data)
    return expected_hash == hash_obj.finalize()