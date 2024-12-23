import hashlib

secure_algorithms = {
    'SHA256'   : hashlib.sha256,
    'SHA384'   : hashlib.sha384,
    'SHA512'   : hashlib.sha512,
    'SHA3-256' : hashlib.sha3_256,
    'SHA3-384' : hashlib.sha3_384,
    'SHA3-512' : hashlib.sha3_512,
    'blake2b'  : hashlib.blake2b,
    'blake2s'  : hashlib.blake2s
    
}
# Deprecated due to collision attacks
# Not recommended to use 
non_secure_algorithms ={
    'md5'    : hashlib.md5,
    'SHA224' : hashlib.sha224,
    'sha1'   : hashlib.sha1
}

def calculate_hash(data, algorithm='sha256'):
    if algorithm in secure_algorithms:
        hash_obj = secure_algorithms[algorithm]()
    elif algorithm in non_secure_algorithms:
        hash_obj = non_secure_algorithms[algorithm]()
    else:
        return("Failure", "Unsupported algorithm")
    try:
        hash_obj.update(data)
        return ("Success", hash_obj.hexdigest())
    except Exception as e:
        return ("Error", str(e))

def verify_hash(data, expected_hash, algorithm='sha256'):
    if algorithm in secure_algorithms:
        hash_obj = secure_algorithms[algorithm]()
    elif algorithm in non_secure_algorithms:
        hash_obj = non_secure_algorithms[algorithm]()
    else:
        return("Failure", "Unsupported algorithm")
    try:
        hash_obj.update(data)
        if expected_hash == hash_obj.hexdigest():
            return ("Success", "Hash Verified")
        else:
            return("Failure", "Invalid Hash")
    except Exception as e:
        return("Error", str(e))