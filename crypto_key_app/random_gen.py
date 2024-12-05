import os
import base64

key_lengths = {
    "AES-128": 16,
    "AES-192": 24,
    "AES-256": 32
}

def generate_random_bytes(num_bytes):
    return os.urandom(num_bytes)

def gen_symmetric_key(algorithm):
    if algorithm not in key_lengths:
        return ("Error", "Unsupported algorithm. Supported algorithms: AES-128, AES-192, AES-256")

    key_size = key_lengths[algorithm]
    random_bytes = generate_random_bytes(key_size)

    # Encode the random bytes in PEM format
    pem_key = base64.b64encode(random_bytes).decode('utf-8')
    pem_key = f"-----BEGIN AES KEY-----\n{pem_key}\n-----END AES KEY-----"
    return ("Success", pem_key)
