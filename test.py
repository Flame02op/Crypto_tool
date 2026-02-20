from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from crypto_key_app import key_management as keys
from crypto_key_app import key_conversion as convert
import hashlib

while True:
    private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=int(2048)
            )
    public_key = private_key.public_key()

    public_number = public_key.public_numbers()
    modulus = public_number.n
    exponent = public_number.e

    modulus = hex(modulus)[2:]
    exponent = hex(exponent)[2:]
    # print(len(modulus), modulus)
    exponent = "000" + exponent
    # print(len(exponent), exponent)

    combined_bytes = bytes.fromhex(modulus) + bytes.fromhex(exponent)

    hash_obj1 = hashes.Hash(hashes.SHA256())
    hash_obj1.update(combined_bytes)
    digest1 = hash_obj1.finalize()
    print(len(digest1) * 8, digest1.hex())

    # hash_obj2 = hashlib.sha256()
    # hash_obj2.update(combined_bytes)
    # digest2 = hash_obj2.hexdigest()
    # print(len(digest2) * 8, digest2)
    # if digest.hex()[-2 : ] == "00" : #Last byte zero check
    # if digest.hex()[:2] == "00": #First byte zero check
    #     key_type = "RSA"
    #     keys.save_private_key(key_type,private_key)
    #     keys.save_public_key(key_type, public_key) 
    #     break
    if any(byte == 0 for byte in digest1[1:-1]):  #any byte (except the first and last) is zero
        key_type = "RSA"
        try:
            keys.save_private_key(key_type, private_key)
            keys.save_public_key(key_type, public_key)
        except Exception as e:
            raise Exception (f"Error occurred : {str(e)}")
        break
