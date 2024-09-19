from crypto_key_app import key_management
from cryptography.hazmat.primitives.asymmetric import rsa
from crypto_key_app import random_gen
from crypto_key_app import signatures
from crypto_key_app import key_conversion as convert
from crypto_key_app import hashlib_hashing as hash
from crypto_key_app import crypto_hashing as cry_hash
from crypto_key_app import encryption_decryption as encrypt_decrypt


if __name__ == "__main__":
    # secret_key, public_key = key_management.generate_rsa_key_pair(256)
    # print(type(secret_key), " ", type(public_key))
    # print(isinstance(secret_key, rsa.RSAPrivateKey))
    # print(isinstance(public_key, rsa.RSAPublicKey))   
    # key_management.show_rsa_key_pair(secret_key, public_key)
    # rsa_sign = signatures.generate_rsa_signature(secret_key, b"This is a message to be signed")
    # signatures.verify_rsa_signature(public_key, b"This is a message to be signed", rsa_sign)
    # print(random_gen.generate_random_bytes(16))
    # Tested below conversions. Apparently, only the secret key can be converted to hex and back to pem.  
    # This is because of the attribute "private_bytes" which is not found for public key
    # Need to check if the conversion of the public key is even viable. If yes the find a way to do that
    # secret_key = convert.pem_to_hex(secret_key)
    # print(secret_key)
    # secret_key = convert.hex_to_pem(secret_key)
    # print(secret_key)
    # user_hash_algorithm = input("Enter your hash algorithm eg: sha256, sha512 etc : ").lower()
    # digest = hash.calculate_hash(b"This is a message", user_hash_algorithm)
    # print(hash.verify_hash(b"This is a message", digest, user_hash_algorithm))
    # user_hash_algorithm = input("Enter your hash algorithm eg: sha256, sha512 etc : ").lower()
    # digest = cry_hash.calculate_hash(b"This is a message", user_hash_algorithm)
    # print(cry_hash.verify_hash(b"This is a message", digest, user_hash_algorithm))
    key = random_gen.generate_random_bytes(32)
    iv = random_gen.generate_random_bytes(16)
    ciphertext = encrypt_decrypt.aes_encrypt(key, iv, "This is a message to be encrypted", 'CBC')
    print(ciphertext)
    plaintext = encrypt_decrypt.aes_decrypt(key, iv, ciphertext)
    print(f"Readable text {plaintext}")
    

    
 
    

