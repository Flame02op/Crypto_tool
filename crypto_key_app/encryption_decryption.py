from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import padding as pad
from cryptography.hazmat.primitives import hashes


aes_encryption = {
    "CBC" : modes.CBC,
    "CTR" : modes.CTR
}

encryption_algorithms = {
    "SHA256"     : hashes.SHA256,
    "SHA384"     : hashes.SHA384,
    "SHA512"     : hashes.SHA512,
    "MD5"        : hashes.MD5,
    "SHA3-256"   : hashes.SHA3_256,
    "SHA3-384"   : hashes.SHA3_384,
    "SHA3-512"   : hashes.SHA3_512,
    'blake2b'    : hashes.BLAKE2b,
    'blake2s'    : hashes.BLAKE2s,
}

def aes_encrypt(key, iv, plaintext, encryption_algorithm = "CBC"):
    if encryption_algorithm not in aes_encryption:
        return ("Failure", f"Given algorithm '{encryption_algorithm}' is not supported for encryption. Please provide a valid encryption algorithm : CBC or CTR")
    try:
        cipher = Cipher(algorithms.AES(key), aes_encryption[encryption_algorithm](iv))
        encryptor = cipher.encryptor()
        
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_plaintext = padder.update(plaintext.encode()) + padder.finalize()
        
        return ("Success" , encryptor.update(padded_plaintext) + encryptor.finalize())
    except Exception as e:
        return ("Error", str(e))

def aes_decrypt(key, iv, ciphertext, encryption_algorithm='CBC'):
    if encryption_algorithm not in aes_encryption:
        return ("Failure", f"Given algorithm '{encryption_algorithm}' is not supported for decryption. Please provide a valid encryption algorithm : CBC or CTR")
    try:
        cipher = Cipher(algorithms.AES(key), aes_encryption[encryption_algorithm](iv))
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
        
        return ("Success", unpadded_data)
    except Exception as e:
        return ("Error", str(e))

def rsa_encrypt(public_key, plaintext, encryption_algorithm):
    if encryption_algorithm not in encryption_algorithms:
        return ("Error", f"Given algorithm '{encryption_algorithm}' is not supported for encryption")
    try:
        ciphertext = public_key.encrypt(
            plaintext,
            pad.OAEP(
                mgf=pad.MGF1(algorithm=encryption_algorithms[encryption_algorithm]()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ("Success", ciphertext)
    except Exception as e:
        return ("Error", str(e))

def rsa_decrypt(private_key, ciphertext, encryption_algorithm):
    if encryption_algorithm not in encryption_algorithms:
        return ("Error", f"Given algorithm '{encryption_algorithm}' is not supported for decryption")
    try:
        plaintext = private_key.decrypt(
            ciphertext,
            pad.OAEP(
                mgf=pad.MGF1(algorithm=encryption_algorithms[encryption_algorithm]()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ("Success", plaintext)
    except Exception as e:
        return ("Error", str(e))
