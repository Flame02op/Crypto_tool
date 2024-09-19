from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

aes_encryption = {
    "CBC" : modes.CBC,
    "CTR" : modes.CTR
}

def aes_encrypt(key, iv, plaintext, encryption_algorithm):
    if encryption_algorithm not in aes_encryption:
        raise Exception(f"Given algorithm '{encryption_algorithm}' is not supported for encryption/decryption. Please provide a valid encryption algorithm : CBC or CTR")
    cipher = Cipher(algorithms.AES(key), aes_encryption[encryption_algorithm](iv))
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()

def aes_decrypt(key, iv, ciphertext, encryption_algorithm):
    if encryption_algorithm not in aes_encryption:
        raise Exception(f"Given algorithm '{encryption_algorithm}' is not supported for encryption/decryption. Please provide a valid encryption algorithm : CBC or CTR")
    cipher = Cipher(algorithms.AES(key), aes_encryption[encryption_algorithm](iv))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()
