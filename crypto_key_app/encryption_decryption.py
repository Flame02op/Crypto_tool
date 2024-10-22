from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

aes_encryption = {
    "CBC" : modes.CBC,
    "CTR" : modes.CTR
}
def aes_encrypt(key, iv, plaintext, encryption_algorithm = "CBC"):
    if encryption_algorithm not in aes_encryption:
        raise Exception(f"Given algorithm '{encryption_algorithm}' is not supported for encryption/decryption. Please provide a valid encryption algorithm : CBC or CTR")
    cipher = Cipher(algorithms.AES(key), aes_encryption[encryption_algorithm](iv))
    encryptor = cipher.encryptor()
    
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_plaintext = padder.update(plaintext.encode()) + padder.finalize()
    
    return encryptor.update(padded_plaintext) + encryptor.finalize()

def aes_decrypt(key, iv, ciphertext, encryption_algorithm='CBC'):
    if encryption_algorithm not in aes_encryption:
        raise Exception(f"Given algorithm '{encryption_algorithm}' is not supported for encryption/decryption. Please provide a valid encryption algorithm : CBC or CTR")
    cipher = Cipher(algorithms.AES(key), aes_encryption[encryption_algorithm](iv))
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
    
    return unpadded_data
