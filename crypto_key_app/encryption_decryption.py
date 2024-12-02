from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import padding as pad
from cryptography.hazmat.primitives import hashes


aes_encryption = {
    "CBC" : modes.CBC,
    "CTR" : modes.CTR
}
def aes_encrypt(key, iv, plaintext, encryption_algorithm = "CBC"):
    if encryption_algorithm not in aes_encryption:
        return ("Failure", f"Given algorithm '{encryption_algorithm}' is not supported for encryption/decryption. Please provide a valid encryption algorithm : CBC or CTR")
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
        return ("Failure", f"Given algorithm '{encryption_algorithm}' is not supported for encryption/decryption. Please provide a valid encryption algorithm : CBC or CTR")
    try:
        cipher = Cipher(algorithms.AES(key), aes_encryption[encryption_algorithm](iv))
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
        
        return ("Success", unpadded_data)
    except Exception as e:
        return ("Error", str(e))

def rsa_encrypt(public_key, plaintext):
    try:
        ciphertext = public_key.encrypt(
            plaintext,
            pad.OAEP(
                mgf=pad.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ("Success", ciphertext)
    except Exception as e:
        return ("Error", str(e))

def rsa_decrypt(private_key, ciphertext):
    try:
        plaintext = private_key.decrypt(
            ciphertext,
            pad.OAEP(
                mgf=pad.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ("Success", plaintext)
    except Exception as e:
        return ("Error", str(e))
