from crypto_key_app import key_management as keys
from cryptography.hazmat.primitives.asymmetric import rsa
from crypto_key_app import random_gen
from crypto_key_app import rsa_signatures as rsa_sign
from crypto_key_app import ecdsa_signatures as ecdsa_sign
from crypto_key_app import key_conversion as convert
from crypto_key_app import hashlib_hashing as hashlib_hash
from crypto_key_app import crypto_hashing as cry_hash
from crypto_key_app import encryption_decryption as encrypt_decrypt
from crypto_key_app import cmac
from crypto_key_app import crc
from crypto_key_app import ed25519_signatures as ed25519_sign
import time
import os


private_key = ""
public_key = ""
longMessage_callOut  = 0
hasher = ""

def createTempDir(path):
    if not os.path.exists(path):
        os.makedirs(path)

def checkFilePath(path):
    if os.path.exists(path):
        return True
    else:
        return False
    
def removeFile(path):
    if os.path.exists(path):
        os.remove(path)

def If_load_key(key_type, filepath):
    global private_key, public_key
    if checkFilePath(filepath) == False:
        return ("Warning", f"The file path {os.path.split(filepath)[1]} does not exist")
    else:
        if key_type == "Private":
            private_key = keys.load_key(key_type, filepath)
        else:
            public_key = keys.load_key(key_type, filepath)
    
def If_generateKey(key_type, key_alg):
    global public_key, private_key
    if key_type == "RSA":
        private_key, public_key = keys.generate_rsa_key_pair(key_alg)
    elif key_type == "ECDSA":
        private_key, public_key = keys.generate_ecdsa_key_pair(key_alg) 
    else:
        private_key, public_key = keys.generate_ed25519_key_pair(key_alg)

    createTempDir("./Temp/Keys")
    try:
        keys.save_private_key(private_key, key_type)
        keys.save_public_key(public_key, key_type)
    except Exception as e:
        print(e)
        return("Warning", "An exception occurred, check the log for further details")
        
    return("Success", f"Key pair of key type : {key_type} generated at Temp/Keys")

def If_generateSign(key_type, private_key_file, input_file, hash_algo):
    for file in [private_key_file, input_file]:
        if checkFilePath(file):
            return ("Warning", f"The file path {os.path.split(file)[1]} does not exist")
    
    key = keys.load_key(key_type, private_key_file)
    with open(input_file) as fin:
        message = fin.read()
    input_file_name = os.path.split(input_file)[1]
    createTempDir("./Temp/Sign")

    if key_type == "RSA":
        signature = rsa_sign.generate_rsa_signature(key, message, hash_algo)
    elif key_type == "ECDSA":
        signature = ecdsa_sign.generate_ecdsa_signature(key, message, hash_algo)       
    else:
        signature = ed25519_sign.generate_ed25519_signature(key, message, hash_algo)
        
    with open(f"./Temp/Sign/{input_file_name}.Signed", "wb") as sign_file:
        sign_file.write(signature)
    
    return ("Success", "Signature generated")

def IF_generateHasherLongMessage(key_type, hash_algo):
    global longMessage_callOut
    if key_type == "RSA":
        hasher = rsa_sign.generate_hash_longMessage(hash_algo)
    elif key_type == "ECDSA":
        hasher = ecdsa_sign.generate_hash_longMessage(hash_algo)
    else:
        return ("Warning", f"The key type {key_type} does not supports signing for long messages")
    
    createTempDir("./Temp/Sign")
    with open("./Temp/Sign/Hasher.hash", "wb") as fout:
        fout.write(hasher)
  
    longMessage_callOut +=1

    return("Success", "Hasher generated at file path Temp/Sign/Hasher.hash")

def If_UpdateHasherLongMessage(key_type, input_file, hasher_file):
    if longMessage_callOut > 0:
        for file in [input_file, hasher_file]:
            if not checkFilePath(file):
                return ("Warning", f"The file path {os.path.split(file)[1]} does not exist")
        
        with open(input_file, "rb") as fin:
            message = fin.read()
        with open(hasher_file, "rb") as fin:
            hasher = fin.read()

        if key_type == "RSA":
            hasher = rsa_sign.update_hash_longMessage(hasher, message)
        elif key_type == "ECDSA":
            hasher = ecdsa_sign.update_hash_longMessage(hasher, message) 

        with open(hasher_file, "wb") as fout:
            fout.write(hasher)

        return ("Success", "Hasher updated")

def If_generateSignForLongMessage(key_type, private_key_file, hasher_file, hash_algo):   
    if longMessage_callOut != 0:
        for file in [private_key_file,hasher_file]:
            if not checkFilePath(file):
                return ("Warning", f"The file path {os.path.split(file)[1]} does not exist")
            
        key = keys.load_key(key_type, private_key_file)

        with open(hasher_file, "rb") as fin:
            hasher = fin.read()
        hasher_file_name = os.path.split(hasher_file)[1]
        if key_type == "RSA":
            signature = rsa_sign.generate_rsa_signature_longMessage(key, hasher, hash_algo)
        elif key_type == "ECDSA":
            signature = ecdsa_sign.generate_ecdsa_signature_longMessage(key, hasher, hash_algo) 
        else:
            return ("Warning", "Ed25519 does not support long message signing")

        createTempDir("./Temp/Sign")
        with open(f"./Temp/Sign/{hasher_file_name}.sign", "wb") as fout:
            fout.write(signature)

        return ("Success", "Signature generated")

def If_verifySignature(key_type, public_Key_file, input_file, signature_file, hash_algo):

    for file in [input_file, public_Key_file, signature_file]:
        if not checkFilePath(file):
            return("Warning", f"The file path {os.path.split(file)[1]} does not exist")
        
    key = keys.load_key(key_type, public_Key_file)
    with open(input_file, "rb") as fin:
        message = fin.read()
    with open(signature_file, "rb") as fin:
        signature = fin.read()

    result = None
    if key_type == "RSA":
        result = rsa_sign.verify_rsa_signature(key, message, signature, hash_algo)
    elif key_type == "ECDSA":
        result = ecdsa_sign.verify_ecdsa_signature(key, message, signature, hash_algo)
    else:
        result = ed25519_sign.verify_ed25519_signature(key, message, signature, hash_algo)

    if result:
        return ("Success", "Signature verified")
    
def If_VerifySignature_LongMessage(key_type, public_Key_file, hasher_file, signature_file, hash_algo):
    for file in [public_Key_file, hasher_file, signature_file]:
        if not checkFilePath(file):
            return("Warning",  f"The file path {file} does not exist")

    key = keys.load_key(key_type, public_Key_file)

    with open(hasher_file, "rb") as fin:
        hasher = fin.read()
    with open(signature_file, 'rb') as fin:
        signature = fin.read()

    result = None
    if key_type == "RSA":
        result = rsa_sign.verify_rsa_signature_longMessage(key, hasher, signature, hash_algo)
    elif key_type == "ECDSA":
        result = ecdsa_sign.verify_ecdsa_signature_longMessage(key, hasher, signature, hash_algo)
    else:
        return ("Warning", "Ed25519 does not support long message verification") 
    if result:
        return ("Success", "Signature verified")
    
def If_aes_encrypt(key_file, input_file, iv_file, aes_algo):
    for file in [key_file, input_file, iv_file]:
        if not checkFilePath(file):
            return("Warning", f"The file path {os.path.split(file)[1]} does not exist")
        
    with open(key_file, "rb") as fin:
        key = fin.read()

    with open(input_file, "r") as fin:
        plain_text = fin.read()

    with open(iv_file, "rb") as fin:
        iv = fin.read()

    encrypted_data = encrypt_decrypt.aes_encrypt(key, iv, plain_text, aes_algo)
    createTempDir("./Temp/Encrypt")
    removeFile(f"./Temp/Encrypt/{aes_algo.lower()}_encrypted_data.enc")
    with open (f"./Temp/Encrypt/{aes_algo.lower()}_encrypted_data.enc" , "wb") as fout:
        fout.write(encrypted_data)

    return ("Success", "Encryption successful")

def If_rsa_encrypt(public_key_file, input_file, hash_algo):
    for file in [public_key_file, input_file]:
        if not checkFilePath(file):
            return("Warning", f"The file path {os.path.split(file)[1]} does not exist")
        
    key = keys.load_key("RSA", public_key_file)

    with open(input_file, "r") as fin:
        plain_text = fin.read()

    encrypted_data = encrypt_decrypt.rsa_encrypt(key, plain_text)
    createTempDir("./Temp/Encrypt")
    removeFile("./Temp/Encrypt/rsa_encrypted_data.enc" )
    with open ("./Temp/Encrypt/rsa_encrypted_data.enc" , "wb") as fout:
        fout.write(encrypted_data)

    return ("Success", "Encryption successful")

def If_aes_decrypt(key_file, iv_file, encrypted_file, aes_algo):
    for file in [key_file, iv_file, encrypted_file]:
        if not checkFilePath(file):
            return("Warning", f"The file path {os.path.split(file)[1]} does not exist")
        
    with open(key_file, "rb") as fin:
        key = fin.read()

    with open(encrypted_file, "rb") as fin:
        cipher_text = fin.read()

    with open(iv_file, "rb") as fin:
        iv = fin.read()

    plain_text = encrypt_decrypt.aes_decrypt(key, iv, cipher_text, aes_algo)
    createTempDir("./Temp/Encrypt")
    removeFile(f"./Temp/Encrypt/{aes_algo.lower()}_decrypted_data.txt")
    with open (f"./Temp/Encrypt/{aes_algo.lower()}_decrypted_data.txt" , "w") as fout:
        fout.write(plain_text)

    return ("Success", "Decryption successful")

def If_rsa_decrypt(private_key_file, encrypted_file):
    for file in [private_key_file, encrypted_file]:
        if not checkFilePath(file):
            return("Warning", f"The file path {os.path.split(file)[1]} does not exist")
        
    private_key = keys.load_key("RSA", private_key_file)

    with open(encrypted_file, "rb") as fin:
        cipher_text = fin.read()

    plain_text = encrypt_decrypt.rsa_decrypt(private_key, cipher_text)
    createTempDir("./Temp/Encrypt")
    removeFile("./Temp/Encrypt/rsa_decrypted_data.txt")
    with open ("./Temp/Encrypt/rsa_decrypted_data.txt" , "w") as fout:
        fout.write(plain_text)

    return ("Success", "Decryption successful")

def If_generate_hash(input_file, hash_algo):
    if not checkFilePath(input_file):
        return("Warning", f"The file {os.path.split(input_file)[1]} does not exist")
    
    with open(input_file , "rb") as fin:
        data = fin.read()

    gen_hash = hashlib_hash.calculate_hash(data, hash_algo)
    createTempDir("./Temp/Hashes")
    removeFile("./Temp/Hashes/generated_hash.hash")
    with open("./Temp/Hashes/generated_hash.hash", "wb") as fout:
        fout.write(gen_hash)

    return ("Success", "Hash Generated")

def If_verify_hash(input_file, hash_file, hash_algo):
    for file in [input_file, hash_file]:
        if not checkFilePath(file):
            return("Warning", f"The file {os.path.split(file)[1]} does not exist")

    with open(input_file , "rb") as fin:
        data = fin.read()

    with open(hash_file , "rb") as fin:
        expected_hash = fin.read()

    result = hashlib_hash.verify_hash(data, expected_hash, hash_algo)
    if result:
        return ("Success", "Hash Verified")
    else:
        return("Failed", "Hash did not match")

def If_generate_CMAC(input_file, key_file):
    for file in [input_file, key_file]:
        if not checkFilePath(file):
            return("Warning", f"The file {os.path.split(file)[1]} does not exist")

    with open(input_file , "rb") as fin:
        message = fin.read()
    input_file_name = os.path.split(input_file)[1]
    with open(key_file , "rb") as fin:
        key = fin.read()

    try:
        gen_cmac = cmac.generate_cmac(key, message)
        createTempDir("./Temp/CMAC")
        with open(f"./Temp/CMAC/{input_file_name}.cmac", "wb") as fout:
            fout.write(gen_cmac)
        return("Success", "CMAC generated")
    except Exception as e:
        print("Error occurred", e)
        return("Error", "An error occurred, please check the log for more info")
    



    

    
 
    

