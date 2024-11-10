from crypto_key_app import key_management as keys
from cryptography.hazmat.primitives.asymmetric import rsa
from crypto_key_app import random_gen
from crypto_key_app import rsa_signatures as rsa_sign
from crypto_key_app import ecdsa_signatures as ecdsa_sign
from crypto_key_app import key_conversion as convert
from crypto_key_app import hashlib_hashing as hash
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
    if not os.path.exists(path):
        return False
    else:
        return True

def If_load_key(key_type, key_alg, filepath):
    global private_key, public_key
    if checkFilePath(filepath) == False:
        return ("Warning", f"The file path {filepath} does not exist")
    else:
        if key_type == "Private":
            private_key = keys.load_key(key_alg, filepath)
        else:
            public_key = keys.load_key(key_alg, filepath)

    
def If_generateKey(key_type, key_alg):
    global public_key, private_key
    if key_type == "RSA":
        private_key, public_key = keys.generate_rsa_key_pair(key_alg)
    elif key_type == "ECDSA":
        private_key, public_key = keys.generate_ecdsa_key_pair(key_alg) 
    else:
        private_key, public_key = keys.generate_ed25519_key_pair(key_alg)

    createTempDir("./Temp/Keys")
    with open("./Temp/Keys/private_key.pem", 'wb') as key_file:
            key_file.write(private_key)

    with open("./Temp/Keys/public_key.pem", 'wb') as key_file:
            key_file.write(public_key)
   

def If_generateSign(key_type, key, input_file, hash):
    if checkFilePath(input_file) == False:
        return ("Warning", f"The file path {input_file} does not exist")
    else:
        with open(input_file) as fin:
            message = fin.read()

        _, input_file = os.path.split(input_file)
        createTempDir("./Temp/Signatures")

        if key_type == "RSA":
            signature = rsa_sign.generate_rsa_signature(key, message, hash)
        elif key_type == "ECDSA":
            signature = ecdsa_sign.generate_ecdsa_signature(key, message, hash)       
        else:
            signature = ed25519_sign.generate_ed25519_signature(key, message, hash)
            
        with open(f"./Temp/Signatures/{input_file}.Signed", "wb") as sign_file:
                sign_file.write(signature)

def If_generateHashForLongMessage(key_type, input_file, hash):
    global longMessage_callOut
    if checkFilePath(input_file) == False:
            return ("Warning", f"The file path {input_file} does not exist")
    else:
        with open(input_file, "rb") as fin:
                message = fin.read()

    if longMessage_callOut == 0:     
        if key_type == "RSA":
            hasher = rsa_sign.generate_hash_longMessage(hash)
            hasher = rsa_sign.update_hash_longMessage(hasher, message)
        elif key_type == "ECDSA":
            hasher = ecdsa_sign.generate_hash_longMessage(hash) 
            hasher = ecdsa_sign.update_hash_longMessage(hasher, message)    
        longMessage_callOut += 1

    else:
        if key_type == "RSA":
            hasher = rsa_sign.update_hash_longMessage(hasher, message)
        elif key_type == "ECDSA":
            hasher = ecdsa_sign.update_hash_longMessage(hasher, message) 

# To do
def If_generateSignForLongMessage(key_type, key, input_file, hash):   
    if longMessage_callOut != 0:
        if checkFilePath(input_file) == False:
           return ("Warning", f"The file path {input_file} does not exist")
        else:
            with open(input_file, "rb") as fin:
                message = fin.read()
        _, input_file = os.path.split(input_file)
        if not os.path.exists("./Temp/Signatures"):
            os.makedirs("./Temp/Signatures")

        if key_type == "RSA":
            signature = rsa_sign.generate_rsa_signature_longMessage(key, hasher, hash)
        elif key_type == "ECDSA":
            signature = ecdsa_sign.generate_ecdsa_signature_longMessage(key, hasher, hash) 
        else:
            return ("Warning", "Ed25519 does not support long message signing")


def If_verifySignature(publicKey, input_file, key_type, signature_file, selected_hash):
    if checkFilePath(input_file) == False or checkFilePath(signature_file) == False:
        return("Warning",  f"The file path {input_file} or {signature_file} does not exist")
    else:
        with open(input_file, "rb") as fin:
            message = fin.read()
        with open(signature_file, "rb") as fin:
            signature = fin.read()

        if key_type == "RSA":
            rsa_sign.verify_rsa_signature(publicKey, message, signature, selected_hash)
        elif key_type == "ECDSA":
            ecdsa_sign.verify_ecdsa_signature(publicKey, message, signature, selected_hash)
        else:
            ed25519_sign.verify_ed25519_signature(publicKey, message, signature, selected_hash)
    
def If_VerifySignature_LongMessage(publicKey, input_file, key_type, signature_file, selected_hash):
    if checkFilePath(input_file) == False or checkFilePath(signature_file) == False:
        return("Warning",  f"The file path {input_file} or {signature_file} does not exist")
    else:
        with open(input_file, "rb") as fin:
            message = fin.read()
        with open(signature_file, 'rb') as fin:
            signature = fin.read()

        if key_type == "RSA":
            rsa_sign.verify_rsa_signature_longMessage(publicKey, hasher, signature, selected_hash)
        elif key_type == "ECDSA":
            ecdsa_sign.verify_ecdsa_signature_longMessage(publicKey, hasher, signature, selected_hash)
        else:
            return ("Warning", "Ed25519 does not support long message verification") 
    

if __name__ == "__main__":
    # secret_key, public_key = keys.generate_rsa_key_pair(256)
    # rsa_signature = rsa_sign.generate_rsa_signature(secret_key, b"This is a message to be signed", 'md5')
    # rsa_sign.verify_rsa_signature(public_key, b"This is a message to be signed", rsa_signature, 'md5')
    # message1 = b"This is a really really long message that is going to be split in 2-3 different message chunks. This is done because the signing depends on the key size which is defined in key_management"
    # message2 = b"This individual chunk is a part of a big data block that has to be signed. Since this data (as a whole) can be bigger in size than the key itself, and thus cannot be signed in a single call"
    # hasher = rsa_sign.generate_hash_longMessage('sha256')
    # rsa_sign.update_hash_longMessage(hasher, message1)
    # rsa_sign.update_hash_longMessage(hasher, message2)
    # rsa_signature = rsa_sign.generate_rsa_signature_longMessage(secret_key,hasher,'sha256')
    # message1 = b"This is a really really long message that is going to be split in 2-3 different message chunks. This is done because the signing depends on the key size which is defined in key_management"
    # message2 = b"This individual chunk is a part of a big data block that has to be signed. Since this data (as a whole) can be bigger in size than the key itself, and thus cannot be signed in a single call"
    # hasher2 = rsa_sign.generate_hash_longMessage('sha256')
    # rsa_sign.update_hash_longMessage(hasher2, message1)
    # rsa_sign.update_hash_longMessage(hasher2, message2)
    # rsa_sign.verify_rsa_signature_longMessage(public_key,hasher2, rsa_signature, 'sha256')
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
    # key = random_gen.generate_random_bytes(32)
    # key = random_gen.generate_random_bytes(24)
    # iv = random_gen.generate_random_bytes(16)
    # ciphertext = encrypt_decrypt.aes_encrypt(key, iv, "This is a message to be encrypted", 'CBC')
    # print(ciphertext)
    # plaintext = encrypt_decrypt.aes_decrypt(key, iv, ciphertext)
    # print(f"Readable text {plaintext}")
    # message = b'test message'
    # cmac_value = cmac.generate_cmac(key, message)
    # print(cmac_value.hex())
    # print(cmac.verify_cmac(key, message, cmac_value))

    # message = b"This message is generated for testing"
    # cmac_value, time_stamp = cmac.generate_cmac_with_timestamp(key, message)
    # time_stamp= str(int(time.time())).encode('utf-8')
    # print(cmac_value.hex())
    # time.sleep(15)
    # print(cmac.verify_cmac_with_timestamp(key, message, cmac_value, time_stamp, time_threshold=10))
    # Verify the CMAC and get the calculated CMAC
    # try:
    #     calculated_cmac = cmac.verify_cmac(key, message, cmac_value)
    #     print(f"Verified CMAC: {calculated_cmac.hex()}")
    # except cmac.InvalidSignature as e:
    #     print(str(e))
    # calculated_crc = crc.calculate_crc("This is a message to be calculated", algorithm="crc-8")
    # print(crc.verify_crc(b"This is a message to be calculated", 'crc-32', calculated_crc))
    # secret_key, public_key = keys.generate_ecdsa_key_pair('secp256r1')
    # # keys.show_key_pair(secret_key,public_key)
    # message = b"This is a message to be signed"
    # signature = ecdsa_sign.generate_ecdsa_signature(secret_key, message, 'sha256')
    # ecdsa_sign.verify_ecdsa_signature(public_key,message,signature,'sha256')
    # message1 = b"This is a really really long message that is going to be split in 2-3 different message chunks. This is done because the signing depends on the key size which is defined in key_management"
    # message2 = b"This individual chunk is a part of a big data block that has to be signed. Since this data (as a whole) can be bigger in size than the key itself, and thus cannot be signed in a single call"
    # hasher = ecdsa_sign.generate_hash_longMessage('sha256')
    # ecdsa_sign.update_hash_longMessage(hasher, message1)
    # ecdsa_sign.update_hash_longMessage(hasher, message2)
    # ecdsa_signature =ecdsa_sign.generate_ecdsa_signature_longMessage(secret_key,hasher,'sha256')
    # message1 = b"This is a really really long message that is going to be split in 2-3 different message chunks. This is done because the signing depends on the key size which is defined in key_management"
    # message2 = b"This individual chunk is a part of a big data block that has to be signed. Since this data (as a whole) can be bigger in size than the key itself, and thus cannot be signed in a single call"
    # hasher2 = ecdsa_sign.generate_hash_longMessage('sha256')
    # ecdsa_sign.update_hash_longMessage(hasher2, message1)
    # ecdsa_sign.update_hash_longMessage(hasher2, message2)
    # ecdsa_sign.verify_ecdsa_signature_longMessage(public_key,hasher2, ecdsa_signature, 'sha256')
    
    pass

    

    
 
    

