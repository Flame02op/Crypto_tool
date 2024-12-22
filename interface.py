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
from cryptography.hazmat.primitives import hashes
import time
import os
import pickle

longMessage_callOut  = 0

def createTempDir(path):
    if not os.path.exists(path):
        os.makedirs(path)

createTempDir("./Temp")
with open("./Temp/log_file.txt", "w") as log:
    log.write("Logging started at : " + time.ctime() + "\n")

def checkFilePath(path):
    if os.path.exists(path):
        return True
    else:
        return False
    
def If_generateKey(key_type, key_alg):
    # global public_key, private_key
    if key_type == "RSA":
        retList = keys.generate_rsa_key_pair(key_alg)
    elif key_type == "ECDSA":
        retList = keys.generate_ecdsa_key_pair(key_alg)
    elif key_type == "ED25519":
        retList = keys.generate_ed25519_key_pair()
    else:
        retList = random_gen.gen_symmetric_key(key_alg)

    status = retList[0]
    createTempDir("./Temp/Keys")
    if status == "Success":
        if "Symmetric" in key_type:
            key = retList[1]
            createTempDir("./Temp/Keys")
            with open("./Temp/Keys/Symmetric_key.pem", "w") as fout:
                fout.write(key)
            return("Success", f"{key_type} key generated at Temp/Keys")
        else:
            private_key = retList[1]
            public_key = retList[2]
            try:
                keys.save_private_key(key_type,private_key)
                keys.save_public_key(key_type, public_key)
            except Exception as e:
                with open ("./Temp/log_file.txt", "a") as log:
                    log.write("\n*********** Key generation failed ***********\n")
                    log.write(f"Error occurred : {str(e)}")
                    log.write("\n*********************************************\n")
                return("Error", "An exception occurred, check the log for further details")
            return("Success", f"Key pair of key type : {key_type} generated at Temp/Keys")
    else:
        with open ("./Temp/log_file.txt", "a") as log:
            log.write("\n*********** Key generation failed ***********\n")
            log.write(f"Error occurred : {retList[1]}")
            log.write("\n*********************************************\n")
        return("Error", "An error occurred : Please refer the log file for more details : Temp/log_file.txt")

def If_pem_to_hex(key_type, key_file):
    if not checkFilePath(key_file):
        return ("Warning", f"The file path {os.path.split(key_file)[1]} does not exist")

    key_file_name = os.path.split(key_file)[1]
    if key_type in ["RSA", "ECDSA", "ED25519"]:
        retList = keys.load_key(key_type, key_file)
        if retList[0] == "Success":
            pem_key = retList[1]
        else:
            with open ("./Temp/log_file.txt", "a") as log:
                log.write("\n*********** Key conversion failed ***********\n")
                log.write(f"Error occurred : {retList[1]}")
                log.write("\n*********************************************\n")
            return("Error", "An error occurred : Please refer the log file for more details : Temp/log_file.txt")
    else:
        try:
            retList = keys.load_symmetric_key(key_file)
            if retList[0] == "Success":
                pem_key = retList[1]
        except (ValueError, AttributeError):
            with open(key_file, "rb") as fin:
                pem_key = fin.read()
        except Exception as e:
            with open ("./Temp/log_file.txt", "a") as log:
                log.write("\n*********** Key conversion failed ***********\n")
                log.write(f"Error occurred : {str(e)}")
                log.write("\n*********************************************\n")
            return("Error", "An error occurred : Please refer the log file for more details : Temp/log_file.txt")

    retList = []
    key_file_name,_ = os.path.splitext(key_file_name)
    retList = convert.pem_to_hex(pem_key)
    if retList[0] == "Success":
        hex_key = retList[1]
        createTempDir("./Temp/Keys")
        with open(f"./Temp/Keys/{key_file_name}.hex", "w") as fout:
            fout.write(hex_key)
        return ("Success", "Conversion Successful")
    else:
        with open ("./Temp/log_file.txt", "a") as log:
            log.write("\n*********** Key conversion failed ***********\n")
            log.write(f"Error occurred : {retList[1]}")
            log.write("\n*********************************************\n")
        return("Error", "An error occurred : Please refer the log file for more details : Temp/log_file.txt")

def If_hex_to_pem(key_type, key_file):
    if not checkFilePath(key_file):
        return ("Warning", f"The file path {os.path.split(key_file)[1]} does not exist")

    with open(key_file, "r") as fin:
        hex_key = fin.read().strip()

    key_file_name = os.path.splitext(os.path.split(key_file)[1])[0]
    retList = convert.hex_to_pem(key_type, hex_key)
    if retList[0] == "Success":
        pem_key = retList[1]
        createTempDir("./Temp/Keys")
        if key_type in ["RSA", "ECDSA", "ED25519"]:

            if key_type == "ED25519":
                try:
                    keys.save_private_key(key_type, pem_key, True)
                    return ("Success", "Conversion Successful")
                except Exception as e:
                    pass
            else:
                try:
                    keys.save_private_key(key_type, pem_key)
                    return ("Success", "Conversion Successful")
                except Exception as e:
                    pass

            try:
                keys.save_public_key(key_type, pem_key)
                return ("Success", "Conversion Successful")
            except Exception as e:
                with open ("./Temp/log_file.txt", "a") as log:
                    log.write("\n*********** Key conversion failed ***********\n")
                    log.write(f"Error occurred : {retList[1]}")
                    log.write("\n*********************************************\n")
                return("Error", "An error occurred : Please refer the log file for more details : Temp/log_file.txt")
        else:
            with open(f"./Temp/Keys/{key_file_name}.pem", "w") as fout:
                fout.write(pem_key)
            return ("Success", "Conversion Successful")
    elif retList[0] == "Failure":
        return retList
    else:
        with open ("./Temp/log_file.txt", "a") as log:
            log.write("\n*********** Key conversion failed ***********\n")
            log.write(f"Error occurred : {retList[1]}")
            log.write("\n*********************************************\n")
        return("Error", "An error occurred : Please refer the log file for more details : Temp/log_file.txt")

def If_generate_sign(key_type, private_key_file, input_file, hash_algo):
    for file in [private_key_file, input_file]:
        if not checkFilePath(file):
            return ("Warning", f"The file path {os.path.split(file)[1]} does not exist")
    
    retList = keys.load_key(key_type, private_key_file)
    status = retList[0]
    if status == "Success":
        key = retList[1]
    elif status == "Failure":
        return retList
    else:
        with open ("./Temp/log_file.txt", "a") as log:
            log.write("\n******** signature generation failed ********\n")
            log.write(f"Error occurred : {retList[1]}")
            log.write("\n*********************************************\n")
        return("Error", "An error occurred : Please refer the log file for more details : Temp/log_file.txt")

    retList = []
    with open(input_file, "rb") as fin:
        message = fin.read()
    input_file_name = os.path.splitext(os.path.split(input_file)[1])[0]
    createTempDir("./Temp/Sign")
    if key_type == "RSA":
        retList = rsa_sign.generate_rsa_signature(key, message, hash_algo)
    elif key_type == "ECDSA":
        retList = ecdsa_sign.generate_ecdsa_signature(key, message, hash_algo)
    else:
        retList = ed25519_sign.generate_ed25519_signature(key, message)

    if retList[0] == "Success":
        signature = retList[1]
        with open(f"./Temp/Sign/{input_file_name}.Signed", "wb") as sign_file:
            sign_file.write(signature)
        return ("Success", "Signature generated")
    elif status == "Failure":
        failure_msg = retList[1]
        return ("Failure", failure_msg)
    else:
        with open ("./Temp/log_file.txt", "a") as log:
            log.write("\n******** signature generation failed ********\n")
            log.write(f"Error occurred : {retList[1]}")
            log.write("\n*********************************************\n")
        return("Error", "An error occurred : Please refer the log file for more details : Temp/log_file.txt")

def If_generateHasherLongMessage(key_type, hash_algo):
    global longMessage_callOut
    createTempDir("./Temp/Sign")
    if key_type == "RSA":
        retList = rsa_sign.generate_hash_longMessage(hash_algo, "./Temp/Sign/rsa_hasher.hash")
    elif key_type == "ECDSA":
        retList = ecdsa_sign.generate_hash_longMessage(hash_algo, "./Temp/Sign/ecdsa_hasher.hash")
    else:
        return ("Warning", f"{key_type} does not supports signing for long messages")
    status = retList[0]
    if status == "Success":
        longMessage_callOut +=1
        return("Success", "Hasher generated at file path Temp/Sign/Hasher.hash")
    elif status == "Error":
        with open ("./Temp/log_file.txt", "a") as log:
            log.write("\n******** signature generation failed ********\n")
            log.write(f"Error occurred : {retList[1]}")
            log.write("\n*********************************************\n")
        return("Error", "An error occurred : Please refer the log file for more details : Temp/log_file.txt")
    else:
        return("Warning", "Invalid Hash algorithm")

def If_updateHasherLongMessage(key_type, input_file, hasher_file):
    if longMessage_callOut > 0:

        for file in [input_file, hasher_file]:
            if not checkFilePath(file):
                return ("Warning", f"The file path {os.path.split(file)[1]} does not exist")
        with open(input_file, "rb") as fin:
            message = fin.read()

        with open(hasher_file, "rb") as fin:
            selected_hash, state = pickle.load(fin)

        # Recreate the hasher object
        hasher_obj = hashes.Hash(getattr(hashes, selected_hash)())

        # Update the hasher with the serialized state
        hasher_obj.update(state)

        if key_type == "RSA":
            retList = rsa_sign.update_hash_longMessage(hasher_obj, message, selected_hash, hasher_file)
        elif key_type == "ECDSA":
            retList = ecdsa_sign.update_hash_longMessage(hasher_obj, message, selected_hash, hasher_file)
        else:
            return ("Warning", f"The key type {key_type} does not supports signing for long messages")
        if retList[0] == "Success":
            return retList
        else:
            with open ("./Temp/log_file.txt", "a") as log:
                log.write("\n******** signature generation failed ********\n")
                log.write(f"Error occurred : {retList[1]}")
                log.write("\n*********************************************\n")
            return("Error", "An error occurred : Please refer the log file for more details : Temp/log_file.txt")
    else:
        return ("Warning", "Generate Hasher for long message first")

def If_generate_signForLongMessage(key_type, private_key_file, hasher_file, hash_algo):
    if longMessage_callOut != 0:
        for file in [private_key_file,hasher_file]:
            if not checkFilePath(file):
                return ("Warning", f"The file path {os.path.split(file)[1]} does not exist")

        retList = keys.load_key(key_type, private_key_file)
        if retList[0] == "Success":
            key = retList[1]
        elif retList[0] == "Failure":
            return retList
        else:
            with open ("./Temp/log_file.txt", "a") as log:
                log.write("\n******** signature generation failed ********\n")
                log.write(f"Error occurred : {retList[1]}")
                log.write("\n*********************************************\n")
            return("Error", "An error occurred : Please refer the log file for more details : Temp/log_file.txt")

        retList = []
        try:
            with open(hasher_file, "rb") as fin:
                selected_hash, state = pickle.load(fin)
            hasher_obj = hashes.Hash(getattr(hashes, selected_hash)())
            hasher_obj.update(state)
        except Exception as e:
            with open ("./Temp/log_file.txt", "a") as log:
                log.write("\n******** signature generation failed ********\n")
                log.write(f"Error occurred : {str(e)}")
                log.write("\n*********************************************\n")
            return("Error", "An error occurred : Please refer the log file for more details : Temp/log_file.txt")

        hasher_file_name =os.path.splitext( os.path.split(hasher_file)[1])[0]
        if key_type == "RSA":
            retList = rsa_sign.generate_rsa_signature_longMessage(key, hasher_obj, hash_algo)
        elif key_type == "ECDSA":
            retList = ecdsa_sign.generate_ecdsa_signature_longMessage(key, hasher_obj, hash_algo) 
        else:
            return ("Warning", f"{key_type} does not support long message signing")
        if retList[0] == "Success":
            signature = retList[1]
            createTempDir("./Temp/Sign")
            with open(f"./Temp/Sign/{hasher_file_name}.sign", "wb") as fout:
                fout.write(signature)
            return ("Success", "Signature generated")
        else:
            with open ("./Temp/log_file.txt", "a") as log:
                log.write("\n******** signature generation failed ********\n")
                log.write(f"Error occurred : {retList[1]}")
                log.write("\n*********************************************\n")
            return("Error", "An error occurred : Please refer the log file for more details : Temp/log_file.txt")
    else:
        return ("Warning", "Generate Hasher for long message first")

def If_verify_signature(key_type, public_Key_file, input_file, signature_file, hash_algo):

    for file in [input_file, public_Key_file, signature_file]:
        if not checkFilePath(file):
            return("Warning", f"The file path {os.path.split(file)[1]} does not exist")
        
    retList = keys.load_key(key_type, public_Key_file)
    if retList[0] == "Success":
        key = retList[1]
    elif retList[0] == "Failure":
        return retList
    else:
        with open ("./Temp/log_file.txt", "a") as log:
            log.write("\n******* signature verification failed *******\n")
            log.write(f"Error occurred : {retList[1]}")
            log.write("\n*********************************************\n")
        return("Error", "An error occurred : Please refer the log file for more details : Temp/log_file.txt")

    with open(input_file, "rb") as fin:
        message = fin.read()
    with open(signature_file, "rb") as fin:
        signature = fin.read()

    retList = []
    if key_type == "RSA":
        retList = rsa_sign.verify_rsa_signature(key, message, signature, hash_algo)
    elif key_type == "ECDSA":
        retList = ecdsa_sign.verify_ecdsa_signature(key, message, signature, hash_algo)
    else:
        retList = ed25519_sign.verify_ed25519_signature(key, message, signature)

    if retList[0] == "Success" or retList[0] == "Failure":
        return retList
    else:
        with open ("./Temp/log_file.txt", "a") as log:
            log.write("\n******* signature verification failed *******\n")
            log.write(f"Error occurred : {retList[1]}")
            log.write("\n*********************************************\n")
        return("Error", "An error occurred : Please refer the log file for more details : Temp/log_file.txt")
    
def If_verify_signature_LongMessage(key_type, public_Key_file, hasher_file, signature_file, hash_algo):
    for file in [public_Key_file, hasher_file, signature_file]:
        if not checkFilePath(file):
            return("Warning",  f"The file path {file} does not exist")

    retList = keys.load_key(key_type, public_Key_file)
    if retList[0] == "Success":
        key = retList[1]
    elif retList[0] == "Failure":
        return retList
    else:
        with open ("./Temp/log_file.txt", "a") as log:
            log.write("\n******* signature verification failed *******\n")
            log.write(f"Error occurred : {retList[1]}")
            log.write("\n*********************************************\n")
        return("Error", "An error occurred : Please refer the log file for more details : Temp/log_file.txt")

    try:
        with open(hasher_file, "rb") as fin:
            selected_hash, state = pickle.load(fin)
        hasher_obj = hashes.Hash(getattr(hashes, selected_hash)())
        hasher_obj.update(state)
    except Exception as e:
        with open ("./Temp/log_file.txt", "a") as log:
            log.write("\n******** signature generation failed ********\n")
            log.write(f"Error occurred : {str(e)}")
            log.write("\n*********************************************\n")
        return("Error", "An error occurred : Please refer the log file for more details : Temp/log_file.txt")

    with open(signature_file, 'rb') as fin:
        signature = fin.read()

    retList = []
    if key_type == "RSA":
        retList = rsa_sign.verify_rsa_signature_longMessage(key, hasher_obj, signature, hash_algo)
    elif key_type == "ECDSA":
        retList = ecdsa_sign.verify_ecdsa_signature_longMessage(key, hasher_obj, signature, hash_algo)
    else:
        return ("Warning", "Ed25519 does not support long message verification") 
    
    if retList[0] == "Error":
        with open ("./Temp/log_file.txt", "a") as log:
            log.write("\n******* signature verification failed *******\n")
            log.write(f"Error occurred : {retList[1]}")
            log.write("\n*********************************************\n")
        return("Error", "An error occurred : Please refer the log file for more details : Temp/log_file.txt")
    else:
        return retList

def If_aes_encrypt(key_file, input_file, iv_file, aes_algo):
    for file in [key_file, input_file, iv_file]:
        if not checkFilePath(file):
            return("Warning", f"The file path {os.path.split(file)[1]} does not exist")

    try:
        retList = keys.load_symmetric_key(key_file)
        if retList[0] == "Success":
            key = retList[1]
    except (ValueError, AttributeError):
        with open(key_file, "rb") as fin:
            key = fin.read()
    except Exception as e:
        with open ("./Temp/log_file.txt", "a") as log:
            log.write("\n************ Encryption failed **************\n")
            log.write(f"Error occurred : {str(e)}")
            log.write("\n*********************************************\n")
        return("Error", "An error occurred : Please refer the log file for more details : Temp/log_file.txt")

    with open(input_file, "r") as fin:
        plain_text = fin.read()

    with open(iv_file, "rb") as fin:
        iv = fin.read()
    retList = []
    retList = encrypt_decrypt.aes_encrypt(key, iv, plain_text, aes_algo)
    if retList[0] == "Success":
        encrypted_data = retList[1]
        createTempDir("./Temp/Encrypt")
        with open (f"./Temp/Encrypt/{aes_algo.lower()}_encrypted_data.enc" , "wb") as fout:
            fout.write(encrypted_data)
        return ("Success", "Encryption successful")
    elif retList[0] == "Error":
        return retList
    else:
        with open ("./Temp/log_file.txt", "a") as log:
            log.write("\n************* Encryption failed *************\n")
            log.write(f"Error occurred : {retList[1]}")
            log.write("\n*********************************************\n")
        return("Error", "An error occurred : Please refer the log file for more details : Temp/log_file.txt")

def If_rsa_encrypt(public_key_file, input_file, hash_algo):
    for file in [public_key_file, input_file]:
        if not checkFilePath(file):
            return("Warning", f"The file path {os.path.split(file)[1]} does not exist")
    retList = keys.load_key("RSA", public_key_file)
    if retList[0] == "Success":
        public_key = retList[1]
    elif retList[0] == "Failure":
        return retList
    else:
        with open ("./Temp/log_file.txt", "a") as log:
            log.write("\n************* Encryption failed *************\n")
            log.write(f"Error occurred : {retList[1]}")
            log.write("\n*********************************************\n")
        return("Error", "An error occurred : Please refer the log file for more details : Temp/log_file.txt")

    with open(input_file, "rb") as fin:
        plain_text = fin.read()
    retList = encrypt_decrypt.rsa_encrypt(public_key, plain_text, hash_algo)
    if retList[0] == "Success":
        encrypted_data = retList[1]
        createTempDir("./Temp/Encrypt")
        with open ("./Temp/Encrypt/rsa_encrypted_data.enc" , "wb") as fout:
            fout.write(encrypted_data)
        return ("Success", "Encryption successful")
    elif retList[0] == "Error":
        return retList
    else:
        with open ("./Temp/log_file.txt", "a") as log:
            log.write("\n************* Encryption failed *************\n")
            log.write(f"Error occurred : {retList[1]}")
            log.write("\n*********************************************\n")
        return("Error", "An error occurred : Please refer the log file for more details : Temp/log_file.txt")

def If_aes_decrypt(key_file, iv_file, encrypted_file, aes_algo):
    for file in [key_file, iv_file, encrypted_file]:
        if not checkFilePath(file):
            return("Warning", f"The file path {os.path.split(file)[1]} does not exist")

    try:
        retList = keys.load_symmetric_key(key_file)
        if retList[0] == "Success":
            key = retList[1]
    except (ValueError, AttributeError):
        with open(key_file, "rb") as fin:
            key = fin.read()
    except Exception as e:
        with open ("./Temp/log_file.txt", "a") as log:
            log.write("\n************ Decryption Failed **************\n")
            log.write(f"Error occurred : {str(e)}")
            log.write("\n*********************************************\n")
        return("Error", "An error occurred : Please refer the log file for more details : Temp/log_file.txt")

    with open(encrypted_file, "rb") as fin:
        cipher_text = fin.read()

    with open(iv_file, "rb") as fin:
        iv = fin.read()
    retList = []
    retList = encrypt_decrypt.aes_decrypt(key, iv, cipher_text, aes_algo)
    if retList[0] == "Success":
        plain_text = retList[1]
        createTempDir("./Temp/Encrypt")
        with open (f"./Temp/Encrypt/{aes_algo.lower()}_decrypted_data.txt" , "wb") as fout:
            fout.write(plain_text)
        return ("Success", "Decryption successful")
    elif retList[0] == "Failure":
        return retList
    else:
        with open ("./Temp/log_file.txt", "a") as log:
            log.write("\n************* Decryption failed *************\n")
            log.write(f"Error occurred : {retList[1]}")
            log.write("\n*********************************************\n")
        return("Error", "An error occurred : Please refer the log file for more details : Temp/log_file.txt")

def If_rsa_decrypt(private_key_file, encrypted_file, hash_algo):
    for file in [private_key_file, encrypted_file]:
        if not checkFilePath(file):
            return("Warning", f"The file path {os.path.split(file)[1]} does not exist")
        
    retList = keys.load_key("RSA", private_key_file)
    if retList[0] == "Success":
        private_key = retList[1]
    elif retList[0] == "Failure":
        return retList
    else:
        with open ("./Temp/log_file.txt", "a") as log:
            log.write("\n************* Encryption failed *************\n")
            log.write(f"Error occurred : {retList[1]}")
            log.write("\n*********************************************\n")
        return("Error", "An error occurred : Please refer the log file for more details : Temp/log_file.txt")

    with open(encrypted_file, "rb") as fin:
        cipher_text = fin.read()
    retList = []
    retList = encrypt_decrypt.rsa_decrypt(private_key, cipher_text, hash_algo)
    if retList[0] == "Success":
        plain_text = retList[1]
        createTempDir("./Temp/Encrypt")
        with open ("./Temp/Encrypt/rsa_decrypted_data.txt" , "wb") as fout:
            fout.write(plain_text)
        return ("Success", "Decryption successful")
    elif retList[0] == "Failure":
        return retList
    else:
        with open ("./Temp/log_file.txt", "a") as log:
            log.write("\n************* Decryption failed *************\n")
            log.write(f"Error occurred : {retList[1]}")
            log.write("\n*********************************************\n")
        return("Error", "An error occurred : Please refer the log file for more details : Temp/log_file.txt")

def If_generate_hash(input_file, hash_algo):
    if not checkFilePath(input_file):
        return("Warning", f"The file {os.path.split(input_file)[1]} does not exist")
    
    with open(input_file , "rb") as fin:
        data = fin.read()

    retList = hashlib_hash.calculate_hash(data, hash_algo)
    if retList[0] == "Success":
        gen_hash = retList[1]
        createTempDir("./Temp/Hashes")
        with open("./Temp/Hashes/generated_hash.hash", "w") as fout:
            fout.write(gen_hash)

        return ("Success", "Hash Generated")
    elif retList[0] == "Failure":
        return retList
    else:
        with open ("./Temp/log_file.txt", "a") as log:
            log.write("\n************ Hash generation failed *********\n")
            log.write(f"Error occurred : {retList[1]}")
            log.write("\n*********************************************\n")
        return("Error", "An error occurred : Please refer the log file for more details : Temp/log_file.txt")

def If_verify_hash(input_file, hash_file, hash_algo):
    for file in [input_file, hash_file]:
        if not checkFilePath(file):
            return("Warning", f"The file {os.path.split(file)[1]} does not exist")

    with open(input_file , "rb") as fin:
        data = fin.read()

    with open(hash_file , "r") as fin:
        expected_hash = fin.read()

    retList = hashlib_hash.verify_hash(data, expected_hash, hash_algo)
    if retList[0] == "Success" or retList[0] == "Failure":
        return retList
    else:
        with open ("./Temp/log_file.txt", "a") as log:
            log.write("\n********** Hash verification failed *********\n")
            log.write(f"Error occurred : {retList[1]}")
            log.write("\n*********************************************\n")
        return("Error", "An error occurred : Please refer the log file for more details : Temp/log_file.txt")

def If_generate_CMAC(key_file, input_file):
    for file in [key_file, input_file]:
        if not checkFilePath(file):
            return("Warning", f"The file {os.path.split(file)[1]} does not exist")

    with open(input_file , "rb") as fin:
        message = fin.read()
    input_file_name = os.path.splitext(os.path.split(input_file)[1])[0]

    try:
        retList = keys.load_symmetric_key(key_file)
        if retList[0] == "Success":
            key = retList[1]
    except (ValueError, AttributeError):
        with open(key_file, "rb") as fin:
            key = fin.read()
    except Exception as e:
        with open ("./Temp/log_file.txt", "a") as log:
            log.write("\n************ CMAC generation failed *********\n")
            log.write(f"Error occurred : {str(e)}")
            log.write("\n*********************************************\n")
        return("Error", "An error occurred : Please refer the log file for more details : Temp/log_file.txt")
    retList = []
    retList = cmac.generate_cmac(key, message)
    if retList[0] == "Success":
        gen_cmac = retList[1]
        createTempDir("./Temp/CMAC")
        with open(f"./Temp/CMAC/{input_file_name}.cmac", "wb") as fout:
            fout.write(gen_cmac)
        return("Success", "CMAC generated")
    else:
        with open ("./Temp/log_file.txt", "a") as log:
            log.write("\n************ CMAC generation failed *********\n")
            log.write(f"Error occurred : {retList[1]}")
            log.write("\n*********************************************\n")
        return("Error", "An error occurred : Please refer the log file for more details : Temp/log_file.txt")
    
def If_verify_cmac(key_file, input_file, cmac_file):
    for file in [key_file, input_file, cmac_file]:
        if not checkFilePath(file):
            return("Warning", f"The file {os.path.split(file)[1]} does not exist")

    with open(input_file, "rb") as fin:
        message = fin.read()

    try:
        retList = keys.load_symmetric_key(key_file)
        if retList[0] == "Success":
            key = retList[1]
    except (ValueError, AttributeError):
        with open(key_file, "rb") as fin:
            key = fin.read()
    except Exception as e:
        with open ("./Temp/log_file.txt", "a") as log:
            log.write("\n********** CMAC verification failed ********\n")
            log.write(f"Error occurred : {str(e)}")
            log.write("\n*********************************************\n")
        return("Error", "An error occurred : Please refer the log file for more details : Temp/log_file.txt")

    with open(cmac_file, "rb") as fin:
        expected_cmac = fin.read()
    retList = []
    retList = cmac.verify_cmac(key, message, expected_cmac)
    if retList[0] == "Success" or retList[0] == "Failure":
        return retList
    else:
        with open ("./Temp/log_file.txt", "a") as log:
            log.write("\n********** CMAC verification failed *********\n")
            log.write(f"Error occurred : {retList[1]}")
            log.write("\n*********************************************\n")
        return("Error", "An error occurred : Please refer the log file for more details : Temp/log_file.txt")
    
def If_generate_cmac_with_time_stamp( key_file, input_file, timestamp):
    for file in [key_file, input_file]:
        if not checkFilePath(file):
            return("Warning", f"The file {os.path.split(file)[1]} does not exist")
    with open(input_file, "rb") as fin:
        message = fin.read()
    input_file_name = os.path.splitext(os.path.split(input_file)[1])[0]

    try:
        retList = keys.load_symmetric_key(key_file)
        if retList[0] == "Success":
            key = retList[1]
    except (ValueError, AttributeError):
        with open(key_file, "rb") as fin:
            key = fin.read()
    except Exception as e:
        with open ("./Temp/log_file.txt", "a") as log:
            log.write("\n************ CMAC generation failed *********\n")
            log.write(f"Error occurred : {str(e)}")
            log.write("\n*********************************************\n")
        return("Error", "An error occurred : Please refer the log file for more details : Temp/log_file.txt")
    retList = []
    timestamp = timestamp.encode('utf-8')
    retList = cmac.generate_cmac_with_timestamp(key, message, timestamp)
    if retList[0] == "Success":
        gen_cmac = retList[1]
        createTempDir("./Temp/CMAC")
        with open(f"./Temp/CMAC/{input_file_name}.cmac", "wb") as fout:
            fout.write(gen_cmac)
        return("Success", "CMAC generated")
    else:
        with open ("./Temp/log_file.txt", "a") as log:
            log.write("\n************ CMAC generation failed *********\n")
            log.write(f"Error occurred : {retList[1]}")
            log.write("\n*********************************************\n")
        return("Error", "An error occurred : Please refer the log file for more details : Temp/log_file.txt")

def If_verify_cmac_with_time_stamp(key_file, input_file, cmac_file, timestamp, time_threshold):
    for file in [key_file, input_file, cmac_file]:
        if not checkFilePath(file):
            return("Warning", f"The file {os.path.split(file)[1]} does not exist")

    with open(input_file, "rb") as fin:
        message = fin.read()

    try:
        retList = keys.load_symmetric_key(key_file)
        if retList[0] == "Success":
            key = retList[1]
    except (ValueError, AttributeError):
        with open(key_file, "rb") as fin:
            key = fin.read()
    except Exception as e:
        with open ("./Temp/log_file.txt", "a") as log:
            log.write("\n********** CMAC verification failed *********\n")
            log.write(f"Error occurred : {str(e)}")
            log.write("\n*********************************************\n")
        return("Error", "An error occurred : Please refer the log file for more details : Temp/log_file.txt")

    with open(cmac_file, "rb") as fin:
        expected_cmac = fin.read()
    retList = []
    retList = cmac.verify_cmac_with_timestamp(key, message, expected_cmac, timestamp, int(time_threshold))
    if retList[0] == "Success" or retList[0] == "Failure":
        return retList
    else:
        with open ("./Temp/log_file.txt", "a") as log:
            log.write("\n*********** CRC generation failed ***********\n")
            log.write(f"Error occurred : {retList[1]}")
            log.write("\n*********************************************\n")
        return("Error", "An error occurred : Please refer the log file for more details : Temp/log_file.txt")

def If_generate_crc(input_file, algorithm):
    if not checkFilePath(input_file):
        return("Warning", f"The file {os.path.split(input_file)[1]} does not exist")

    with open(input_file, "rb") as fin:
        data = fin.read()

    input_file_name = os.path.splitext(os.path.split(input_file)[1])[0]
    retList = crc.calculate_crc(data, algorithm.lower())
    if retList[0] == "Success":
        gen_crc = str(retList[1])
        createTempDir("./Temp/CRC")
        with open(f"./Temp/CRC/{input_file_name}.txt", "w") as fout:
            fout.write(gen_crc)
        return("Success", "CRC generated successfully")
    elif retList[0] == "Failure":
        return retList
    else:
        with open ("./Temp/log_file.txt", "a") as log:
            log.write("\n********** CRC verification failed **********\n")
            log.write(f"Error occurred : {retList[1]}")
            log.write("\n*********************************************\n")
        return("Error", "An error occurred : Please refer the log file for more details : Temp/log_file.txt")
    
def If_verify_crc(input_file, crc_file, algorithm):
    for file in [input_file, crc_file]:
        if not checkFilePath(file):
            return("Warning", f"The file {os.path.split(input_file)[1]} does not exist")

    with open(input_file, "rb") as fin:
        data = fin.read()
    with open(crc_file) as fin:
        calculated_crc = fin.read()

    retList = crc.verify_crc(data, algorithm.lower(), int(calculated_crc))
    if retList[0] == "Success" or retList[0] == "Failure":
        return retList
    else:
        with open ("./Temp/log_file.txt", "a") as log:
            log.write("\n********** CRC verification failed **********\n")
            log.write(f"Error occurred : {retList[1]}")
            log.write("\n*********************************************\n")
        return("Error", "An error occurred : Please refer the log file for more details : Temp/log_file.txt")

def If_generate_random_bytes(num_bytes):
    random_bytes = random_gen.generate_random_bytes(int(num_bytes))
    createTempDir("./Temp/Random/")
    with open("./Temp/Random/Random_bytes.bin", "wb") as fout:
        fout.write(random_bytes)

if __name__ == "__main__":
    print("Execution started")
