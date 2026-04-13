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
from crypto_key_app import srec_parser as sparser
from crypto_key_app import hex_parser as hparser
import time
import os
import pickle
import base64

# Base directory for all temporary output files
TEMP_DIR = "./Temp"
LOG_FILE = os.path.join(TEMP_DIR, "log_file.txt")

# Counter tracking how many times a long-message hasher has been initialised.
# A non-zero value indicates that a hasher file is ready for subsequent steps.
longMessage_callOut = 0

# ── Internal helpers ────────────────────────────────────────────────────────

_temp_initialised = False


def _init_temp_dir():
    """Create the temporary working directory and initialise the log file.

    Called lazily on the first operation that needs it so that merely
    importing this module does not create filesystem artefacts (which would
    interfere with unit testing).
    """
    global _temp_initialised
    if _temp_initialised:
        return
    createTempDir(TEMP_DIR)
    with open(LOG_FILE, "w") as log:
        log.write("Logging started at : " + time.ctime() + "\n")
    _temp_initialised = True


def _write_log(section: str, message: str) -> None:
    """Append a labelled error block to the log file."""
    _init_temp_dir()
    with open(LOG_FILE, "a") as log:
        log.write(f"\n{'*' * 13} {section} {'*' * 13}\n")
        log.write(f"Error occurred : {message}")
        log.write(f"\n{'*' * 45}\n")


def _load_symmetric_key_raw(key_file: str):
    """Load a symmetric key from *key_file*, returning the raw key bytes.

    Tries the structured PEM loader first; falls back to reading the file
    as raw binary when the PEM loader raises ``ValueError`` or
    ``AttributeError`` (i.e. the key is already in raw binary form).

    Returns the key bytes on success, or raises on unexpected errors.
    """
    try:
        ret = keys.load_symmetric_key(key_file)
        if ret[0] == "Success":
            return ret[1]
        raise ValueError(ret[1])
    except (ValueError, AttributeError):
        with open(key_file, "rb") as fin:
            return fin.read()


# ── Public helpers ───────────────────────────────────────────────────────────

def createTempDir(path: str) -> None:
    """Create *path* (and any missing parents) if it does not already exist."""
    if not os.path.exists(path):
        os.makedirs(path)


def get_input_file_data(input_file: str, start_add, end_add):
    """Detect the format of *input_file* and parse its data.

    Returns parsed bytes on success, ``"unknown"`` when the format cannot be
    detected, or ``None`` when the parser reports an error.
    """
    file_type = ""
    with open(input_file, 'r') as fin:
        for line in fin:
            line = line.strip()
            if not line:
                continue
            if line.startswith('S') and len(line) > 2 and line[1].isdigit():
                file_type = "srec"
                break
            elif line.startswith(':') and input_file.endswith(".hex"):
                file_type = 'hex'
                break
            else:
                # If the line doesn't match either, keep checking
                continue

    if file_type == "srec":
        return sparser.parse_data(input_file, start_add, end_add)
    elif file_type == "hex":
        return hparser.parse_data(input_file, start_add, end_add)
    else:
        return "unknown"

def checkFilePath(path: str) -> bool:
    """Return ``True`` when *path* exists on the filesystem."""
    return os.path.exists(path)


def If_generateKey(key_type, key_alg):
    if key_type == "RSA":
        retList = keys.generate_rsa_key_pair(key_alg)
    elif key_type == "ECDSA":
        retList = keys.generate_ecdsa_key_pair(key_alg)
    elif key_type == "ED25519":
        retList = keys.generate_ed25519_key_pair()
    else:
        retList = random_gen.gen_symmetric_key(key_alg)

    _init_temp_dir()
    status = retList[0]
    createTempDir(os.path.join(TEMP_DIR, "Keys"))
    if status == "Success":
        if "Symmetric" in key_type:
            key = retList[1]
            with open(os.path.join(TEMP_DIR, "Keys", "Symmetric_key.pem"), "w") as fout:
                fout.write(key)
            return ("Success", f"{key_type} key generated at Temp/Keys")
        else:
            private_key = retList[1]
            public_key = retList[2]
            try:
                keys.save_private_key(key_type, private_key)
                keys.save_public_key(key_type, public_key)
            except Exception as e:
                _write_log("Key generation failed", str(e))
                return ("Error", "An exception occurred, check the log for further details")
            return ("Success", f"Key pair of key type : {key_type} generated at Temp/Keys")
    else:
        _write_log("Key generation failed", retList[1])
        return ("Error", "An error occurred : Please refer the log file for more details : Temp/log_file.txt")

def If_pem_to_hex(key_type, key_file):
    if not checkFilePath(key_file):
        return ("Warning", f"The file path {os.path.split(key_file)[1]} does not exist")

    key_file_name = os.path.split(key_file)[1]
    if key_type in ["RSA", "ECDSA", "ED25519"]:
        retList = keys.load_key(key_type, key_file)
        if retList[0] == "Success":
            pem_key = retList[1]
        else:
            _write_log("Key conversion failed", retList[1])
            return ("Error", "An error occurred : Please refer the log file for more details : Temp/log_file.txt")
    else:
        try:
            pem_key = _load_symmetric_key_raw(key_file)
        except Exception as e:
            _write_log("Key conversion failed", str(e))
            return ("Error", "An error occurred : Please refer the log file for more details : Temp/log_file.txt")

    key_file_name, _ = os.path.splitext(key_file_name)
    retList = convert.pem_to_hex(pem_key)
    if retList[0] == "Success":
        hex_key = retList[1]
        createTempDir(os.path.join(TEMP_DIR, "Keys"))
        with open(os.path.join(TEMP_DIR, "Keys", f"{key_file_name}.hex"), "w") as fout:
            fout.write(hex_key)
        return ("Success", "Conversion Successful")
    else:
        _write_log("Key conversion failed", retList[1])
        return ("Error", "An error occurred : Please refer the log file for more details : Temp/log_file.txt")

def If_hex_to_pem(key_type, key_file):
    if not checkFilePath(key_file):
        return ("Warning", f"The file path {os.path.split(key_file)[1]} does not exist")

    with open(key_file, "r") as fin:
        hex_key = fin.read().strip()

    key_file_name = os.path.splitext(os.path.split(key_file)[1])[0]
    retList = convert.hex_to_pem(key_type, hex_key)
    if retList[0] == "Success":
        pem_key = retList[1]
        createTempDir(os.path.join(TEMP_DIR, "Keys"))
        if key_type in ["RSA", "ECDSA", "ED25519"]:
            if key_type == "ED25519":
                try:
                    keys.save_private_key(key_type, pem_key, True)
                    return ("Success", "Conversion Successful")
                except Exception:
                    pass
            else:
                try:
                    keys.save_private_key(key_type, pem_key)
                    return ("Success", "Conversion Successful")
                except Exception:
                    pass

            try:
                keys.save_public_key(key_type, pem_key)
                return ("Success", "Conversion Successful")
            except Exception as e:
                _write_log("Key conversion failed", str(e))
                return ("Error", "An error occurred : Please refer the log file for more details : Temp/log_file.txt")
        else:
            with open(os.path.join(TEMP_DIR, "Keys", f"{key_file_name}.pem"), "w") as fout:
                fout.write(pem_key)
            return ("Success", "Conversion Successful")
    elif retList[0] == "Failure":
        return retList
    else:
        _write_log("Key conversion failed", retList[1])
        return ("Error", "An error occurred : Please refer the log file for more details : Temp/log_file.txt")

def If_generate_sign(key_type, private_key_file, input_file, hash_algo, start_add, end_add):
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
        _write_log("signature generation failed", retList[1])
        return ("Error", "An error occurred : Please refer the log file for more details : Temp/log_file.txt")

    message = get_input_file_data(input_file, start_add, end_add)
    if message == "unknown":
        return ("Warning", "The input file is not in SREC or Intel HEX format, please provide a valid file")
    elif message is None:
        return ("Error", "An error occurred while reading the input file, please check the file format and content")

    input_file_name = os.path.splitext(os.path.split(input_file)[1])[0]
    createTempDir(os.path.join(TEMP_DIR, "Sign"))
    if key_type == "RSA":
        retList = rsa_sign.generate_rsa_signature(key, message, hash_algo)
    elif key_type == "ECDSA":
        retList = ecdsa_sign.generate_ecdsa_signature(key, message, hash_algo)
    else:
        retList = ed25519_sign.generate_ed25519_signature(key, message)

    if retList[0] == "Success":
        signature = base64.b64encode(retList[1]).decode('utf-8')
        with open(os.path.join(TEMP_DIR, "Sign", f"{input_file_name}.Signed"), "w") as sign_file:
            sign_file.write(signature)
        return ("Success", "Signature generated")
    elif retList[0] == "Failure":
        return retList
    else:
        _write_log("signature generation failed", retList[1])
        return ("Error", "An error occurred : Please refer the log file for more details : Temp/log_file.txt")

def If_generateHasherLongMessage(key_type, hash_algo):
    global longMessage_callOut
    createTempDir(os.path.join(TEMP_DIR, "Sign"))
    if key_type == "RSA":
        retList = rsa_sign.generate_hash_longMessage(
            hash_algo, os.path.join(TEMP_DIR, "Sign", "rsa_hasher.hash")
        )
    elif key_type == "ECDSA":
        retList = ecdsa_sign.generate_hash_longMessage(
            hash_algo, os.path.join(TEMP_DIR, "Sign", "ecdsa_hasher.hash")
        )
    else:
        return ("Warning", f"{key_type} does not supports signing for long messages")
    status = retList[0]
    if status == "Success":
        longMessage_callOut += 1
        return ("Success", "Hasher generated at file path Temp/Sign/Hasher.hash")
    elif status == "Error":
        _write_log("signature generation failed", retList[1])
        return ("Error", "An error occurred : Please refer the log file for more details : Temp/log_file.txt")
    else:
        return ("Warning", "Invalid Hash algorithm")

def If_updateHasherLongMessage(key_type, input_file, hasher_file, start_add, end_add):
    if longMessage_callOut > 0:
        for file in [input_file, hasher_file]:
            if not checkFilePath(file):
                return ("Warning", f"The file path {os.path.split(file)[1]} does not exist")

        message = get_input_file_data(input_file, start_add, end_add)
        if message == "unknown":
            return ("Warning", "The input file is not in SREC or Intel HEX format, please provide a valid file")
        elif message is None:
            return ("Error", "An error occurred while reading the input file, please check the file format and content")

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
            _write_log("signature generation failed", retList[1])
            return ("Error", "An error occurred : Please refer the log file for more details : Temp/log_file.txt")
    else:
        return ("Warning", "Generate Hasher for long message first")

def If_generate_signForLongMessage(key_type, private_key_file, hasher_file, hash_algo):
    if longMessage_callOut != 0:
        for file in [private_key_file, hasher_file]:
            if not checkFilePath(file):
                return ("Warning", f"The file path {os.path.split(file)[1]} does not exist")

        retList = keys.load_key(key_type, private_key_file)
        if retList[0] == "Success":
            key = retList[1]
        elif retList[0] == "Failure":
            return retList
        else:
            _write_log("signature generation failed", retList[1])
            return ("Error", "An error occurred : Please refer the log file for more details : Temp/log_file.txt")

        try:
            with open(hasher_file, "rb") as fin:
                selected_hash, state = pickle.load(fin)
            hasher_obj = hashes.Hash(getattr(hashes, selected_hash)())
            hasher_obj.update(state)
        except Exception as e:
            _write_log("signature generation failed", str(e))
            return ("Error", "An error occurred : Please refer the log file for more details : Temp/log_file.txt")

        hasher_file_name = os.path.splitext(os.path.split(hasher_file)[1])[0]
        if key_type == "RSA":
            retList = rsa_sign.generate_rsa_signature_longMessage(key, hasher_obj, hash_algo)
        elif key_type == "ECDSA":
            retList = ecdsa_sign.generate_ecdsa_signature_longMessage(key, hasher_obj, hash_algo)
        else:
            return ("Warning", f"{key_type} does not support long message signing")
        if retList[0] == "Success":
            signature = base64.b64encode(retList[1]).decode('utf-8')
            createTempDir(os.path.join(TEMP_DIR, "Sign"))
            with open(os.path.join(TEMP_DIR, "Sign", f"{hasher_file_name}.sign"), "w") as fout:
                fout.write(signature)
            return ("Success", "Signature generated")
        else:
            _write_log("signature generation failed", retList[1])
            return ("Error", "An error occurred : Please refer the log file for more details : Temp/log_file.txt")
    else:
        return ("Warning", "Generate Hasher for long message first")

def If_verify_signature(key_type, public_Key_file, input_file, signature_file, hash_algo, start_add, end_add):
    for file in [input_file, public_Key_file, signature_file]:
        if not checkFilePath(file):
            return ("Warning", f"The file path {os.path.split(file)[1]} does not exist")

    retList = keys.load_key(key_type, public_Key_file)
    if retList[0] == "Success":
        key = retList[1]
    elif retList[0] == "Failure":
        return retList
    else:
        _write_log("signature verification failed", retList[1])
        return ("Error", "An error occurred : Please refer the log file for more details : Temp/log_file.txt")

    message = get_input_file_data(input_file, start_add, end_add)
    if message == "unknown":
        return ("Warning", "The input file is not in SREC or Intel HEX format, please provide a valid file")
    elif message is None:
        return ("Error", "An error occurred while reading the input file, please check the file format and content")

    with open(signature_file, "r") as fin:
        signature_b64 = fin.read()
    signature = base64.b64decode(signature_b64)

    if key_type == "RSA":
        retList = rsa_sign.verify_rsa_signature(key, message, signature, hash_algo)
    elif key_type == "ECDSA":
        retList = ecdsa_sign.verify_ecdsa_signature(key, message, signature, hash_algo)
    else:
        retList = ed25519_sign.verify_ed25519_signature(key, message, signature)

    if retList[0] == "Success" or retList[0] == "Failure":
        return retList
    else:
        _write_log("signature verification failed", retList[1])
        return ("Error", "An error occurred : Please refer the log file for more details : Temp/log_file.txt")
    
def If_verify_signature_LongMessage(key_type, public_Key_file, hasher_file, signature_file, hash_algo):
    for file in [public_Key_file, hasher_file, signature_file]:
        if not checkFilePath(file):
            return ("Warning", f"The file path {file} does not exist")

    retList = keys.load_key(key_type, public_Key_file)
    if retList[0] == "Success":
        key = retList[1]
    elif retList[0] == "Failure":
        return retList
    else:
        _write_log("signature verification failed", retList[1])
        return ("Error", "An error occurred : Please refer the log file for more details : Temp/log_file.txt")

    try:
        with open(hasher_file, "rb") as fin:
            selected_hash, state = pickle.load(fin)
        hasher_obj = hashes.Hash(getattr(hashes, selected_hash)())
        hasher_obj.update(state)
    except Exception as e:
        _write_log("signature generation failed", str(e))
        return ("Error", "An error occurred : Please refer the log file for more details : Temp/log_file.txt")

    with open(signature_file, 'r') as fin:
        signature_b64 = fin.read()
    signature = base64.b64decode(signature_b64)

    if key_type == "RSA":
        retList = rsa_sign.verify_rsa_signature_longMessage(key, hasher_obj, signature, hash_algo)
    elif key_type == "ECDSA":
        retList = ecdsa_sign.verify_ecdsa_signature_longMessage(key, hasher_obj, signature, hash_algo)
    else:
        return ("Warning", "Ed25519 does not support long message verification")

    if retList[0] == "Error":
        _write_log("signature verification failed", retList[1])
        return ("Error", "An error occurred : Please refer the log file for more details : Temp/log_file.txt")
    else:
        return retList

def If_aes_encrypt(key_file, input_file, iv_file, aes_algo, start_add, end_add):
    for file in [key_file, input_file, iv_file]:
        if not checkFilePath(file):
            return ("Warning", f"The file path {os.path.split(file)[1]} does not exist")

    try:
        key = _load_symmetric_key_raw(key_file)
    except Exception as e:
        _write_log("Encryption failed", str(e))
        return ("Error", "An error occurred : Please refer the log file for more details : Temp/log_file.txt")

    message = get_input_file_data(input_file, start_add, end_add)
    if message == "unknown":
        return ("Warning", "The input file is not in SREC or Intel HEX format, please provide a valid file")
    elif message is None:
        return ("Error", "An error occurred while reading the input file, please check the file format and content")

    with open(iv_file, "rb") as fin:
        iv = fin.read()
    retList = encrypt_decrypt.aes_encrypt(key, iv, message, aes_algo)
    if retList[0] == "Success":
        encrypted_data = retList[1]
        createTempDir(os.path.join(TEMP_DIR, "Encrypt"))
        with open(os.path.join(TEMP_DIR, "Encrypt", f"{aes_algo.lower()}_encrypted_data.enc"), "wb") as fout:
            fout.write(encrypted_data)
        return ("Success", "Encryption successful")
    elif retList[0] == "Error":
        return retList
    else:
        _write_log("Encryption failed", retList[1])
        return ("Error", "An error occurred : Please refer the log file for more details : Temp/log_file.txt")

def If_rsa_encrypt(public_key_file, input_file, hash_algo, start_add, end_add):
    for file in [public_key_file, input_file]:
        if not checkFilePath(file):
            return ("Warning", f"The file path {os.path.split(file)[1]} does not exist")
    retList = keys.load_key("RSA", public_key_file)
    if retList[0] == "Success":
        public_key = retList[1]
    elif retList[0] == "Failure":
        return retList
    else:
        _write_log("Encryption failed", retList[1])
        return ("Error", "An error occurred : Please refer the log file for more details : Temp/log_file.txt")

    message = get_input_file_data(input_file, start_add, end_add)
    if message == "unknown":
        return ("Warning", "The input file is not in SREC or Intel HEX format, please provide a valid file")
    elif message is None:
        return ("Error", "An error occurred while reading the input file, please check the file format and content")
    retList = encrypt_decrypt.rsa_encrypt(public_key, message, hash_algo)
    if retList[0] == "Success":
        encrypted_data = retList[1]
        createTempDir(os.path.join(TEMP_DIR, "Encrypt"))
        with open(os.path.join(TEMP_DIR, "Encrypt", "rsa_encrypted_data.enc"), "wb") as fout:
            fout.write(encrypted_data)
        return ("Success", "Encryption successful")
    elif retList[0] == "Error":
        return retList
    else:
        _write_log("Encryption failed", retList[1])
        return ("Error", "An error occurred : Please refer the log file for more details : Temp/log_file.txt")

def If_aes_decrypt(key_file, iv_file, encrypted_file, aes_algo):
    for file in [key_file, iv_file, encrypted_file]:
        if not checkFilePath(file):
            return ("Warning", f"The file path {os.path.split(file)[1]} does not exist")

    try:
        key = _load_symmetric_key_raw(key_file)
    except Exception as e:
        _write_log("Decryption Failed", str(e))
        return ("Error", "An error occurred : Please refer the log file for more details : Temp/log_file.txt")

    with open(encrypted_file, "rb") as fin:
        cipher_text = fin.read()

    with open(iv_file, "rb") as fin:
        iv = fin.read()
    retList = encrypt_decrypt.aes_decrypt(key, iv, cipher_text, aes_algo)
    if retList[0] == "Success":
        plain_text = retList[1]
        createTempDir(os.path.join(TEMP_DIR, "Encrypt"))
        with open(os.path.join(TEMP_DIR, "Encrypt", f"{aes_algo.lower()}_decrypted_data.txt"), "wb") as fout:
            fout.write(plain_text)
        return ("Success", "Decryption successful")
    elif retList[0] == "Failure":
        return retList
    else:
        _write_log("Decryption failed", retList[1])
        return ("Error", "An error occurred : Please refer the log file for more details : Temp/log_file.txt")

def If_rsa_decrypt(private_key_file, encrypted_file, hash_algo):
    for file in [private_key_file, encrypted_file]:
        if not checkFilePath(file):
            return ("Warning", f"The file path {os.path.split(file)[1]} does not exist")

    retList = keys.load_key("RSA", private_key_file)
    if retList[0] == "Success":
        private_key = retList[1]
    elif retList[0] == "Failure":
        return retList
    else:
        _write_log("Decryption failed", retList[1])
        return ("Error", "An error occurred : Please refer the log file for more details : Temp/log_file.txt")

    with open(encrypted_file, "rb") as fin:
        cipher_text = fin.read()
    retList = encrypt_decrypt.rsa_decrypt(private_key, cipher_text, hash_algo)
    if retList[0] == "Success":
        plain_text = retList[1]
        createTempDir(os.path.join(TEMP_DIR, "Encrypt"))
        with open(os.path.join(TEMP_DIR, "Encrypt", "rsa_decrypted_data.txt"), "wb") as fout:
            fout.write(plain_text)
        return ("Success", "Decryption successful")
    elif retList[0] == "Failure":
        return retList
    else:
        _write_log("Decryption failed", retList[1])
        return ("Error", "An error occurred : Please refer the log file for more details : Temp/log_file.txt")

def If_generate_hash(input_file, hash_algo, start_add, end_add):
    if not checkFilePath(input_file):
        return ("Warning", f"The file {os.path.split(input_file)[1]} does not exist")

    message = get_input_file_data(input_file, start_add, end_add)
    if message == "unknown":
        return ("Warning", "The input file is not in SREC or Intel HEX format, please provide a valid file")
    elif message is None:
        return ("Error", "An error occurred while reading the input file, please check the file format and content")

    retList = hashlib_hash.calculate_hash(message, hash_algo)
    if retList[0] == "Success":
        gen_hash = retList[1]
        createTempDir(os.path.join(TEMP_DIR, "Hashes"))
        with open(os.path.join(TEMP_DIR, "Hashes", "generated_hash.hash"), "w") as fout:
            fout.write(gen_hash)
        return ("Success", "Hash Generated")
    elif retList[0] == "Failure":
        return retList
    else:
        _write_log("Hash generation failed", retList[1])
        return ("Error", "An error occurred : Please refer the log file for more details : Temp/log_file.txt")

def If_verify_hash(input_file, hash_file, hash_algo, start_add, end_add):
    for file in [input_file, hash_file]:
        if not checkFilePath(file):
            return ("Warning", f"The file {os.path.split(file)[1]} does not exist")

    message = get_input_file_data(input_file, start_add, end_add)
    if message == "unknown":
        return ("Warning", "The input file is not in SREC or Intel HEX format, please provide a valid file")
    elif message is None:
        return ("Error", "An error occurred while reading the input file, please check the file format and content")

    with open(hash_file, "r") as fin:
        expected_hash = fin.read()

    retList = hashlib_hash.verify_hash(message, expected_hash, hash_algo)
    if retList[0] == "Success" or retList[0] == "Failure":
        return retList
    else:
        _write_log("Hash verification failed", retList[1])
        return ("Error", "An error occurred : Please refer the log file for more details : Temp/log_file.txt")

def If_generate_CMAC(key_file, input_file, start_add, end_add):
    for file in [key_file, input_file]:
        if not checkFilePath(file):
            return ("Warning", f"The file {os.path.split(file)[1]} does not exist")

    message = get_input_file_data(input_file, start_add, end_add)
    if message == "unknown":
        return ("Warning", "The input file is not in SREC or Intel HEX format, please provide a valid file")
    elif message is None:
        return ("Error", "An error occurred while reading the input file, please check the file format and content")

    input_file_name = os.path.splitext(os.path.split(input_file)[1])[0]

    try:
        key = _load_symmetric_key_raw(key_file)
    except Exception as e:
        _write_log("CMAC generation failed", str(e))
        return ("Error", "An error occurred : Please refer the log file for more details : Temp/log_file.txt")

    retList = cmac.generate_cmac(key, message)
    if retList[0] == "Success":
        gen_cmac = retList[1]
        createTempDir(os.path.join(TEMP_DIR, "CMAC"))
        with open(os.path.join(TEMP_DIR, "CMAC", f"{input_file_name}.cmac"), "wb") as fout:
            fout.write(gen_cmac)
        return ("Success", "CMAC generated")
    else:
        _write_log("CMAC generation failed", retList[1])
        return ("Error", "An error occurred : Please refer the log file for more details : Temp/log_file.txt")
    
def If_verify_cmac(key_file, input_file, cmac_file, start_add, end_add):
    for file in [key_file, input_file, cmac_file]:
        if not checkFilePath(file):
            return ("Warning", f"The file {os.path.split(file)[1]} does not exist")

    message = get_input_file_data(input_file, start_add, end_add)
    if message == "unknown":
        return ("Warning", "The input file is not in SREC or Intel HEX format, please provide a valid file")
    elif message is None:
        return ("Error", "An error occurred while reading the input file, please check the file format and content")

    try:
        key = _load_symmetric_key_raw(key_file)
    except Exception as e:
        _write_log("CMAC verification failed", str(e))
        return ("Error", "An error occurred : Please refer the log file for more details : Temp/log_file.txt")

    with open(cmac_file, "rb") as fin:
        expected_cmac = fin.read()
    retList = cmac.verify_cmac(key, message, expected_cmac)
    if retList[0] == "Success" or retList[0] == "Failure":
        return retList
    else:
        _write_log("CMAC verification failed", retList[1])
        return ("Error", "An error occurred : Please refer the log file for more details : Temp/log_file.txt")
    
def If_generate_cmac_with_time_stamp(key_file, input_file, timestamp, start_add, end_add):
    for file in [key_file, input_file]:
        if not checkFilePath(file):
            return ("Warning", f"The file {os.path.split(file)[1]} does not exist")

    message = get_input_file_data(input_file, start_add, end_add)
    if message == "unknown":
        return ("Warning", "The input file is not in SREC or Intel HEX format, please provide a valid file")
    elif message is None:
        return ("Error", "An error occurred while reading the input file, please check the file format and content")

    input_file_name = os.path.splitext(os.path.split(input_file)[1])[0]

    try:
        key = _load_symmetric_key_raw(key_file)
    except Exception as e:
        _write_log("CMAC generation failed", str(e))
        return ("Error", "An error occurred : Please refer the log file for more details : Temp/log_file.txt")

    timestamp = timestamp.encode('utf-8')
    retList = cmac.generate_cmac_with_timestamp(key, message, timestamp)
    if retList[0] == "Success":
        gen_cmac = retList[1]
        createTempDir(os.path.join(TEMP_DIR, "CMAC"))
        with open(os.path.join(TEMP_DIR, "CMAC", f"{input_file_name}.cmac"), "wb") as fout:
            fout.write(gen_cmac)
        return ("Success", "CMAC generated")
    else:
        _write_log("CMAC generation failed", retList[1])
        return ("Error", "An error occurred : Please refer the log file for more details : Temp/log_file.txt")

def If_verify_cmac_with_time_stamp(key_file, input_file, cmac_file, timestamp, time_threshold, start_add, end_add):
    for file in [key_file, input_file, cmac_file]:
        if not checkFilePath(file):
            return ("Warning", f"The file {os.path.split(file)[1]} does not exist")

    message = get_input_file_data(input_file, start_add, end_add)
    if message == "unknown":
        return ("Warning", "The input file is not in SREC or Intel HEX format, please provide a valid file")
    elif message is None:
        return ("Error", "An error occurred while reading the input file, please check the file format and content")

    try:
        key = _load_symmetric_key_raw(key_file)
    except Exception as e:
        _write_log("CMAC verification failed", str(e))
        return ("Error", "An error occurred : Please refer the log file for more details : Temp/log_file.txt")

    with open(cmac_file, "rb") as fin:
        expected_cmac = fin.read()
    retList = cmac.verify_cmac_with_timestamp(key, message, expected_cmac, timestamp, int(time_threshold))
    if retList[0] == "Success" or retList[0] == "Failure":
        return retList
    else:
        _write_log("CMAC verification failed", retList[1])
        return ("Error", "An error occurred : Please refer the log file for more details : Temp/log_file.txt")

def If_generate_crc(input_file, algorithm, start_add, end_add):
    if not checkFilePath(input_file):
        return ("Warning", f"The file {os.path.split(input_file)[1]} does not exist")

    message = get_input_file_data(input_file, start_add, end_add)
    if message == "unknown":
        return ("Warning", "The input file is not in SREC or Intel HEX format, please provide a valid file")
    elif message is None:
        return ("Error", "An error occurred while reading the input file, please check the file format and content")

    input_file_name = os.path.splitext(os.path.split(input_file)[1])[0]
    retList = crc.calculate_crc(message, algorithm.lower())
    if retList[0] == "Success":
        gen_crc = str(retList[1])
        createTempDir(os.path.join(TEMP_DIR, "CRC"))
        with open(os.path.join(TEMP_DIR, "CRC", f"{input_file_name}.txt"), "w") as fout:
            fout.write(gen_crc)
        return ("Success", "CRC generated successfully")
    elif retList[0] == "Failure":
        return retList
    else:
        _write_log("CRC generation failed", retList[1])
        return ("Error", "An error occurred : Please refer the log file for more details : Temp/log_file.txt")
    
def If_verify_crc(input_file, crc_file, algorithm, start_add, end_add):
    for file in [input_file, crc_file]:
        if not checkFilePath(file):
            return ("Warning", f"The file {os.path.split(input_file)[1]} does not exist")

    message = get_input_file_data(input_file, start_add, end_add)
    if message == "unknown":
        return ("Warning", "The input file is not in SREC or Intel HEX format, please provide a valid file")
    elif message is None:
        return ("Error", "An error occurred while reading the input file, please check the file format and content")

    with open(crc_file) as fin:
        calculated_crc = fin.read()

    retList = crc.verify_crc(message, algorithm.lower(), int(calculated_crc))
    if retList[0] == "Success" or retList[0] == "Failure":
        return retList
    else:
        _write_log("CRC verification failed", retList[1])
        return ("Error", "An error occurred : Please refer the log file for more details : Temp/log_file.txt")


def If_generate_random_bytes(num_bytes):
    random_bytes = random_gen.generate_random_bytes(int(num_bytes))
    createTempDir(os.path.join(TEMP_DIR, "Random"))
    with open(os.path.join(TEMP_DIR, "Random", "Random_bytes.bin"), "wb") as fout:
        fout.write(random_bytes)


if __name__ == "__main__":
    print("Execution started")
    # file_list = ["Zeekr_IHU_CX1E_BM.srec", "Zeekr_IHU_CX1E_BM.hex", "output.txt", "./output.log", "./output.bin", "KDS_C0_CM2E_Filled_AB.hex"]
    # for file in file_list:
    #     retval = get_input_file_type(f"./Crypto_tool/{file}")
    #     print(file, retval)

