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
    
    # if not os.path.exists("./Temp/Keys"):
    #     os.makedirs("./Temp/Keys")
    # status, private_key, public_key = keys.generate_ecdsa_key_pair("secp256r1")
    # print(status)
    # keys.save_private_key("ECDSA", private_key)
    # keys.save_public_key("ECDSA", public_key)
    # status, private_key, public_key = keys.generate_ed25519_key_pair()
    # print(status)
    # keys.save_private_key("ED25519", private_key)
    # keys.save_public_key("ED25519", public_key)
    # status, private_key, public_key = keys.generate_rsa_key_pair(256)
    # print(status)
    # keys.save_private_key("RSA", private_key)
    # keys.save_public_key("RSA", public_key)
    
    # if status == "Success":
    #     keys.show_key_pair(private_key, public_key)
    # else:
    #     print(private_key)
    
    status, private_key = keys.load_key("ED25519", "./Temp/Keys/ed25519_private_key.pem")
    print(status)
    status, public_key = keys.load_key("ED25519", "./Temp/Keys/ed25519_public_key.pem")
    print(status)
    keys.show_key_pair(private_key, public_key)
