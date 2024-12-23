import time
from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.exceptions import InvalidSignature

def validate_key_length(key):
    if len(key) not in {16, 24, 32}:  # AES key lengths in bytes
        raise ValueError("Invalid key length! Key must be 16, 24, or 32 bytes.")

def validate_message(message):
    if not isinstance(message, (bytes, bytearray)):
        raise ValueError("Message must be of type bytes or bytearray.")
    
def generate_cmac(key, message):
    try:
        validate_key_length(key)
        validate_message(message)
    except Exception as e:
        return ("Error", str(e))
    
    try:
        cmac_obj = cmac.CMAC(algorithms.AES(key), backend=default_backend())
        cmac_obj.update(message)
        return ("Success", cmac_obj.finalize())
    except Exception as e:
        return ("Error", str(e))

def verify_cmac(key, message, expected_cmac):
    try:
        validate_key_length(key)
        validate_message(message)
        cmac_obj = cmac.CMAC(algorithms.AES(key), backend=default_backend())
        cmac_obj.update(message)
        cmac_obj.verify(expected_cmac)
        return ("Success", "CMAC verified")
    except InvalidSignature:
        return ("Failure", "Verification failed")
    except Exception as e:
        return ("Error", str(e))
   
def generate_cmac_with_timestamp(key, message, timestamp):
    try:
        validate_key_length(key)
        validate_message(message)
        # timestamp = str(int(time.time())).encode('utf-8')
        # Appending the message with a timestamp to prevent replay-attacks
        message_with_timestamp = timestamp + message
        cmac_obj = cmac.CMAC(algorithms.AES(key))
        cmac_obj.update(message_with_timestamp)
        return ("Success", cmac_obj.finalize())
    except Exception as e:
        return ("Error", e, None)

def verify_cmac_with_timestamp(key, message, expected_cmac, timestamp, time_threshold=60):
    try:
        validate_key_length(key)
        validate_message(message)
        # Verify that the timestamp is within the acceptable threshold
        current_time = time.time()
        message_time = int(timestamp)
        if abs(current_time - message_time) > time_threshold:
            return ("Failure", "Timestamp is not within the acceptable range!")
        # Prepend the timestamp to the message for verification
        # ensure that this is exact opposite of that in the generation
        # if the timestamp is appended in the generation, then it should be prepended here
        message_with_timestamp = timestamp.encode('utf-8') + message
        cmac_obj = cmac.CMAC(algorithms.AES(key), backend=default_backend())
        cmac_obj.update(message_with_timestamp)
        cmac_obj.verify(expected_cmac)
        return ("Success", "CMAC verified")
    except InvalidSignature:
        return ("Failure", "Verification failed")
    except Exception as e:
        return ("Error", str(e))
