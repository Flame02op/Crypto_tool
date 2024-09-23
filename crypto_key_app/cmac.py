from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.exceptions import InvalidSignature

def generate_cmac(key, message):
    generate = cmac.CMAC(algorithms.AES(key))
    generate.update(message)
    return generate.finalize()

def verify_cmac(key, message, cmac_value):
    verify = cmac.CMAC(algorithms.AES(key))
    verify.update(message)
    try:
        verify.verify(cmac_value)
        return True
    except InvalidSignature:
        return False


