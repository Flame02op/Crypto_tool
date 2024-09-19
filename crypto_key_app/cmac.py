from cryptography.hazmat.primitives.cmac import CMAC
from cryptography.hazmat.primitives.ciphers import algorithms

def generate_cmac(key, message):
    cmac = CMAC(algorithms.AES(key))
    cmac.update(message)
    return cmac.finalize()

def verify_cmac(key, message, cmac_value):
    cmac = CMAC(algorithms.AES(key))
    cmac.update(message)
    cmac.verify(cmac_value)