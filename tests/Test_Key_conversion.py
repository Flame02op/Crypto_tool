import unittest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from sys import path as sys_path
from os import path as os_path
sys_path.append(os_path.abspath(os_path.join(os_path.dirname(__file__),'..')))
from crypto_key_app.key_conversion import pem_to_hex, hex_to_pem

class TestKeyConversion_H2P(unittest.TestCase):

    def test_pem_to_hex(self):
        # Generate a private key for testing
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        # Convert the private key to PEM format
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

        # Convert the PEM key to hex
        status, hex_key = pem_to_hex(private_key)
        self.assertEqual(status, "Success")

        # Convert the hex key back to PEM bytes
        pem_bytes_from_hex = bytes.fromhex(hex_key)

        # Check if the original PEM and the PEM from hex are the same
        self.assertEqual(pem, pem_bytes_from_hex)


class TestKeyConversion_P2H(unittest.TestCase):

    def test_hex_to_pem(self):
        # Generate a private key for testing
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        
        # Convert the private key to PEM format
        pem_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Convert the PEM key to hex
        hex_key = pem_key.hex()
        
        # Convert the hex key back to PEM
        status, result_pem = hex_to_pem("RSA", hex_key)

        # Serialize the returned pem object
        result_pem = result_pem.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        self.assertEqual(status, "Success")
        
        # Check if the original PEM and the result PEM are the same
        self.assertEqual(pem_key, result_pem)

if __name__ == '__main__':
    unittest.main()