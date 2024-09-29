import unittest
from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from sys import path as sys_path
from os import path as os_path
sys_path.append(os_path.abspath(os_path.join(os_path.dirname(__file__),'..')))
from crypto_key_app.rsa_signatures import generate_hash_longMessage, update_hash_longMessage, verify_rsa_signature_longMessage

class TestRSASignatures(unittest.TestCase):

    def setUp(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self.public_key = self.private_key.public_key()
        self.message = b"Test message for RSA signature"
        self.hasher = generate_hash_longMessage('sha256')
        update_hash_longMessage(self.hasher, self.message)
        self.signature = self.private_key.sign(
            self.hasher.finalize(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            utils.Prehashed(hashes.SHA256())
        )

    def test_verify_rsa_signature_longMessage_valid(self):
        hasher = generate_hash_longMessage('sha256')
        update_hash_longMessage(hasher, self.message)
        result = verify_rsa_signature_longMessage(self.public_key, hasher, self.signature, 'sha256')
        self.assertIsNone(result)  # verify_rsa_signature_longMessage returns None on success

    def test_verify_rsa_signature_longMessage_invalid_signature(self):
        hasher = generate_hash_longMessage('sha256')
        update_hash_longMessage(hasher, self.message)
        invalid_signature = b"invalid_signature"
        result = verify_rsa_signature_longMessage(self.public_key, hasher, invalid_signature, 'sha256')
        self.assertIsNone(result)  # verify_rsa_signature_longMessage returns None on invalid signature

    def test_verify_rsa_signature_longMessage_invalid_hash_algorithm(self):
        hasher = generate_hash_longMessage('sha256')
        update_hash_longMessage(hasher, self.message)
        with self.assertRaises(ValueError):
            verify_rsa_signature_longMessage(self.public_key, hasher, self.signature, 'invalid_hash')

    def test_verify_rsa_signature_longMessage_invalid_hasher(self):
        invalid_hasher = "invalid_hasher"
        with self.assertRaises(ValueError):
            verify_rsa_signature_longMessage(self.public_key, invalid_hasher, self.signature, 'sha256')



if __name__ == '__main__':
    unittest.main()