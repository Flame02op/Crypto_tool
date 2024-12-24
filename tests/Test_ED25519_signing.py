import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from sys import path as sys_path
from os import path as os_path
sys_path.append(os_path.abspath(os_path.join(os_path.dirname(__file__),'..')))
from crypto_key_app.ed25519_signatures import generate_ed25519_signature, verify_ed25519_signature

class TestEd25519Signatures(unittest.TestCase):

    def setUp(self):
        self.private_key = Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        self.message = b"Test message for Ed25519 signature"

    def test_generate_ed25519_signature_valid(self):
        status, signature = generate_ed25519_signature(self.private_key, self.message)
        self.assertEqual(status, "Success")
        self.assertIsNotNone(signature)
        self.assertIsInstance(signature, bytes)

    def test_generate_ed25519_signature_invalid_message(self):
        status, result = generate_ed25519_signature(self.private_key, "invalid_message")
        self.assertEqual(status, "Error")
        self.assertIn("Message must be of type bytes or bytearray", result)

    def test_verify_ed25519_signature_valid(self):
        status, signature = generate_ed25519_signature(self.private_key, self.message)
        self.assertEqual(status, "Success")
        status, result = verify_ed25519_signature(self.public_key, self.message, signature)
        self.assertEqual(status, "Success")
        self.assertEqual(result, "Signature Verified")

    def test_verify_ed25519_signature_invalid_signature(self):
        invalid_signature = b"invalid_signature"
        status, result = verify_ed25519_signature(self.public_key, self.message, invalid_signature)
        self.assertEqual(status, "Failure")
        self.assertEqual(result, "Invalid Signature")

    def test_verify_ed25519_signature_invalid_message(self):
        status, signature = generate_ed25519_signature(self.private_key, self.message)
        self.assertEqual(status, "Success")
        status, result = verify_ed25519_signature(self.public_key, "invalid_message", signature)
        self.assertEqual(status, "Error")
        self.assertIn("Message must be of type bytes or bytearray", result)

if __name__ == '__main__':
    unittest.main()