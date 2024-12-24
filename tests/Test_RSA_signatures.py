import unittest
from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

from sys import path as sys_path
from os import path as os_path
sys_path.append(os_path.abspath(os_path.join(os_path.dirname(__file__),'..')))
from crypto_key_app.rsa_signatures import generate_hash_longMessage, update_hash_longMessage, verify_rsa_signature_longMessage, generate_rsa_signature_longMessage, generate_rsa_signature, verify_rsa_signature

class TestRSASignatures(unittest.TestCase):

    def setUp(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self.public_key = self.private_key.public_key()
        self.message = b"Test message for RSA signature"
        self.hasher = generate_hash_longMessage('SHA256')
        update_hash_longMessage(self.hasher, self.message)
        status, self.signature = generate_rsa_signature_longMessage(self.private_key, self.hasher, 'SHA256')
        self.assertEqual(status, "Success")

    def test_verify_rsa_signature_longMessage_valid(self):
        hasher = generate_hash_longMessage('SHA256')
        update_hash_longMessage(hasher, self.message)
        status, result = verify_rsa_signature_longMessage(self.public_key, hasher, self.signature, 'SHA256')
        self.assertEqual(status, "Success")
        self.assertEqual(result, "Signature Verified")

    def test_verify_rsa_signature_longMessage_invalid_signature(self):
        hasher = generate_hash_longMessage('SHA256')
        update_hash_longMessage(hasher, self.message)
        invalid_signature = b"invalid_signature"
        status, result = verify_rsa_signature_longMessage(self.public_key, hasher, invalid_signature, 'SHA256')
        self.assertEqual(status, "Failure")
        self.assertEqual(result, "Invalid Signature")

    def test_verify_rsa_signature_longMessage_invalid_hash_algorithm(self):
        hasher = generate_hash_longMessage('SHA256')
        update_hash_longMessage(hasher, self.message)
        status, result = verify_rsa_signature_longMessage(self.public_key, hasher, self.signature, 'invalid_hash')
        self.assertEqual(status, "Error")
        self.assertIn("Please select a valid hash algorithm", result)

    def test_verify_rsa_signature_longMessage_invalid_hasher(self):
        invalid_hasher = "invalid_hasher"
        status, result = verify_rsa_signature_longMessage(self.public_key, invalid_hasher, self.signature, 'SHA256')
        self.assertEqual(status, "Error")
        self.assertIn("Invalid hasher object", result)

class TestGenerateRSASignatures(unittest.TestCase):

    def setUp(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self.message = b"Test message for RSA signature"
        self.hasher = generate_hash_longMessage('SHA256')
        update_hash_longMessage(self.hasher, self.message)

    def test_generate_rsa_signature_longMessage(self):
        status, signature = generate_rsa_signature_longMessage(self.private_key, self.hasher, 'SHA256')
        self.assertEqual(status, "Success")
        self.assertIsNotNone(signature)
        self.assertIsInstance(signature, bytes)

    def test_generate_rsa_signature_longMessage_invalid_hash(self):
        status, result = generate_rsa_signature_longMessage(self.private_key, self.hasher, 'invalid_hash')
        self.assertEqual(status, "Error")
        self.assertIn("Please select a valid hash algorithm", result)

    def test_generate_rsa_signature_longMessage_invalid_hasher(self):
        status, result = generate_rsa_signature_longMessage(self.private_key, "invalid_hasher", 'SHA256')
        self.assertEqual(status, "Error")
        self.assertIn("Invalid hasher object", result)

class TestGenerateHash(unittest.TestCase):

    def test_generate_hash_longMessage_valid(self):
        hasher = generate_hash_longMessage('SHA256')
        self.assertIsInstance(hasher, hashes.Hash)
        self.assertEqual(hasher.algorithm.name, 'sha256')

    def test_generate_hash_longMessage_invalid(self):
        status, result = generate_hash_longMessage('invalid_hash')
        self.assertEqual(status, "Error")
        self.assertIn("Please select a valid hash algorithm", result)

    def test_generate_hash_longMessage_default(self):
        hasher = generate_hash_longMessage('SHA256')
        self.assertIsInstance(hasher, hashes.Hash)
        self.assertEqual(hasher.algorithm.name, 'sha256')

class TestUpdateRSAHash(unittest.TestCase):

    def test_update_hash_longMessage_valid(self):
        hasher = generate_hash_longMessage('SHA256')
        message_block = b"test message"
        status, result = update_hash_longMessage(hasher, message_block)
        self.assertEqual(status, "Success")
        self.assertEqual(result, "Hasher Updated")

    def test_update_hash_longMessage_invalid_hasher(self):
        status, result = update_hash_longMessage(None, b"test message")
        self.assertEqual(status, "Error")
        self.assertIn("Invalid hasher object", result)

    def test_update_hash_longMessage_invalid_message(self):
        hasher = generate_hash_longMessage('SHA256')
        status, result = update_hash_longMessage(hasher, "invalid message")
        self.assertEqual(status, "Error")
        self.assertIn("Message must be of type bytes or bytearray", result)

class TestVerifyRSASignatures(unittest.TestCase):

    def setUp(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self.public_key = self.private_key.public_key()
        self.message = b"Test message"
        status, self.signature = generate_rsa_signature(self.private_key, self.message, 'SHA256')
        self.assertEqual(status, "Success")

    def test_verify_rsa_signature_valid(self):
        status, result = verify_rsa_signature(self.public_key, self.message, self.signature, 'SHA256')
        self.assertEqual(status, "Success")
        self.assertEqual(result, "Signature verified")

    def test_verify_rsa_signature_invalid(self):
        invalid_signature = b"Invalid signature"
        status, result = verify_rsa_signature(self.public_key, self.message, invalid_signature, 'SHA256')
        self.assertEqual(status, "Failure")
        self.assertEqual(result, "Invalid Signature")

    def test_verify_rsa_signature_invalid_message(self):
        invalid_message = b"Invalid message"
        status, result = verify_rsa_signature(self.public_key, invalid_message, self.signature, 'SHA256')
        self.assertEqual(status, "Failure")
        self.assertEqual(result, "Invalid Signature")

class TestGenerateRSASignatures(unittest.TestCase):

    def setUp(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self.message = b"Test message"
        self.selected_hash = 'SHA256'

    def test_generate_rsa_signature_valid(self):
        status, signature = generate_rsa_signature(self.private_key, self.message, self.selected_hash)
        self.assertEqual(status, "Success")
        self.assertIsNotNone(signature)

    def test_generate_rsa_signature_invalid_hash(self):
        status, result = generate_rsa_signature(self.private_key, self.message, 'invalid_hash')
        self.assertEqual(status, "Error")
        self.assertIn("Please select a valid hash algorithm", result)

    def test_generate_rsa_signature_invalid_message(self):
        status, result = generate_rsa_signature(self.private_key, "invalid_message", self.selected_hash)
        self.assertEqual(status, "Error")
        self.assertIn("Message must be of type bytes or bytearray", result)

if __name__ == '__main__':
    unittest.main()