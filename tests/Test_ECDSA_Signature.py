import unittest
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from sys import path as sys_path
from os import path as os_path
sys_path.append(os_path.abspath(os_path.join(os_path.dirname(__file__),'..')))
from crypto_key_app.ecdsa_signatures import generate_hash_longMessage, update_hash_longMessage,verify_ecdsa_signature_longMessage, generate_ecdsa_signature_longMessage, verify_ecdsa_signature, generate_ecdsa_signature


class TestVerifyECDSASignatureLongMessage(unittest.TestCase):

    def setUp(self):
        self.private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        self.public_key = self.private_key.public_key()
        self.message = b"Test message for ECDSA signature"
        self.hasher = generate_hash_longMessage('sha256')
        update_hash_longMessage(self.hasher, self.message)
        self.signature = self.private_key.sign(
            self.hasher.finalize(),
            ec.ECDSA(hashes.SHA256())
        )

    def test_verify_valid_signature(self):
        hasher = generate_hash_longMessage('sha256')
        update_hash_longMessage(hasher, self.message)
        result = verify_ecdsa_signature_longMessage(self.public_key, hasher, self.signature, 'sha256')
        self.assertIsNone(result)  # verify_ecdsa_signature_longMessage prints "sign verified" and returns None

    def test_verify_invalid_signature(self):
        hasher = generate_hash_longMessage('sha256')
        update_hash_longMessage(hasher, self.message)
        invalid_signature = b"invalid_signature"
        result = verify_ecdsa_signature_longMessage(self.public_key, hasher, invalid_signature, 'sha256')
        self.assertIsNone(result)  # verify_ecdsa_signature_longMessage prints "Signature is invalid" and returns None

    def test_verify_invalid_hash_algorithm(self):
        hasher = generate_hash_longMessage('sha256')
        update_hash_longMessage(hasher, self.message)
        with self.assertRaises(ValueError):
            verify_ecdsa_signature_longMessage(self.public_key, hasher, self.signature, 'invalid_hash')

    def test_verify_invalid_hasher(self):
        invalid_hasher = object()  # Not a valid hasher object
        with self.assertRaises(ValueError):
            verify_ecdsa_signature_longMessage(self.public_key, invalid_hasher, self.signature, 'sha256')

class TestGenerateECDSASignaturesLongMessage(unittest.TestCase):

    def setUp(self):
        self.private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        self.message = b"Test message for ECDSA signature"
        self.hasher = generate_hash_longMessage('sha256')
        update_hash_longMessage(self.hasher, self.message)

    def test_generate_ecdsa_signature_longMessage(self):
        signature = generate_ecdsa_signature_longMessage(self.private_key, self.hasher, 'sha256')
        self.assertIsNotNone(signature)
        self.assertIsInstance(signature, bytes)

    def test_generate_ecdsa_signature_longMessage_invalid_hash(self):
        with self.assertRaises(ValueError):
            generate_ecdsa_signature_longMessage(self.private_key, self.hasher, 'invalid_hash')

    def test_generate_ecdsa_signature_longMessage_invalid_hasher(self):
        with self.assertRaises(ValueError):
            generate_ecdsa_signature_longMessage(self.private_key, "invalid_hasher", 'sha256')

class TestGenerateHash(unittest.TestCase):

    def test_generate_hash_longMessage_valid(self):
        hasher = generate_hash_longMessage('sha256')
        self.assertIsInstance(hasher, hashes.Hash)
        self.assertEqual(hasher.algorithm.name, 'sha256')

    def test_generate_hash_longMessage_invalid(self):
        with self.assertRaises(ValueError):
            generate_hash_longMessage('invalid_hash')

    def test_generate_hash_longMessage_default(self):
        hasher = generate_hash_longMessage()
        self.assertIsInstance(hasher, hashes.Hash)
        self.assertEqual(hasher.algorithm.name, 'sha256')

class TestUpdateECDSAHash(unittest.TestCase):

    def test_update_hash_longMessage_valid(self):
        hasher = generate_hash_longMessage('sha256')
        message_block = b"test message"
        update_hash_longMessage(hasher, message_block)
        assert hasher is not None

    def test_update_hash_longMessage_invalid_hasher(self):
        with pytest.raises(ValueError, match="Invalid hasher object, please create a hasher object with generate_hash_longmessage"):
            update_hash_longMessage(None, b"test message")

    def test_update_hash_longMessage_invalid_message(self):
        hasher = generate_hash_longMessage('sha256')
        with pytest.raises(ValueError, match="Message must be of type bytes or bytearray."):
            update_hash_longMessage(hasher, "invalid message")

class TestVerifyECDSASignatures(unittest.TestCase):

    def setUp(self):
        self.private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        self.public_key = self.private_key.public_key()
        self.message = b"Test message"
        self.signature = generate_ecdsa_signature(self.private_key, self.message, 'sha256')

    def test_verify_ecdsa_signature_valid(self):
        result = verify_ecdsa_signature(self.public_key, self.message, self.signature, 'sha256')
        self.assertIsNone(result)  # verify_ecdsa_signature prints "sign verified" and returns None on success

    def test_verify_ecdsa_signature_invalid(self):
        invalid_signature = b"Invalid signature"
        result = verify_ecdsa_signature(self.public_key, self.message, invalid_signature, 'sha256')
        self.assertIsNone(result)  # verify_ecdsa_signature prints "Signature is invalid" and returns None on failure

    def test_verify_ecdsa_signature_invalid_message(self):
        invalid_message = b"Invalid message"
        result = verify_ecdsa_signature(self.public_key, invalid_message, self.signature, 'sha256')
        self.assertIsNone(result)  # verify_ecdsa_signature prints "Signature is invalid" and returns None on failure

class TestGenerateECDSASignatures(unittest.TestCase):

    def setUp(self):
        self.private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        self.message = b"Test message"
        self.selected_hash = 'sha256'

    def test_generate_ecdsa_signature_valid(self):
        signature = generate_ecdsa_signature(self.private_key, self.message, self.selected_hash)
        self.assertIsNotNone(signature)

    def test_generate_ecdsa_signature_invalid_hash(self):
        with self.assertRaises(ValueError):
            generate_ecdsa_signature(self.private_key, self.message, 'invalid_hash')

    def test_generate_ecdsa_signature_invalid_message(self):
        with self.assertRaises(ValueError):
            generate_ecdsa_signature(self.private_key, "invalid_message", self.selected_hash)
        
if __name__ == '__main__':
    unittest.main()