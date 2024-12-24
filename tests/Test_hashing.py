import unittest
from unittest.mock import patch

from sys import path as sys_path
from os import path as os_path
sys_path.append(os_path.join(os_path.dirname(__file__), ".."))
from crypto_key_app.hashlib_hashing import calculate_hash, verify_hash

class TestCalculateHash(unittest.TestCase):

    def test_secure_algorithm_sha256(self):
        data = b"test data"
        expected_hash = '916f0027a575074ce72a331777c3478d6513f786a591bd892da1a577bf2335f9'
        status, result = calculate_hash(data, 'SHA256')
        self.assertEqual(status, "Success")
        self.assertEqual(result, expected_hash)

    def test_non_secure_algorithm_md5(self):
        data = b"test data"
        expected_hash = 'eb733a00c0c9d336e65691a37ab54293'
        status, result = calculate_hash(data, 'md5')
        self.assertEqual(status, "Success")
        self.assertEqual(result, expected_hash)

    def test_unsupported_algorithm(self):
        data = b"test data"
        status, result = calculate_hash(data, 'unsupported_algorithm')
        self.assertEqual(status, "Failure")
        self.assertEqual(result, "Unsupported algorithm")

class TestVerifyHash(unittest.TestCase):

    def test_verify_hash_sha256(self):
        data = b"test data"
        expected_hash = '916f0027a575074ce72a331777c3478d6513f786a591bd892da1a577bf2335f9'
        status, result = verify_hash(data, expected_hash, 'SHA256')
        self.assertEqual(status, "Success")
        self.assertEqual(result, "Hash Verified")

    def test_verify_hash_sha256_incorrect(self):
        data = b"test data"
        expected_hash = "incorrecthash"
        status, result = verify_hash(data, expected_hash, 'SHA256')
        self.assertEqual(status, "Failure")
        self.assertEqual(result, "Invalid Hash")

    def test_verify_hash_md5(self):
        data = b"test data"
        expected_hash = 'eb733a00c0c9d336e65691a37ab54293'
        status, result = verify_hash(data, expected_hash, 'md5')
        self.assertEqual(status, "Success")
        self.assertEqual(result, "Hash Verified")

    def test_verify_hash_md5_incorrect(self):
        data = b"test data"
        expected_hash = "incorrecthash"
        status, result = verify_hash(data, expected_hash, 'md5')
        self.assertEqual(status, "Failure")
        self.assertEqual(result, "Invalid Hash")

    def test_verify_hash_unsupported_algorithm(self):
        data = b"test data"
        expected_hash = "somehash"
        status, result = verify_hash(data, expected_hash, 'unsupported_algo')
        self.assertEqual(status, "Failure")
        self.assertEqual(result, "Unsupported algorithm")

if __name__ == '__main__':
    unittest.main()