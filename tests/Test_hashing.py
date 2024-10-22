import unittest, pytest
from unittest.mock import patch

from sys import path as sys_path
from os import path as os_path
sys_path.append(os_path.join(os_path.dirname(__file__), ".."))
from crypto_key_app.hashlib_hashing import calculate_hash, verify_hash

class TestCalculateHash(unittest.TestCase):

    def test_secure_algorithm_sha256(self):
        data = b"test data"
        expected_hash = b'\x9f\x86\xd0\x81\x88L\xd9\xad\xa0\x9a\x23\x1e\xaa\xf8\x8e\xae\x1a\x1f\x6b\x8a\x16\x99\x1b\x6a\x1e\x52\x9a\x5a\xaa\x82\x7e\xe6'
        self.assertEqual(calculate_hash(data, 'sha256'), expected_hash)

    def test_non_secure_algorithm_md5(self):
        data = b"test data"
        expected_hash = b'\xeb\x73\x0b\x3a\x93\x8e\x2f\x2f\x1e\x8b\x6a\x8e\x1b\x6a\x1e\x52\x9a\x5a\xaa\x82\x7e\xe6'
        with patch('builtins.input', return_value='yes'):
            self.assertEqual(calculate_hash(data, 'md5'), expected_hash)

    def test_unsupported_algorithm(self):
        data = b"test data"
        with self.assertRaises(ValueError):
            calculate_hash(data, 'unsupported_algorithm')

    def test_non_secure_algorithm_decline(self):
        data = b"test data"
        with patch('builtins.input', return_value='no'):
            self.assertIsNone(calculate_hash(data, 'md5'))

    def test_verify_hash_sha256(self):
        data = b"test data"
        expected_hash = "9c56cc51b1d4c9b2a5e6b6e4b3b8b1e5e4b3b8b1e5e4b3b8b1e5e4b3b8b1e5e"
        assert verify_hash(data, expected_hash, 'sha256') == True

    def test_verify_hash_sha256_incorrect(self):
        data = b"test data"
        expected_hash = "incorrecthash"
        assert verify_hash(data, expected_hash, 'sha256') == False

    def test_verify_hash_md5(self):
        data = b"test data"
        expected_hash = "eb733a00c0c9d336e65691a37ab54293"
        assert verify_hash(data, expected_hash, 'md5') == True

    def test_verify_hash_md5_incorrect(self):
        data = b"test data"
        expected_hash = "incorrecthash"
        assert verify_hash(data, expected_hash, 'md5') == False

    def test_verify_hash_unsupported_algorithm(self):
        data = b"test data"
        expected_hash = "somehash"
        with pytest.raises(ValueError, match="Unsupported algorithm"):
            verify_hash(data, expected_hash, 'unsupported_algo')

if __name__ == '__main__':
    unittest.main()