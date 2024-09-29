import unittest
import time
import pytest
from cryptography.hazmat.primitives import cmac

from sys import path as sys_path
from os import path as os_path
sys_path.append(os_path.abspath(os_path.join(os_path.dirname(__file__),'..')))
from crypto_key_app.cmac import verify_cmac_with_timestamp, generate_cmac_with_timestamp, generate_cmac, verify_cmac

class TestVerifyCmac(unittest.TestCase):
    def setUp(self):
        self.key = b'0123456789abcdef'  # 16 bytes key for AES
        self.message = b'This is a test message.'
        self.valid_cmac = generate_cmac(self.key, self.message)

    def test_valid_cmac(self):
        self.assertTrue(verify_cmac(self.key, self.message, self.valid_cmac))

    def test_invalid_cmac(self):
        invalid_cmac = b'\x00' * len(self.valid_cmac)
        self.assertFalse(verify_cmac(self.key, self.message, invalid_cmac))

    def test_invalid_key_length(self):
        invalid_key = b'01234567'  # 8 bytes key, invalid for AES
        with self.assertRaises(ValueError):
            verify_cmac(invalid_key, self.message, self.valid_cmac)

    def test_invalid_message_type(self):
        invalid_message = 'This is a test message.'  # Not bytes or bytearray
        with self.assertRaises(ValueError):
            verify_cmac(self.key, invalid_message, self.valid_cmac)

class TestGenerateCmac:
    def test_generate_cmac_valid(self):
        key = b'0123456789abcdef'  # 16 bytes key
        message = b'This is a test message.'
        result = generate_cmac(key, message)
        assert result is not None
        assert isinstance(result, bytes)

    def test_generate_cmac_invalid_key_length(self):
        key = b'01234567'  # 8 bytes key, invalid length
        message = b'This is a test message.'
        with pytest.raises(ValueError, match="Invalid key length! Key must be 16, 24, or 32 bytes."):
            generate_cmac(key, message)

    def test_generate_cmac_invalid_message_type(self):
        key = b'0123456789abcdef'  # 16 bytes key
        message = 'This is a test message.'  # Invalid type, should be bytes or bytearray
        with pytest.raises(ValueError, match="Message must be of type bytes or bytearray."):
            generate_cmac(key, message)

class TestCMACWithTimestamp(unittest.TestCase):

    def setUp(self):
        self.key = b'\x01' * 16
        self.message = b'This is a test message'
        self.time_threshold = 10

    def test_verify_cmac_with_timestamp_valid(self):
        expected_cmac, timestamp = generate_cmac_with_timestamp(self.key, self.message)
        result = verify_cmac_with_timestamp(self.key, self.message, expected_cmac, timestamp, self.time_threshold)
        self.assertTrue(result)

    def test_verify_cmac_with_timestamp_invalid_cmac(self):
        expected_cmac, timestamp = generate_cmac_with_timestamp(self.key, self.message)
        invalid_cmac = b'\x00' * len(expected_cmac)
        result = verify_cmac_with_timestamp(self.key, self.message, invalid_cmac, timestamp, self.time_threshold)
        self.assertFalse(result)

    def test_verify_cmac_with_timestamp_expired(self):
        expected_cmac, timestamp = generate_cmac_with_timestamp(self.key, self.message)
        time.sleep(self.time_threshold + 1)
        result = verify_cmac_with_timestamp(self.key, self.message, expected_cmac, timestamp, self.time_threshold)
        self.assertFalse(result)

    def test_verify_cmac_with_timestamp_invalid_key(self):
        expected_cmac, timestamp = generate_cmac_with_timestamp(self.key, self.message)
        invalid_key = b'\x02' * 16
        result = verify_cmac_with_timestamp(invalid_key, self.message, expected_cmac, timestamp, self.time_threshold)
        self.assertFalse(result)

    def test_verify_cmac_with_timestamp_invalid_message(self):
        expected_cmac, timestamp = generate_cmac_with_timestamp(self.key, self.message)
        invalid_message = b'This is an invalid message'
        result = verify_cmac_with_timestamp(self.key, invalid_message, expected_cmac, timestamp, self.time_threshold)
        self.assertFalse(result)

class TestGenerateCmacWithTimestamp(unittest.TestCase):

    def test_valid_inputs(self):
        key = b'0123456789abcdef'  # 16 bytes key
        message = b'This is a test message.'
        cmac, timestamp = generate_cmac_with_timestamp(key, message)
        self.assertIsNotNone(cmac)
        self.assertIsNotNone(timestamp)
        self.assertEqual(len(timestamp), 10)  # Timestamp should be 10 bytes long

    def test_invalid_key_length(self):
        key = b'01234567'  # 8 bytes key, invalid length
        message = b'This is a test message.'
        with self.assertRaises(ValueError) as context:
            generate_cmac_with_timestamp(key, message)
        self.assertEqual(str(context.exception), "Invalid key length! Key must be 16, 24, or 32 bytes.")

    def test_invalid_message_type(self):
        key = b'0123456789abcdef'  # 16 bytes key
        message = 'This is a test message.'  # Invalid type, should be bytes
        with self.assertRaises(ValueError) as context:
            generate_cmac_with_timestamp(key, message)
        self.assertEqual(str(context.exception), "Message must be of type bytes or bytearray.")

    def test_exception_handling(self):
        key = b'0123456789abcdef'  # 16 bytes key
        message = b'This is a test message.'
        # Temporarily modify the cmac.CMAC to raise an exception
        original_cmac = cmac.CMAC
        cmac.CMAC = lambda *args, **kwargs: (_ for _ in ()).throw(Exception("Test exception"))
        try:
            result = generate_cmac_with_timestamp(key, message)
            self.assertIsNone(result)
        finally:
            cmac.CMAC = original_cmac

if __name__ == '__main__':
    unittest.main()