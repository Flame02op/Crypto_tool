import unittest
import time
import pytest
from cryptography.hazmat.primitives import cmac

from sys import path as sys_path
from os import path as os_path
sys_path.append(os_path.abspath(os_path.join(os_path.dirname(__file__),'..')))
from crypto_key_app.cmac import verify_cmac_with_timestamp, generate_cmac_with_timestamp, generate_cmac, verify_cmac

class TestGenerateCmac:
    def test_generate_cmac_valid(self):
        key = b'0123456789abcdef'  # 16 bytes key
        message = b'This is a test message.'
        status, cmac= generate_cmac(key, message)
        self.assertEqual(status, "Success")
        self.assertIsNotNone(cmac)
        self.assertTrue(isinstance(cmac, bytes))

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
class TestVerifyCmac(unittest.TestCase):
    def setUp(self):
        self.key = b'0123456789abcdef'  # 16 bytes key for AES
        self.message = b'This is a test message.'
        _, self.valid_cmac = generate_cmac(self.key, self.message)

    def test_valid_cmac(self):
        status, _ = verify_cmac(self.key, self.message, self.valid_cmac)
        self.assertEqual(status, "Success")

    def test_invalid_cmac(self):
        invalid_cmac = b'\x00' * len(self.valid_cmac)
        status, error_message = verify_cmac(self.key, self.message, invalid_cmac)
        self.assertEqual(status, "Failure")
        self.assertIn("Verification failed", error_message)

    def test_invalid_key_length(self):
        invalid_key = b'01234567'  # 8 bytes key, invalid for AES
        status,_ = verify_cmac(invalid_key, self.message, self.valid_cmac)
        self.assertEqual(status, "Error")

    def test_invalid_message_type(self):
        invalid_message = 'This is a test message.'  # Not bytes or bytearray
        status,_ = verify_cmac(self.key, invalid_message, self.valid_cmac)
        self.assertEqual(status, "Error")

class TestGenerateCmacWithTimestamp(unittest.TestCase):

    def test_valid_inputs(self):
        key = b'0123456789abcdef'  # 16 bytes key
        message = b'This is a test message.'
        timestamp = str(int(time.time())).encode()
        status, cmac = generate_cmac_with_timestamp(key, message, timestamp)
        self.assertEqual(status, "Success")
        self.assertIsNotNone(cmac)
        self.assertEqual(len(timestamp), 10)  # Timestamp should be 10 bytes long

    def test_invalid_key_length(self):
        key = b'01234567'  # 8 bytes key, invalid length
        message = b'This is a test message.'
        timestamp = str(int(time.time())).encode()
        status, error_message = generate_cmac_with_timestamp(key, message, timestamp)
        self.assertEqual(status, "Error")
        self.assertIn("Invalid key length! Key must be 16, 24, or 32 bytes", error_message)

    def test_invalid_message_type(self):
        key = b'0123456789abcdef'  # 16 bytes key
        message = 'This is a test message.'  # Invalid type, should be bytes
        timestamp = str(int(time.time())).encode()
        status, error_message = generate_cmac_with_timestamp(key, message,  timestamp)
        self.assertEqual(status, "Error")
        self.assertIn("Message must be of type bytes or bytearray", error_message)

    def test_exception_handling(self):
        key = b'0123456789abcdef'  # 16 bytes key
        message = b'This is a test message.'
        # Temporarily modify the cmac.CMAC to raise an exception
        original_cmac = cmac.CMAC
        cmac.CMAC = lambda *args, **kwargs: (_ for _ in ()).throw(Exception("Test exception"))
        try:
            retList = generate_cmac_with_timestamp(key, message, str(int(time.time())).encode())
            self.assertEqual(retList[0], "Error")
        finally:
            cmac.CMAC = original_cmac

class TestCMACWithTimestamp(unittest.TestCase):

    def setUp(self):
        self.key = b'\x01' * 16
        self.message = b'This is a test message'
        self.timestamp = str(int(time.time())).encode()
        self.time_threshold = 10

    def test_verify_cmac_with_timestamp_valid(self):
        status, expected_cmac = generate_cmac_with_timestamp(self.key, self.message, self.timestamp)
        self.assertEqual(status, "Success")
        status, _ = verify_cmac_with_timestamp(self.key, self.message, expected_cmac, self.timestamp.decode(), self.time_threshold)
        self.assertEqual(status, "Success")

    def test_verify_cmac_with_timestamp_invalid_cmac(self):
        status, expected_cmac = generate_cmac_with_timestamp(self.key, self.message, self.timestamp)
        invalid_cmac = b'\x00' * len(expected_cmac)
        status, error_message = verify_cmac_with_timestamp(self.key, self.message, invalid_cmac, self.timestamp.decode(), self.time_threshold)
        self.assertEqual(status, "Failure")
        self.assertEqual(error_message, "Verification failed")
   
    def test_verify_cmac_with_timestamp_expired(self):
        status, expected_cmac = generate_cmac_with_timestamp(self.key, self.message, self.timestamp)
        time.sleep(self.time_threshold + 1)
        status, error_message = verify_cmac_with_timestamp(self.key, self.message, expected_cmac, self.timestamp.decode(), self.time_threshold)
        self.assertEqual(status, "Failure")
        self.assertIn("Timestamp is not within the acceptable range", error_message)

    def test_verify_cmac_with_timestamp_invalid_key(self):
        status, expected_cmac = generate_cmac_with_timestamp(self.key, self.message, self.timestamp)
        invalid_key = b'\x02' * 16
        status, error_message = verify_cmac_with_timestamp(invalid_key, self.message, expected_cmac, self.timestamp.decode(), self.time_threshold)
        self.assertEqual(status, "Failure")
        self.assertEqual(error_message, "Verification failed")

    def test_verify_cmac_with_timestamp_invalid_message(self):
        status, expected_cmac = generate_cmac_with_timestamp(self.key, self.message, self.timestamp)
        invalid_message = b'This is an invalid message'
        status, error_message = verify_cmac_with_timestamp(self.key, invalid_message, expected_cmac, self.timestamp.decode(), self.time_threshold)
        self.assertEqual(status, "Failure")
        self.assertEqual(error_message, "Verification failed")


if __name__ == '__main__':
    unittest.main()