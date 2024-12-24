import unittest
from unittest import mock
from sys import path as sys_path
from os import path as os_path
sys_path.append(os_path.abspath(os_path.join(os_path.dirname(__file__),'..')))
from crypto_key_app.crc import calculate_crc, verify_crc

class TestCalculateCRC(unittest.TestCase):

    def test_calculate_crc_valid_data(self):
        data = "hello world"
        algorithm = "crc-32"
        expected_crc = 222957957
        status, crc = calculate_crc(data, algorithm)
        self.assertEqual(status, "Success")
        self.assertEqual(crc, expected_crc)

    def test_calculate_crc_invalid_algorithm(self):
        data = "hello world"
        algorithm = "invalid-crc"
        status, error_message = calculate_crc(data, algorithm)
        self.assertEqual(status, "Failure")
        self.assertIn("Invalid algorithm", error_message)

    def test_calculate_crc_empty_data(self):
        data = ""
        algorithm = "crc-32"
        expected_crc = 0
        self.assertEqual(calculate_crc(data, algorithm)[1], expected_crc)

    def test_calculate_crc_non_string_data(self):
        data = b"hello world"
        algorithm = "crc-32"
        expected_crc = 222957957
        self.assertEqual(calculate_crc(data, algorithm)[1], expected_crc)

    def test_calculate_crc_error_handling(self):
        data = "hello world"
        algorithm = "crc-32"
        with mock.patch('crcmod.predefined.mkPredefinedCrcFun', side_effect=Exception("Mocked error")):
            self.assertEqual(calculate_crc(data, algorithm)[0], "Error")

class TestVerifyCRC(unittest.TestCase):

    def test_verify_crc_valid(self):
        data = "hello world"
        algorithm = "crc-32"
        _, calculated_crc = calculate_crc(data, algorithm)
        self.assertTrue(verify_crc(data, algorithm, calculated_crc)[0], "Success")

    def test_verify_crc_invalid(self):
        data = "hello world"
        algorithm = "crc-32"
        _, calculated_crc = calculate_crc(data, algorithm)
        self.assertTrue(verify_crc(data, algorithm, calculated_crc + 1), "Failure")

    def test_verify_crc_invalid_algorithm(self):
        data = "hello world"
        algorithm = "invalid-crc"
        status, error_message = verify_crc(data, algorithm, 12345)
        self.assertEqual(status, "Failure")
        self.assertIn("Verification failed", error_message)

if __name__ == '__main__':
    unittest.main()