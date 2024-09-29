import unittest
from sys import path as sys_path
from os import path as os_path
sys_path.append(os_path.abspath(os_path.join(os_path.dirname(__file__),'..')))
from crypto_key_app.crc import calculate_crc, verify_crc

class TestCalculateCRC(unittest.TestCase):

    def test_calculate_crc_valid_data(self):
        data = "hello world"
        algorithm = "crc-32"
        expected_crc = 222957957
        self.assertEqual(calculate_crc(data, algorithm), expected_crc)

    def test_calculate_crc_invalid_algorithm(self):
        data = "hello world"
        algorithm = "invalid-crc"
        with self.assertRaises(ValueError):
            calculate_crc(data, algorithm)

    def test_calculate_crc_empty_data(self):
        data = ""
        algorithm = "crc-32"
        expected_crc = 0
        self.assertEqual(calculate_crc(data, algorithm), expected_crc)

    def test_calculate_crc_non_string_data(self):
        data = b"hello world"
        algorithm = "crc-32"
        expected_crc = 222957957
        self.assertEqual(calculate_crc(data, algorithm), expected_crc)

    def test_calculate_crc_error_handling(self):
        data = "hello world"
        algorithm = "crc-32"
        with unittest.mock.patch('crcmod.predefined.mkPredefinedCrcFun', side_effect=Exception("Mocked error")):
            self.assertIsNone(calculate_crc(data, algorithm))

class TestVerifyCRC(unittest.TestCase):

    def test_verify_crc_valid(self):
        data = "hello world"
        algorithm = "crc-32"
        calculated_crc = calculate_crc(data, algorithm)
        self.assertTrue(verify_crc(data, algorithm, calculated_crc))

    def test_verify_crc_invalid(self):
        data = "hello world"
        algorithm = "crc-32"
        calculated_crc = calculate_crc(data, algorithm)
        self.assertFalse(verify_crc(data, algorithm, calculated_crc + 1))

    def test_verify_crc_invalid_algorithm(self):
        data = "hello world"
        algorithm = "invalid-crc"
        with self.assertRaises(ValueError):
            verify_crc(data, algorithm, 12345)

if __name__ == '__main__':
    unittest.main()