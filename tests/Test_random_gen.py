import unittest
from sys import path as sys_path
from os import path as os_path
sys_path.append(os_path.abspath(os_path.join(os_path.dirname(__file__),'..')))
from crypto_key_app.random_gen import generate_random_bytes, gen_symmetric_key

class TestRandomGen(unittest.TestCase):

    def test_generate_random_bytes(self):
        num_bytes = 16
        random_bytes = generate_random_bytes(num_bytes)
        self.assertEqual(len(random_bytes), num_bytes)
        self.assertIsInstance(random_bytes, bytes)

    def test_gen_symmetric_key_aes_128(self):
        status, pem_key = gen_symmetric_key("AES-128")
        self.assertEqual(status, "Success")
        self.assertIn("-----BEGIN AES KEY-----", pem_key)
        self.assertIn("-----END AES KEY-----", pem_key)

    def test_gen_symmetric_key_aes_192(self):
        status, pem_key = gen_symmetric_key("AES-192")
        self.assertEqual(status, "Success")
        self.assertIn("-----BEGIN AES KEY-----", pem_key)
        self.assertIn("-----END AES KEY-----", pem_key)

    def test_gen_symmetric_key_aes_256(self):
        status, pem_key = gen_symmetric_key("AES-256")
        self.assertEqual(status, "Success")
        self.assertIn("-----BEGIN AES KEY-----", pem_key)
        self.assertIn("-----END AES KEY-----", pem_key)

    def test_gen_symmetric_key_unsupported_algorithm(self):
        status, result = gen_symmetric_key("unsupported_algorithm")
        self.assertEqual(status, "Error")
        self.assertEqual(result, "Unsupported algorithm. Supported algorithms: AES-128, AES-192, AES-256")

if __name__ == '__main__':
    unittest.main()