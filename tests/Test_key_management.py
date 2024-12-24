import unittest
import io
from contextlib import redirect_stdout
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization

from sys import path as sys_path
from os import path as os_path
sys_path.append(os_path.abspath(os_path.join(os_path.dirname(__file__),'..')))
from crypto_key_app.key_management import generate_rsa_key_pair, generate_ecdsa_key_pair, show_key_pair

class TestGenerateRSAKeyPair(unittest.TestCase):

    def test_generate_rsa_key_pair_valid_key_size(self):
        status, private_key, public_key = generate_rsa_key_pair(256)
        self.assertEqual(status, "Success")
        self.assertIsNotNone(private_key)
        self.assertIsNotNone(public_key)
        self.assertEqual(private_key.key_size, 2048)
        self.assertEqual(public_key.key_size, 2048)

    def test_generate_rsa_key_pair_invalid_key_size(self):
        status, error_message, _ = generate_rsa_key_pair(127)
        self.assertEqual(status, "Error")
        self.assertEqual(
            error_message,
            "Keys with size less than 1024 bits or 128 bytes are generally considered to be unsecured."
        )

    def test_generate_rsa_key_pair_unsupported_key_size(self):
        status, error_message, _ = generate_rsa_key_pair(300)
        self.assertEqual(status, "Error")
        self.assertEqual(
            error_message,
            "Key with given size 300 Bytes is not supported"
        )

class TestGenerateECDSAKeyPair(unittest.TestCase):

    def test_generate_ecdsa_key_pair_default(self):
        status, private_key, public_key = generate_ecdsa_key_pair()
        self.assertEqual(status, "Success")
        self.assertIsInstance(private_key, ec.EllipticCurvePrivateKey)
        self.assertIsInstance(public_key, ec.EllipticCurvePublicKey)

    def test_generate_ecdsa_key_pair_secp256r1(self):
        status, private_key, public_key = generate_ecdsa_key_pair('secp256r1')
        self.assertEqual(status, "Success")
        self.assertIsInstance(private_key, ec.EllipticCurvePrivateKey)
        self.assertIsInstance(public_key, ec.EllipticCurvePublicKey)

    def test_generate_ecdsa_key_pair_invalid_curve(self):
        status, error_message, _ = generate_ecdsa_key_pair('invalid_curve')
        self.assertEqual(status, "Error")
        self.assertIn("The given algorithm is not supported", error_message)

    def test_generate_ecdsa_key_pair_default_curve(self):
        status, private_key, public_key = generate_ecdsa_key_pair()
        self.assertEqual(status, "Success")
        self.assertIsInstance(private_key, ec.EllipticCurvePrivateKey)
        self.assertIsInstance(public_key, ec.EllipticCurvePublicKey)


class TestShowKeyPair(unittest.TestCase):

    def test_show_key_pair_rsa(self):
        private_key, public_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        ), rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        ).public_key()
        
        f = io.StringIO()
        with redirect_stdout(f):
            show_key_pair(private_key, public_key)
        output = f.getvalue()
        
        self.assertIn("Private Key:", output)
        self.assertIn("Public Key:", output)

    def test_show_key_pair_ecdsa(self):
        private_key, public_key = ec.generate_private_key(
            ec.SECP256R1()
        ), ec.generate_private_key(
            ec.SECP256R1()
        ).public_key()
        
        f = io.StringIO()
        with redirect_stdout(f):
            show_key_pair(private_key, public_key)
        output = f.getvalue()
        
        self.assertIn("Private Key:", output)
        self.assertIn("Public Key:", output)
        
if __name__ == "__main__":
    unittest.main()