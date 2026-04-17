"""Unit tests for interface.py.

Tests use mocking to avoid real filesystem and crypto dependencies, so they
run quickly and deterministically without requiring actual key/data files.
"""
import os
import unittest
from unittest.mock import MagicMock, mock_open, patch

from sys import path as sys_path
from os import path as os_path
sys_path.append(os_path.abspath(os_path.join(os_path.dirname(__file__), '..')))

# Patch the side-effect-free module-level imports before importing interface
import interface


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

class TestCheckFilePath(unittest.TestCase):
    def test_existing_path(self):
        self.assertTrue(interface.checkFilePath(os.path.dirname(__file__)))

    def test_missing_path(self):
        self.assertFalse(interface.checkFilePath("/nonexistent/path/xyz"))


class TestCreateTempDir(unittest.TestCase):
    def test_creates_directory(self):
        tmp = "/tmp/_crypto_test_dir_"
        if os.path.exists(tmp):
            os.rmdir(tmp)
        interface.createTempDir(tmp)
        self.assertTrue(os.path.isdir(tmp))
        os.rmdir(tmp)

    def test_does_not_fail_if_exists(self):
        tmp = "/tmp"
        # Should not raise even though /tmp already exists
        interface.createTempDir(tmp)


# ---------------------------------------------------------------------------
# If_generateKey
# ---------------------------------------------------------------------------

class TestIfGenerateKey(unittest.TestCase):

    @patch("interface.keys.generate_rsa_key_pair")
    @patch("interface.keys.save_private_key")
    @patch("interface.keys.save_public_key")
    @patch("interface.createTempDir")
    @patch("interface._init_temp_dir")
    def test_rsa_success(self, mock_init, mock_mkdir, mock_pub, mock_priv, mock_gen):
        mock_gen.return_value = ("Success", MagicMock(), MagicMock())
        status, msg = interface.If_generateKey("RSA", "256")
        self.assertEqual(status, "Success")
        self.assertIn("RSA", msg)

    @patch("interface.keys.generate_rsa_key_pair")
    @patch("interface.createTempDir")
    @patch("interface._init_temp_dir")
    @patch("interface._write_log")
    def test_rsa_error(self, mock_log, mock_init, mock_mkdir, mock_gen):
        mock_gen.return_value = ("Error", "some error")
        status, msg = interface.If_generateKey("RSA", "256")
        self.assertEqual(status, "Error")
        mock_log.assert_called_once()

    @patch("interface.random_gen.gen_symmetric_key")
    @patch("interface.createTempDir")
    @patch("interface._init_temp_dir")
    def test_symmetric_success(self, mock_init, mock_mkdir, mock_gen):
        mock_gen.return_value = ("Success", "AABBCC")
        m = mock_open()
        with patch("builtins.open", m):
            status, msg = interface.If_generateKey("Symmetric key", "AES128")
        self.assertEqual(status, "Success")
        self.assertIn("Symmetric", msg)


# ---------------------------------------------------------------------------
# If_generateKey – key save exception
# ---------------------------------------------------------------------------

    @patch("interface.keys.generate_rsa_key_pair")
    @patch("interface.keys.save_private_key", side_effect=Exception("disk full"))
    @patch("interface.createTempDir")
    @patch("interface._init_temp_dir")
    @patch("interface._write_log")
    def test_rsa_save_exception(self, mock_log, mock_init, mock_mkdir, mock_priv, mock_gen):
        mock_gen.return_value = ("Success", MagicMock(), MagicMock())
        status, _ = interface.If_generateKey("RSA", "256")
        self.assertEqual(status, "Error")
        mock_log.assert_called_once()


# ---------------------------------------------------------------------------
# If_pem_to_hex
# ---------------------------------------------------------------------------

class TestIfPemToHex(unittest.TestCase):

    def test_missing_file_returns_warning(self):
        status, msg = interface.If_pem_to_hex("RSA", "/nonexistent/key.pem")
        self.assertEqual(status, "Warning")
        self.assertIn("does not exist", msg)

    @patch("interface.keys.load_key")
    @patch("interface.convert.pem_to_hex")
    @patch("interface.createTempDir")
    @patch("builtins.open", mock_open())
    def test_rsa_success(self, mock_mkdir, mock_conv, mock_load):
        mock_load.return_value = ("Success", b"fakepem")
        mock_conv.return_value = ("Success", "AABBCC")
        with patch("interface.checkFilePath", return_value=True):
            status, msg = interface.If_pem_to_hex("RSA", "/fake/RSA_priv.pem")
        self.assertEqual(status, "Success")

    @patch("interface.keys.load_key")
    @patch("interface._write_log")
    def test_rsa_load_failure(self, mock_log, mock_load):
        mock_load.return_value = ("Error", "bad key")
        with patch("interface.checkFilePath", return_value=True):
            status, _ = interface.If_pem_to_hex("RSA", "/fake/key.pem")
        self.assertEqual(status, "Error")
        mock_log.assert_called_once()


# ---------------------------------------------------------------------------
# If_hex_to_pem
# ---------------------------------------------------------------------------

class TestIfHexToPem(unittest.TestCase):

    def test_missing_file_returns_warning(self):
        status, _ = interface.If_hex_to_pem("RSA", "/nonexistent/key.hex")
        self.assertEqual(status, "Warning")

    @patch("interface.convert.hex_to_pem")
    @patch("interface.createTempDir")
    @patch("builtins.open", mock_open(read_data="AABBCC"))
    def test_symmetric_success(self, mock_mkdir, mock_conv):
        mock_conv.return_value = ("Success", "-----BEGIN KEY-----")
        with patch("interface.checkFilePath", return_value=True):
            status, msg = interface.If_hex_to_pem("AES", "/fake/key.hex")
        self.assertEqual(status, "Success")

    @patch("interface.convert.hex_to_pem")
    @patch("builtins.open", mock_open(read_data="AABBCC"))
    def test_failure_passthrough(self, mock_conv):
        mock_conv.return_value = ("Failure", "unsupported key type")
        with patch("interface.checkFilePath", return_value=True):
            status, msg = interface.If_hex_to_pem("RSA", "/fake/key.hex")
        self.assertEqual(status, "Failure")


# ---------------------------------------------------------------------------
# If_generate_hash (also covers the verify_hash bug-fix check)
# ---------------------------------------------------------------------------

class TestIfGenerateHash(unittest.TestCase):

    def test_missing_file_returns_warning(self):
        status, _ = interface.If_generate_hash("/nonexistent.hex", "SHA256", 0, 0)
        self.assertEqual(status, "Warning")

    @patch("interface.get_input_file_data", return_value="unknown")
    def test_unknown_format_returns_warning(self, _):
        with patch("interface.checkFilePath", return_value=True):
            status, msg = interface.If_generate_hash("/fake.hex", "SHA256", 0, 0)
        self.assertEqual(status, "Warning")
        self.assertIn("SREC or Intel HEX", msg)

    @patch("interface.get_input_file_data", return_value=None)
    def test_none_data_returns_error(self, _):
        with patch("interface.checkFilePath", return_value=True):
            status, _ = interface.If_generate_hash("/fake.hex", "SHA256", 0, 0)
        self.assertEqual(status, "Error")

    @patch("interface.hashlib_hash.calculate_hash")
    @patch("interface.get_input_file_data", return_value=b"data")
    @patch("interface.createTempDir")
    @patch("builtins.open", mock_open())
    def test_success(self, mock_mkdir, _, mock_calc):
        mock_calc.return_value = ("Success", "abc123")
        with patch("interface.checkFilePath", return_value=True):
            status, msg = interface.If_generate_hash("/fake.hex", "SHA256", 0, 0)
        self.assertEqual(status, "Success")
        self.assertEqual(msg, "Hash Generated")


# ---------------------------------------------------------------------------
# If_verify_hash – specifically tests the bug-fix (was using `data`, now `message`)
# ---------------------------------------------------------------------------

class TestIfVerifyHash(unittest.TestCase):

    def test_missing_files_returns_warning(self):
        status, _ = interface.If_verify_hash(
            "/nonexistent.hex", "/also_missing.hash", "SHA256", 0, 0
        )
        self.assertEqual(status, "Warning")

    @patch("interface.hashlib_hash.verify_hash")
    @patch("interface.get_input_file_data", return_value=b"data")
    @patch("builtins.open", mock_open(read_data="abc123"))
    def test_success_uses_message_not_data(self, _, mock_verify):
        """Regression test: verify_hash must receive `message`, not the
        previously-undefined `data` variable."""
        mock_verify.return_value = ("Success", "Hash Verified")
        with patch("interface.checkFilePath", return_value=True):
            status, msg = interface.If_verify_hash(
                "/fake.hex", "/fake.hash", "SHA256", 0, 0
            )
        self.assertEqual(status, "Success")
        # Confirm verify_hash was called with the parsed bytes, not NameError
        mock_verify.assert_called_once_with(b"data", "abc123", "SHA256")

    @patch("interface.hashlib_hash.verify_hash")
    @patch("interface.get_input_file_data", return_value=b"data")
    @patch("builtins.open", mock_open(read_data="abc123"))
    def test_failure_passthrough(self, _, mock_verify):
        mock_verify.return_value = ("Failure", "Invalid Hash")
        with patch("interface.checkFilePath", return_value=True):
            status, _ = interface.If_verify_hash(
                "/fake.hex", "/fake.hash", "SHA256", 0, 0
            )
        self.assertEqual(status, "Failure")


# ---------------------------------------------------------------------------
# If_generate_sign
# ---------------------------------------------------------------------------

class TestIfGenerateSign(unittest.TestCase):

    def test_missing_private_key_returns_warning(self):
        status, _ = interface.If_generate_sign(
            "RSA", "/nonexistent.pem", "/nonexistent.hex", "SHA256", 0, 0
        )
        self.assertEqual(status, "Warning")

    @patch("interface.keys.load_key")
    @patch("interface.get_input_file_data", return_value="unknown")
    def test_unknown_format_returns_warning(self, _, mock_load):
        mock_load.return_value = ("Success", MagicMock())
        with patch("interface.checkFilePath", return_value=True):
            status, msg = interface.If_generate_sign(
                "RSA", "/k.pem", "/f.hex", "SHA256", 0, 0
            )
        self.assertEqual(status, "Warning")

    @patch("interface.rsa_sign.generate_rsa_signature")
    @patch("interface.keys.load_key")
    @patch("interface.get_input_file_data", return_value=b"data")
    @patch("interface.createTempDir")
    @patch("builtins.open", mock_open())
    def test_rsa_success(self, mock_mkdir, _, mock_load, mock_sign):
        mock_load.return_value = ("Success", MagicMock())
        mock_sign.return_value = ("Success", b"\x00\x01\x02")
        with patch("interface.checkFilePath", return_value=True):
            status, msg = interface.If_generate_sign(
                "RSA", "/k.pem", "/f.hex", "SHA256", 0, 0
            )
        self.assertEqual(status, "Success")

    @patch("interface.keys.load_key")
    @patch("interface._write_log")
    def test_load_key_error_writes_log(self, mock_log, mock_load):
        mock_load.return_value = ("Error", "some error")
        with patch("interface.checkFilePath", return_value=True):
            status, _ = interface.If_generate_sign(
                "RSA", "/k.pem", "/f.hex", "SHA256", 0, 0
            )
        self.assertEqual(status, "Error")
        mock_log.assert_called_once()


# ---------------------------------------------------------------------------
# If_generateHasherLongMessage  (pre-condition checks)
# ---------------------------------------------------------------------------

class TestIfGenerateHasherLongMessage(unittest.TestCase):

    def test_ed25519_returns_warning(self):
        status, msg = interface.If_generateHasherLongMessage("ED25519", "SHA256")
        self.assertEqual(status, "Warning")
        self.assertIn("ED25519", msg)


# ---------------------------------------------------------------------------
# If_updateHasherLongMessage / If_generate_signForLongMessage
# ---------------------------------------------------------------------------

class TestLongMessageGuard(unittest.TestCase):

    def setUp(self):
        # Force longMessage_callOut to 0 before each test
        interface.longMessage_callOut = 0

    def test_update_without_prior_hasher_returns_warning(self):
        status, msg = interface.If_updateHasherLongMessage(
            "RSA", "/f.hex", "/h.hash", 0, 0
        )
        self.assertEqual(status, "Warning")

    def test_sign_without_prior_hasher_returns_warning(self):
        status, msg = interface.If_generate_signForLongMessage(
            "RSA", "/k.pem", "/h.hash", "SHA256"
        )
        self.assertEqual(status, "Warning")


# ---------------------------------------------------------------------------
# If_generate_CMAC
# ---------------------------------------------------------------------------

class TestIfGenerateCMAC(unittest.TestCase):

    def test_missing_file_returns_warning(self):
        status, _ = interface.If_generate_CMAC(
            "/nonexistent_key", "/nonexistent_input", 0, 0
        )
        self.assertEqual(status, "Warning")

    @patch("interface.cmac.generate_cmac")
    @patch("interface._load_symmetric_key_raw", return_value=b"0123456789abcdef")
    @patch("interface.get_input_file_data", return_value=b"payload")
    @patch("interface.createTempDir")
    @patch("builtins.open", mock_open())
    def test_success(self, mock_mkdir, _, mock_key, mock_gen):
        mock_gen.return_value = ("Success", b"\xde\xad\xbe\xef")
        with patch("interface.checkFilePath", return_value=True):
            status, msg = interface.If_generate_CMAC("/k.pem", "/f.hex", 0, 0)
        self.assertEqual(status, "Success")


# ---------------------------------------------------------------------------
# If_generate_crc / If_verify_crc
# ---------------------------------------------------------------------------

class TestIfGenerateCRC(unittest.TestCase):

    def test_missing_file_returns_warning(self):
        status, _ = interface.If_generate_crc("/nonexistent.hex", "crc32", 0, 0)
        self.assertEqual(status, "Warning")

    @patch("interface.crc.calculate_crc")
    @patch("interface.get_input_file_data", return_value=b"data")
    @patch("interface.createTempDir")
    @patch("builtins.open", mock_open())
    def test_success(self, mock_mkdir, _, mock_calc):
        mock_calc.return_value = ("Success", 12345)
        with patch("interface.checkFilePath", return_value=True):
            status, _ = interface.If_generate_crc("/fake.hex", "crc32", 0, 0)
        self.assertEqual(status, "Success")

    @patch("interface.crc.calculate_crc")
    @patch("interface.get_input_file_data", return_value=b"data")
    def test_failure_passthrough(self, _, mock_calc):
        mock_calc.return_value = ("Failure", "unsupported algo")
        with patch("interface.checkFilePath", return_value=True):
            status, _ = interface.If_generate_crc("/fake.hex", "badcrc", 0, 0)
        self.assertEqual(status, "Failure")


class TestIfVerifyCRC(unittest.TestCase):

    def test_missing_file_returns_warning(self):
        status, _ = interface.If_verify_crc(
            "/nonexistent.hex", "/nonexistent.txt", "crc32", 0, 0
        )
        self.assertEqual(status, "Warning")

    @patch("interface.crc.verify_crc")
    @patch("interface.get_input_file_data", return_value=b"data")
    @patch("builtins.open", mock_open(read_data="12345"))
    def test_success(self, _, mock_verify):
        mock_verify.return_value = ("Success", "CRC verified")
        with patch("interface.checkFilePath", return_value=True):
            status, _ = interface.If_verify_crc(
                "/fake.hex", "/fake.txt", "crc32", 0, 0
            )
        self.assertEqual(status, "Success")


# ---------------------------------------------------------------------------
# If_aes_encrypt / If_aes_decrypt
# ---------------------------------------------------------------------------

class TestIfAesEncrypt(unittest.TestCase):

    def test_missing_file_returns_warning(self):
        status, _ = interface.If_aes_encrypt(
            "/nokey", "/nofile", "/noiv", "AES_CBC", 0, 0
        )
        self.assertEqual(status, "Warning")

    @patch("interface.encrypt_decrypt.aes_encrypt")
    @patch("interface._load_symmetric_key_raw", return_value=b"key16bytes_12345")
    @patch("interface.get_input_file_data", return_value=b"plaintext")
    @patch("interface.createTempDir")
    @patch("builtins.open", mock_open(read_data=b"\x00" * 16))
    def test_success(self, mock_mkdir, _, mock_key, mock_enc):
        mock_enc.return_value = ("Success", b"ciphertext")
        with patch("interface.checkFilePath", return_value=True):
            status, _ = interface.If_aes_encrypt(
                "/k.pem", "/f.hex", "/iv.bin", "AES_CBC", 0, 0
            )
        self.assertEqual(status, "Success")


class TestIfAesDecrypt(unittest.TestCase):

    def test_missing_file_returns_warning(self):
        status, _ = interface.If_aes_decrypt("/nokey", "/noiv", "/noenc", "AES_CBC")
        self.assertEqual(status, "Warning")

    @patch("interface.encrypt_decrypt.aes_decrypt")
    @patch("interface._load_symmetric_key_raw", return_value=b"key16bytes_12345")
    @patch("interface.createTempDir")
    @patch("builtins.open", mock_open(read_data=b"\x00" * 16))
    def test_success(self, mock_mkdir, mock_key, mock_dec):
        mock_dec.return_value = ("Success", b"plaintext")
        with patch("interface.checkFilePath", return_value=True):
            status, _ = interface.If_aes_decrypt(
                "/k.pem", "/iv.bin", "/enc.enc", "AES_CBC"
            )
        self.assertEqual(status, "Success")


# ---------------------------------------------------------------------------
# _load_symmetric_key_raw helper
# ---------------------------------------------------------------------------

class TestLoadSymmetricKeyRaw(unittest.TestCase):

    @patch("interface.keys.load_symmetric_key")
    def test_returns_key_on_success(self, mock_load):
        mock_load.return_value = ("Success", b"rawkey")
        result = interface._load_symmetric_key_raw("/fake.pem")
        self.assertEqual(result, b"rawkey")

    @patch("interface.keys.load_symmetric_key", side_effect=ValueError("not pem"))
    @patch("builtins.open", mock_open(read_data=b"rawbytes"))
    def test_falls_back_to_raw_read_on_value_error(self, mock_load):
        result = interface._load_symmetric_key_raw("/fake.bin")
        self.assertEqual(result, b"rawbytes")

    @patch("interface.keys.load_symmetric_key", side_effect=AttributeError)
    @patch("builtins.open", mock_open(read_data=b"rawbytes"))
    def test_falls_back_to_raw_read_on_attribute_error(self, mock_load):
        result = interface._load_symmetric_key_raw("/fake.bin")
        self.assertEqual(result, b"rawbytes")


if __name__ == "__main__":
    unittest.main()
