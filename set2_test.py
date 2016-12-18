import set1
import set2
import unittest


class TestSet2(unittest.TestCase):

    def test_pkcs7_pad(self):
        self.assertEqual(set2.pkcs7_pad(b"YELLOW SUBMARINE", block_size=20), b"YELLOW SUBMARINE\x04\x04\x04\x04")
        self.assertEqual(set2.pkcs7_pad(b"YELLOW SUBMARINES", block_size=20), b"YELLOW SUBMARINES\x03\x03\x03")
        self.assertEqual(set2.pkcs7_pad(b"hello", block_size=5), b"hello\x05\x05\x05\x05\x05")

    def test_pkcs7_unpad(self):
        self.assertEqual(set2.pkcs7_unpad(b"YELLOW SUBMARINE\x04\x04\x04\x04"), b"YELLOW SUBMARINE")
        self.assertEqual(set2.pkcs7_unpad(b"YELLOW SUBMARINES\x03\x03\x03"), b"YELLOW SUBMARINES")
        self.assertEqual(set2.pkcs7_unpad(b"hello\x05\x05\x05\x05\x05"), b"hello")

    def test_aes_ecb_helpers(self):
        msg = b"aksdfkasjdf;kasksaksjdf;kasljfjm"
        ciph = set2.encrypt_aes_ecb(msg, b"MELLOW SUBMARINE")
        self.assertEqual(set1.decrypt_aes_ecb(ciph, b"MELLOW SUBMARINE"), msg)

    def test_xor(self):
        self.assertEqual(set2.xor(b"\x0f\x45", b"\x11\x60"), b"\x1e\x25")

    def test_decrypt_aes_cbc(self):
        ciph = set1.read_base64_encoded_file("fixtures/10.in")
        key = b"YELLOW SUBMARINE"
        iv = bytes(16)

        with open("fixtures/10.out.expect", "rb") as f:
            expected_msg = f.read()

        self.assertEqual(set2.decrypt_aes_cbc(ciph, key, iv), expected_msg)


if __name__ == '__main__':
    unittest.main()
