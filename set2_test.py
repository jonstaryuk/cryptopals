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


if __name__ == '__main__':
    unittest.main()
