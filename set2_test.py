import set2
import unittest


class TestSet2(unittest.TestCase):

    def test_pkcs7_pad(self):
        self.assertEqual(set2.pkcs7_pad(b"YELLOW SUBMARINE", 20), b"YELLOW SUBMARINE\x04\x04\x04\x04")
        self.assertEqual(set2.pkcs7_pad(b"YELLOW SUBMARINES", 20), b"YELLOW SUBMARINES\x03\x03\x03")


if __name__ == '__main__':
    unittest.main()
