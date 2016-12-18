import set1
import unittest

class TestSet1(unittest.TestCase):

    def test_base64_from_hex(self):
        data = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
        expect = b"SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
        self.assertEqual(set1.base64_from_hex(data), expect)

    def test_fixed_xor(self):
        a = "1c0111001f010100061a024b53535009181c"
        b = "686974207468652062756c6c277320657965"
        self.assertEqual(set1.fixed_xor(a, b), "746865206b696420646f6e277420706c6179")

    def test_xor_bytestring(self):
        self.assertEqual(set1.xor_bytestring(b"hi", ord("M")), b"%$")
        self.assertEqual(set1.xor_bytestring(b"hi", "M"), b"%$")

    def test_english_score(self):
        self.assertTrue(set1.english_score(b"Hello, how are you?") < set1.english_score(b"HH0p0FP(*MHIMW(F*M*F@"))
        self.assertTrue(set1.english_score(b"What light through yonder window breaks") < set1.english_score(b"()JF#(*EJMFIEJI))"))

    def test_break_single_byte_xor(self):
        data = bytes.fromhex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
        self.assertEqual(set1.break_single_byte_xor(data), b"Cooking MC's like a pound of bacon")

    def test_find_single_byte_xor_in_file(self):
        # Takes too long to run on every test
        # set1.find_single_byte_xor_in_file('4.in')
        # expect: b'Now that the party is jumping\n'
        pass

    def test_encrypt_repeating_key_xor(self):
        plaintext = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
        expect = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
        actual = set1.encrypt_repeating_key_xor(plaintext, "ICE")
        self.assertEqual(expect, actual.hex())

    def test_hamming_distance(self):
        self.assertEqual(set1.hamming_distance(b"this is a test", b"wokka wokka!!!"), 37)

if __name__ == '__main__':
    unittest.main()
