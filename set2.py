import os
import random
import set1
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def pkcs7_pad(data, block_size=16):
    if len(data) < block_size:
        pad = block_size - len(data)
    else:
        pad = block_size - len(data) % block_size
        if pad == 0:
            pad = block_size

    data = data + (chr(pad).encode() * pad)

    return data


def pkcs7_unpad(data):
    data = bytearray(data)

    pad = data[-1]
    assert pad > 0

    return bytes(data[:-pad])


def encrypt_aes_ecb(data, key):
    if type(key) == str:
        key = key.encode()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()


def xor(a, b):
    return bytes([a[i] ^ b[i] for i in range(len(a))])


def encrypt_aes_cbc(msg, key, iv, block_size=16):
    assert len(key) == len(iv) == block_size

    msg = pkcs7_pad(msg, block_size)
    blocks = [msg[i:i+block_size] for i in range(0, len(msg), block_size)]

    ciph = []
    prev = iv
    for block in blocks:
        prev = encrypt_aes_ecb(xor(block, prev), key)
        ciph.append(prev)

    return b"".join(ciph)


def decrypt_aes_cbc(ciph, key, iv, block_size=16):
    assert len(key) == len(iv) == block_size

    blocks = [ciph[i:i+block_size] for i in range(0, len(ciph), block_size)]

    msg = []
    prev = iv
    for block in blocks:
        msg.append(xor(set1.decrypt_aes_ecb(block, key), prev))
        prev = block

    return pkcs7_unpad(b"".join(msg))


def encrypt_randomly(data, test_list=None):
    key = os.urandom(16)

    pad1amt = random.randint(5, 10)
    pad2amt = random.randint(5, 10)
    data = os.urandom(pad1amt) + data + os.urandom(pad2amt)

    mode = "ECB" if os.urandom(1)[0] % 2 == 0 else "CBC"

    if test_list is not None:
        test_list.append(mode)

    if mode == "ECB":
        data = pkcs7_pad(data)
        assert len(data) % 16 == 0
        return encrypt_aes_ecb(data, key)
    else:
        iv = os.urandom(16)
        return encrypt_aes_cbc(data, key, iv)


def detect_ecb_cbc(encrypt):
    data = b"yellowsubmarine yellowsubmarine yellowsubmarine yellowsubmarine"
    ciph = encrypt(data)
    blocks = [ciph[i:i+16] for i in range(0, len(ciph), 16)]

    if blocks[2] == blocks[3]:
        return "ECB"
    else:
        return "CBC"
