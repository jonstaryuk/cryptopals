import set1
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def pkcs7_pad(data, block_size=16):
    data = bytearray(data)

    if len(data) < block_size:
        pad = block_size - len(data)
    else:
        pad = len(data) % block_size
        if pad == 0:
            pad = block_size

    for i in range(pad):
        data.append(pad)

    return bytes(data)


def pkcs7_unpad(data):
    data = bytearray(data)

    pad = data[-1]
    assert pad > 0

    return bytes(data[:-pad])


def encrypt_aes_ecb(block, key):
    if type(key) == str:
        key = key.encode()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(block) + encryptor.finalize()


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

