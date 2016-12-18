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
