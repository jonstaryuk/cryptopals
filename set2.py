def pkcs7_pad(data, size):
    if type(data) == str:
        data = data.encode()
    data = bytearray(data)
    pad = size - len(data)
    for i in range(pad):
        data.append(pad)
    return data
