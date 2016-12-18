def pkcs7_pad(data, size):
    if type(data) == str:
        data = data.encode()
    data = bytearray(data)
    for i in range(size - len(data)):
        data.append(ord('\x04'))
    return data
