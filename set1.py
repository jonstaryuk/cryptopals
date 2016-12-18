import base64

ENGLISH_BYTE_HISTOGRAM = [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.001669449081803005, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.17576913904125924, 0.00023849272597185786, 0.0, 0.0, 0.0, 0.0, 0.0, 0.004769854519437157, 0.00023849272597185786, 0.00023849272597185786, 0.0, 0.0, 0.009539709038874314, 0.0, 0.02241831624135464, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0028619127116622945, 0.0, 0.0, 0.0, 0.0, 0.0009539709038874314, 0.0, 0.002146434533746721, 0.0014309563558311473, 0.0011924636298592892, 0.001669449081803005, 0.0, 0.0011924636298592892, 0.0014309563558311473, 0.0026234199856904365, 0.003100405437634152, 0.00023849272597185786, 0.0004769854519437157, 0.0009539709038874314, 0.0019079418077748629, 0.001669449081803005, 0.0011924636298592892, 0.0011924636298592892, 0.00023849272597185786, 0.0007154781779155736, 0.0028619127116622945, 0.0026234199856904365, 0.0, 0.0, 0.001669449081803005, 0.0, 0.00023849272597185786, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.05747674695921774, 0.010493679942761746, 0.01764846172191748, 0.028380634390651086, 0.093966134032912, 0.019079418077748628, 0.02003338898163606, 0.04674457429048414, 0.04483663248270928, 0.0004769854519437157, 0.010732172668733603, 0.0379203434295254, 0.014071070832339614, 0.04340567612687813, 0.05747674695921774, 0.014786549010255187, 0.001669449081803005, 0.05103744335797758, 0.05079895063200572, 0.06773193417600763, 0.02313379441927021, 0.0076317672310994514, 0.013832578106367757, 0.0, 0.017171476269973767, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]

def base64_from_hex(data):
    return base64.b64encode(bytes.fromhex(data))

def fixed_xor(a, b):
    a = bytes.fromhex(a)
    b = bytes.fromhex(b)

    assert len(a) == len(b)

    output = bytearray()
    for i in range(len(a)):
        output.append(a[i] ^ b[i])

    return output.hex()

def xor_bytestring(data, key):
    """Does an XOR of each byte in 'data' with the byte 'key'"""
    if type(key) == str:
        key = ord(key[0])

    output = bytearray()
    for byte in data:
        output.append(byte ^ key)

    return bytes(output)

def byte_histogram(data):
    occurrences = [0 for x in range(256)]
    for b in data:
        occurrences[b] += 1
    length = float(len(data))
    return [n / length for n in occurrences]

def english_score(plaintext):
    """Lower is better"""
    observed = byte_histogram(plaintext)
    chi_squared = 0
    for i in range(256):
        expected = ENGLISH_BYTE_HISTOGRAM[i] + 0.000000000001
        chi_squared += (observed[i] - expected) ** 2 / expected
    return chi_squared

def break_single_byte_xor(ciphertext):
    candidates = []
    for i in range(256):
        plaintext = xor_bytestring(ciphertext, i)
        candidates.append((plaintext, english_score(plaintext)))

    candidates.sort(key=lambda tup: tup[1])

    return candidates[0][0]

def find_single_byte_xor_in_file(file):
    strings = []
    with open(file, "r") as f:
        for line in f:
            if line[-1] == '\n':
                line = line[:-1]
            strings.append(bytes.fromhex(line))

    plaintexts = []
    for string in strings:
        solution = break_single_byte_xor(string)
        plaintexts.append((solution, english_score(solution)))

    plaintexts.sort(key=lambda tup: tup[1])

    return plaintexts[0][0]

def encrypt_repeating_key_xor(plaintext, key):
    if type(plaintext) == str:
        plaintext = plaintext.encode()
    if type(key) == str:
        key = key.encode()

    key_length = len(key)

    output = bytearray()
    for i in range(len(plaintext)):
        output.append(plaintext[i] ^ key[i % key_length])

    return bytes(output)
