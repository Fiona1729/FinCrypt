from sha import SHAKE256
from random import SystemRandom
random = SystemRandom()


def pkcs7_pad(data, padding):
    pad = padding - (len(data) % padding)
    return data + bytes([pad] * pad)


def pkcs7_unpad(data, padding):
    if len(data) % padding != 0:
        raise ValueError('Improper padding!')

    pad = data[-1]

    return data[:-pad]


def oaep_pad(message: bytes, append_length=32):
    message = pkcs7_pad(message, 32)

    r = random.getrandbits(append_length)
    length = len(message)
    message = int.from_bytes(message, 'little')

    x = int.from_bytes(SHAKE256(r.to_bytes(append_length, 'little')).digest(length), 'little') ^ message
    y = int.from_bytes(SHAKE256(x.to_bytes(length, 'little')).digest(append_length), 'little') ^ r

    return x.to_bytes(length, 'little') + y.to_bytes(append_length, 'little')


def oaep_unpad(data: bytes, append_length=32):
    length = len(data) - append_length
    x, y = int.from_bytes(data[:-append_length], 'little'), int.from_bytes(data[-append_length:], 'little')

    r = (y ^ int.from_bytes(SHAKE256(x.to_bytes(length, 'little')).digest(append_length), 'little')).to_bytes(append_length, 'little')
    message = x ^ int.from_bytes(SHAKE256(r).digest(length), 'little')

    return pkcs7_unpad(message.to_bytes(length, 'little'), 32)
