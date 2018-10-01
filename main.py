import string
import sha2


def get_blocks(message, block_size=256):
    block_nums = []
    for block in [message[i:i + block_size] for i in range(0, len(message), block_size)]:
        block_num = 0
        block = block[::-1]
        for i, char in enumerate(block):
            block_num += char * (256 ** i)
        block_nums.append(block_num)
    return block_nums


def get_text(block_nums):
    message = []
    for block in block_nums:
        block_text = []
        while block:
            message_num = block % 256
            block = block // 256
            block_text.append(bytes([message_num]))
        block_text.reverse()
        message.extend(block_text)
    return b''.join(message)


def encrypt_number(n, e, num):
    return pow(num, e, n)


def decrypt_number(n, d, num):
    return pow(num, d, n)


def encrypt_message(n, e, message, key_size):
    encrypted_blocks = []
    encoded_blocks = []

    block_size = key_size // 8

    for block in get_blocks(message, block_size):
        encrypted_blocks.append(encrypt_number(n, e, block))

    for block in encrypted_blocks:
        encoded_blocks.append(to_base64(block))

    return ','.join(encoded_blocks)


def sign_message(n, e, message, keysize):
    encrypted_blocks = []
    encoded_blocks = []

    blocksize = keysize // 8

    message_hash = sha2.SHA256(message).digest()

    for block in get_blocks(message_hash, blocksize):
        encrypted_blocks.append(encrypt_number(n, e, block))

    for block in encrypted_blocks:
        encoded_blocks.append(to_base64(block))

    return ','.join(encoded_blocks)


def decrypt_message(n, d, encrypted_message):
    decoded_blocks = []
    decrypted_blocks = []

    for block in encrypted_message.split(','):
        decoded_blocks.append(from_base64(block))

    for block in decoded_blocks:
        decrypted_blocks.append(decrypt_number(n, d, block))

    return get_text(decrypted_blocks)


def authenticate_message(n, d, plaintext, encrypted_hash):
    decoded_blocks = []
    decrypted_blocks = []

    for block in encrypted_hash.split(','):
        decoded_blocks.append(from_base64(block))

    for block in decoded_blocks:
        decrypted_blocks.append(decrypt_number(n, d, block))

    alleged_hash = get_text(decrypted_blocks)
    return alleged_hash == sha2.SHA256(plaintext).digest()


base64_literals = string.ascii_uppercase + string.ascii_lowercase + string.digits + '+='


def to_base64(x):
    digits = []
    while x:
        digits.append(base64_literals[x % 64])
        x //= 64
    digits.reverse()
    return ''.join(digits)


def from_base64(base64):
    block_num = 0
    base64 = base64[::-1]
    for i, char in enumerate(base64):
        block_num += base64_literals.find(char) * (64 ** i)
    return block_num


if __name__ == '__main__':
    with open('main_pubkey.txt') as f:
        size, n, e, sigN, sigD = [int(i) for i in f.read().split(',')]
    with open('main_privkey.txt') as f:
        null, null, d, null, sigE = [int(i) for i in f.read().split(',')]

    text = b'Hello, World!'

    encrypted = encrypt_message(n, e, text, size)
    signature = sign_message(sigN, sigE, text, size)
    decrypted = decrypt_message(n, d, encrypted)
    authenticated = authenticate_message(sigN, sigD, decrypted, signature)
    assert decrypted == text
    assert authenticated
