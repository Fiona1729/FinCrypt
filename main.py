#!/usr/bin/env python3

import resin
import sys
import os
import argparse
import base64
import zlib
import randomart
import string
from block import Decrypter, Encrypter, AESModeOfOperationCBC

BASE_PATH = os.path.dirname(__file__)
BASE64_LITERALS = string.ascii_uppercase + string.ascii_lowercase + string.digits + '+='
PUBLIC_PATH = os.path.join(BASE_PATH, 'public_keys')
PRIVATE_KEY = os.path.join(BASE_PATH, 'private_key', 'private.asc')


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
    encrypted_key = []
    encoded_key = []
    encrypted_iv = []
    encoded_iv = []
    encoded_message = []

    key = os.urandom(32)
    iv = os.urandom(16)

    block_size = key_size // 8

    message_encrypter = Encrypter(mode=AESModeOfOperationCBC(key=key, iv=iv))

    encrypted_blocks = message_encrypter.feed(message)

    encrypted_blocks += message_encrypter.feed()

    for block in get_blocks(key, block_size):
        encrypted_key.append(encrypt_number(n, e, block))
    for block in encrypted_key:
        encoded_key.append(int_to_base64(block))

    for block in get_blocks(iv, block_size):
        encrypted_iv.append(encrypt_number(n, e, block))
    for block in encrypted_iv:
        encoded_iv.append(int_to_base64(block))

    for block in get_blocks(encrypted_blocks, block_size):
        encoded_message.append(int_to_base64(block))

    final_key = ','.join(encoded_key)
    final_iv = ','.join(encoded_iv)
    final_message = ','.join(encoded_message)

    return '_'.join([final_key, final_iv, final_message])


def decrypt_message(n, d, full_message):
    encoded_key, encoded_iv, encoded_message = full_message.split('_')
    encrypted_key = []
    decrypted_key = []
    encrypted_iv = []
    decrypted_iv = []
    encrypted_message = []
    decrypted_message = []

    for block in encoded_key.split(','):
        encrypted_key.append(int_from_base64(block))
    for block in encrypted_key:
        decrypted_key.append(decrypt_number(n, d, block))
    decrypted_key = get_text(decrypted_key)

    for block in encoded_iv.split(','):
        encrypted_iv.append(int_from_base64(block))
    for block in encrypted_iv:
        decrypted_iv.append(decrypt_number(n, d, block))
    decrypted_iv = get_text(decrypted_iv)

    message_decryptor = Decrypter(mode=AESModeOfOperationCBC(decrypted_key, iv=decrypted_iv))

    for block in encoded_message.split(','):
        encrypted_message.append(int_from_base64(block))
    decoded_message = get_text(encrypted_message)

    decrypted_message = message_decryptor.feed(decoded_message)
    decrypted_message += message_decryptor.feed()

    return decrypted_message


def sign_message(n, e, message, key_size):
    encrypted_blocks = []
    encoded_blocks = []

    block_size = key_size // 8

    message_hash = resin.SHA256(message).digest()

    for block in get_blocks(message_hash, block_size):
        encrypted_blocks.append(encrypt_number(n, e, block))

    for block in encrypted_blocks:
        encoded_blocks.append(int_to_base64(block))

    return ','.join(encoded_blocks)


def authenticate_message(n, d, plaintext, encrypted_hash):
    decoded_blocks = []
    decrypted_blocks = []

    for block in encrypted_hash.split(','):
        decoded_blocks.append(int_from_base64(block))

    for block in decoded_blocks:
        decrypted_blocks.append(decrypt_number(n, d, block))

    alleged_hash = get_text(decrypted_blocks)
    return alleged_hash == resin.SHA256(plaintext).digest()


def int_to_base64(x):
    digits = []
    while x:
        digits.append(BASE64_LITERALS[x % 64])
        x //= 64
    digits.reverse()
    return ''.join(digits)


def int_from_base64(base64):
    block_num = 0
    base64 = base64[::-1]
    for i, char in enumerate(base64):
        block_num += BASE64_LITERALS.find(char) * (64 ** i)
    return block_num


def decode_b64_string(string):
    return base64.b64decode(string.encode('utf-8')).decode('utf-8')


def read_key(key_text):
    key_parts = ''.join(key_text.split('\n')).split(',')
    key_size = int_from_base64(key_parts[0])

    message_n = int_from_base64(key_parts[1])

    message_exp = int_from_base64(key_parts[2])

    signature_n = int_from_base64(key_parts[3])

    signature_exp = int_from_base64(key_parts[4])

    name = decode_b64_string(key_parts[5])

    email = decode_b64_string(key_parts[6])
    return {'key_size': key_size, 'n': message_n, 'exp': message_exp, 'sig_n': signature_n, 'sig_exp': signature_exp,
            'name': name, 'email': email}


def encrypt_and_sign(message, recipient):
    recipient_key = os.path.join(PUBLIC_PATH, recipient)

    if not os.path.exists(recipient_key):
        print('Recipient keyfile does not exist.')
        sys.exit()

    with open(recipient_key) as f:
        recipient_key = read_key(f.read())

    with open(PRIVATE_KEY) as f:
        signer_key = read_key(f.read())

    encrypted_message = encrypt_message(recipient_key['n'], recipient_key['exp'], message, recipient_key['key_size'])
    signature = sign_message(signer_key['sig_n'], signer_key['sig_exp'], message, signer_key['key_size'])

    return '|'.join([encrypted_message, signature])


def decrypt_and_verify(message, sender):
    encrypted_message, signature = message.split('|')
    sender_key = os.path.join(PUBLIC_PATH, sender)

    if not os.path.exists(sender_key):
        print('Sender keyfile does not exist.')
        sys.exit()

    with open(PRIVATE_KEY) as f:
        decryption_key = read_key(f.read())

    with open(sender_key) as f:
        sender_key = read_key(f.read())

    decrypted_message = decrypt_message(decryption_key['n'], decryption_key['exp'], encrypted_message)
    authenticated = authenticate_message(sender_key['sig_n'], sender_key['sig_exp'], decrypted_message, signature)

    return decrypted_message, authenticated


def encrypt_stream(args):
    message = encrypt_and_sign(zlib.compress(args.infile.read()), args.recipient)
    sys.stdout.write('\n'.join([message[i:i + 76] for i in range(0, len(message), 76)]))


def decrypt_stream(args):
    message, verified = decrypt_and_verify(''.join(args.infile.read().split('\n')), args.sender)
    sys.stdout.buffer.write(zlib.decompress(message))
    if not verified:
        sys.stderr.write('Verification failed.')


def enum_keys(args):
    key_enum = ''
    for key_file in os.listdir(PUBLIC_PATH):
        with open(os.path.join(PUBLIC_PATH, key_file)) as f:
            key_text = f.read()
        key = read_key(key_text)
        hash = resin.SHA256(key_text.encode('utf-8')).hexdigest()
        hash_formatted = ':'.join([hash[i:i + 2] for i in range(0, len(hash), 2)]).upper()
        key_randomart = randomart.randomart(hash, 'SHA256')
        format = f"{key_file}:\nName: {key['name']}:\nEmail: {key['email']}\nHash: " \
                 f"{hash_formatted}\nKeyArt:\n{key_randomart}"
        key_enum += format + '\n\n'
    sys.stdout.write(key_enum.strip())


def test():
    texts = [b'Hello, World!', b'ET Come Home', b'\x02\x03\x04\x05']
    for text in texts:
        message = encrypt_and_sign(text, 'public.asc')
        decrypted, verified = decrypt_and_verify(message, 'public.asc')
        assert decrypted == text
        assert verified

    sys.stdout.write('Done running tests!')


parser = argparse.ArgumentParser(
    description='Encrypt and decrypt using FinCrypt. Place your private key as '
                './private_key/private.asc, and distribute your public key.')
parser.add_argument('--enumerate_keys', '-N', action='store_const', dest='func', const=enum_keys)
subparsers = parser.add_subparsers(title='sub-commands', description='Encryption and decryption sub-commands')

parser_encrypt = subparsers.add_parser('encrypt', aliases=['e'], help='Encrypt a message.')
parser_encrypt.add_argument('recipient', type=str, default=None,
                            help='The filename of the recipient\'s public key. '
                                 'Always defaults to the /public_keys directory.')
parser_encrypt.add_argument('infile', nargs='?', type=argparse.FileType('rb'), default=sys.stdin.buffer,
                            help='File to encrypt. Defaults to stdin.')
parser_encrypt.set_defaults(func=encrypt_stream)

parser_decrypt = subparsers.add_parser('decrypt', aliases=['d'], help='Decrypt a message.')
parser_decrypt.add_argument('sender', type=str, default=None,
                            help='The filename of the sender\'s public key. '
                                 'Always defaults to the /public_keys directory.')
parser_decrypt.add_argument('infile', nargs='?', type=argparse.FileType('r'), default=sys.stdin,
                            help='The filename or path of the encrypted file. Defaults to stdin.')
parser_decrypt.set_defaults(func=decrypt_stream)

args = parser.parse_args()

try:
    args.func
except NameError:
    sys.stderr.write('FinCrypt requires arguments!')
    sys.exit()

args.func(args)
