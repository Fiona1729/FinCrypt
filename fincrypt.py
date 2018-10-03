#!/usr/bin/env python3

import resin
import sys
import os
import argparse
import base64
import zlib
import randomart
import string
import re
from key_asn1 import FinCryptKey
from message_asn1 import FinCryptMessage
from pyasn1.codec.ber.decoder import decode as decode_ber
from pyasn1.codec.native.encoder import encode as encode_native
from pyasn1.codec.der.encoder import encode as encode_der
from block import Decrypter, Encrypter, AESModeOfOperationCBC


BASE_PATH = os.path.dirname(__file__)
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
    encrypted_iv = []

    key = os.urandom(32)
    iv = os.urandom(16)

    block_size = key_size // 8

    message_encryptor = Encrypter(mode=AESModeOfOperationCBC(key=key, iv=iv))

    encrypted_blocks = message_encryptor.feed(message)

    encrypted_blocks += message_encryptor.feed()

    for block in get_blocks(key, block_size):
        encrypted_key.append(encrypt_number(n, e, block))

    for block in get_blocks(iv, block_size):
        encrypted_iv.append(encrypt_number(n, e, block))

    return encrypted_key, encrypted_iv, encrypted_blocks


def decrypt_message(n, d, encrypted_key, encrypted_iv, encrypted_message):
    decrypted_key = []
    decrypted_iv = []
    decrypted_message = []

    for block in encrypted_key:
        decrypted_key.append(decrypt_number(n, d, block))
    decrypted_key = get_text(decrypted_key)

    for block in encrypted_iv:
        decrypted_iv.append(decrypt_number(n, d, block))
    decrypted_iv = get_text(decrypted_iv)

    message_decryptor = Decrypter(mode=AESModeOfOperationCBC(decrypted_key, iv=decrypted_iv))

    decrypted_message = message_decryptor.feed(encrypted_message)
    decrypted_message += message_decryptor.feed()

    return decrypted_message


def sign_message(n, e, message, key_size):
    encrypted_blocks = []

    block_size = key_size // 8

    message_hash = resin.SHA512(message).digest()

    for block in get_blocks(message_hash, block_size):
        encrypted_blocks.append(encrypt_number(n, e, block))

    return encrypted_blocks


def authenticate_message(n, d, plaintext, encrypted_blocks):
    decrypted_blocks = []

    for block in encrypted_blocks:
        decrypted_blocks.append(decrypt_number(n, d, block))

    alleged_hash = get_text(decrypted_blocks)
    return alleged_hash == resin.SHA512(plaintext).digest()


def strip_headers(pem_text):
    match = re.match(r'(?:-+ (BEGIN FINCRYPT (?:PUBLIC |PRIVATE )?(?:KEY|MESSAGE)) -+\n)([a-zA-Z0-9\n+\/=]+)(?:-+ END FINCRYPT (?:PUBLIC |PRIVATE )?(?:KEY|MESSAGE) -+)', pem_text)
    if match is None:
      return None, None
    return match[1], match[2]


def read_message(message_text):
    header, message = strip_headers(message_text)
    if header != 'BEGIN FINCRYPT MESSAGE':
      sys.stderr.write('Message was malformed.')
      sys.exit()
    return message


def read_key(key_text, desired_header):
    key_header, key_text = strip_headers(key_text)

    if key_header is None or key_header != desired_header:
        raise Exception

    try:
        b64_decoded = base64.urlsafe_b64decode(key_text.encode('utf-8'))
        key, _ = decode_ber(b64_decoded, asn1Spec=FinCryptKey())
        key = encode_native(key)
    except:
        raise Exception

    return {'key_size': key['keysize'], 'n': key['mod'], 'exp': key['exp'], 'sig_n': key['sigmod'], 'sig_exp': key['sigexp'],
            'name': key['name'], 'email': key['email']}


def encrypt_and_sign(message, recipient):
    recipient_key = os.path.join(PUBLIC_PATH, recipient)

    if not os.path.exists(recipient_key):
        print('Recipient keyfile does not exist.')
        sys.exit()
    try:
        with open(recipient_key) as f:
            recipient_key = read_key(f.read(), 'BEGIN FINCRYPT PUBLIC KEY')
    except:
        sys.stderr.write('Recipient\'s key file is malformed.')
        sys.exit()

    try:
        with open(PRIVATE_KEY) as f:
            signer_key = read_key(f.read(), 'BEGIN FINCRYPT PRIVATE KEY')
    except:
        sys.stderr.write('Private key file is malformed or does not exist.')
        sys.exit()


    encrypted_key, encrypted_iv, encrypted_blocks = encrypt_message(recipient_key['n'], recipient_key['exp'], message, recipient_key['key_size'])
    signature = sign_message(signer_key['sig_n'], signer_key['sig_exp'], message, signer_key['key_size'])

    encrypted_message = FinCryptMessage()

    encrypted_message['key'].extend(encrypted_key)
    encrypted_message['iv'].extend(encrypted_iv)
    encrypted_message['message'] = encrypted_blocks
    encrypted_message['signature'].extend(signature)

    encoded_message = encode_der(encrypted_message)

    return encoded_message


def decrypt_and_verify(message, sender):
    sender_key = os.path.join(PUBLIC_PATH, sender)

    if not os.path.exists(sender_key):
        print('Sender keyfile does not exist.')
        sys.exit()
    try:
        with open(PRIVATE_KEY) as f:
            decryption_key = read_key(f.read(), 'BEGIN FINCRYPT PRIVATE KEY')
    except:
        sys.stderr.write('Private key file is malformed or does not exist.')
    try:
        with open(sender_key) as f:
            sender_key = read_key(f.read(), 'BEGIN FINCRYPT PUBLIC KEY')
    except:
        sys.stderr.write('Sender key file is malformed.')
    try:
        decoded, _ = decode_ber(message, asn1Spec=FinCryptMessage())
        decoded = encode_native(decoded)
    except:
        return None, False

    try:
        decrypted_message = decrypt_message(decryption_key['n'], decryption_key['exp'], decoded['key'], decoded['iv'], decoded['message'])
    except:
        decrypted_message = None

    try:
        authenticated = authenticate_message(sender_key['sig_n'], sender_key['sig_exp'], decrypted_message, decoded['signature'])
    except:
        authenticated = False

    return decrypted_message, authenticated


def encrypt_text(arguments):
    message = encrypt_and_sign(zlib.compress(arguments.infile.read()), arguments.recipient)

    message = base64.b64encode(message).decode('utf-8')

    sys.stdout.write(' BEGIN FINCRYPT MESSAGE '.center(76, '-') + '\n')
    sys.stdout.write('\n'.join([message[i:i + 76] for i in range(0, len(message), 76)]))
    sys.stdout.write('\n' + ' END FINCRYPT MESSAGE '.center(76, '-'))


def decrypt_text(arguments):
    in_message = ''.join(read_message(arguments.infile.read()).split('\n'))

    in_message = base64.b64decode(in_message)

    message, verified = decrypt_and_verify(in_message, arguments.sender)
    if message is None:
        sys.stderr.write('Decryption failed.\n')
    else:
        try:
            sys.stdout.buffer.write(zlib.decompress(message))
        except:
            sys.stderr.write('Decompression failed.\n')
    if not verified:
        sys.stderr.write('Verification failed. Message is not intact.\n')


def encrypt_binary(arguments):
    message = encrypt_and_sign(zlib.compress(arguments.infile.read()), arguments.recipient)

    sys.stdout.buffer.write(message)


def decrypt_binary(arguments):
    in_message = arguments.infile.read()

    message, verified = decrypt_and_verify(in_message, arguments.sender)
    if message is None:
        sys.stderr.write('Decryption failed.\n')
    else:
        try:
            sys.stdout.buffer.write(zlib.decompress(message))
        except:
            sys.stderr.write('Decompression failed.\n')
    if not verified:
        sys.stderr.write('Verification failed. Message is not intact.\n')


def enum_keys(arguments):
    key_enum = ''
    for key_file in os.listdir(PUBLIC_PATH):
        with open(os.path.join(PUBLIC_PATH, key_file)) as f:
            key_text = f.read()
        key = read_key(key_text, 'BEGIN FINCRYPT PUBLIC KEY')

        key_hash = resin.SHA512(key_text.encode('utf-8')).hexdigest()
        key_hash_formatted = ':'.join([key_hash[i:i + 2] for i in range(0, len(key_hash), 2)]).upper()

        key_randomart = randomart.randomart(key_hash, 'SHA512')

        formatted_key = f"{key_file}:\nName: {key['name'].decode('utf-8')}\nEmail: {key['email'].decode('utf-8')}\nHash: " \
                        f"{key_hash_formatted}\nKeyArt:\n{key_randomart}"

        key_enum += formatted_key + '\n\n'
    sys.stdout.write(key_enum.strip())


def main():
    parser = argparse.ArgumentParser(
        description='Encrypt and decrypt using FinCrypt. Place your private key as '
                    './private_key/private.asc, and distribute your public key.')

    parser.add_argument('--enumerate-keys', '-N', action='store_const', dest='func', const=enum_keys)
    subparsers = parser.add_subparsers(title='sub-commands', description='Encryption and decryption sub-commands')

    parser_encrypt = subparsers.add_parser('encrypt', aliases=['e'], help='Encrypt a message/file.')
    parser_encrypt.add_argument('recipient', type=str, default=None,
                                help='The filename of the recipient\'s public key. '
                                    'Always defaults to the /public_keys directory.')
    parser_encrypt.add_argument('infile', nargs='?', type=argparse.FileType('rb'), default=sys.stdin.buffer,
                                help='File to encrypt. Defaults to stdin.')
    parser_encrypt.set_defaults(func=encrypt_text)

    parser_decrypt = subparsers.add_parser('decrypt', aliases=['d'], help='Decrypt a message.')
    parser_decrypt.add_argument('sender', type=str, default=None,
                                help='The filename of the sender\'s public key. '
                                    'Always defaults to the /public_keys directory.')
    parser_decrypt.add_argument('infile', nargs='?', type=argparse.FileType('r'), default=sys.stdin,
                                help='The filename or path of the encrypted file. Defaults to stdin.')
    parser_decrypt.set_defaults(func=decrypt_text)


    parser_encrypt_binary = subparsers.add_parser('encryptbin', aliases=['eb'], help='Encrypt a message/file with binary encoding. '
                                                                                     'Provides space savings at the cost of readability.')
    parser_encrypt_binary.add_argument('recipient', type=str, default=None,
                                help='The filename of the recipient\'s public key. '
                                    'Always defaults to the /public_keys directory.')
    parser_encrypt_binary.add_argument('infile', nargs='?', type=argparse.FileType('rb'), default=sys.stdin.buffer,
                                help='File to encrypt. Defaults to stdin.')
    parser_encrypt_binary.set_defaults(func=encrypt_binary)

    parser_decrypt_binary = subparsers.add_parser('decryptbin', aliases=['db'], help='Decrypt a message/file with binary encoding.')
    parser_decrypt_binary.add_argument('sender', type=str, default=None,
                                help='The filename of the sender\'s public key. '
                                    'Always defaults to the /public_keys directory.')
    parser_decrypt_binary.add_argument('infile', nargs='?', type=argparse.FileType('rb'), default=sys.stdin,
                                help='The filename or path of the encrypted file. Defaults to stdin.')
    parser_decrypt_binary.set_defaults(func=decrypt_binary)


    args = parser.parse_args()


    if args.func is None:
        parser.print_help()
        sys.exit()

    args.func(args)


if __name__ == '__main__':
    main()
