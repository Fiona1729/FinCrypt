#!/usr/bin/env python3

import sha
import sys
import os
import argparse
import base64
import zlib
import randomart
import re
from key_asn1 import FinCryptPublicKey, FinCryptPrivateKey
from message_asn1 import FinCryptMessage
from pyasn1.codec.ber.decoder import decode as decode_ber
from pyasn1.codec.native.encoder import encode as encode_native
from pyasn1.codec.der.encoder import encode as encode_der
from aes import Decrypter, Encrypter, AESModeOfOperationCBC

BASE_PATH = os.path.dirname(__file__)
PUBLIC_PATH = os.path.join(BASE_PATH, 'public_keys')
PRIVATE_KEY = os.path.join(BASE_PATH, 'private_key', 'private.asc')


class FinCryptDecodingError(Exception):
    def __init__(self, *args, **kwargs):
        Exception.__init__(self, *args, **kwargs)


def get_blocks(message, block_size=256):
    """
    Splits a message (bytes) into blocks of size block_size, then encodes each block
    as a base 256 integer. Can be reversed using get_bytes

    :param message: Message (bytes)
    :param block_size: Block size (int)
    :return: Blocks (list of int)
    """

    block_nums = []
    for block in [message[i:i + block_size] for i in range(0, len(message), block_size)]:
        block_num = 0
        block = block[::-1]
        for i, char in enumerate(block):
            block_num += char * (256 ** i)
        block_nums.append(block_num)
    return block_nums


def get_bytes(block_nums):
    """
    Takes an array of block integers and turns them back into a bytes object.
    Decodes using base 256.

    :param block_nums: Blocks (list of ints)
    :return: Original data (bytes)
    """

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
    """
    Encrypts a number using the RSA cipher
    NOTE:
    Just the pow function with renamed arguments. Used for better code readability.

    :param n: Encryption modulus (int)
    :param e: Encryption exponent (int)
    :param num: Number to encrypt (int)
    :return: Encrypted value (int)
    """

    return pow(num, e, n)


def decrypt_number(n, d, num):
    """
    Decrypts a number using the RSA cipher
    NOTE:
    Just the pow function with renamed arguments. Used for better code readability.

    :param n: Decryption modulus (int)
    :param d: Decryption exponent (int)
    :param num: Number to Decrypt (int)
    :return: Original number (int)
    """

    return pow(num, d, n)


def encrypt_message(n, e, message, key_size):
    """
    Encrypts a message using RSA and AES-256
    First generates a random AES key and IV with os.urandom()
    Then encrypts the original message with that key
    Then encrypts the AES key with the RSA key

    NOTE:
    This means that plaintext will not have the same ciphertext
    when encrypted twice. Keep this in mind if you require reproducibility behavior

    :param n: Encryption modulus (int)
    :param e: Encryption exponent (int)
    :param message: Message (bytes)
    :param key_size: The keysize, in bits, of the RSA public key (int)
    :return: Tuple (encrypted key (list of ints), encrypted IV (list of ints), and encrypted message (bytes))
    """

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
    """
    Decrypts a message encrypted by the encrypt_message function
    First decrypts the AES key and IV using RSA
    Then decrypts the data using the AES key and IV

    :param n: Decryption modulus (int)
    :param d: Decryption exponent (int)
    :param encrypted_key: RSA encrypted key (list of ints)
    :param encrypted_iv: RSA encrypted IV (list of ints)
    :param encrypted_message: AES encrypted data (bytes
    :return: Decrypted data (bytes)
    """

    decrypted_key = []
    decrypted_iv = []

    for block in encrypted_key:
        decrypted_key.append(decrypt_number(n, d, block))
    decrypted_key = get_bytes(decrypted_key)

    for block in encrypted_iv:
        decrypted_iv.append(decrypt_number(n, d, block))
    decrypted_iv = get_bytes(decrypted_iv)

    message_decryptor = Decrypter(mode=AESModeOfOperationCBC(decrypted_key, iv=decrypted_iv))

    decrypted_message = message_decryptor.feed(encrypted_message)
    decrypted_message += message_decryptor.feed()

    return decrypted_message


def sign_message(n, e, message, key_size):
    """
    Signs a message using an RSA signature private key (n and e), a message,
    and keysize

    Computes SHA512 hash of plaintext, and then encrypts it with private key

    :param n: Encryption modulus (int)
    :param e: Encryption exponent (int)
    :param message: Message to sign (bytes)
    :param key_size: Key size in bits (int)
    :return: Signature (list of ints)
    """

    encrypted_blocks = []

    block_size = key_size // 8

    message_hash = sha.SHA512(message).digest()

    for block in get_blocks(message_hash, block_size):
        encrypted_blocks.append(encrypt_number(n, e, block))

    return encrypted_blocks


def authenticate_message(n, d, plaintext, encrypted_blocks):
    """
    Authenticates a message when given a plaintext and signature

    Decrypts hash with public key, and compares alleged hash with actual
    hash of plaintext.

    :param n: Decryption modulus (int)
    :param d: Decryption exponent (int)
    :param plaintext: Decrypted plaintext to verify (bytes)
    :param encrypted_blocks: The signature (list of ints)
    :return: Whether the message signature is valid (boolean)
    """

    decrypted_blocks = []

    for block in encrypted_blocks:
        decrypted_blocks.append(decrypt_number(n, d, block))

    alleged_hash = get_bytes(decrypted_blocks)
    return alleged_hash == sha.SHA512(plaintext).digest()


def strip_headers(pem_text):
    """
    Strips the headers off a a FinCrypt key or message.

    :param pem_text: Text of key or message (string)
    :return: Tuple (header (ie. 'BEGIN FINCRYPT MESSAGE'), base64 (string))
    """

    match = re.match(
        r'(?:-+ (BEGIN FINCRYPT (?:PUBLIC |PRIVATE )?(?:KEY|MESSAGE)) -+\n)([a-zA-Z0-9\n+/=]+)'
        r'(?:-+ END FINCRYPT (?:PUBLIC |PRIVATE )?(?:KEY|MESSAGE) -+)', pem_text)
    if match is None:
        return None, None
    return match[1], match[2]


def read_message(message_text):
    """
    Reads a message, strips off and validates headers.
    Raises ValueError if the message was malformed.

    :param message_text: Message text (string)
    :return: Base64 of message (string)
    """

    header, message = strip_headers(message_text)
    if header != 'BEGIN FINCRYPT MESSAGE':
        raise ValueError('Message was malformed.')
    return message


def read_public_key(key_text):
    """
    Reads a FinCrypt public key. Returns a dictionary of all public key values.
    Raises exception if key is malformed or unreadable.

    The ASN.1 specification for a FinCrypt public key resides in key_asn1.py

    :param key_text: Key text (string)
    :return: Dictionary of all key ASN.1 values
    """

    key_header, key_text = strip_headers(key_text)

    if key_header is None or key_header != 'BEGIN FINCRYPT PUBLIC KEY':
        raise ValueError

    b64_decoded = base64.urlsafe_b64decode(key_text.encode('utf-8'))
    key, _ = decode_ber(b64_decoded, asn1Spec=FinCryptPublicKey())
    key = encode_native(key)

    return {'keysize': key['keysize'], 'modulus': key['modulus'], 'exponent':
            key['exponent'], 'sigModulus': key['sigModulus'], 'sigExponent':
            key['sigExponent'], 'name': key['name'], 'email': key['email']}


def read_private_key(key_text):
    """
    Reads a FinCrypt private key. Returns a dictionary of all usable private key values.
    Raises an exception if key is malformed or unreadable.

    The ASN.1 specification for a FinCrypt private key resides in key_asn1.py

    :param key_text: Key text (string)
    :return: Dictionary of all key ASN.1 values except for primes P and Q
    """

    key_header, key_text = strip_headers(key_text)

    if key_header is None or key_header != 'BEGIN FINCRYPT PRIVATE KEY':
        raise ValueError

    b64_decoded = base64.urlsafe_b64decode(key_text.encode('utf-8'))
    key, _ = decode_ber(b64_decoded, asn1Spec=FinCryptPrivateKey())
    key = encode_native(key)

    return {'keysize': key['keysize'], 'modulus': key['modulus'], 'publicExponent':
            key['publicExponent'], 'privateExponent': key['privateExponent'],
            'sigModulus': key['sigModulus'], 'sigPublicExponent': key['sigPublicExponent'],
            'sigPrivateExponent': key['sigPrivateExponent'], 'name': key['name'], 'email': key['email']}


def encrypt_and_sign(message, recipient):
    """
    Encrypts and signs a message using a recipient's public key name
    Looks for the recipient's public key in the public_keys/ directory.
    Looks for your private key as private_key/private.asc

    The ASN.1 specification for a FinCrypt message resides in message_asn1.py

    Raises exceptions if key files are not found, or are malformed.

    :param message: Message to encrypt (bytes)
    :param recipient: Recipient's public key filename (string)
    :return: Bytes of encrypted and encoded message and signature.
    """

    recipient_key = os.path.join(PUBLIC_PATH, recipient)

    if not os.path.exists(recipient_key):
        raise FileNotFoundError('Recipient keyfile does not exist.')

    if not os.path.exists(PRIVATE_KEY):
        raise FileNotFoundError('Private keyfile does not exist.')

    try:
        with open(recipient_key) as f:
            recipient_key = read_public_key(f.read())
    except Exception:
        raise FinCryptDecodingError('Recipient keyfile was malformed.')

    try:
        with open(PRIVATE_KEY) as f:
            signer_key = read_private_key(f.read())
    except Exception:
        raise FinCryptDecodingError('Private key file is malformed.')

    encrypted_key, encrypted_iv, encrypted_blocks = encrypt_message(recipient_key['modulus'], recipient_key['exponent'],
                                                                    message,
                                                                    recipient_key['keysize'])
    signature = sign_message(signer_key['sigModulus'], signer_key['sigPrivateExponent'], message, signer_key['keysize'])

    encrypted_message = FinCryptMessage()

    encrypted_message['key'].extend(encrypted_key)
    encrypted_message['iv'].extend(encrypted_iv)
    encrypted_message['message'] = encrypted_blocks
    encrypted_message['signature'].extend(signature)

    encoded_message = encode_der(encrypted_message)

    return encoded_message


def decrypt_and_verify(message, sender):
    """
    Decrypts and verifies a message using a sender's public key name
    Looks for the sender's public key in the public_keys/ directory.
    Looks for your private key as private_key/private.asc

    The ASN.1 specification for a FinCrypt message resides in message_asn1.py

    Raises exceptions if key files are not found, or are malformed.

    :param message: Message to decrypt (bytes)
    :param sender: Sender's public key filename (string)
    :return: Tuple (decrypted message (bytes), whether the message was verified (boolean))
    If message was unable to be decrypted, the tuple will be (None, False)
    """

    sender_key = os.path.join(PUBLIC_PATH, sender)

    if not os.path.exists(sender_key):
        raise FileNotFoundError('Sender keyfile does not exist.')

    if not os.path.exists(PRIVATE_KEY):
        raise FileNotFoundError('Private keyfile does not exist.')

    try:
        with open(PRIVATE_KEY) as f:
            decryption_key = read_private_key(f.read())
    except Exception:
        raise FinCryptDecodingError('Private key file is malformed or does not exist.')

    try:
        with open(sender_key) as f:
            sender_key = read_public_key(f.read())
    except Exception:
        raise FinCryptDecodingError('Sender key file is malformed.')

    try:
        decoded, _ = decode_ber(message, asn1Spec=FinCryptMessage())
        decoded = encode_native(decoded)
    except Exception:
        return None, False

    try:
        decrypted_message = decrypt_message(decryption_key['modulus'], decryption_key['privateExponent'],
                                            decoded['key'], decoded['iv'],
                                            decoded['message'])
    except Exception:
        decrypted_message = None

    try:
        authenticated = authenticate_message(sender_key['sigModulus'], sender_key['sigExponent'], decrypted_message,
                                             decoded['signature'])
    except Exception:
        authenticated = False

    return decrypted_message, authenticated


def encrypt_text(arguments):
    """
    Encrypts a file object when given a argparser arguments object. Not intended for use as an import.
    Outputs the resulting encrypted file as a FinCrypt message in plaintext.
    Writes resulting encrypted message to stdout.

    :param arguments: Argparser arguments object.
    :return: None
    """
    try:
        message = encrypt_and_sign(zlib.compress(arguments.infile.read()), arguments.recipient)
    except Exception as e:
        sys.stderr.write('%s\n' % e)
        sys.exit()

    message = base64.b64encode(message).decode('utf-8')

    sys.stdout.write(' BEGIN FINCRYPT MESSAGE '.center(76, '-') + '\n')
    sys.stdout.write('\n'.join([message[i:i + 76] for i in range(0, len(message), 76)]))
    sys.stdout.write('\n' + ' END FINCRYPT MESSAGE '.center(76, '-'))


def decrypt_text(arguments):
    """
    Decrypts a file object when given a argparser arguments object. Not intended for use as an import.
    Reads the file object as a FinCrypt message in plaintext.
    Writes resulting decrypted bytes to stdout.

    :param arguments: Argparser arguments object.
    :return: None
    """

    try:
        in_message = read_message(arguments.infile.read())

        in_message = ''.join(in_message.split('\n'))

        in_message = base64.b64decode(in_message)

        message, verified = decrypt_and_verify(in_message, arguments.sender)
    except Exception as e:
        sys.stderr.write('%s\n' % e)
        sys.exit()

    if message is None:
        sys.stderr.write('Decryption failed.\n')
    else:
        try:
            sys.stdout.buffer.write(zlib.decompress(message))
        except Exception:
            sys.stderr.write('Decompression failed.\n')

    if not verified:
        sys.stderr.write('Verification failed. Message is not intact.\n')


def encrypt_binary(arguments):
    """
    Encrypts a file object when given a argparser arguments object. Not intended for use as an import.
    Outputs the resulting encrypted file as a FinCrypt message in binary encoding.
    Writes resulting encrypted message to stdout.

    :param arguments: Argparser arguments object.
    :return: None
    """

    try:
        message = encrypt_and_sign(zlib.compress(arguments.infile.read()), arguments.recipient)
    except Exception as e:
        sys.stderr.write('%s\n' % e)
        sys.exit()


    sys.stdout.buffer.write(message)


def decrypt_binary(arguments):
    """
    Decrypts a file object when given a argparser arguments object. Not intended for use as an import.
    Reads the file object as a FinCrypt message in binary encoding.
    Writes resulting decrypted bytes to stdout.

    :param arguments: Argparser arguments object
    :return: None
    """

    in_message = arguments.infile.read()
    try:
        message, verified = decrypt_and_verify(in_message, arguments.sender)
    except Exception as e:
        sys.stderr.write('%s\n' % e)
        sys.exit()

    if message is None:
        sys.stderr.write('Decryption failed.\n')
    else:
        try:
            sys.stdout.buffer.write(zlib.decompress(message))
        except Exception:
            sys.stderr.write('Decompression failed.\n')

    if not verified:
        sys.stderr.write('Verification failed. Message is not intact.\n')


def enum_keys(arguments):
    """
    Enumerates all keys residing in the public_keys directory.
    Prints to stdout a formatted explanation of the key, with:
    Filename
    User Name
    Email
    Hash
    Randomart

    :param arguments: Argparser arguments object
    :return: None
    """

    key_enum = ''
    for key_file in os.listdir(PUBLIC_PATH):
        with open(os.path.join(PUBLIC_PATH, key_file)) as f:
            key_text = f.read()

        key = read_public_key(key_text)

        key_hash = sha.SHA512(key_text.encode('utf-8')).hexdigest()
        key_hash_formatted = ':'.join([key_hash[i:i + 2] for i in range(0, len(key_hash), 2)]).upper()

        # Only use the first 64 characters of the hash so it fills up less of the board.
        key_randomart = randomart.randomart(key_hash[:64], 'SHA512')

        formatted_key = f"{key_file}:\nName: {key['name'].decode('utf-8')}\nEmail: {key['email'].decode('utf-8')}" \
                        f"\nHash: {key_hash_formatted}\nKeyArt:\n{key_randomart}"

        key_enum += formatted_key + '\n\n'

    sys.stdout.write(key_enum.strip())


def main():
    """
    Parses command line arguments.
    Try fincrypt.py -h for help with arguments.

    :return: None
    """
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

    parser_encrypt_binary = subparsers.add_parser('encryptbin', aliases=['eb'],
                                                  help='Encrypt a message/file with binary encoding. '
                                                       'Provides space savings at the cost of readability.')
    parser_encrypt_binary.add_argument('recipient', type=str, default=None,
                                       help='The filename of the recipient\'s public key. '
                                            'Always defaults to the /public_keys directory.')
    parser_encrypt_binary.add_argument('infile', nargs='?', type=argparse.FileType('rb'), default=sys.stdin.buffer,
                                       help='File to encrypt. Defaults to stdin.')
    parser_encrypt_binary.set_defaults(func=encrypt_binary)

    parser_decrypt_binary = subparsers.add_parser('decryptbin', aliases=['db'],
                                                  help='Decrypt a message/file with binary encoding.')
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
