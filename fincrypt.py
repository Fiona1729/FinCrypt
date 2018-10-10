#!/usr/bin/env python3

import sha
import traceback
import sys
import os
import argparse
import base64
import zlib
import randomart
import re
import ecc
import hashlib
from asn1spec import FinCryptPublicKey, FinCryptPrivateKey, FinCryptMessage
from pyasn1.codec.ber.decoder import decode as decode_ber
from pyasn1.codec.native.encoder import encode as encode_native
from pyasn1.codec.der.encoder import encode as encode_der
from aes import Decrypter, Encrypter, AESModeOfOperationCBC


BASE_PATH = os.path.dirname(__file__)
PUBLIC_PATH = os.path.join(BASE_PATH, 'public_keys')
PRIVATE_KEY = os.path.join(BASE_PATH, 'private_key', 'private.asc')

_flatten = lambda l: [item for sublist in l for item in sublist]

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


def sign_number(k, num):
    """
    Sign a number using ECDSA.
    Number must have a lower bit length than ecc.CURVE.n

    :param k: ECC Private key scalar (int)
    :param num: Number to sign (int)
    :return: Tuple(r (int), s (int))
    """
    
    dsa = ecc.ECDSA(ecc.CURVE)

    return dsa.sign(num, ecc.ECPrivateKey(k, ecc.CURVE))


def validate_number(kx, ky, r, s, num):
    """
    Validate an r and an s using ECDSA

    :param kx: Public key kx (int)
    :param ky: Public key ky (int)
    :param r: r value of signature (int)
    :param s: s value of signature (int)
    :param num: Number value to validate (int)
    :return: Whether signature is valid (bool)
    """

    dsa = ecc.ECDSA(ecc.CURVE)

    return dsa.validate(r, s, num, ecc.ECPublicKey(ecc.AffineCurvePoint(kx, ky, ecc.CURVE)))


def encrypt_message(kx, ky, message):
    """
    Encrypts a message using ECC and AES-256
    First generates a random AES key and IV with os.urandom()
    Then encrypts the original message with that key
    Then encrypts the AES key with the RSA key

    NOTE:
    This means that plaintext will not have the same ciphertext
    when encrypted twice. Keep this in mind if you require reproducibility behavior

    :param kx: Public key kx (int)
    :param ky: Public key ky (int)
    :param message: Message (bytes)
    :return: Tuple (encrypted key (list of ints), encrypted IV (list of ints),
    and encrypted message (bytes))
    """

    encrypted_key = []
    encrypted_iv = []

    eis = ecc.ECEIS(ecc.CURVE)

    r, key_point = eis.exchange(ecc.ECPublicKey(ecc.AffineCurvePoint(kx, ky, ecc.CURVE)))

    key = hashlib.pbkdf2_hmac('sha256', get_bytes([int(key_point.x)]) + get_bytes([int(key_point.y)]), b'fincrypt', 1000000, 32 + 16)
    
    message_encryptor = Encrypter(mode=AESModeOfOperationCBC(key=key[:32], iv=key[32:]))

    encrypted_blocks = message_encryptor.feed(message)

    encrypted_blocks += message_encryptor.feed()

    encrypted_key = [int(r.x), int(r.y)]
    
    return encrypted_key, encrypted_blocks


def decrypt_message(k, encrypted_key, encrypted_message):
    """
    Decrypts a message encrypted by the encrypt_message function
    First decrypts the AES key and IV using ECC
    Then decrypts the data using the AES key and IV

    :param k: Private key k
    :param encrypted_key: ECC encrypted key (list of of ints)
    :param encrypted_iv: ECC encrypted IV (list of ints)
    :param encrypted_message: AES encrypted data (bytes
    :return: Decrypted data (bytes)
    """
    eis = ecc.ECEIS(ecc.CURVE)
    
    key_point = eis.recover(ecc.AffineCurvePoint(encrypted_key[0], encrypted_key[1], ecc.CURVE), ecc.ECPrivateKey(k, ecc.CURVE))

    key = key = hashlib.pbkdf2_hmac('sha256', get_bytes([int(key_point.x)]) + get_bytes([int(key_point.y)]), b'fincrypt', 1000000, 32 + 16)

    message_decryptor = Decrypter(mode=AESModeOfOperationCBC(key[:32], iv=key[32:]))

    decrypted_message = message_decryptor.feed(encrypted_message)
    decrypted_message += message_decryptor.feed()

    return decrypted_message


def sign_message(k, message):
    """
    Signs a message using an RSA signature private key (n and e), a message,

    Computes SHA512 hash of plaintext, and then encrypts it with private key

    :param k: ECC key k
    :param message: Message to sign (bytes)
    :return: Signature (list of ints)
    """

    message_hash = sha.SHA512(message).digest()

    block = get_blocks(message_hash, 1024)

    return sign_number(k, block[0])


def authenticate_message(kx, ky, plaintext, signature):
    """
    Authenticates a message when given a plaintext and signature

    Decrypts hash with public key, and compares alleged hash with actual
    hash of plaintext.

    :param kx: ECC Public key kx
    :param ky: ECC Public key ky
    :param plaintext: Decrypted plaintext to verify (bytes)
    :param signature: The signature (list of ints)
    :return: Whether the message signature is valid (boolean)
    """

    message_hash = sha.SHA512(plaintext).digest()

    block = get_blocks(message_hash, 1024)

    return validate_number(kx, ky, signature[0], signature[1], block[0])


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

    The ASN.1 specification for a FinCrypt public key resides in asn1spec.py

    :param key_text: Key text (string)
    :return: Dictionary of all key ASN.1 values
    """

    key_header, key_text = strip_headers(key_text)

    if key_header is None or key_header != 'BEGIN FINCRYPT PUBLIC KEY':
        raise ValueError

    b64_decoded = base64.urlsafe_b64decode(key_text.encode('utf-8'))
    key, _ = decode_ber(b64_decoded, asn1Spec=FinCryptPublicKey())
    key = encode_native(key)

    return {'kx': key['kx'], 'ky': key['ky'], 'name': key['name'], 'email': key['email']}


def read_private_key(key_text):
    """
    Reads a FinCrypt private key. Returns a dictionary of all usable private key values.
    Raises an exception if key is malformed or unreadable.

    The ASN.1 specification for a FinCrypt private key resides in asn1spec.py

    :param key_text: Key text (string)
    :return: Dictionary of all key ASN.1 values except for primes P and Q
    """

    key_header, key_text = strip_headers(key_text)

    if key_header is None or key_header != 'BEGIN FINCRYPT PRIVATE KEY':
        raise ValueError

    b64_decoded = base64.urlsafe_b64decode(key_text.encode('utf-8'))
    key, _ = decode_ber(b64_decoded, asn1Spec=FinCryptPrivateKey())
    key = encode_native(key)

    return {'k': key['k'], 'name': key['name'], 'email': key['email']}


def encrypt_and_sign(message, recipient):
    """
    Encrypts and signs a message using a recipient's public key name
    Looks for the recipient's public key in the public_keys/ directory.
    Looks for your private key as private_key/private.asc

    The ASN.1 specification for a FinCrypt message resides in asn1spec.py

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

    encrypted_key, encrypted_blocks = encrypt_message(recipient_key['kx'], recipient_key['ky'],
                                                                    message)
    signature = sign_message(signer_key['k'], message)

    encrypted_message = FinCryptMessage()

    encrypted_message['message'] = encrypted_blocks
    encrypted_message['key'].extend(encrypted_key)
    encrypted_message['signature'].extend(signature)

    encoded_message = encode_der(encrypted_message)

    return encoded_message


def decrypt_and_verify(message, sender):
    """
    Decrypts and verifies a message using a sender's public key name
    Looks for the sender's public key in the public_keys/ directory.
    Looks for your private key as private_key/private.asc

    The ASN.1 specification for a FinCrypt message resides in asn1spec.py

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
        decrypted_message = decrypt_message(decryption_key['k'],
                                            decoded['key'], decoded['message'])
    except Exception as e:
        raise e
        decrypted_message = None
        
    try:
        authenticated = authenticate_message(sender_key['kx'], sender_key['ky'], decrypted_message,
                                             decoded['signature'])
    except Exception as e:
        raise e
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
        message = encrypt_and_sign(zlib.compress(arguments.infile.read(), level=9), arguments.recipient)
    except Exception as e:
        raise e
        sys.stderr.write('%s\n' % str(e))
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
        message = encrypt_and_sign(zlib.compress(arguments.infile.read(), level=9), arguments.recipient)
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
    message, verified = decrypt_and_verify(in_message, arguments.sender)

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
