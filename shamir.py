"""
The following Python implementation of Shamir's Secret Sharing is
released into the Public Domain under the terms of CC0 and OWFa:
https://creativecommons.org/publicdomain/zero/1.0/
http://www.openwebfoundation.org/legal/the-owf-1-0-agreements/owfa-1-0
"""

import random
import functools
import time
import math

from asn1spec import FinCryptMnemonicKey
from pyasn1.codec.der.encoder import encode as encode_asn1
from pyasn1.codec.native.encoder import encode as encode_native
from pyasn1.codec.ber.decoder import decode as decode_asn1

# 15th Mersenne Prime
# (for this application we want a known prime number as close as
# possible to our security level; e.g.  desired security level of 128
# bits -- too large and all the ciphertext is large; too small and
# security is compromised)
_PRIME = 2**1279 - 1
# Make it this big so the secret can be up to 1279 bits

_RINT = functools.partial(random.SystemRandom().randint, 0)


def _eval_at(poly, x, prime):
    """evaluates polynomial (coefficient tuple) at x, used to generate a
    shamir pool in _make_shares below.
    """
    accum = 0
    for coeff in reversed(poly):
        accum *= x
        accum += coeff
        accum %= prime
    return accum


def _make_shares(secret, minimum, shares, prime=_PRIME):
    """
    Generates a shamir pool, returns the share
    points.
    """
    if minimum > shares:
        raise ValueError("pool secret would be irrecoverable")
    poly = [secret] + [_RINT(prime) for _ in range(minimum - 1)]
    points = [(i, _eval_at(poly, i, prime))
              for i in range(1, shares + 1)]
    return points


def _extended_gcd(a, b):
    """
    division in integers modulus p means finding the inverse of the
    denominator modulo p and then multiplying the numerator by this
    inverse (Note: inverse of A is B such that A*B % p == 1) this can
    be computed via extended Euclidean algorithm
    http://en.wikipedia.org/wiki/Modular_multiplicative_inverse#Computation
    """
    x = 0
    last_x = 1
    y = 1
    last_y = 0
    while b != 0:
        quot = a // b
        a, b = b, a % b
        x, last_x = last_x - quot * x, x
        y, last_y = last_y - quot * y, y
    return last_x, last_y


def _divmod(num, den, p):
    """compute num / den modulo prime p

    To explain what this means, the return value will be such that
    the following is true: den * _divmod(num, den, p) % p == num
    """
    inv, _ = _extended_gcd(den, p)
    return num * inv


def _lagrange_interpolate(x, x_s, y_s, p):
    """
    Find the y-value for the given x, given n (x, y) points;
    k points will define a polynomial of up to kth order
    """
    k = len(x_s)
    assert k == len(set(x_s))
    
    def product(vals):  # product of inputs
        accum = 1
        for v in vals:
            accum *= v
        return accum
    nums = []  # avoid inexact division
    dens = []
    for i in range(k):
        others = list(x_s)
        cur = others.pop(i)
        nums.append(product(x - o for o in others))
        dens.append(product(cur - o for o in others))
    den = product(dens)
    num = sum([_divmod(nums[i] * den * y_s[i] % p, dens[i], p)
               for i in range(k)])
    return (_divmod(num, den, p) + p) % p


def _recover_secret(shares, prime=_PRIME):
    """
    Recover the secret from share points
    (x,y points on the polynomial)
    """
    if len(shares) < 2:
        raise ValueError("need at least two shares")
    x_s, y_s = zip(*shares)
    return _lagrange_interpolate(0, x_s, y_s, prime)


def encode_share(share, minimum, shares, timestamp):
    # Encodes
    x, y = share

    share_asn1 = FinCryptMnemonicKey()

    share_asn1['x'] = x
    share_asn1['y'] = y
    share_asn1['n'] = minimum
    share_asn1['k'] = shares
    share_asn1['uuid'] = timestamp

    share_bytes = encode_asn1(share_asn1)

    return share_bytes


def decode_share(share_bytes):
    share, _ = decode_asn1(share_bytes, asn1Spec=FinCryptMnemonicKey())
    return encode_native(share)


def split_secret(secret, minimum, num_shares):
    secret = int.from_bytes(secret, byteorder='little')

    shares = _make_shares(secret=secret, minimum=minimum, shares=num_shares)

    timestamp = round(time.time())

    encoded_shares = []

    for share in shares:
        encoded_shares.append(encode_share(share, minimum, num_shares, timestamp))

    return encoded_shares


def recover_secret(share_list):
    shares = [decode_share(share) for share in share_list]

    # Checks to see if all items in list are identical
    def same(items):
        return all([x == items[0] for x in items])

    # Make sure all shares UUIDs are identical
    assert same(list(map(lambda x: x['uuid'], shares)))

    assert same(list(map(lambda x: x['n'], shares)))

    assert same(list(map(lambda x: x['k'], shares)))

    # Return tuples of x, y values for our _recover_secret function
    shares = list(map(lambda k: (k['x'], k['y']), shares))

    secret_int = _recover_secret(shares)

    return int.to_bytes(secret_int, byteorder='little', length=math.ceil(secret_int.bit_length() / 8))


def split_key(args):
    input_key = args.keyfile.read()

    if args.n > args.k:
        sys.stderr.write("Can't possibly recover key with given n and k!")
        sys.exit()

    try:
        headerless = strip_headers(input_key)
        key_bytes = urlsafe_b64decode(headerless[1])
    except Exception:
        sys.stderr.write('Improperly formatted key!')
        sys.exit()

    try:
        encoded_shares = split_secret(key_bytes, args.n, args.k)
    except Exception:
        sys.stderr.write('Could not split key!')
        sys.exit()

    try:
        printable_shares = [mnemonic_encode(share) for share in encoded_shares]
        sys.stdout.write('\n\n'.join(printable_shares))
    except Exception:
        sys.stderr.write('Could not mnemonically encode shares!')
        sys.exit()


def recover_key(args):
    shares = []

    first_share = input('Please enter the mnemonic phrase for your first share\n>>>')

    shares.append(first_share)
    try:
        num_required = decode_share(mnemonic_decode(first_share))['n'] - 1
    except Exception:
        sys.stderr.write('Corrupted share!')
        sys.exit()

    while num_required > 0:
        shares.append(input('\nPlease enter the mnemonic phrase for another share.\n'
                            'There are %s shares left to enter.\n>>>' % num_required).strip(' \t'))
        num_required -= 1

    try:
        secret = recover_secret(list([mnemonic_decode(share) for share in shares]))
        secret_encoded = urlsafe_b64encode(secret).decode('utf-8')
    except Exception:
        sys.stderr.write('Invalid shares!')
        sys.exit()
    sys.stdout.write(' BEGIN FINCRYPT PRIVATE KEY '.center(76, '-') + '\n')
    sys.stdout.write('\n'.join([secret_encoded[i:i + 76] for i in range(0, len(secret_encoded), 76)]))
    sys.stdout.write('\n' + ' END FINCRYPT PRIVATE KEY '.center(76, '-'))


if __name__ == '__main__':
    import argparse
    import sys
    from base64 import urlsafe_b64decode, urlsafe_b64encode

    from mnemonic import mnemonic_encode, mnemonic_decode
    from fincrypt import strip_headers

    parser = argparse.ArgumentParser(description='Split a FinCrypt private key into k secrets, of which n'
                                                 'are required to get the FinCrypt key back')
    parser.set_defaults(func=None)
    subparsers = parser.add_subparsers(title='sub-commands', description='Splitting and recovering sub-commmands')

    parser_split = subparsers.add_parser('split', aliases=['s'], help='Split a key.')
    parser_split.add_argument('-n', type=int, default=3, help='The number of secrets required to get the FinCrypt private key back')
    parser_split.add_argument('-k', type=int, default=6, help='The number of total secrets to generate.')
    parser_split.add_argument('keyfile', type=argparse.FileType('r'), help='The filename of the FinCrypt private key')
    parser_split.set_defaults(func=split_key)

    parser_recover = subparsers.add_parser('recover', aliases=['r'], help='Recover a key.')
    parser_recover.set_defaults(func=recover_key)

    args = parser.parse_args()

    if args.func is None:
        parser.print_help()
        sys.exit()

    args.func(args)
