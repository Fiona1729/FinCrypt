import random
import sys
import os
import string
import base64
from pyasn1.codec.der.encoder import encode
from asn1spec import FinCryptPublicKey, FinCryptPrivateKey

BASE64_LITERALS = string.ascii_uppercase + string.ascii_lowercase + string.digits + '+='

sysrandom = random.SystemRandom()


def gcd(a, b):
    """
    Calculates the GCD of two numbers using Euclid's algorithm.

    :param a: A
    :param b: B
    :return: GCD
    """

    while a != 0:
        a, b = b % a, a
    return b


def modinv(a, m):
    """
    Calculates the modular inverse of a and m using Euclid's extended algorithm

    :param a: A
    :param m: M
    :return: Modular inverse if it exists, None otherwise.
    """

    if gcd(a, m) != 1:
        return None  # If a and m aren't coprime, there is no mod inverse

    u1, u2, u3 = 1, 0, a
    v1, v2, v3 = 0, 1, m
    while v3 != 0:
        q = u3 // v3
        v1, v2, v3, u1, u2, u3 = (u1 - q * v1), (u2 - q * v2), (u3 - q * v3), v1, v2, v3
    return u1 % m


def rabin_miller(p):
    """
    Fast Rabin Miller primality test.

    :param p: The number to test for primality
    :return: Whether the number is prime with a great degree of certainty
    """

    if p < 2:  # Less than two means number is prime
        return False
    if p != 2 and p % 2 == 0:  # Divisible by two means number is prime.
        return False
    s = p - 1
    while s % 2 == 0:
        s >>= 1
    for x in range(10):
        a = sysrandom.randrange(p - 1) + 1
        t = s
        m = pow(a, t, p)
        while t != p - 1 and m != 1 and m != p - 1:
            m = (m * m) % p
            t = t * 2
        if m != p - 1 and t % 2 == 0:
            return False
    return True


def prime(p):
    """
    Returns whether a number is prime to a great degree of certainty.
    Performs smaller checks before calling rabin_miller

    :param p: Number to test
    :return: Whether p is prime
    """

    if (p < 2):
        return False

    primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103,
              107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223,
              227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347,
              349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463,
              467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607,
              613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743,
              751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883,
              887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997]

    if p in primes:
        return True

    for prime in primes:
        if (p % prime == 0):
            return False

    return rabin_miller(p)


def gen_prime(prime_size=4096):
    """
    Returns a random prime number of key_size bits

    :param prime_size: Prime number size
    :return: Number
    """

    while True:
        num = sysrandom.randrange(2 ** (prime_size - 1), 2 ** (prime_size))
        if prime(num):
            return num


def gen_key(key_size):
    """
    Generates an RSA encryption and decryption keypair.

    :param key_size: Key size in bits. RSA doesn't work when encrypting numbers with over key_size bits.
    :return: Tuple of tuples ((n, e), (n, d))
    """

    # Generate N, our modulus.
    print('Generating P prime')
    p = gen_prime(key_size)
    print('Generating Q prime')
    q = gen_prime(key_size)
    n = p * q

    # Find a number that is coprime with PHI(n)
    # PHI(n) == (p - 1) * (q - 1)
    # This is encryption exponent
    print('Finding E that is coprime with PHI(p * q)')
    while True:
        e = random.randrange(2 ** (key_size - 1), 2 ** (key_size))
        if gcd(e, (p - 1) * (q - 1)) == 1:
            break

    # Find the decryption exponent, which is the mod inverse of e and PHI(n)
    print('Finding D that is mod inverse of e and PHI(p * q)')
    d = modinv(e, (p - 1) * (q - 1))

    return n, e, d, p, q


def encode_string(string):
    """
    Encodes a string into base64

    :param string: String
    :return: Encoded string
    """
    return base64.b64encode(string.encode('utf-8')).decode('utf-8')


def num_length(num):
    """
    Returns the length in digits of num

    :param num: Num
    :return: Length in digits
    """

    return len(str(num))


def gen_key_files(pub_name, priv_name, key_size, *, name, email):
    """
    Generates key files. Public keys contain an encryption key for messages and
    a decryption key for signatures. Private keys contain a decryption key for messages
    and an encryption key for signatures.

    :param pub_name: Public key filename
    :param priv_name: Private key filename
    :param key_size: Keysize in bits
    :param name: User's name
    :param email: User's email
    :return: None
    """

    if os.path.exists(pub_name) or os.path.exists(priv_name):
        print('Key files already exist!')
        sys.exit()

    print('Generating message encryption keypair')
    n, e, d, p, q = gen_key(key_size)

    print('Generating message signing keypair')
    sign, sige, sigd, sigp, sigq = gen_key(key_size)

    pub_key = FinCryptPublicKey()
    priv_key = FinCryptPrivateKey()

    print('The public key is 4 numbers with %s, %s, %s, and %s digits.' % (num_length(n),
                                                                           num_length(e),
                                                                           num_length(sign),
                                                                           num_length(sigd)))

    pub_key['keysize'] = key_size
    pub_key['modulus'] = n
    pub_key['exponent'] = e
    pub_key['sigModulus'] = sign
    pub_key['sigExponent'] = sigd
    pub_key['name'] = name
    pub_key['email'] = email

    priv_key['keysize'] = key_size
    priv_key['modulus'] = n
    priv_key['publicExponent'] = e
    priv_key['privateExponent'] = d
    priv_key['primeP'] = p
    priv_key['primeQ'] = q
    priv_key['sigModulus'] = sign
    priv_key['sigPublicExponent'] = sigd
    priv_key['sigPrivateExponent'] = sige
    priv_key['sigPrimeP'] = sigp
    priv_key['sigPrimeQ'] = sigq
    priv_key['name'] = name
    priv_key['email'] = email

    pub_key_bytes = encode(pub_key)
    priv_key_bytes = encode(priv_key)

    public = base64.b64encode(pub_key_bytes).decode('utf-8')
    private = base64.b64encode(priv_key_bytes).decode('utf-8')

    with open(pub_name, 'w') as f:
        f.write(' BEGIN FINCRYPT PUBLIC KEY '.center(76, '-') + '\n')
        f.write('\n'.join([public[i:i + 76] for i in range(0, len(public), 76)]))
        f.write('\n' + ' END FINCRYPT PUBLIC KEY '.center(76, '-'))

    with open(priv_name, 'w') as f:
        f.write(' BEGIN FINCRYPT PRIVATE KEY '.center(76, '-') + '\n')
        f.write('\n'.join([private[i:i + 76] for i in range(0, len(private), 76)]))
        f.write('\n' + ' END FINCRYPT PRIVATE KEY '.center(76, '-'))


if __name__ == '__main__':
    print('FinCrypt Key Generation Utility')

    name = input('Please enter your name as you would like it to appear on your key.\n>>>')

    email = input('Please enter the email you wish to appear on your key.\n>>>')

    pub_file = input('Please enter the desired filename of the public key.\n'
                     'Try and make it descriptive so others can easily recognize it.\n>>>')

    priv_file = input('Please enter the desired filename of the private key.\n'
                      'Rename this key private.asc and put it into your private_key directory.\n>>>')

    print('\nBeginning key generation\n\n')

    gen_key_files(pub_file, priv_file, 4096, name=name[:50], email=email[:80])
