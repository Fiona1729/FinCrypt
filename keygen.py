#!/usr/bin/env python3

import sys
import os
import base64
import ecc
from pyasn1.codec.der.encoder import encode
from asn1spec import FinCryptPublicKey, FinCryptPrivateKey


def num_length(num):
    """
    Returns the length in digits of num

    :param num: Num
    :return: Length in digits
    """

    return len(str(num))


def gen_key_files(pub_name, priv_name, *, key_name, key_email):
    """
    Generates key files. Public keys contain an encryption key for messages and
    a decryption key for signatures. Private keys contain a decryption key for messages
    and an encryption key for signatures.

    :param pub_name: Public key filename
    :param priv_name: Private key filename
    :param key_name: User's name
    :param key_email: User's email
    :return: None
    """

    if os.path.exists(pub_name) or os.path.exists(priv_name):
        print('Key files already exist!')
        sys.exit()

    el_gamal = ecc.ElGamal(ecc.CURVE)

    public, private = el_gamal.keygen()
    sig_public, sig_private = el_gamal.keygen()

    pub_key = FinCryptPublicKey()
    priv_key = FinCryptPrivateKey()

    pub_key['kx'] = public.x
    pub_key['ky'] = public.y
    pub_key['sigk'] = sig_private
    pub_key['name'] = key_name
    pub_key['email'] = key_email

    priv_key['k'] = private
    priv_key['sigkx'] = sig_public.x
    priv_key['sigky'] = sig_public.y
    priv_key['name'] = key_name
    priv_key['email'] = key_email

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

    gen_key_files(pub_file, priv_file, key_name=name[:50], key_email=email[:80])
