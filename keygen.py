#!/usr/bin/env python3

import sys
import os
import base64
import ecc
import qrcode
import reedsolomon
from pyasn1.codec.der.encoder import encode
from asn1spec import FinCryptPublicKey, FinCryptPrivateKey


def num_length(num):
    """
    Returns the length in digits of num

    :param num: Num
    :return: Length in digits
    """

    return len(str(num))


def gen_key_files(*, key_name, key_email):
    """
    Generates keys. Public keys contain an encryption key for messages and
    a decryption key for signatures. Private keys contain a decryption key for messages
    and an encryption key for signatures.

    :param key_name: User's name
    :param key_email: User's email
    :return: Public key string, private key string
    """

    private = ecc.ECPrivateKey.generate(ecc.CURVE)

    public = private.pubkey

    pub_key = FinCryptPublicKey()
    priv_key = FinCryptPrivateKey()

    pub_key['kx'] = public.point.x
    pub_key['ky'] = public.point.y
    pub_key['name'] = key_name
    pub_key['email'] = key_email

    priv_key['k'] = private.scalar
    priv_key['name'] = key_name
    priv_key['email'] = key_email

    pub_key_bytes = encode(pub_key)
    priv_key_bytes = encode(priv_key)

    rsc = reedsolomon.RSCodec(30)

    pub_key_bytes = bytes(rsc.encode(pub_key_bytes))

    public = base64.urlsafe_b64encode(pub_key_bytes).decode('utf-8')
    private = base64.urlsafe_b64encode(priv_key_bytes).decode('utf-8')

    public_string = ' BEGIN FINCRYPT PUBLIC KEY '.center(76, '-') + '\n'
    public_string += '\n'.join([public[i:i + 76] for i in range(0, len(public), 76)])
    public_string += '\n' + ' END FINCRYPT PUBLIC KEY '.center(76, '-')

    private_string = ' BEGIN FINCRYPT PRIVATE KEY '.center(76, '-') + '\n'
    private_string += '\n'.join([private[i:i + 76] for i in range(0, len(private), 76)])
    private_string += '\n' + ' END FINCRYPT PRIVATE KEY '.center(76, '-')

    return public_string, private_string


if __name__ == '__main__':
    print('FinCrypt Key Generation Utility')

    name = input('Please enter your name as you would like it to appear on your key.\n>>>')

    email = input('Please enter the email you wish to appear on your key.\n>>>')

    pub_file = input('Please enter the desired filename of the public key.\n'
                     'Try and make it descriptive so others can easily recognize it.\n>>>')

    priv_file = input('Please enter the desired filename of the private key.\n'
                      'Rename this key private.asc and put it into your private_key directory.\n>>>')

    print('Your key will also be saved in a QR code. You can have your friends scan this QR code'
          '\nand save it as a public key file to give them your key.')

    if os.path.exists(pub_file) or os.path.exists(priv_file):
        print('Key files already exist!')
        sys.exit()

    public_string, private_string = gen_key_files(key_name=name[:50], key_email=email[:80])

    with open(pub_file, 'w') as f:
        f.write(public_string)

    with open(priv_file, 'w') as f:
        f.write(private_string)

    qr = qrcode.QRCode(version=None,
                       error_correction=qrcode.constants.ERROR_CORRECT_H,
                       box_size=15,
                       border=10)

    qr.add_data(public_string)
    qr.make(fit=True)

    img = qr.make_image(fill_color='black', back_color='white')
    qr_filename = pub_file.rsplit('.', 1)[0] + '.png'

    img.save(qr_filename)