import fincrypt
import io
import os
import keygen
from random import SystemRandom

random = SystemRandom()


def test_encrypt(message: bytes, public_key, private_key):
    encrypted = fincrypt.encrypt_and_sign(message, public_key, private_key)
    public_key.seek(0)
    private_key.seek(0)
    return encrypted


def test_decrypt(message: bytes, public_key, private_key):
    decrypted, verified = fincrypt.decrypt_and_verify(message, public_key, private_key)
    public_key.seek(0)
    private_key.seek(0)
    return decrypted, verified


if __name__ == '__main__':
    for i in range(32):
        public_key, private_key = keygen.gen_key_files(key_name='Fin', key_email='example@example.com')
        public_key = io.StringIO(public_key)
        private_key = io.StringIO(private_key)
        for j in range(4):
            print('Key %s, message %s, total test number: %s' % (i + 1, j + 1, i * 4 + j + 1))
            plaintext = os.urandom(random.randint(1, 2000))
            encrypted = test_encrypt(plaintext, public_key, private_key)
            decrypted = test_decrypt(encrypted, public_key, private_key)
            assert plaintext == decrypted[0] and decrypted[1]
    print('Done')
