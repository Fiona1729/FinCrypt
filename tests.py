import fincrypt
import io
import os
from random import SystemRandom

random = SystemRandom()

PUBLIC_KEY = io.StringIO("""------------------------ BEGIN FINCRYPT PUBLIC KEY -------------------------
MIG2AkIBpDXwvZYy4rfyR+mK7Ltq778PSeUFEMt4wGS8sCOrRv23nKOoaeDqooxUUqUz32agTX8T
2PEb6XK+SAomCR3kQdsCQgEyD+BlVsS3k73ArkWQbPJEV0Voo+7GdNyECdynKfPXJxSGayNUM+dt
OxU3L5fnG+0Fpl+ToMXkybRIintGU54y+QwPRmluaWFuIEJsYWNrZXR0DBtzcGFtc3Vja2Vyc3Vu
aXRlZEBnbWFpbC5jb20=
------------------------- END FINCRYPT PUBLIC KEY --------------------------""")

PRIVATE_KEY = io.StringIO("""------------------------ BEGIN FINCRYPT PRIVATE KEY ------------------------
MHECQWsqbjjiIL+Zx4Z7UV51zYLcxGpYt8mQJ8LyXi02HWTS/StBlqUOWaFL70NFWPXmmN0kI4h2
9ACHiFN2vgl1QsyFDA9GaW5pYW4gQmxhY2tldHQMG3NwYW1zdWNrZXJzdW5pdGVkQGdtYWlsLmNv
bQ==
------------------------- END FINCRYPT PRIVATE KEY -------------------------""")


def test_encrypt(message: bytes):
    encrypted = fincrypt.encrypt_and_sign(message, PUBLIC_KEY, PRIVATE_KEY)
    PUBLIC_KEY.seek(0)
    PRIVATE_KEY.seek(0)
    return encrypted


def test_decrypt(message: bytes):
    decrypted, verified = fincrypt.decrypt_and_verify(message, PUBLIC_KEY, PRIVATE_KEY)
    PUBLIC_KEY.seek(0)
    PRIVATE_KEY.seek(0)
    return decrypted, verified


if __name__ == '__main__':
    for i in range(64):
        print(i)
        plaintext = os.urandom(random.randint(1, 2000))
        encrypted = test_encrypt(plaintext)
        decrypted = test_decrypt(encrypted)
        assert plaintext == decrypted[0] and decrypted[1]
    print('Done')
