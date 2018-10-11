import fincrypt
import io
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
    try:
        message = fincrypt.encrypt_and_sign(message, PUBLIC_KEY, PRIVATE_KEY)

if __name__ == '__main__':