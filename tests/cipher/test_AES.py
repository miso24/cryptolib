from cryptolib.cipher import AES
from binascii import hexlify, unhexlify
import pytest


test_vectors = [
    # FIPS 197, Advanced Encryption Standard
    # https://csrc.nist.gov/csrc/media/publications/fips/197/final/documents/fips-197.pdf
    (
        '00112233445566778899aabbccddeeff',
        '000102030405060708090a0b0c0d0e0f',
        '69c4e0d86a7b0430d8cdb78070b4c55a',
    ),
    (
        '00112233445566778899aabbccddeeff',
        '000102030405060708090a0b0c0d0e0f1011121314151617',
        'dda97ca4864cdfe06eaf70a0ec0d7191',
    ),
    (
        '00112233445566778899aabbccddeeff',
        '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
        '8ea2b7ca516745bfeafc49904b496089',
    )
]


@pytest.mark.parametrize(('plain', 'key', 'cipher'), test_vectors)
def test_AES(plain, key, cipher):
    plain, key, cipher = map(unhexlify, [plain, key, cipher])
    enc = AES.encrypt(plain, key)
    dec = AES.decrypt(enc, key)
    assert enc == cipher
    assert dec == plain
