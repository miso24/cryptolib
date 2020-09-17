from cryptolib.cipher import DES
from binascii import unhexlify
import pytest


test_vectors = [
    (
        '0001020304050607',
        '0001020304050607',
        'e1b246e5a7c74cbc',
    ),
    (
        '08090a0b0c0d0e0f',
        '08090a0b0c0d0e0f',
        '51755e9f3435ae99',
    ),
    (
        '4142434445464748',
        '0001020304050607',
        '09f36c50507f0d7c',
    )
]


@pytest.mark.parametrize(('plain', 'key', 'cipher'), test_vectors)
def test_DES(plain, key, cipher):
    plain, key, cipher = map(unhexlify, [plain, key, cipher])
    enc = DES.encrypt(plain, key)
    dec = DES.decrypt(enc, key)
    assert enc == cipher
    assert dec == plain
