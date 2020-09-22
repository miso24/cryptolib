from cryptolib.cipher import AES
from binascii import hexlify, unhexlify
import pytest


test_vectors = [
    (
        '000102030405060708090a0b0c0d0e0f',
        '000102030405060708090a0b0c0d0e0f',
        'c6a13b37878f5b826f4f8162a1c8d879b1a29273be2c4207a5ace393398cb6fb',
    ),
    (
        '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
        '000102030405060708090a0b0c0d0e0f',
        'c6a13b37878f5b826f4f8162a1c8d87935d9dcdb829fec3352e7bf10b84be4a5d866f9cc6e02819e2d216105f43c2f6f',
    ),
    (
        '41455320286b65792d313238626974206d6f64652d43424329',
        '000102030405060708090a0b0c0d0e0f',
        '60f8ba09639f2b0cd1359a0a00d0eff8b114fb17466d74b7e7b2ba7c2910ceaa',
    ),
    (
        '000102030405060708090a0b0c0d0e0f',
        '000102030405060708090a0b0c0d0e0f1011121314151617',
        '916251821c73a522c396d627380196075f9d65297404307e9497f45625d5fd48',
    ),
    (
        '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
        '000102030405060708090a0b0c0d0e0f1011121314151617',
        '916251821c73a522c396d627380196071817db150e771c589ed080493de7338b87f9fdefebbf43c0a38325a4c7d4fee4',
    ),
    (
        '41455320286b65792d313932626974206d6f64652d43424329',
        '000102030405060708090a0b0c0d0e0f1011121314151617',
        '40af9b508e631348e991fb77ea565de01fbdd3131528a3b1f245ba58c3e7b719'
    ),
    (
        '000102030405060708090a0b0c0d0e0f',
        '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
        'f29000b62a499fd0a9f39a6add2e778053c8742d0ea29b2712f6c7af4048f4b4',
    ),
    (
        '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
        '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
        'f29000b62a499fd0a9f39a6add2e77809543b86fc046fa883a9446b82e47d12d371a2690c225b574ad74b7066f379d8d',
    ),
    (
        '41455320286b65792d323536626979206d6f64652d43424329',
        '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
        '8b2f54dce1d6a4dceeb276e379e525cded0e15db50a6f72b82a156ae811e624e',
    )
]


@pytest.fixture(params=test_vectors)
def vectors(request):
    return map(unhexlify, request.param)


def pad(block_size, x):
    pad_size = block_size - (len(x) % block_size)
    return x + bytes([pad_size] * pad_size)


def unpad(x):
    pad_size = x[-1]
    return x[:-pad_size]


def test_cbc(vectors):
    plain, key, cipher = vectors
    iv = unhexlify('000102030405060708090a0b0c0d0e0f')
    aes = AES.new(key, AES.MODE_CBC, iv=iv)
    block_size = aes.cipher_algo.block_size
    enc = aes.encrypt(pad(block_size, plain))
    dec = unpad(aes.decrypt(enc))
    assert enc == cipher
    assert dec == plain
