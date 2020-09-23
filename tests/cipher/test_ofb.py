from cryptolib.cipher import AES
from binascii import unhexlify
import pytest


test_vectors = [
    (
        '000102030405060708090a0b0c0d0e0f',
        '000102030405060708090a0b0c0d0e0f',
        '0a9509b6456bf642f9ca9e53ca5ee455bef70eb551c7be5bfb70aedc492fa673',
    ),
    (
        '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
        '000102030405060708090a0b0c0d0e0f',
        '0a9509b6456bf642f9ca9e53ca5ee455bef60cb655c2b85cf379a4d74522a87c90a3e96ad04e93aaf3b4517856f65005',
    ),
    (
        '41455320286b65792d313238626974206d6f64652d4f464229',
        '000102030405060708090a0b0c0d0e0f',
        '4bd158956905953cdcf2a660a43a9e7ac3887ac06c98e809c267b9cb5e38b164',
    ),
    (
        '000102030405060708090a0b0c0d0e0f',
        '000102030405060708090a0b0c0d0e0f1011121314151617',
        '0061bdfd42864dbfd255f3ad13ff2ea13e94db02b34907a08e35b2b22de18fcc',
    ),
    (
        '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
        '000102030405060708090a0b0c0d0e0f1011121314151617',
        '0061bdfd42864dbfd255f3ad13ff2ea13e95d901b74c01a7863cb8b921ec81c3c5b2eb5c71ce3ecdc006c6fa45a22ed2',
    ),
    (
        '41455320286b65792d313932626974206d6f64652d4f464229',
        '000102030405060708090a0b0c0d0e0f1011121314151617',
        '4125ecde6ee82ec1f76dc0947d9b548e43ebaf778e1651f2b722a5a53af698db',
    ),
    (
        '000102030405060708090a0b0c0d0e0f',
        '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
        '5a6f06540cfe7791f8275f360ecea89dddec3525211be57b3ea79ab24acd6741',
    ),
    (
        '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
        '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
        '5a6f06540cfe7791f8275f360ecea89ddded3726251ee37c36ae90b946c0694eb44e5969e42566313cf168e27651691b'
    ),
    (
        '41455320286b65792d323536626974206d6f64652d4f464229',
        '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
        '1b2b5777209014efdd1c600b60aad2b2a09341501c44b32907b08da55dda7056',
    )
]


def pad(block_size, x):
    pad_size = block_size - (len(x) % block_size)
    return x + bytes([pad_size] * pad_size)


def unpad(x):
    pad_size = x[-1]
    return x[:-pad_size]


@pytest.fixture(params=test_vectors)
def vectors(request):
    return map(unhexlify, request.param)


def test_ofb(vectors):
    plain, key, cipher = vectors
    iv = 0x000102030405060708090a0b0c0d0e0f.to_bytes(16, "big")
    aes = AES.new(key, AES.MODE_OFB, iv)
    block_size = aes.cipher_algo.block_size
    enc = aes.encrypt(pad(block_size, plain))
    dec = unpad(aes.decrypt(enc))
    assert enc == cipher
    assert dec == plain
