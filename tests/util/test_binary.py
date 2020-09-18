from cryptolib.util import binary
import pytest


@pytest.mark.parametrize(('_long', '_bytes'), [
    (0x30, b'0'),
    (0x4142434445464748, b'ABCDEFGH'),
    (0x48656c6c6f2c576f726c6421, b'Hello,World!'),
    (0xe38193e38293e381abe381a1e381afe4b896e7958c,
     b'\xe3\x81\x93\xe3\x82\x93\xe3\x81\xab\xe3\x81\xa1\xe3\x81\xaf\xe4\xb8\x96\xe7\x95\x8c')
])
def test_convert_long_bytes(_long, _bytes):
    assert _long == binary.bytes2long(_bytes)
    assert _bytes == binary.long2bytes(_long)


@pytest.mark.parametrize(('_hex_prefix', '_hex', '_bytes'), [
    ('0x30', '30', b'0'),
    ('0x41414141', '41414141', b'AAAAA'),
    ('0x48656c6c6f2c576f726c6421', '48656c6c6f2c576f726c6421', b'Hello,World!')
])
def test_convert_hex_bytes(_hex_prefix, _hex, _bytes):
    assert binary.hex2bytes(_hex_prefix) == _bytes
    assert binary.hex2bytes(_hex) == _bytes
