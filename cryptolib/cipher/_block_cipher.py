from __future__ import annotations
from typing import TYPE_CHECKING
from cryptolib.cipher._ecb import ECBMode
from cryptolib.cipher._cbc import CBCMode
from cryptolib.cipher._ofb import OFBMode
from cryptolib.cipher._cfb import CFBMode
from cryptolib.cipher._block_common import (
    MODE_ECB,
    MODE_CBC,
    MODE_OFB,
    MODE_CFB,
)


if TYPE_CHECKING:
    from cryptolib.cipher._block_common import BlockCipherAlgo, BlockCipherMode


def create_cipher(key: bytes, algo: BlockCipherAlgo, mode: int, iv: bytes = None) -> BlockCipherMode:
    iv = b'\x00' * algo.block_size if iv is None else iv
    if mode == MODE_ECB:
        return ECBMode(key, algo)
    elif mode == MODE_CBC:
        return CBCMode(key, algo, iv)
    elif mode == MODE_OFB:
        return OFBMode(key, algo, iv)
    elif mode == MODE_CFB:
        return CFBMode(key, algo, iv)
    raise ValueError('Invalid mode')
