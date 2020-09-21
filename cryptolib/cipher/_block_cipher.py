from __future__ import annotations
from typing import overload, TYPE_CHECKING
from cryptolib.cipher._ecb import ECBMode
from cryptolib.cipher._cbc import CBCMode
from cryptolib.cipher._block_common import (
    MODE_ECB,
    MODE_CBC
)


if TYPE_CHECKING:
    from cryptolib.cipher._block_common import BlockCipherAlgo, BlockCipherMode


@overload
def create_cipher(key: bytes, algo: BlockCipherAlgo, mode: int, iv: bytes) -> BlockCipherMode:
    if mode == MODE_CBC:
        return CBCMode(key, algo, iv)
    raise ValueError('Invalid mode')


def create_cipher(key: bytes, algo: BlockCipherAlgo, mode: int) -> BlockCipherMode:
    if mode == MODE_ECB:
        return ECBMode(key, algo)
    raise ValueError('Invalid mode')
