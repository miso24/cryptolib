from __future__ import annotations
from typing import overload, TYPE_CHECKING

if TYPE_CHECKING:
    from cryptolib.cipher._block_common import BlockCipherAlgo, BlockCipherMode


@overload
def create_cipher(key: bytes, algo: BlockCipherAlgo, mode: int) -> BlockCipherMode:
    pass


@overload
def create_cipher(key: bytes, algo: BlockCipherAlgo, mode: int, iv: bytes) -> BlockCipherMode:
    pass
