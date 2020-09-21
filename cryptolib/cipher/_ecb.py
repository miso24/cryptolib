from __future__ import annotations
from typing import TYPE_CHECKING
from cryptolib.cipher._block_common import BlockCipherMode, split_block


if TYPE_CHECKING:
    from cryptolib.cipher._block_common import BlockCipherAlgo


class ECBMode(BlockCipherMode):
    def __init__(self, key: bytes, cipher_algo: BlockCipherAlgo) -> None:
        super().__init__(key, cipher_algo)

    def encrypt(self, plain: bytes) -> bytes:
        rslt = b''
        for block in split_block(plain, self.cipher_algo):
            rslt += self.cipher_algo.encrypt(block, self.key)
        return rslt

    def decrypt(self, cipher: bytes) -> bytes:
        rslt = b''
        for block in split_block(cipher, self.cipher_algo):
            rslt += self.cipher_algo.decrypt(block, self.key)
        return rslt
