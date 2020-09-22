from __future__ import annotations
from cryptolib.cipher._block_common import BlockCipherMode, split_block
from cryptolib.util.binary import xor_bytes
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from cryptolib.cipher._block_common import BlockCipherAlgo


class CBCMode(BlockCipherMode):
    def __init__(self, key: bytes, cipher_algo: BlockCipherAlgo, iv: bytes) -> None:
        super().__init__(key, cipher_algo)
        self.iv = iv

    def encrypt(self, plain: bytes) -> bytes:
        rslt = b''
        tmp = self.iv
        for block in split_block(plain, self.cipher_algo):
            block = xor_bytes(block, tmp)
            tmp = self.cipher_algo.encrypt(block, self.key)
            rslt += tmp
        return rslt

    def decrypt(self, cipher: bytes) -> bytes:
        rslt = b''
        tmp = self.iv
        for block in split_block(cipher, self.cipher_algo):
            dec = self.cipher_algo.decrypt(block, self.key)
            rslt += xor_bytes(tmp, dec)
            tmp = block
        return rslt
