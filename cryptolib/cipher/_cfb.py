from __future__ import annotations
from cryptolib.cipher._block_common import BlockCipherMode, split_block
from cryptolib.util.binary import xor_bytes
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from cryptolib.cipher._block_common import BlockCipherAlgo


class CFBMode(BlockCipherMode):
    def __init__(self, key: bytes, cipher_algo: BlockCipherAlgo, iv: bytes) -> None:
        super().__init__(key, cipher_algo)
        self.iv = iv

    def encrypt(self, plain: bytes) -> bytes:
        rslt = b''
        x = self.iv
        for m in plain:
            ci = bytes([m ^ self.cipher_algo.encrypt(x, self.key)[0]])
            x = x[1:] + ci
            rslt += ci
        return rslt

    def decrypt(self, cipher: bytes) -> bytes:
        rslt = b''
        x = self.iv
        for c in cipher:
            mi = bytes([c ^ self.cipher_algo.encrypt(x, self.key)[0]])
            x = x[1:] + bytes([c])
            rslt += mi
        return rslt
