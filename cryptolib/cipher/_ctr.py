from __future__ import annotations
from cryptolib.cipher._block_common import BlockCipherMode, split_block
from typing import TYPE_CHECKING
from cryptolib.util.binary import xor_bytes, bytes2long, long2bytes


if TYPE_CHECKING:
    from cryptolib.cipher._block_common import BlockCipherAlgo


class CTRMode(BlockCipherMode):
    def __init__(self, key: bytes, cipher_algo: BlockCipherAlgo, nonce: bytes) -> None:
        super().__init__(key, cipher_algo)
        self.nonce = nonce

    def encrypt(self, plain: bytes) -> bytes:
        rslt = b''
        counter = bytes2long(self.nonce)
        counter_max = pow(2, self.cipher_algo.block_size * 8)
        for block in split_block(plain, self.cipher_algo):
            tmp_c = self.cipher_algo.encrypt(counter.to_bytes(16, "big"), self.key)
            rslt += xor_bytes(tmp_c, block)
            counter = (counter + 1) % counter_max
        bs = self.cipher_algo.block_size
        rem = len(plain) % bs
        if rem != 0:
            tmp_c = self.cipher_algo.encrypt(counter.to_bytes(16, "big"), self.key)
            rslt += xor_bytes(tmp_c[:rem], plain[-rem:])
        return rslt

    def decrypt(self, cipher: bytes) -> bytes:
        return self.encrypt(cipher)
