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
        bs = self.cipher_algo.block_size
        rslt = b''
        counter = bytes2long(self.nonce)
        counter_max = pow(2, bs * 8)

        for block in split_block(plain, self.cipher_algo):
            ctr = self.cipher_algo.encrypt(counter.to_bytes(bs, "big"), self.key)
            rslt += xor_bytes(ctr, block)
            counter = (counter + 1) % counter_max

        rem = len(plain) % bs
        if rem != 0:
            ctr = self.cipher_algo.encrypt(counter.to_bytes(bs, "big"), self.key)
            rslt += xor_bytes(ctr[:rem], plain[-rem:])
        return rslt

    def decrypt(self, cipher: bytes) -> bytes:
        return self.encrypt(cipher)
