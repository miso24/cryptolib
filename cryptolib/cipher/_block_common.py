from typing import Callable, Iterator, NamedTuple
from abc import ABCMeta, abstractmethod

EncryptFunc = Callable[[bytes, bytes], bytes]
DecryptFunc = Callable[[bytes, bytes], bytes]


class BlockCipherAlgo(NamedTuple):
    block_size: int
    encrypt: EncryptFunc
    decrypt: DecryptFunc


class BlockCipherMode(metaclass=ABCMeta):
    def __init__(self, key: bytes, cipher_algo: BlockCipherAlgo) -> None:
        self.key = key
        self.cipher_algo = cipher_algo

    @abstractmethod
    def encrypt(self, plain: bytes) -> bytes:
        pass

    @abstractmethod
    def decrypt(self, cipher: bytes) -> bytes:
        pass


def split_block(data: bytes, cipher_algo: BlockCipherAlgo) -> Iterator[bytes]:
    bs = cipher_algo.block_size
    for i in range(0, len(data) // bs):
        yield data[i*bs:i*bs+bs]
