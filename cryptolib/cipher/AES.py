from __future__ import annotations
from functools import lru_cache
from cryptolib.util.binary import xor_bytes
from cryptolib.cipher._block_cipher import create_cipher
from cryptolib.cipher._block_common import BlockCipherAlgo
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cryptolib.cipher._block_common import BlockCipherMode


class ByteMatrix:
    def __init__(self, data, size=4):
        assert(size ** 2 == len(data))

        self.size = size
        self.matrix = []
        for j in range(size):
            row = []
            for i in range(size):
                row.append(data[i*size+j])
            self.matrix.append(row)

    def pprint(self):
        for j in range(self.size):
            for i in range(self.size):
                print("%02x " % self.matrix[j][i], end="")
            print()
        print()

    def bytes(self):
        rslt = [0] * pow(self.size, 2)
        for j in range(self.size):
            for i in range(self.size):
                rslt[i*self.size+j] = self.matrix[j][i]
        return bytes(rslt)

    def __setitem__(self, key, value):
        if isinstance(key, tuple) and len(key) == 2:
            row, col = key
            if isinstance(col, slice):
                for idx, r in enumerate(self.matrix[col]):
                    r[row] = value[idx]
            else:
                self.matrix[col][row] = value

    def __getitem__(self, item):
        if isinstance(item, tuple) and len(item) == 2:
            row, col = item
            if isinstance(col, int):
                return self.matrix[col][row]
            elif isinstance(col, slice):
                return [c[row] for c in self.matrix[col]]

    @classmethod
    def from_words(cls, words, size=4):
        return cls(b''.join(words), size)


# GF(2) polynomial
GF_MODULO = 0b100011011


def poly_divmod(a, b):
    if b == 1:
        return a, 0
    al, bl = a.bit_length(), b.bit_length()
    quoitent = 0
    while al >= bl:
        a ^= (b << (al - bl))
        quoitent |= 1 << (al - bl)
        al = a.bit_length()
    return quoitent, a


def poly_mul(a, b):
    product = 0
    while a and b:
        if b & 1:
            product ^= a
        a = (a << 1) ^ (0x11b if a & 0x80 else 0x00)
        b >>= 1
    return product


def poly_exgcd(a, b):
    x0, y0, x1, y1 = 0, 1, 1, 0
    while True:
        q, r = poly_divmod(b, a)
        if not r:
            break
        a, b = r, a
        x0, x1 = x1, x0 ^ poly_mul(x1, q)
        y0, y1 = y1, y0 ^ poly_mul(y1, q)
    return x1, y1, b


@lru_cache
def poly_inverse(x):
    inv, _, _ = poly_exgcd(x, GF_MODULO)
    return inv


# AES S-box
SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]

# AES Inverse S-box
INV_SBOX = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
]


def sub_word(b_array):
    return bytearray([SBOX[(b >> 4) * 16 + (b & 0xf)] for b in b_array])


def rot_word(b):
    return b[1:] + b[:1]


def add_round_key(st, key):
    for j in range(4):
        for i in range(4):
            st[i, j] = st[i, j] ^ key[i, j]


def mix_columns(st):
    for j in range(4):
        col = st[j, :]
        st[j, 0] = poly_mul(2, col[0]) ^ poly_mul(3, col[1]) ^ col[2] ^ col[3]
        st[j, 1] = col[0] ^ poly_mul(2, col[1]) ^ poly_mul(3, col[2]) ^ col[3]
        st[j, 2] = col[0] ^ col[1] ^ poly_mul(2, col[2]) ^ poly_mul(3, col[3])
        st[j, 3] = poly_mul(3, col[0]) ^ col[1] ^ col[2] ^ poly_mul(2, col[3])


def shift_rows(st):
    for i in range(4):
        st[:, i] = st[i:, i] + st[:i, i]


def sub_bytes(st):
    for j in range(4):
        for i in range(4):
            val = st[i, j]
            st[i, j] = SBOX[(val >> 4) * 16 + (val & 0xf)]


def inv_sub_bytes(st):
    for j in range(4):
        for i in range(4):
            val = st[i, j]
            st[i, j] = INV_SBOX[(val >> 4) * 16 + (val & 0xf)]


def inv_shift_rows(st):
    for i in range(4):
        st[:, i] = st[-i:, i] + st[:-i, i]


def inv_mix_columns(st):
    for j in range(4):
        col = st[j, :]
        st[j, 0] = poly_mul(14, col[0]) ^ poly_mul(
            11, col[1]) ^ poly_mul(13, col[2]) ^ poly_mul(9, col[3])
        st[j, 1] = poly_mul(9, col[0]) ^ poly_mul(
            14, col[1]) ^ poly_mul(11, col[2]) ^ poly_mul(13, col[3])
        st[j, 2] = poly_mul(13, col[0]) ^ poly_mul(
            9, col[1]) ^ poly_mul(14, col[2]) ^ poly_mul(11, col[3])
        st[j, 3] = poly_mul(11, col[0]) ^ poly_mul(
            13, col[1]) ^ poly_mul(9, col[2]) ^ poly_mul(14, col[3])


def subkey_gen(key, nr):
    kw = len(key) // 4
    round_num = int(nr / (kw / 4))
    ws = [key[i:i+4] for i in range(0, len(key), 4)]
    for i in range(round_num):
        w = ws[-1]
        _, r = poly_divmod(pow(2, i), GF_MODULO)
        rcon = bytearray([r] + [0] * (kw - 1))
        temp = xor_bytes(sub_word(rot_word(w)), rcon)
        nw = [None] * kw
        for j in range(kw):
            if kw == 8 and j == 4:
                temp = sub_word(temp)
            nw[j] = xor_bytes(ws[i*kw+j], temp)
            temp = nw[j]
        ws.extend(nw)
    if kw != 4:
        ws = ws[:-(kw-4)]
    subkeys = [ByteMatrix.from_words(ws[i:i+4]) for i in range(0, len(ws), 4)]
    return subkeys


def _encrypt(plain, key, Nr):
    subkeys = subkey_gen(key, Nr)
    s = ByteMatrix(plain)
    add_round_key(s, subkeys[0])

    for i in range(1, Nr):
        sub_bytes(s)
        shift_rows(s)
        mix_columns(s)
        add_round_key(s, subkeys[i])

    sub_bytes(s)
    shift_rows(s)
    add_round_key(s, subkeys[-1])
    return s.bytes()


def _decrypt(plain, key, Nr):
    subkeys = [*reversed(subkey_gen(key, Nr))]
    s = ByteMatrix(plain)

    for i in range(Nr):
        add_round_key(s, subkeys[i])
        if i:
            inv_mix_columns(s)
        inv_shift_rows(s)
        inv_sub_bytes(s)

    add_round_key(s, subkeys[-1])
    return s.bytes()


def encrypt(plain: bytes, key: bytes) -> bytes:
    key_length = len(key)
    if key_length == 16:
        Nr = 10
    elif key_length == 24:
        Nr = 12
    elif key_length == 32:
        Nr = 14
    else:
        raise ValueError('invalid key length')
    return _encrypt(plain, key, Nr)


def decrypt(plain: bytes, key: bytes) -> bytes:
    key_length = len(key)
    if key_length == 16:
        Nr = 10
    elif key_length == 24:
        Nr = 12
    elif key_length == 32:
        Nr = 14
    else:
        raise ValueError('invalid key length')
    return _decrypt(plain, key, Nr)


def new(key: bytes, mode: int, iv: bytes = None) -> BlockCipherMode:
    AES_algo = BlockCipherAlgo(
        16,
        encrypt,
        decrypt,
    )
    if iv is None:
        return create_cipher(key, AES_algo, mode)
    return create_cipher(key, AES_algo, mode, iv)
