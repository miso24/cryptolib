import struct
import math


def xor_bytes(a, b):
    return bytes([x ^ y for x, y in zip(a, b)])


def byte_length(long):
    return math.ceil(long.bit_length() / 8)


def hex2bytes(h):
    """

    convert hex to bytes

    Args:
        h (str): hex string

    Returns:
        bytes

    Examples:
        >>> hex2bytes("0x41414141")
        b'AAAA'
        >>> hex2bytes("42424242")
        b'BBBB'
    """
    if h.startswith("0x"):
        h = h[2:]
    return bytes.fromhex(h)


def hex2long(h):
    """

    convert hex to long

    Args:
        h (str): hex string

    Returns:
        bytes

    Examples:
        >>> hex2long("0x41414141")
        1094795585
        >>> hex2long("41414141")
        1094795585
    """
    if not h.startswith("0x"):
        h = "0x" + h
    return int(h, 16)


def bytes2long(b):
    """

    convert bytes to long

    Args:
        b (bytes)

    Returns:
        int

    Examples:
        >>> bytes2long(b'AAAA')
        1094795585
        >>> bytes2long(b'Hello,World!')
        22405534230757306350502175777
    """
    if len(b) % 8 != 0:
        b = b'\x00' * (8 - len(b) % 8) + b
    rslt = 0
    for _ in range(len(b) // 8):
        rslt += struct.unpack('>Q', b[:8])[0]
        rslt <<= 64
        b = b[8:]
    rslt >>= 64
    return rslt
    

def long2bytes(long):
    """

    convert long to bytes

    Args:
        long (int)

    Returns:
        bytes

    Examples:
        >>> long2bytes(0x41414141)
        b'AAAA'
        >>> long2bytes(22405534230757306350502175777)
        b'Hello,World!'
    """
    mask = (1 << 64) - 1
    rslt = b''
    bl = byte_length(long)
    while long:
        rslt = struct.pack('>Q', long & mask) + rslt
        long >>= 64
    if bl % 8 == 0:
        return rslt
    return rslt[(8-bl%8):]
