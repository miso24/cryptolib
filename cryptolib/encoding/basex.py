from cryptolib.util.binary import bytes2long
from typing import Union
import struct
import base64


_b58table = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def b16dec(data: Union[str, bytes]) -> bytes:
    """

    Base16 decode

    Args:
        data (Union[str, bytes])

    Returns:
        bytes: decoded data
    """
    return base64.b16decode(data)


def b16enc(data: bytes) -> bytes:
    """

    Base16 encode

    Args:
        data (bytes)

    Returns:
        bytes: encoded data
    """
    return base64.b16encode(data)


def b32dec(data: Union[str, bytes]) -> bytes:
    """

    Base32 decode

    Args:
        data (Union[str, bytes])

    Returns:
        bytes: decoded data
    """
    return base64.b32decode(data)


def b32enc(data: bytes) -> bytes:
    """

    Base32 encode

    Args:
        data (bytes)

    Returns:
        bytes: encoded data
    """
    return base64.b32encode(data)


def b58enc(data: bytes) -> bytes:
    """

    Base58 encode

    Args:
        data (bytes)

    Returns:
        bytes: encoded data
    """
    long = bytes2long(data)
    rslt = b''

    while long:
        rslt = struct.pack('<B', _b58table[long % 58]) + rslt
        long //= 58
    return rslt


def b58dec(data: Union[str, bytes]) -> bytes:
    """

    Base58 decode

    Args:
        data (Union[str, bytes])

    Returns:
        bytes: decoded data
    """
    if isinstance(data, str):
        data = data.encode()

    rslt = b''
    long = 0

    for byte in data:
        long = long * 58 + _b58table.index(byte)

    while long:
        rslt = struct.pack('<B', long % 256) + rslt
        long >>= 8
    return rslt


def b64dec(data: Union[str, bytes]) -> bytes:
    """

    Base64 decode

    Args:
        data (Union[str, bytes])

    Returns:
        bytes: decoded data
    """
    return base64.b64decode(data)


def b64enc(data: bytes) -> bytes:
    """

    Base64 encode

    Args:
        data (bytes)

    Returns:
        bytes: encoded data
    """
    return base64.b64encode(data)


def b85dec(data: Union[str, bytes]) -> bytes:
    """

    Base85 decode

    Args:
        data (Union[str, bytes])

    Returns:
        bytes: decoded data
    """
    return base64.b85decode(data)


def b85enc(data: bytes) -> bytes:
    """

    Base85 encode

    Args:
        data (bytes)

    Returns:
        bytes: encoded data
    """

    return base64.b85encode(data)
