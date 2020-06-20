from cryptolib.encoding.bytes import long2bytes, bytes2long
import struct
import base64


_b58table = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def b16dec(data):
    """

    Base16 decode

    Args:
        data (bytes) 

    Returns:
        bytes: decoded data
    """
    return base64.b16decode(data)

def b16enc(data):
    """

    Base16 encode

    Args:
        data (bytes)

    Returns:
        bytes: encoded data
    """
    return base64.b16encode(data)

def b32dec(data):
    """

    Base32 decode

    Args:
        data (bytes) 

    Returns:
        bytes: decoded data
    """
    return base64.b32decode(data)

def b32enc(data):
    """

    Base32 encode

    Args:
        data (bytes)

    Returns:
        bytes: encoded data
    """
    return base64.b32encode(data)

def b58enc(data):
    """

    Base58 encode

    Args:
        data (Union[str, bytes])

    Returns:
        bytes: encoded data
    """
    if isinstance(data, str):
        data = data.encode()

    l = bytes2long(data)
    rslt = b''

    while l:
        rslt = struct.pack('<B', _b58table[l % 58]) + rslt
        l //= 58
    return rslt

def b58dec(data):
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
    l = 0

    for byte in data:
        l = l * 58 + _b58table.index(byte)

    while l:
        rslt = struct.pack('<B', l % 256) + rslt
        l >>= 8
    return rslt

def b64dec(data):
    """

    Base64 decode

    Args:
        data (bytes) 

    Returns:
        bytes: decoded data
    """
    return base64.b64decode(data)

def b64enc(data):
    """

    Base64 encode

    Args:
        data (bytes)

    Returns:
        bytes: encoded data
    """
    return base64.b64encode(data)


def b85dec(data):
    """

    Base85 decode

    Args:
        data (bytes) 

    Returns:
        bytes: decoded data
    """
    return base64.b85decode(data)

def b85enc(data):
    """

    Base85 encode

    Args:
        data (bytes)

    Returns:
        bytes: encoded data
    """

    return base64.b85encode(data)
