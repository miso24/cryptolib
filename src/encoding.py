import codecs
import base64
import math

def xor(s, n):
    """XOR

    xor encode

    Args:
        s (str): string
        n (int): xor val
    
    Returns:
        str: xor encoded data
    """
    return ''.join([chr(ord(c) ^ n) for c in s])

def xor_b(b, n):
    """XOR

    xor encode

    Args:
        b (bytes): string
        n (int): xor val
    
    Returns:
        bytes: xor encoded data
    """
    return bytes([ord(c) ^ n for c in b])

def rot13(data):
    return codecs.decode(data, encoding="rot13")

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

def hex2bytes(h):
    """Hex to Bytes
   
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
    """Hex to Long
   
    convert hex to long

    Args:
        h (str): hex string

    Returns:
        bytes

    Examples:
        >>> hex2bytes("0x41414141")
        1094795585
        >>> hex2bytes("41414141")
        1094795585
    """

    if not h.startswith("0x"):
        h = "0x" + h
    return int(h, 16)

def long2bytes(l):
    """Long to Bytes

    convert long to bytes

    Args:
        l (long)

    Returns:
        bytes: converted long
    """
    b = []
    while l:
        b.insert(0, l & 0xff)
        l >>= 8
    return bytes(b)

def bytes2long(b):
    """Bytes to Long

    convert bytes to long

    Args:
        b (bytes)

    Returns:
        long: converted bytes
    """
    l = 0
    for byte in b:
        l += byte
        l <<= 8
    l >>= 8
    return l
