import codecs
from Crypto.Util.number import *
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
    return ''.join([ord(c) ^ n for c in s])

def xor_b(b, n):
    """XOR

    xor encode

    Args:
        b (bytes): string
        n (int): xor val
    
    Returns:
        bytes: xor encoded data
    """
    return b''.join([ord(c) ^ n for c in b])

def rot13(data):
    return codecs.decode(data, encoding="rot13")

def b64dec(data):
    """Base64 decode

    decode encoded data

    Args:
        data (bytes) 

    Returns:
        bytes: decoded data
    """
    return codecs.decode(data, encoding="base64")

def b64enc(data):
    """Base64 encode

    encode data

    Args:
        data (bytes)

    Returns:
        bytes: encoded data
    """
    return codecs.encode(data, encoding="base64")

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

def long2bytes(l, endian="big"):
    """Long to Bytes

    convert long to bytes

    Args:
        l (long)

    Returns:
        bytes: converted long
    """
    b = b''
    while l:
        b = (l & 0xff).to_bytes(1, "big") + b
        l >>= 8
    return b

def bytes2long(b, endian="big"):
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
