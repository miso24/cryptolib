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
