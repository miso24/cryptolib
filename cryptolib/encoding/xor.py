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
