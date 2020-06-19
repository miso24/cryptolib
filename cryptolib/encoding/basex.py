import base64

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

