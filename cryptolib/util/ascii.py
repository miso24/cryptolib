import string


def upper2idx(c: str) -> int:
    return string.ascii_uppercase.index(c)


def lower2idx(c: str) -> int:
    return string.ascii_lowercase.index(c)


def idx2lower(idx: int) -> str:
    return string.ascii_lowercase[idx]


def idx2upper(idx: int) -> str:
    return string.ascii_uppercase[idx]


def alphabet_idx(c: str) -> int:
    """
    Alphabet

    Args:
        c (str)
    """
    if c.isupper():
        return upper2idx(c)
    elif c.islower():
        return lower2idx(c)
    return -1
