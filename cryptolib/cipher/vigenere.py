from cryptolib.util.ascii import upper2idx, lower2idx, idx2upper, idx2lower


def encrypt(plain: str, key: str) -> str:
    """
    
    Vigenere cipher: encrypt

    Args
        plain (str)
        key (str)

    Returns:
        str
    """
    rslt = ""
    for idx, c in enumerate(plain):
        if not c.isalpha():
            rslt += c
            continue
        curr_k = key[idx % len(key)]
        k = upper2idx(curr_k) if curr_k.isupper() else lower2idx(curr_k)
        if c.isupper():
            rslt += idx2upper((upper2idx(c) + k) % 26)
        elif c.islower():
            rslt += idx2lower((lower2idx(c) + k) % 26)
    return rslt


def decrypt(cipher: str, key: str) -> str:
    """
    
    Vigenere cipher: decrypt

    Args:
        cipher (str)
        key (str)

    Returns:
        str
    """
    rslt = ""
    ctr = 0
    for c in cipher:
        if not c.isascii() or not c.isalpha():
            rslt += c
            continue
        curr_k = key[ctr % len(key)]
        k = upper2idx(curr_k) if curr_k.isupper() else lower2idx(curr_k)
        if c.isupper():
            rslt += idx2upper((upper2idx(c) - k) % 26)
        elif c.islower():
            rslt += idx2lower((lower2idx(c) - k) % 26)
        ctr += 1
    return rslt
