import string

from cryptolib.util.ascii import *


def vigenere_encrypt(plain, key):
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

def vigenere_decrypt(cipher, key):
    rslt = ""
    for idx, c in enumerate(cipher):
        if not c.isalpha():
            rslt += c
            continue
        curr_k = key[idx % len(key)]
        k = upper2idx(curr_k) if curr_k.isupper() else lower2idx(curr_k)
        if c.isupper():
            rslt += idx2upper((upper2idx(c) - k) % 26)
        elif c.islower():
            rslt += idx2lower((lower2idx(c) - k) % 26)
    return rslt
