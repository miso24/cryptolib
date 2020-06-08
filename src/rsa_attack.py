import secrets
import math
import random
import gmpy2

from cryptolib.number import *

def common_modulus_attack(n, e1, e2, c1, c2):
    """Common Modulus Attack

    execute common modulus attack

    Args:
        n  (int): RSA n
        e1 (int): RSA e1
        e2 (int): RSA e2
        c1 (int): RSA c1
        c2 (int): RSA c2

    Returns:
        long: RSA plain text
    """
    _, s1, s2 =  exgcd(e1, e2)
    v = pow(c1, s1, n)
    w = pow(c2, s2, n)
    m = (v * w) % n
    return m

def low_public_exponent_attack(c, e):
    """Low Public Exponent Attack

    Args:
        c (int): RSA encrypted value
        e (int): RSA public exponent

    Returns:
        int: RSA plain text
        bool: is success 
    """
    m, res = gmpy2.iroot(e, c)
    return int(m), res
