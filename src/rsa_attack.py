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

def to_contfracs(a, b):
    contfracs = []
    while b:
        contfracs.append(a // b)
        a, b = b, a % b
    return contfracs

def contfracs_to_rational(contfracs):
    if len(contfracs) == 0:
        return 1, 0
    elif len(contfracs) == 1:
        return contfracs[0], 1
    elif len(contfracs) == 2:
        return contfracs[0] * contfracs[1] + 1, contfracs[1]

    n0, d0 = contfracs[0], 1
    n1, d1 = n0 * contfracs[1] + 1, contfracs[1]
    for q in contfracs[2:]:
        n0, n1 = n1, n1 * q + n0
        d0, d1 = d1, d1 * q + d0
    return n1, d1

def convergent_from_contfrac(contfracs):
    convergents = []
    for i in range(len(contfracs)):
        contfrac = contfracs[:i+1]
        if i % 2 == 0:
            contfrac[-1] += 1
        convergents.append(contfracs_to_rational(contfrac))
    return convergents

def wieners_attack(e, n):
    """Wiener's Attack

    Args:
        e (long): RSA public key e
        n (long): RSA public key n

    Returns:
        long: RSA private key

    Examples:
        >>> wieners_attack(2621, 8927)
        5
    """
    convergents = convergent_from_contfrac(to_contfracs(e, n))
    for k, dg in convergents:
        edg = e * dg
        phi = edg // k

        x = n - phi + 1
        # (n - phi + 1) // 2 is integer and ((n - phi + 1) // 2)^2 - pq is perfect square
        if x % 2 == 0 and gmpy2.is_square(pow(x // 2, 2) - n):
            return dg // (edg % k)
    return None
