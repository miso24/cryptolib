from cryptolib.number import exgcd, crt
from typing import List, Tuple, Optional
import gmpy2


def common_modulus_attack(n: int, e1: int, e2: int, c1: int, c2: int) -> int:
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
    _, s1, s2 = exgcd(e1, e2)
    v = pow(c1, s1, n)
    w = pow(c2, s2, n)
    m = (v * w) % n
    return m


def low_public_exponent_attack(c: int, e: int) -> Tuple[int, bool]:
    """Low Public Exponent Attack

    Args:
        c (int): RSA encrypted value
        e (int): RSA public exponent

    Returns:
        int: RSA plain text
        bool: is success
    """
    m, res = gmpy2.iroot(c, e)
    return int(m), res


def to_contfrac(a: int, b: int) -> List[int]:
    contfrac = []
    while b:
        contfrac.append(a // b)
        a, b = b, a % b
    return contfrac


def contfrac_to_rational(contfrac: List[int]) -> Tuple[int, int]:
    if len(contfrac) == 0:
        return 1, 0
    elif len(contfrac) == 1:
        return contfrac[0], 1
    elif len(contfrac) == 2:
        return contfrac[0] * contfrac[1] + 1, contfrac[1]

    n0, d0 = contfrac[0], 1
    n1, d1 = n0 * contfrac[1] + 1, contfrac[1]
    for q in contfrac[2:]:
        n0, n1 = n1, n1 * q + n0
        d0, d1 = d1, d1 * q + d0
    return n1, d1


def convergents_from_contfrac(contfrac: List[int]) -> List[Tuple[int, int]]:
    convergents = []
    for i in range(len(contfrac)):
        c = contfrac[:i+1]
        if i % 2 == 0:
            c[-1] += 1
        convergents.append(contfrac_to_rational(c))
    return convergents


def wieners_attack(e: int, n: int) -> Optional[int]:
    """Wiener's Attack

    Args:
        e (long): RSA public key e
        n (long): RSA public key n

    Returns:
        Optional[int]: RSA private key

    Examples:
        >>> wieners_attack(2621, 8927)
        5

    Refs:
        - https://github.com/orisano/owiener
        - https://github.com/pablocelayes/rsa-wiener-attack
        - http://www.reverse-engineering.info/Cryptography/ShortSecretExponents.pdf
    """
    convergents = convergents_from_contfrac(to_contfrac(e, n))
    for k, dg in convergents:
        edg = e * dg
        phi = edg // k

        x = n - phi + 1
        # (n - phi + 1) // 2 is integer and ((n - phi + 1) // 2)^2 - pq is perfect square
        if x % 2 == 0 and gmpy2.is_square(pow(x // 2, 2) - n):
            return dg // (edg % k)
    return None


def hasteds_broadcast_attack(e: int, ni: List[int], ci: List[int]) -> Tuple[int, bool]:
    """

    Hasted's broadcast attack

    Args:
        e (int): public exponent
        ni (List[int]): public keys
        ci (List[int]): ciphers

    Returns:
        long: plaintext

    Refs:
        - http://elliptic-shiho.hatenablog.com/entry/2015/11/12/182219
        - http://inaz2.hatenablog.com/entry/2016/01/15/011138
    """
    m_e = crt(ni, ci)
    m, rslt = gmpy2.iroot(m_e, e)
    return int(m), rslt
