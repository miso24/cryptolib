from functools import reduce
from typing import List, Tuple
import random
import math
import secrets

import gmpy2


def lcm(a: int, b: int) -> int:
    """LCM

    calculate lcm

    Args:
        a: (int)
        b: (int)

    Returns:
        int: LCM of a and b
    """
    return a * b // math.gcd(a, b)


def exgcd(a: int, b: int) -> Tuple[int, int, int]:
    """Euclid

    ax + by = gcd(a: int, b:int) -> int
    calculate x and y and gcd(a: int, b:int) -> int

    Args:
        a (int)
        b (int)

    Returns:
        int: GCD of a and b
        int: x
        int: y
    """
    x0, y0, x1, y1 = 0, 1, 1, 0
    while a != 0:
        q, a, b = b // a, b % a, a
        x0, x1 = x1, x0 - x1 * q
        y0, y1 = y1, y0 - y1 * q
    return b, x0, y0


def inverse_mod(u: int, v: int) -> int:
    """Inverse Mod

    ux ≡ 1 (mod v)
    calculate x

    Args:
        u (int)
        v (int)

    Returns:
        int: x
    """
    g, x, _ = exgcd(u % v, v)
    if g != 1:
        raise Exception('mod inverse is not exist!')
    return x % v


def miller_rabin(n: int, k: int = 20) -> int:
    """miller rabin

    Miller rabin test

    Args:
        n (long): integer to be tested for primality
        k (int): the number of rounds of testing

    Returns:
        bool: is prime

    Examples:
        >>> miller_rabin(98959625207757469)
        True
        >>> miller_rabin(629685412367973552)
        False
    """
    if n == 2:
        return True
    if n & 1 == 0 or n == 0:
        return False

    mpz_n = gmpy2.mpz(n)
    r, d = 0, mpz_n - 1
    while d & 1 != 0:
        d >>= 1
        r += 1

    for _ in range(k):
        a = gmpy2.mpz(random.randint(1, mpz_n - 1))
        x = gmpy2.powmod(a, d, mpz_n)
        if x == 1 or x == mpz_n - 1:
            continue
        for _ in range(r):
            x = gmpy2.powmod(x, 2, mpz_n)
            if x == mpz_n - 1:
                break
        else:
            return False
    return True


def crt(nl: List[int], al: List[int]) -> int:
    """

    Chinise Reminder Theorem

    Args:
        nl (List[int]): modulos
        al (List[int]): a

    Returns:
        int

    References:
        - http://elliptic-shiho.hatenablog.com/entry/2016/04/03/020117
        - https://qiita.com/drken/items/ae02240cd1f8edfc86fd
    """
    N = reduce(lambda x, y: x * y, nl, 1)
    rslt = 0
    for n, a in zip(nl, al):
        m = N // n
        _, x, _ = exgcd(m, n)
        rslt += x * m * a
        rslt %= N
    return rslt


def get_randint(n: int) -> int:
    """

    get random number range 0 ~ n


    Args:
        n (int): max value

    Returns:
        int: random number (range 0 ~ n)
    """
    return random.randint(0, n)


def get_randbits(n: int) -> int:
    """

    get n bits random number

    Args:
        n (int): bits size

    Returns:
        int: n bits random number
    """
    return secrets.randbits(n)


def get_prime(n: int) -> int:
    """

    get n bits prime number

    Args:
        n (int): bits size

    Returns:
        int: n bits prime number
    """
    p = secrets.randbits(n)
    while not is_prime(p):
        p = secrets.randbits(n)
    return p


next_prime_cache = {}


def next_prime(n: int) -> int:
    """

    get next prime number

    Args:
        n (int): start

    Returns:
        int: first prime number greater than n
    """
    if n not in next_prime_cache:
        next_prime_cache[n] = gmpy2.next_prime(n)
    return next_prime_cache[n]


def logn(x: int, n: int) -> float:
    """

    Base n logarithm of x

    Args:
        x (int): antilogarithm
        n (int): base

    Returns:
        float
    """
    return gmpy2.log(x) / gmpy2.log(n)


def legendre_symbol(a: int, p: int) -> int:
    """

    Legendre symbol

    a ^ (p - 1) / 2 (mod p)
    =  1 a is quadratic residue
      -1 a is non-quadratic residue
       0 a ≡ 0 (mod p)

    Args:
        a (int)
        p (int)

    Returns:
        int
    """
    ls = pow(a, (p - 1) // 2, p)
    return -1 if ls == p - 1 else ls


def toneill_shanks(a: int, p: int) -> int:
    Q, S = p - 1, 0
    while Q % 2 == 0:
        S += 1
        Q >>= 1

    z = 2
    while legendre_symbol(z, p) != -1:
        z += 1

    M, R = S, pow(a, (Q + 1) // 2, p)
    c, t = pow(z, Q, p), pow(a, Q, p)
    while True:
        if t == 0:
            return 0
        elif t == 1:
            return R
        t_ = pow(t, 2, p)
        for i in range(1, M):
            if t_ == 1:
                break
            t_ = pow(t_, 2, p)
        b = pow(c, pow(2, M - i - 1), p)
        M = i
        c = pow(b, 2, p)
        t = (t * pow(b, 2, p)) % p
        R = (R * b) % p


def mod_sqrt(a: int, p: int) -> int:
    if legendre_symbol(a, p) != 1:
        return 0
    elif a == 0:
        return 0
    elif p % 4 == 3:
        return pow(a, (p + 1) // 4, p)

    return toneill_shanks(a, p)


def is_coprime(a: int, b: int) -> bool:
    return gmpy2.gcd(a, b) == 1


def is_prime(n: int) -> bool:
    return miller_rabin(n)
