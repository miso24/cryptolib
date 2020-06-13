import random
import math
import secrets

import gmpy2

def lcm(a, b):
    """LCM
    
    calculate lcm

    Args:
        a: (int)
        b: (int)

    Returns:
        int: LCM of a and b
    """
    return a * b // math.gcd(a, b)

def exgcd(a, b):
    """Euclid

    ax + by = gcd(a, b)
    calculate x and y and gcd(a, b)

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

def inverse_mod(u, v):
    """Inverse Mod

    ux ≡ 1 (mod v)
    calculate x

    Args:
        u (int) 
        v (int) 

    Returns:
        int: x
    """
    g, x, _ = exgcd(u, v)
    if g != 1:
        raise Exception('mod inverse is not exist!')
    return x % v


def miller_rabin(n, k=20):
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
    if n == 2: return True
    if n & 1 == 0 or n == 0: return False

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

def get_randint(n):
    """

    get random number range 0 ~ n


    Args:
        n (int): max value

    Returns:
        int: random number (range 0 ~ n)
    """
    return random.randint(0, n)

def get_randbits(n):
    """

    get n bits random number

    Args:
        n (int): bits size

    Returns:
        int: n bits random number
    """
    return secrets.randbits(n)

def get_prime(n):
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

def next_prime(n):
    """
        
    get next prime number

    Args:
        n (int): start

    Returns:
        int: first prime number greater than n
    """
    p = n + 1
    while not is_prime(p):
        p += 1
    return p

def is_coprime(a, b):
    return math.gcd(a, b) == 1

def is_prime(n):
    return miller_rabin(n)
