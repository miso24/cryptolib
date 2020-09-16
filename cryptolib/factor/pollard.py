import gmpy2
import functools
import random
from cryptolib.number import logn, next_prime


# pollard rho f(x)
def pr_fx(x, c, n):
    return gmpy2.t_mod(x ** 2 - c, n)


def pollard_rho(n, f_c=1):
    """

    Pollard's ρ factorization method

    Args:
        n (int): target
        f_c (int): function param

    Returns:
        int: factor
    """
    x, y = 2, 2
    f = functools.partial(pr_fx, c=f_c, n=n)
    d = 1
    while d == 1:
        x = f(x)
        y = f(f(y))
        d = gmpy2.gcd(abs(x - y), n)
    if d == n:
        f_c = random.randint(2, n)
        return pollard_rho(n, f_c=f_c)
    else:
        return int(d)


def pollard_rho_brent(n, f_c=1):
    """

    Pollard's ρ factorization method (brent)

    Args:
        n (int): target
        f_c (int): function param

    Returns:
        int: factor
    """
    x0 = random.randint(1, n)
    m = random.randint(1, n)
    y = x0
    r, q, g = 1, 1, 1
    f = functools.partial(pr_fx, c=f_c, n=n)
    while g == 1:
        x = y
        for _ in range(1, r):
            y = f(y)
        k = 0
        while k < r and g == 1:
            ys = y
            for _ in range(min(m, r - k)):
                y = f(y)
                q = gmpy2.t_mod(q * abs(x - y), n)
            g = gmpy2.gcd(q, n)
            k += m
        r *= 2
    if g == n:
        while True:
            ys = f(ys)
            g = gmpy2.gcd(abs(x - ys), n)
            if g > 1:
                break
    if g == n:
        return None
    else:
        return int(g)


def pollard_pm1(n, B=2**8, max_try=10):
    """

    Pollard's p - 1 factorization method

    Args:
        n (int): target
        max_try (int): maximum number of tries

    Returns:
        int: factor
    """
    for _ in range(max_try):
        p = 2
        aM = 2
        while p <= B:
            exponent = gmpy2.mpz(logn(B, p))
            M = pow(p, exponent)
            aM = gmpy2.powmod(aM, M, n)
            p = next_prime(p)
        g = gmpy2.gcd(aM - 1, n)
        if 1 < g < n:
            return g
        elif g == 1:
            B *= 2
        elif g == n:
            B //= 2
    return None
