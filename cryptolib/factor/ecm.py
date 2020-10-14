from __future__ import annotations
from cryptolib.number import logn, is_coprime, next_prime
import copy
import gmpy2
import random


class ECMPoint:
    a = 0
    N = 0

    def __init__(self, x: int, y: int) -> int:
        self.x = x
        self.y = y

    def add(self, other: ECMPoint):
        if self.x != other.x:
            nume = other.y - self.y
            deno = other.x - self.x
        elif self.x == other.x and self.y == other.y and other.y != 0:
            nume = 3 * self.x ** 2 + self.a
            deno = 2 * self.y
        else:
            raise Exception('err')
        if not is_coprime(deno, self.N):
            return False
        s = nume * gmpy2.invert(deno, self.N)
        x3 = (s ** 2 - self.x - other.x) % self.N
        y3 = (s * (self.x - x3) - self.y) % self.N
        self.x = x3
        self.y = y3
        return True

    @classmethod
    def init(cls, a: int, N: int) -> None:
        cls.a = a
        cls.N = N


def ecm_calc_factor(p1: ECMPoint, p2: ECMPoint, N: int) -> int:
    if p1.x != p2.x:
        deno = (p2.x - p1.x) % N
    else:
        deno = (p1.y * 2) % N
    return gmpy2.gcd(deno, N)


def ecm(N: int):
    """

    Elliptic-curve factorization method

    Args:
        N (int): target

    Returns:
        int: factor
    """
    L = int(gmpy2.log2(N) ** 2 + gmpy2.log2(N) * 0.25)
    iter_count = 0

    while True:
        a = gmpy2.mpz(random.randint(0, N))
        x = gmpy2.mpz(random.randint(0, N))
        y = gmpy2.mpz(random.randint(0, N))

        ECMPoint.init(a, N)
        P = ECMPoint(x, y)

        prime = gmpy2.mpz(2)

        while prime <= L:
            base = copy.copy(P)
            exponent = gmpy2.mpz(logn(L, prime))
            M = pow(prime, exponent)
            prime = next_prime(prime)

            M -= 1
            while M > 0:
                if M % 2 == 1:
                    add_rslt = P.add(base)
                    if not add_rslt:
                        return ecm_calc_factor(P, base, N)
                add_rslt = base.add(base)
                if not add_rslt:
                    return ecm_calc_factor(base, base, N)
                M //= 2
        iter_count += 1
