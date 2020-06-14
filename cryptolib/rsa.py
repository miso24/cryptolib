import math
import random
import gmpy2

from cryptolib.number import *

def rsa_calc_privatekey(p, q, e):
    """Calc private key

    calculate RSA private key

    Args:
        p (long): prime 1
        q (long): prime 2
        e (long): public key e

    Returns:
        long: private key
    """
    L = lcm(p - 1, q - 1)
    d = inverse_mod(e, L)
    return d

def rsa_keygen(k):
    """RSA keygen

    generate RSA key

    Args:
        k (int): security paramator

    Returns:
        long: public key n
        long: public key e
        long: private key d
    """
    p = get_prime(k // 2)
    q = get_prime(k // 2)

    while not is_coprime(p, q):
        q = get_prime(k // 2)

    n = p * q
    e = 65537
    d = rsa_calc_privatekey(p, q, e)
    return n, e, d

def rsa_primes_from_privatekey(e, d, n, t=100):
    """
    
    calculate primes from private key

    Args:
        e (long): public exponent
        d (long): private key
        n (long): public key
        t (int): num of challenges

    Returns:
        long: prime p
        long: prime q

    Refs:
        - http://elliptic-shiho.hatenablog.com/entry/2015/12/14/043745
    """
    k = d * e - 1
    for _ in range(t):
        g = random.randint(2, n - 1)
        t = k
        while True:
            x = pow(g, t, n)
            t //= 2
            if x > 1 and math.gcd(x - 1, n) > 1:
                p = math.gcd(x - 1, n)
                q = n // p
                return p, q
            if t == 0:
                break
    return -1, -1

def rsa_encrypt(m, n, e):
    """RSA encrypt

    encrypt plaintext

    Args:
        m (long): plaintext
        n (long): public key n
        e (long): public key e

    Returns:
        long: ciphertext
    """
    return pow(m, e, n)

def rsa_decrypt(c, n, d):
    """RSA decrypt

    decrypt ciphertext

    Args:
        c (long): ciphertext
        n (long): public key n
        d (long): private key d

    Returns:
        long: plaintext
    """
    return pow(c, d, n)
