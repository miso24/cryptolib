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
