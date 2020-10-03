from __future__ import annotations
from pyasn1.type import namedtype
from pyasn1.type import univ
from pyasn1.codec.der import decoder, encoder
from pyasn1.error import PyAsn1Error
import math
import random
import gmpy2

from cryptolib.encoding import pem
from cryptolib.util.binary import bytes2long
from cryptolib.number import (
    lcm,
    inverse_mod,
    get_prime,
    is_coprime
)
from typing import Union, Optional, Tuple


class RSAPrivateKeyStruct(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', univ.Integer()),
        namedtype.NamedType('modulus', univ.Integer()),
        namedtype.NamedType('publicExponent', univ.Integer()),
        namedtype.NamedType('privateExponent', univ.Integer()),
        namedtype.NamedType('prime1', univ.Integer()),
        namedtype.NamedType('prime2', univ.Integer()),
        namedtype.NamedType('exponent1', univ.Integer()),
        namedtype.NamedType('exponent2', univ.Integer()),
        namedtype.NamedType('coefficient', univ.Integer()),
    )


class RSAPublicKeyStruct(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('modulus', univ.Integer()),
        namedtype.NamedType('publicExponent', univ.Integer()),
    )


class RSA:
    def __init__(self, n: int, e: int, p: Optional[int] = None, q: Optional[int] = None, d: Optional[int] = None) -> None:
        self.n = n
        self.p = p
        self.q = q
        self.e = e
        self.d = d

    def encrypt(self, m: Union[int, bytes, str]) -> int:
        """RSA encrypt

        encrypt plaintext

        Args:
            m (Union[int, bytes, str]): plaintext

        Returns:
            int: ciphertext
        """
        if isinstance(m, bytes):
            m = bytes2long(m)
        elif isinstance(m, str):
            m = bytes2long(m.encode())

        if self.n is None:
            raise ValueError('public key is not exist')
        if self.e is None:
            raise ValueError('public exponent is not exist')
        return pow(m, self.e, self.n)

    def decrypt(self, c: int) -> int:
        """RSA decrypt

        decrypt ciphertext

        Args:
            c (int): ciphertext

        Returns:
            int: plaintext
        """
        if self.n is None:
            raise ValueError('public key is not exist')
        elif self.d is None:
            raise ValueError('private exponent is not exist')
        return pow(c, self.d, self.n)

    def export_key(self, enc_format: str = "pem") -> bytes:
        """

        Export RSA key

        Args:
            enc_format (str)

        Returns:
            bytes: encoded key
        """
        if self.d:
            marker = pem.RSA_PRIVATE
            data = self._der_encoded_privkey()
        else:
            marker = pem.RSA_PUBLIC
            data = self._der_encoded_pubkey()

        if enc_format == "der":
            return data
        elif enc_format == "pem":
            return pem.encode(data, marker)
        else:
            raise ValueError('format is not found')

    def _der_encoded_privkey(self) -> bytes:
        key_struct = RSAPrivateKeyStruct()
        key_struct['version'] = 0
        key_struct['modulus'] = self.n
        key_struct['publicExponent'] = self.e
        key_struct['privateExponent'] = self.d
        key_struct['prime1'] = self.p
        key_struct['prime2'] = self.q
        key_struct['exponent1'] = self.d % (self.p - 1)
        key_struct['exponent2'] = self.d % (self.q - 1)
        key_struct['coefficient'] = inverse_mod(self.p, self.q)
        encoded = encoder.encode(key_struct)
        return encoded

    def _der_encoded_pubkey(self) -> bytes:
        key_struct = RSAPublicKeyStruct()
        key_struct['modulus'] = self.n
        key_struct['publicExponent'] = self.e
        encoded = encoder.encode(key_struct)
        return encoded


def calc_privatekey(p: int, q: int, e: int) -> int:
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


def encrypt(m: int, e: int, n: int) -> int:
    """RSA encrypt

    encrypt plaintext

    Args:
        m (Union[int, bytes, str]): plaintext
        n (int): public key n
        e (int): public key e

    Returns:
        int: ciphertext
    """
    if isinstance(m, bytes):
        m = bytes2long(m)
    elif isinstance(m, str):
        m = bytes2long(m.encode())

    return pow(m, e, n)


def decrypt(c: int, d: int, n: int) -> int:
    """RSA decrypt

    decrypt ciphertext

    Args:
        c (int): ciphertext
        n (int): public key n
        d (int): private key d

    Returns:
        int: plaintext
    """
    return pow(c, d, n)


def keygen(k: int) -> Tuple[int, int, int]:
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
    d = calc_privatekey(p, q, e)
    return n, e, d


def _primes_from_privatekey(e: int, d: int, n: int, t: int = 100) -> Tuple[int, int]:
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
    k = gmpy2.mpz(d * e - 1)
    for _ in range(t):
        g = gmpy2.mpz(random.randint(2, n - 1))
        t = k
        while True:
            x = gmpy2.powmod(g, t, n)
            t //= 2
            if x > 1 and gmpy2.gcd(x - 1, n) > 1:
                p = gmpy2.gcd(x - 1, n)
                q = n // p
                return int(p), int(q)
            if t == 0:
                break
    return -1, -1


def generate(k: int, e: int = 65537) -> RSA:
    """

    generate RSA key

    Args:
        k (int): security paramator
        e (int): public exponent

    Returns:
        RSA: RSA object
    """
    p = get_prime(k // 2)
    q = get_prime(k // 2)

    while not is_coprime(p, q):
        q = get_prime(k // 2)

    n = p * q
    d = calc_privatekey(p, q, e)
    return RSA(n, e, p, q, d)


def construct(n: int, e: int, p: Optional[int] = None, q: Optional[int] = None, d: Optional[int] = None) -> RSA:
    """

    Construct

    Args:
        n (int): modulus
        e (int): public exponent
        p (int, optional): prime 1
        q (int, optional): prime 2
        d (int, optional): private exponent

    Returns:
        RSA: RSA object
    """
    if not n or not e:
        raise ValueError('n or e needed!')

    if d:
        p, q = _primes_from_privatekey(e, d, n)

    if p and q and not d:
        d = calc_privatekey(p, q, e)
    return RSA(n, e, p, q, d)


def import_key_der(data: bytes) -> RSA:
    """

    Import RSA key (der)

    Args:
        data (bytes): key data

    Returns:
        RSA: RSA object
    """
    key_structs = {
        "public": RSAPublicKeyStruct(),
        "private": RSAPrivateKeyStruct()
    }

    for k in key_structs:
        try:
            key_data, _ = decoder.decode(data, asn1Spec=key_structs[k])
            if k == "public":
                return construct(
                    int(key_data['modulus']),
                    int(key_data['publicExponent'])
                )
            else:
                return construct(
                    int(key_data['modulus']),
                    int(key_data['publicExponent']),
                    int(key_data['prime1']),
                    int(key_data['prime2']),
                    int(key_data['privateExponent'])
                )
        except PyAsn1Error:
            continue
    raise ValueError('invalid key')


def import_key_pem(data: Union[str, bytes]) -> RSA:
    """

    Import RSA key (pem)

    Args:
        data (Union[str, bytes]): key data

    Returns:
        RSA: RSA object
    """
    if isinstance(data, bytes):
        data = data.decode()
    pem_decoded = pem.decode(data)
    if pem_decoded.get(pem.RSA_PRIVATE):
        return import_key_der(pem_decoded[pem.RSA_PRIVATE][0])
    elif pem_decoded.get(pem.RSA_PUBLIC):
        return import_key_der(pem_decoded[pem.RSA_PUBLIC][0])
    raise ValueError('invalid key')
