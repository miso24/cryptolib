from pyasn1.type import namedtype
from pyasn1.type import univ
from pyasn1.codec.der import decoder, encoder
import math
import random
import gmpy2

from cryptolib.encoding import pem
from cryptolib.encoding.bytes import *
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

def rsa_encrypt(m, e, n):
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

def rsa_decrypt(c, d, n):
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
    d = calc_privatekey(p, q, e)
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
    def __init__(self, n, e, p=None, q=None, d=None):
        self.n = n
        self.p = p
        self.q = q
        self.e = e
        self.d = d

    def encrypt(self, m):
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

        if self.n is None:
            raise ValueError('public key is not exist')
        if self.e is None:
            raise ValueError('public exponent is not exist')
        return pow(m, self.e, self.n)

    def decrypt(self, c):
        """RSA decrypt

        decrypt ciphertext

        Args:
            c (int): ciphertext
            n (int): public key n
            d (int): private key d

        Returns:
            int: plaintext
        """
        if self.n is None:
            raise ValueError('public key is not exist')
        elif self.d is None:
            raise ValueError('private exponent is not exist')
        return pow(c, self.d, self.n)

    @classmethod
    def generate(cls, k):
        """

        generate RSA key

        Args:
            k (int): security paramator

        Returns:
            RSA: RSA object
        """
        p = get_prime(k // 2)
        q = get_prime(k // 2)
        
        while not is_coprime(p, q):
            q = get_prime(k // 2)

        n = p * q
        e = 65537
        d = rsa_calc_privatekey(p, q, e)
        return cls(n, e, p, q, d)

    @classmethod
    def construct(cls, n, e, p=None, q=None, d=None):
        if not n or not e:
            raise ValueError('n or e needed!')

        if d:
            p, q = rsa_primes_from_privatekey(e, d, n) 

        if p and q and not d:
            d = rsa_calc_privatekey(p, q, e)
        return cls(n, e, p, q, d)

    @classmethod
    def import_key_der(cls, data):
        key_structs = {
            "public": RSAPublicKeyStruct(),
            "private": RSAPrivateKeyStruct()
        } 

        for k in key_structs:
            try:
                key_data, _ = decoder.decode(data, asn1Spec=key_structs[k])
                if k == "public":
                    return cls.construct(
                        key_data['modulus'],
                        key_data['publicExponent']
                    )
                else:
                    return cls.construct(
                        key_data['modulus'],
                        key_data['publicExponent'],
                        key_data['prime1'],
                        key_data['prime2'],
                        key_data['privateExponent']
                    )
            except:
                continue
        raise ValueError('invalid key')

    @classmethod
    def import_key_pem(cls, data):
        pem_decoded = pem.decode(data)
        if pem_decoded.get(pem.RSA_PRIVATE):
            return cls.import_key_der(pem_decoded[pem.RSA_PRIVATE][0])
        elif pem_decoded.get(pem.RSA_PUBLIC):
            return cls.import_key_der(pem_decoded[pem.RSA_PUBLIC][0])
        raise ValueError('invalid key')
