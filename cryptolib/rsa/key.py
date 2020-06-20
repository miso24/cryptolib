from pyasn1.type import namedtype
from pyasn1.type import univ
from pyasn1.codec.der import decoder, encoder
from cryptolib.encoding import pem
from cryptolib.number import inverse_mod

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

class RSAPublicKey:
    """

    RSA public key

    Attributes:
        n (long): RSA modulus
        e (long): RSA public exponent

    """
    def __init__(self):
        self.n = 0
        self.e = 0

    def import_key(self, pem_data):
        """

        import RSA public key data

        Args:
            pem_data (str): PEM format public key

        """
        data = pem.decode(pem_data, pem.RSA_PUBLIC)
        decoded, _ = decoder.decode(data, asn1Spec=RSAPublicKeyStruct())
        self.n = decoded['modulus']
        self.e = decoded['publicExponent']

    def import_key_from_file(self, filename):
        """

        import RSA public key data from file

        Args:
            filename (str): file name of RSA public key

        """
        with open(filename) as f:
            pem_data = f.read()
        self.import_key(pem_data)

    def export_key(self, enc_format="pem"):
        """

        export RSA public key

        Args:
            enc_format (str): encode format

        Returns:
            Union[str, bytes]: encoded RSA public key

        """
        key = RSAPublicKeyStruct()
        key['modulus'] = self.n
        key['publicExponent'] = self.e

        der_encoded = encoder.encode(key)
        if enc_format == "der":
            return der_encoded
        elif enc_format == "pem":
            return pem.encode(der_encoded, pem.RSA_PUBLIC)
        else:
            raise ValueError('format is not exist!')
        
class RSAPrivateKey:
    """

    RSA Private key

    Attributes:
        n (long): RSA modulus
        e (long): RSA public exponent
        d (long): RSA private exponent
        p (long): RSA prime p
        p (long): RSA prime q

    """

    def __init__(self):
        self.n = 0
        self.e = 0
        self.p = 0
        self.q = 0
        self.d = 0

    def import_key(self, pem_data):
        """

        import RSA public key data

        Args:
            pem_data (str): PEM format public key

        """
        data = pem.decode(pem_data, pem.RSA_PRIVATE)
        decoded, _ = decoder.decode(data, asn1Spec=RSAPrivateKeyStruct())
        self.n = decoded['modulus']
        self.e = decoded['publicExponent']
        self.d = decoded['privateExponent']
        self.p = decoded['prime1']
        self.q = decoded['prime2']

    def import_key_from_file(self, filename):
        """

        import RSA public key data from file

        Args:
            filename (str): file name of RSA public key

        """
        with open(filename) as f:
            pem_data = f.read()
        self.import_key(pem_data) 

    def export_key(self, enc_format="pem"):
        """

        export RSA public key

        Args:
            enc_format (str): encode format

        Returns:
            Union[str, bytes]: encoded RSA public key

        """
        key = RSAPrivateKeyStruct()
        key['version'] = 0
        key['modulus'] = self.n
        key['publicExponent'] = self.e
        key['privateExponent'] = self.d
        key['prime1'] = self.p
        key['prime2'] = self.q
        key['exponent1'] = self.d % (self.p - 1)
        key['exponent2'] = self.d % (self.q - 1)
        key['coefficient'] = inverse_mod(self.p, self.q) 

        der_encoded = encoder.encode(key)
        if enc_format == "der":
            return der_encoded
        elif enc_format == "pem":
            return pem.encode(der_encoded, pem.RSA_PRIVATE)
        else:
            raise ValueError('format is not exist!')
