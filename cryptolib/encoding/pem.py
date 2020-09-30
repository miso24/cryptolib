from cryptolib.encoding.basex import b64dec, b64enc
from typing import Dict, Union
import textwrap
import re


# PEM STRING
X509_OLD = "X509 CERTIFICATE"
X509 = "CERTIFICATE"
X509_TRUSTED = "TRUSTED CERTIFICATE"
X509_REQ_OLD = "NEW CERTIFICATE REQUEST"
X509_REQ = "CERTIFICATE REQUEST"
X509_CRL = "X509 CRL"
EVP_PKEY = "ANY PRIVATE KEY"
PUBLIC = "PUBLIC KEY"
RSA_PRIVATE = "RSA PRIVATE KEY"
RSA_PUBLIC = "RSA PUBLIC KEY"
DSA_PRIVATE = "DSA PRIVATE KEY"
DSA_PUBLIC = "DSA PUBLIC KEY"
PKCS7 = "PKCS7"
PKCS7_SIGNED = "PKCS7 #7 SIGNED DATA"
PKCS8 = "ENCRYPTED PRIVATE KEY"
PKCS8INF = "PRIVATE KEY"
DHPARAMS = "DH PARAMETERS"
DHXPARAMS = "x9.42 DH PARAMETERS"
SSL_SESSION = "SSL SESSION PARAMETERS"
DSAPARAMS = "DSA PARAMETERS"
ECDSA_PUBLIC = "DCDSA PUBLIC KEY"
ECPARAMETERS = "EC PARAMETERS"
ECPRIVATEKEY = "EC PRIVATE KEY"
PARAMETERS = "PARAMETERS"
CMS = "CMS"


def encode(data: bytes, label: str) -> bytes:
    """

    PEM encode

    Args:
        data (bytes)
        label (str)

    Returns:
        bytes: PEM encoded data
    """
    encoded_data = b64enc(data).decode()
    wrapped_data = textwrap.fill(encoded_data, width=64)

    pem_data = f"-----BEGIN {label}-----\n"
    pem_data += wrapped_data + "\n"
    pem_data += f"-----END {label}-----"
    return pem_data.encode()


def decode(pem_data: Union[str, bytes]) -> Dict[str, bytes]:
    """

    PEM decode

    Args:
        pem_data (str): PEM encoded data

    Returns:
        Dict[str, bytes]: PEM decoded data
    """
    if isinstance(pem_data, bytes):
        pem_data = pem_data.decode()
    rslt = {}
    pattern = re.compile(
        r"-----BEGIN (?P<marker>[A-Z\s]+)-----\n(.+?)\n-----END (?P=marker)-----\n?", re.DOTALL)
    for pem in pattern.finditer(pem_data):
        marker, data = pem.groups()
        decoded_data = b64dec(''.join(data.split('\n')))

        if marker not in rslt:
            rslt[marker] = []
        rslt[marker].append(decoded_data)
    return rslt
