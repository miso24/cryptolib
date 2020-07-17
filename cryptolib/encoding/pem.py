import textwrap
import re

from cryptolib.encoding.basex import b64dec, b64enc

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


def encode(data, label):
    """

    PEM encode

    Args:
        data (bytes)
        label (str)

    Returns:
        str: PEM encoded data
    """
    encoded_data = b64enc(data).decode()
    wrapped_data = textwrap.fill(encoded_data, width=64)
    
    pem_data = f"-----BEGIN {label}-----\n"
    pem_data += wrapped_data + "\n"
    pem_data += f"-----END {label}-----"
    return pem_data

def decode(pem_data):
    """

    PEM decode

    Args:
        pem_data (str): PEM encoded data

    Returns:
        Dictionary[bytes]: PEM decoded data
    """
    rslt = {}
    pattern = re.compile(r"-----BEGIN (?P<marker>[A-Z\s]+)-----\n(.+?)\n-----END (?P=marker)-----\n?", re.DOTALL)
    for pem in pattern.finditer(pem_data):
        marker, data = pem.groups()
        decoded_data = b64dec(''.join(data.split('\n')))

        if marker not in rslt:
            rslt[marker] = []
        rslt[marker].append(decoded_data)
    return rslt
