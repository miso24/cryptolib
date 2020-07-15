import textwrap
import re

from cryptolib.encoding.basex import b64dec, b64enc

X509_OLD = "X509 CERTIFICATE"
X509 = "CERTIFICATE"
RSA_PRIVATE = "RSA PRIVATE KEY"
RSA_PUBLIC = "RSA PUBLIC KEY"
PRIVATE = "PRIVATE KEY"
PUBLIC_KEY = "PUBLIC KEY"
MARKERS = [X509_OLD, X509, RSA_PRIVATE, RSA_PUBLIC, PUBLIC_KEY]

def encode(data, marker):
    encoded_data = b64enc(data).decode()
    wraped_data = textwrap.fill(encoded_data, width=64)
    
    pem_data = f"-----BEGIN {marker}-----\n"
    pem_data += wraped_data + "\n"
    pem_data += f"-----END {marker}-----"
    return pem_data

def decode(pem_data):
    """

    PEM decode

    Args:
        pem_data (str): PEM encoded data

    Returns:
        Dictionary[bytes]: PEM decoded data
    """
    rslt = {marker: [] for marker in MARKERS}
    for marker in MARKERS:
        pattern = re.compile(f"-----BEGIN {marker}-----\n(.+?)\n-----END {marker}-----\n?", re.DOTALL)
        data = pattern.finditer(pem_data)

        if data is None:
            continue

        for d in data:
            decoded_data = b64dec(''.join(d.group(1).split('\n')))
            rslt[marker].append(decoded_data)
    return rslt
