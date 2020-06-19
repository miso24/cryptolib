from cryptolib.encoding.basex import b64dec, b64enc
import textwrap
import re

X509_OLD = "X509 CERTIFICATE"
X509 = "CERTIFICATE"
RSA_PRIVATE = "RSA PRIVATE KEY"
RSA_PUBLIC = "RSA PUBLIC KEY"
PRIVATE = "PRIVATE KEY"
PUBLIC = "PUBLIC KEY"

def encode(data, marker):
    encoded_data = b64enc(data).decode()
    wraped_data = textwrap.fill(encoded_data, width=64)
    
    pem_data = f"-----BEGIN {marker}-----\n"
    pem_data += wraped_data + "\n"
    pem_data += f"-----END {marker}-----"
    return pem_data

def decode(pem_data, marker):
    pattern = re.compile(f"-----BEGIN {marker}-----\n(.+?)\n-----END {marker}-----\n?", re.DOTALL)
    m = pattern.search(pem_data)

    if m is None:
        raise ValueError("Not a valid")

    encoded_data = ''.join(m.group(1).split('\n'))
    data = b64dec(encoded_data)
    return data
