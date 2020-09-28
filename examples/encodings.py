from cryptolib.util.binary import *
from cryptolib.encoding.basex import b16enc, b32enc, b58enc, b64enc, b85enc

m = "Hello,World!"

print(f"Base16: {b16enc(m.encode()).decode()}")
print(f"Base32: {b32enc(m.encode()).decode()}")
print(f"Base58: {b58enc(m.encode()).decode()}")
print(f"Base64: {b64enc(m.encode()).decode()}")
print(f"Base85: {b85enc(m.encode()).decode()}")
print(f"long  : {bytes2long(m.encode())}")
