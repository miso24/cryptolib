from cryptolib.encoding import *

m = "Hello,World!"

print(f"xor(key=0x10): {xor(m, 0x10)}")
print(f"rot13 : {rot13(m)}")
print(f"base16: {b16enc(m.encode()).decode()}")
print(f"base32: {b32enc(m.encode()).decode()}")
print(f"base64: {b64enc(m.encode()).decode()}")
print(f"base85: {b85enc(m.encode()).decode()}")
print(f"long  : {bytes2long(m.encode())}")
