from cryptolib.encoding import *

m = "Hello,World!"

print(f"xor(key=0x10): {xor(m, 0x10)}")
print(f"rot13 : {rot13(m)}")
print(f"base64: {b64enc(m.encode()).decode()}")
print(f"long  : {bytes2long(m.encode())}")
