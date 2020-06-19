from cryptolib.rsa import RSA
from cryptolib.encoding.bytes import bytes2long, long2bytes

n, e, d = RSA.keygen(1024)

plaintext = 'This is RSA!'
m = bytes2long(plaintext.encode())

encrypted = RSA.encrypt(m, n, e)
decrypted = RSA.decrypt(encrypted, n, d)

print(f"plaintext: {plaintext}")
print("-" * 20)
print(f"encrypt!: {encrypted}")
print(f"decrypt!: {long2bytes(decrypted)}")
