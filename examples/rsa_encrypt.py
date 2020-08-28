from cryptolib.pubkey import RSA
from cryptolib.encoding.bytes import bytes2long, long2bytes

rsa = RSA.generate(1024)

plaintext = 'This is RSA!'

encrypted = rsa.encrypt(plaintext)
decrypted = rsa.decrypt(encrypted)

print(f"plaintext: {plaintext}")
print("-" * 20)
print(f"encrypt!: {encrypted}")
print(f"decrypt!: {long2bytes(decrypted)}")
