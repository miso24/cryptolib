from cryptolib.rsa import rsa_keygen, rsa_encrypt, rsa_decrypt
from cryptolib.encoding import bytes2long, long2bytes

n, e, d = rsa_keygen(1024)

plaintext = 'This is RSA!'
m = bytes2long(plaintext.encode())

encrypted = rsa_encrypt(m, n, e)
decrypted = rsa_decrypt(encrypted, n, d)

print(f"plaintext: {plaintext}")
print("-" * 20)
print(f"encrypt!: {encrypted}")
print(f"decrypt!: {long2bytes(decrypted)}")
