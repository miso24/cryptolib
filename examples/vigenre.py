from cryptolib.cipher.vigenere import *

plain_text = "Hello,World!"
key = "hoge"

encrypted = vigenere_encrypt(plain_text, key)
decrypted = vigenere_decrypt(encrypted, key)

print(f"plain: {plain_text}")
print(f"encrypted: {encrypted}")
print(f"decrypted: {decrypted}")
