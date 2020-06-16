from cryptolib.number import *
from cryptolib.rsa import *
from cryptolib.encoding import *
from cryptolib.rsa_attack import wieners_attack

p = get_prime(512)
q = get_prime(512)
n = p * q

d = get_prime(64)
e = rsa_calc_privatekey(p, q, d)

m = bytes2long(b'crypto{wl3n3r5_aT74ck}')
c = rsa_encrypt(m, n, e)

print(f"n = {n}")
print(f"e = {e}")
print(f"c = {c}\n")

print("guess...")
guess_d = wieners_attack(e, n)

if guess_d is not None:
    print("Hacked d!")
    print(f"d = {guess_d}")
    print("-" * 30)
    print(f"decrypt: {long2bytes(rsa_decrypt(c, n, guess_d))}")
else:
    print("Hmm...")