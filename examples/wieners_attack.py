from cryptolib.number import get_prime
from cryptolib.pubkey.RSA import rsa_calc_privatekey, rsa_decrypt, RSA
from cryptolib.attack.RSA import wieners_attack
from cryptolib.util.binary import long2bytes

p = get_prime(512)
q = get_prime(512)
n = p * q

d = get_prime(64)
e = rsa_calc_privatekey(p, q, d)

m = b'crypto{wl3n3r5_aT74ck}'
rsa = RSA.construct(n, e)
c = rsa.encrypt(m)

print(f"n = {n}")
print(f"e = {e}")
print(f"c = {c}\n")

print("guess...")
guess_d = wieners_attack(e, n)

if guess_d is not None:
    print("Hacked d!")
    print(f"d = {guess_d}")
    print("-" * 30)
    print(f"decrypt: {long2bytes(rsa_decrypt(c, guess_d, n))}")
else:
    print("Hmm...")
