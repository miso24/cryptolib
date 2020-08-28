from cryptolib.number import get_prime
from cryptolib.encoding.bytes import long2bytes, bytes2long
from cryptolib.pubkey import RSA
from cryptolib.attack.RSA import common_modulus_attack

p = get_prime(512)
q = get_prime(512)

n = p * q
e1 = 65537
e2 = 39317

rsa1 = RSA.construct(n, e1)
rsa2 = RSA.construct(n, e2)

m = 'crypto{c0mmon_mo9u1us_a7t5ck}'

c1 = rsa1.encrypt(m)
c2 = rsa2.encrypt(m)

print(f"c1: {c1}")
print(f"c2: {c2}")

hack_m = common_modulus_attack(n, e1, e2, c1, c2)

print("-" * 20)
print(f"Hacked m: {hack_m}")
print(long2bytes(hack_m).decode())
