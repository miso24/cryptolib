from cryptolib.number import get_prime
from cryptolib.encoding import long2bytes, bytes2long
from cryptolib.rsa_attack import common_modulus_attack

p = get_prime(512)
q = get_prime(512)

n = p * q
e1 = 65537
e2 = 39317

m = bytes2long(b'crypto{c0mmon_mo9u1us_a7t5ck}')
c1 = pow(m, e1, n)
c2 = pow(m, e2, n)

print(f"c1: {c1}")
print(f"c2: {c2}")

hack_m = common_modulus_attack(n, e1, e2, c1, c2)

print("-" * 20)
print(f"Hacked m: {m}")
print(long2bytes(m).decode())
