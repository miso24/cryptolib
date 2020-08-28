from cryptolib.number import *
from cryptolib.encoding.bytes import *
from cryptolib.pubkey.RSA import *
from cryptolib.attack.RSA import hasteds_broadcast_attack

m = b'crypto{h4s73ds_br0adc45t_a7t4ck}'
e = 17
nl = []
cl = []

for i in range(e):
    p = get_prime(512)
    q = get_prime(512)
    n = p * q
    c = rsa_encrypt(m, e, n)
    print(f"c{i+1}: {c}")
    print(f"n{i+1}: {n}")
    nl.append(n)
    cl.append(c)

guess_m, rslt = hasteds_broadcast_attack(e, nl, cl)
print(guess_m, rslt)

print("-"*40)
print("guess...")
if rslt:
    print(long2bytes(guess_m))
else:
    print('Failed!')
