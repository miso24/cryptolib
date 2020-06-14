from cryptolib.number import *
from cryptolib.encoding import *
from cryptolib.rsa import *
from cryptolib.rsa_attack import hasteds_broadcast_attack

m = bytes2long(b'crypto{h4s73ds_br0adc45t_a7t4ck}')
e = 17
nl = []
cl = []

for i in range(e):
    p = get_prime(512)
    q = get_prime(512)
    n = p * q
    c = rsa_encrypt(m, n, e)
    nl.append(n)
    cl.append(c)

guess_m, rslt = hasteds_broadcast_attack(e, nl, cl)

print("guess...")
if rslt:
    print(long2bytes(guess_m))
else:
    print('Failed!')
