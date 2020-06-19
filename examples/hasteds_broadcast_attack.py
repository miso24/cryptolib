from cryptolib.number import *
from cryptolib.encoding.bytes import *
from cryptolib.rsa import RSA
from cryptolib.rsa.attack import *

m = bytes2long(b'crypto{h4s73ds_br0adc45t_a7t4ck}')
e = 17
nl = []
cl = []

for i in range(e):
    p = get_prime(512)
    q = get_prime(512)
    n = p * q
    c = RSA.encrypt(m, n, e)
    nl.append(n)
    cl.append(c)

guess_m, rslt = hasteds_broadcast_attack(e, nl, cl)

print("guess...")
if rslt:
    print(long2bytes(guess_m))
else:
    print('Failed!')
