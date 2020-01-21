from pwn import *
from Crypto.Util.number import *

r = remote('edu-ctf.csie.org', 10191)
r.sendlineafter('> ', '1')
exec(r.recvline())
exec(r.recvline())
exec(r.recvline())

def pollard(n):
	a = 2
	b = 2
	while True:
		a = pow(a, b, n)
		d = GCD(a-1, n)
		if 1 < d < n: return d
		b += 1

p = pollard(n)
q = n // p
d = inverse(e, (p-1)*(q-1))
m = pow(c, d, n)

print(long_to_bytes(m))