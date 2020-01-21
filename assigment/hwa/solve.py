from Crypto.Util.number import *
from Crypto.PublicKey import RSA
from pwn import *
import math


def get_encrypt():
    r.sendlineafter("> ", "1")
    c = int(r.recvline().split('=')[-1])
    e = int(r.recvline().split('=')[-1])
    n = int(r.recvline().split('=')[-1])
    return c, e, n

def _decrypt(ciphertext):
    r.sendlineafter("> ", "2")
    r.sendline(str(ciphertext))
    pt = int(r.recvline().strip().split('=')[-1].strip())
    print 'm:', pt
    return pt

r = remote('edu-ctf.csie.org', 10192)
flag_enc, e, N = get_encrypt()

print "flag_enc: ", flag_enc
print "N: ", N
print "e: ", e
print "\n\n"

upper_limit = N
lower_limit = 0

M = [0]*16
for i in range(16):
    M[(0-i*N)%16] = i

flag = ""
i = 1
while i <= 256+4:
    chosen_ct = flag_enc*pow(16**i, e, N) % N
    output = _decrypt(chosen_ct)
    x = M[output]
    R = (upper_limit-lower_limit)
    upper_limit = lower_limit + ((R * (x+1) - 1) / 16)
    lower_limit = lower_limit + ((R * x + 1) / 16)
    i += 1
    
    print i, upper_limit - lower_limit
    if "FLAG{" in long_to_bytes(upper_limit) and long_to_bytes(upper_limit)[-1] == "}":
        print "Flag : ", long_to_bytes(upper_limit)
    if "FLAG{" in long_to_bytes(lower_limit) and long_to_bytes(lower_limit)[-1] == "}":
        print "Flag : ", long_to_bytes(lower_limit)
        
        
print "Flag : ", long_to_bytes(upper_limit)
print "Flag : ", long_to_bytes(lower_limit)

