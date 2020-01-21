# memory 4058
# 01334058  45 7B DC 41 B7 35 EC F0 F0 F0 F0 DB F9 7B 35 EC  E{ÜA·5ìððððÛù{5ì  
# 01334068  73 B0 F1 79 35 EC 7B 3D FC F3 3D EC FF AE 01 75  s°ñy5ì{=üó=ìÿ®.u  
# 01334078  C2 64 15 7B 35 F8 F3 35 EC FF AE F8 73 B1 13 73  Âd.{5øó5ìÿ®øs±.s  
# 01334088  E1 56 FF AE C1 7B 35 FC F3 35 EC FF AE F8 2B C1  áVÿ®Á{5üó5ìÿ®ø+Á  
# 01334098  64 F4 23 B0 DB F7 DB B5 A8 F1 F0 F0 F0 7B D5 4D  dô#°Û÷Ûµ¨ñððð{ÕM  
# 013340A8  B3 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ³...............  


# 4058 need to plus seed(16)
# shellcode = "45 7B DC 41 B7 35 EC F0 F0 F0 F0 DB F9 7B 35 EC 73 B0 F1 79 35 EC 7B 3D FC F3 3D EC FF AE 01 75 C2 64 15 7B 35 F8 F3 35 EC FF AE F8 73 B1 13 73 E1 56 FF AE C1 7B 35 FC F3 35 EC FF AE F8 2B C1 64 F4 23 B0 DB F7 DB B5 A8 F1 F0 F0 F0 7B D5 4D B3"
# shellcode.split()
# print(" ".join([hex(int(i, 16) + 16) for i in shellcode.split()]))
# print()


# flag hide in 4018
# xor 66(102)
# minus 23(35)

flag = "0F 09 02 0C F8 FA 30 F0 22 22 FA 30 F0 22 22 FA 30 F0 22 22 35 ED E4 F6 FA E4 EC 35 E1 22 22 C6"
flag = flag.split()

tmp = []
for i in flag:
	tmp.append(chr((int(i, 16) ^ 102) - 35))
print("".join(tmp))


# flag = FLAG{y3s!!y3s!!y3s!!0h_my_g0d!!}
