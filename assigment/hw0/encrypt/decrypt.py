from sympy import *
import os
import random
import itertools
from tqdm import tqdm


def op1(p, s):
    return sum([i * j for i, j in zip(s, p)]) % 256

def op2(m, k):
    return bytes([i ^ j for i, j in zip(m, k)])

def op3(m, p):
    return bytes([m[p[i]] for i in range(len(m))])

def op4(m, s):
    return bytes([s[x] for x in m])


def inv_op3(m, p):
    inv_dict = dict()
    for i in range(len(p)):
        inv_dict[p[i]] = i
    return bytes([m[ inv_dict[i] ] for i in range(len(m))])

def inv_op4(m, s):
    inv_dict = dict()
    for i in range(len(s)):
        inv_dict[s[i]] = i
    return bytes([inv_dict[x] for x in m])

def stage0(m):
    random.seed('oalieno')
    p = [int(random.random() * 256) for i in range(16)]
    s = [int(random.random() * 256) for i in range(16)]
    c = b''
    for x in m:
        k = op1(p, s)
        c += bytes([x ^ k])
        s = s[1:] + [k]
    return c

def stage1(m):
    random.seed('oalieno')
    k = [int(random.random() * 256) for i in range(16)]
    p = [i for i in range(16)]
    random.shuffle(p)
    s = [i for i in range(256)]
    random.shuffle(s)

    c = m
    for i in range(16):
        c = op2(c, k)
        c = op3(c, p)
        c = op4(c, s)
    return c

def inv_stage1(m):
    random.seed('oalieno')
    k = [int(random.random() * 256) for i in range(16)]
    p = [i for i in range(16)]
    random.shuffle(p)
    s = [i for i in range(256)]
    random.shuffle(s)

    c = m
    for i in range(16):
        c = inv_op4(c, s)
        c = inv_op3(c, p)
        c = op2(c, k)
    return c



flag = open('cipher', 'rb').read()
assert(len(flag) == 16)
stage = [stage0, inv_stage1]

for i in tqdm(itertools.product('01', repeat=8)):
    key = [int(j) for j in i]
    m = flag
    for j in key:
        m = stage[j](m)
    if m[:4] == b"FLAG":
        print(m)
        break