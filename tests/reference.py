"""Independent word-loop specification; not a production crypto implementation."""
import struct
MASK = 0xffffffff
DELTA = 0x9e3779b9

def rot(x, r):
    r %= 32
    return ((x << r) | (x >> ((32-r) % 32))) & MASK

def words(b): return list(struct.unpack('<' + 'I'*(len(b)//4), b))
def packed(v): return struct.pack('<'+'I'*len(v), *v)
def mx(s,y,z,p,e,k):
    a = (((z>>5) ^ ((y<<2)&MASK)) + ((y>>3) ^ ((z<<4)&MASK))) & MASK
    b = ((s^y) + (k[(p&3)^e]^z)) & MASK
    return a ^ b

def encrypt_words(v,k,variant='original',t=None):
    v=list(v); t=t or [0]*4
    rounds = 32 if variant=='G' else 6+52//len(v)
    keys=[]; s=0
    state=[t[i]^rot(t[(i+1)%4],3) for i in range(4)]
    for r in range(rounds):
        s=(s+DELTA)&MASK
        if variant=='G':
            state=[(rot(state[p]^k[(p+r)%4],9)+(t[(p+r)%4]^s))&MASK for p in range(4)]
            rk=[state[p]^rot(state[(p+1)%4],11) for p in range(4)]
        elif variant=='C':
            mix=(s+0x7f4a7c15*(r+1))&MASK
            const=[0,0xa5a5a5a5,0x3c3c3c3c,0x5a5a5a5a]
            rk=[k[p]^rot(t[p],r+p)^mix^const[p] for p in range(4)]
        else: rk=k
        keys.append(rk)
    if variant=='G':
        v=[v[p]^keys[0][p]^rot(keys[0][(p+1)%4],5) for p in range(4)]
    s=0
    for r in range(rounds):
        s=(s+DELTA)&MASK; e=(s>>2)&3
        for p in range(len(v)):
            mix=mx(s,v[(p+1)%len(v)],v[(p-1)%len(v)],p,e,keys[r])
            if variant in ('B','C'): mix ^= t[p]
            v[p]=(v[p]+mix)&MASK
    if variant=='G':
        v=[v[p]^keys[-1][p]^rot(keys[-1][(p+1)%4],13) for p in range(4)]
    return v

def block(data,key,tweak,variant):
    return packed(encrypt_words(words(data),words(key),variant,words(tweak)))
def original(data,key):
    padded=data+b'\0'*((-len(data))%4)
    return packed(encrypt_words(words(padded)+[len(data)],words(key)))
def ctr(data,key,nonce,variant):
    out=bytearray(data)
    for offset in range(0,len(data),16):
        t=nonce+struct.pack('<I',offset//16)
        stream=block(t if variant=='A' else bytes(16),key,t,variant)
        for i in range(min(16,len(data)-offset)): out[offset+i]^=stream[i]
    return bytes(out)
