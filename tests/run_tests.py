#!/usr/bin/env python3
"""Reproducible correctness tests against Python specifications and real libcrypto."""
import argparse, ctypes as C, hashlib, hmac, json, os, platform, random, shlex, shutil, struct, subprocess, sys, tempfile
from pathlib import Path
from reference import block, original, ctr
ROOT=Path(__file__).resolve().parents[1]
os.chdir(ROOT)
parser=argparse.ArgumentParser();parser.add_argument('--sanitize',action='store_true');args=parser.parse_args()
cc=shlex.split(os.environ.get('CC','cc'))
flags=shlex.split(os.environ.get('CFLAGS','-O2 -Wall -Wextra -Werror'))
try:
    openssl=shlex.split(subprocess.check_output(['pkg-config','--cflags','--libs','openssl'],stderr=subprocess.DEVNULL,text=True))
except (OSError,subprocess.CalledProcessError):
    prefix=next((p for p in [Path('/opt/homebrew/opt/openssl'),Path('/usr/local/opt/openssl')] if p.exists()),None)
    openssl=([f'-I{prefix}/include',f'-L{prefix}/lib','-lcrypto'] if prefix else ['-lcrypto'])
P=C.c_void_p; Z=C.c_size_t; U=C.c_ubyte
class Ctx(C.Structure): _fields_=[('enc',U*16),('mac',U*32)]
def buf(data):
    if isinstance(data,int):return C.create_string_buffer(max(data,1))
    return C.create_string_buffer(data,max(len(data),1))
def api(lib,name,types,ret=C.c_int):
    f=getattr(lib,name);f.argtypes=types;f.restype=ret;return f
rng=random.Random(20261010)
def rand(n):return bytes(rng.randrange(256) for _ in range(n))
checks=0
def check(ok,msg):
    global checks
    checks+=1
    if not ok:raise AssertionError(msg)
lengths=list(range(0,66))+[127,128,129,255,256,257,1023,1024,4095,4096]
with tempfile.TemporaryDirectory(prefix='txxtea-tests-') as td:
    td=Path(td)
    def build(name,sources,extra=()):
        target=td/(name+('.dylib' if sys.platform=='darwin' else '.so'))
        subprocess.run(cc+flags+['-shared','-fPIC']+sources+list(extra)+['-o',str(target)],check=True)
        return C.CDLL(str(target))
    base=build('original',['xxtea.c'])
    libc=C.CDLL(None);free=api(libc,'free',[P],None)
    rawenc=api(base,'xxtea_encrypt_raw',[P,Z,P,C.POINTER(Z)],P)
    rawdec=api(base,'xxtea_decrypt_raw',[P,Z,P,C.POINTER(Z)],P)
    legacy=api(base,'xxtea_encrypt',[P,Z,P,C.POINTER(Z)],P)
    def alloc_call(f,data,key):
        n=Z(99);p=f(buf(data),len(data),buf(key),C.byref(n))
        if not p:return None,n.value
        result=C.string_at(p,n.value);free(p);return result,n.value
    for n in lengths[1:]:
        key=rand(16);pt=rand(n);ct,size=alloc_call(rawenc,pt,key)
        check(ct==original(pt,key),f'original reference {n}')
        check(alloc_call(rawdec,ct,key)==(pt,n),f'original inverse {n}')
    for key in [b'',b'a',b'1234567890',b'abc\0ignored']:
        ct,n=alloc_call(legacy,b'hello',key)
        normalized=key.split(b'\0')[0][:16].ljust(16,b'\0')
        check(ct==original(b'hello',normalized),'legacy string compatibility')
    for n in [0,1,2,3,4,5,6,7,9,10,11,13]:check(alloc_call(rawdec,bytes(n),bytes(16))==(None,0),'invalid ciphertext size')
    outlen=Z(42);check(not rawenc(None,1,buf(bytes(16)),C.byref(outlen)) and outlen.value==0,'null plaintext')
    check(not rawenc(buf(b'x'),1,buf(bytes(16)),None),'null length')
    for n in [2**32,2**64-1] if C.sizeof(Z)==8 else [2**32-1]:
        check(not rawenc(buf(b'x'),n,buf(bytes(16)),C.byref(outlen)),'oversize base')
    key1=b'\0'+bytes(range(1,16));key2=b'\0'+b'X'*15
    check(alloc_call(rawenc,b'hello',key1)[0]!=alloc_call(rawenc,b'hello',key2)[0],'binary key tail matters')
    libs={};vectors={}
    for v,stem in [('A','xxtea128'),('B','txxtea128'),('C','txxtea128_rs'),('D','txxtea128'),('E','txxtea128'),('F','txxtea128'),('G','txxtea128_h')]:
        sources=[f'variants/variant_{v}/{stem}.c']
        if v in 'DEF':sources += [f'variants/variant_{v}/'+{'D':'txxtea_etm.c','E':'txxtea_etm_ctx.c','F':'txxtea_etm_aad.c'}[v]]
        lib=build(v,sources,openssl if v in 'DEF' else []);libs[v]=lib
        enc=api(lib,stem+'_encrypt_block',[P,P,P]+([] if v=='A' else [P]),None)
        dec=api(lib,stem+'_decrypt_block',[P,P,P]+([] if v=='A' else [P]),None)
        stream=api(lib,stem+'_ctr_xor',[P,Z,P,P])
        spec=v if v in 'ABCG' else 'B'
        for i in range(200):
            pt,key,tweak=(bytes(range(16)),bytes(range(16,32)),bytes(range(32,48))) if i==0 else (rand(16),rand(16),rand(16))
            out=buf(16);k=buf(key);t=buf(tweak)
            tail=[k]+([] if v=='A' else [t])
            enc(out,buf(pt),*tail);expected=block(pt,key,tweak,spec)
            check(out.raw[:16]==expected,f'{v} reference {i}')
            if i==0:vectors[v]={'plaintext':pt.hex(),'key':key.hex(),'tweak':tweak.hex(),'ciphertext':expected.hex()}
            dec(out,out,*tail);check(out.raw[:16]==pt,f'{v} inverse/in-place {i}')
            enc(out,out,*tail);check(out.raw[:16]==expected,f'{v} encrypt in-place {i}')
        for n in lengths:
            pt,key,nonce=rand(n),rand(16),rand(12);out=buf(pt)
            check(stream(out,n,buf(key),buf(nonce))==1,f'{v} CTR success')
            check(out.raw[:n]==ctr(pt,key,nonce,spec),f'{v} CTR reference {n}')
            stream(out,n,buf(key),buf(nonce));check(out.raw[:n]==pt,f'{v} CTR roundtrip {n}')
        out=buf(b'canary');before=out.raw
        check(not stream(None,1,buf(bytes(16)),buf(bytes(12))),f'{v} null data')
        if C.sizeof(Z)==8:check(not stream(out,2**36+1,buf(bytes(16)),buf(bytes(12))) and out.raw==before,f'{v} counter overflow rejection')
        print(f'{v}: independent block/CTR reference, inverse, in-place, lengths, invalid arguments PASS')
    master=bytes(range(32));mk=buf(master);nonce=bytes(range(12))
    enc_key=hmac.digest(master,b'enc','sha256')[:16];mac_key=hmac.digest(master,b'mac','sha256')
    dseal=api(libs['D'],'txxtea_etm_seal',[P,Z,P,C.POINTER(P),C.POINTER(Z)])
    dopen=api(libs['D'],'txxtea_etm_open',[P,Z,P,C.POINTER(P),C.POINTER(Z)])
    def d_open(packet,key=master):
        p=P();n=Z(999);ok=dopen(buf(packet),len(packet),buf(key),C.byref(p),C.byref(n))
        data=C.string_at(p,n.value) if p.value else None
        if p.value:free(p)
        return ok,data,n.value
    def packet_ref(pt,nonce,aad=None):
        packet=(b'TX1' if aad is None else b'TX2')+b'\x01'+nonce+struct.pack('<I',len(pt))
        if aad is not None:packet+=struct.pack('<I',len(aad))+aad
        packet+=ctr(pt,enc_key,nonce,'B')
        return packet+hmac.digest(mac_key,packet,'sha256')
    contexts={}
    for v in 'EF':
        ctx=Ctx();prefix='txxtea_etm'+('_aad' if v=='F' else '')
        init=api(libs[v],prefix+'_ctx_init',[P,P]);check(init(C.byref(ctx),mk)==1,'ctx init')
        check(bytes(ctx.enc)==enc_key and bytes(ctx.mac)==mac_key,'independent KDF')
        contexts[v]=ctx
    eseal=api(libs['E'],'txxtea_etm_seal_into',[P,P,Z,P,P,Z,C.POINTER(Z)])
    eopen=api(libs['E'],'txxtea_etm_open_into',[P,P,Z,P,Z,C.POINTER(Z)])
    fseal=api(libs['F'],'txxtea_etm_aad_seal_into',[P,P,Z,P,Z,P,P,Z,C.POINTER(Z)])
    fopen=api(libs['F'],'txxtea_etm_aad_open_into',[P,P,Z,P,Z,C.POINTER(Z),P,Z,C.POINTER(Z)])
    def into_open(v,packet,cap=5000,acap=5000):
        out=buf(b'Z'*5000);aout=buf(b'Q'*5000);n=Z(99);an=Z(99)
        if v=='E':ok=eopen(C.byref(contexts[v]),buf(packet),len(packet),out,cap,C.byref(n))
        else:ok=fopen(C.byref(contexts[v]),buf(packet),len(packet),out,cap,C.byref(n),aout,acap,C.byref(an))
        if not ok:
            check(n.value==0 and out.raw[:5000]==b'Z'*5000,'reject without plaintext')
            if v=='F':check(an.value==0 and aout.raw[:5000]==b'Q'*5000,'reject without AAD')
        return ok,out.raw[:n.value],aout.raw[:an.value] if v=='F' else None
    for n in lengths:
        pt=rand(n);p=P();pn=Z();check(dseal(buf(pt) if n else None,n,mk,C.byref(p),C.byref(pn))==1,'D seal')
        packet=C.string_at(p,pn.value);free(p)
        check(packet==packet_ref(pt,packet[4:16]),'D independent envelope/HMAC')
        check(d_open(packet)==(1,pt,n),'D roundtrip')
        check(into_open('E',packet)[0:2]==(1,pt),'D to E compatibility')
        for v in 'EF':
            aad=rand(n%33);out=buf(n+len(aad)+56);size=Z()
            if v=='E':ok=eseal(C.byref(contexts[v]),buf(pt),n,buf(nonce),out,len(out),C.byref(size))
            else:ok=fseal(C.byref(contexts[v]),buf(pt),n,buf(aad),len(aad),buf(nonce),out,len(out),C.byref(size))
            packet=out.raw[:size.value];expected=packet_ref(pt,nonce,aad if v=='F' else None)
            check(ok==1 and packet==expected,f'{v} independent envelope/HMAC')
            opened=into_open(v,packet);check(opened[0:2]==(1,pt),f'{v} roundtrip')
            if v=='F':check(opened[2]==aad,'F AAD')
            else:check(d_open(packet)==(1,pt,n),'E to D compatibility')
    for v in 'DEF':
        packet=packet_ref(b'authenticated message',nonce,b'metadata' if v=='F' else None)
        op=d_open if v=='D' else lambda x:into_open(v,x)
        for i in range(len(packet)*8):
            tampered=bytearray(packet);tampered[i//8]^=1<<(i%8)
            check(op(bytes(tampered))[0]==0,f'{v} tamper bit {i}')
        for n in range(len(packet)):check(op(packet[:n])[0]==0,f'{v} truncation {n}')
        check(op(packet+b'\0')[0]==0,f'{v} trailing byte')
        if v=='D':check(d_open(packet,bytes(32))[0]==0,'D wrong key')
        else:
            saved=contexts[v];contexts[v]=Ctx();check(op(packet)[0]==0,f'{v} wrong key');contexts[v]=saved
            check(into_open(v,packet,cap=1)[0]==0,f'{v} short capacity')
            if v=='F':check(into_open(v,packet,acap=1)[0]==0,'F short AAD capacity')
        for offset in ([16,20] if v=='F' else [16]):
            corrupted=bytearray(packet);corrupted[offset:offset+4]=b'\xff'*4
            check(op(bytes(corrupted))[0]==0,'oversized declared lengths')
        print(f'{v}: independent HMAC/KDF/envelope, every-bit tamper, truncation, wrong key PASS')
    out=buf(b'Z'*100);n=Z(99)
    check(not eseal(C.byref(contexts['E']),buf(b'x'),1,buf(nonce),out,52,C.byref(n)) and n.value==0 and out.raw[:100]==b'Z'*100,'E short seal buffer')
    check(not fseal(C.byref(contexts['F']),buf(b'x'),1,buf(b'a'),1,buf(nonce),out,56,C.byref(n)) and n.value==0,'F short seal buffer')
    for v in 'EF':
        clear=api(libs[v],'txxtea_etm'+('_aad' if v=='F' else '')+'_ctx_clear',[P],None)
        clear(C.byref(contexts[v]));check(bytes(contexts[v])==bytes(48),'context wipe')
    # Frozen vectors guard against changes to both reference and implementation.
    fixture=ROOT/'tests/known_answers.json'
    check(json.loads(fixture.read_text())==vectors,'frozen known-answer vectors')
    fault_exe=td/'allocation_failures'
    fault_flags=['-fsanitize=address,undefined','-fno-omit-frame-pointer'] if args.sanitize else []
    subprocess.run(cc+flags+fault_flags+['tests/allocation_failures.c','-o',str(fault_exe)],check=True)
    subprocess.run([str(fault_exe)],check=True)
    if args.sanitize:
        exe=td/'sanitizer'
        sources=['tests/sanitize.c','xxtea.c','example/base64.c','variants/variant_A/xxtea128.c','variants/variant_B/txxtea128.c','variants/variant_C/txxtea128_rs.c','variants/variant_G/txxtea128_h.c','variants/variant_D/txxtea_etm.c','variants/variant_E/txxtea_etm_ctx.c','variants/variant_F/txxtea_etm_aad.c']
        subprocess.run(cc+['-O1','-g','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-fno-omit-frame-pointer','-Iinclude']+sources+openssl+['-o',str(exe)],check=True)
        subprocess.run([str(exe)],check=True,env={**os.environ,'UBSAN_OPTIONS':'halt_on_error=1'})
    print(f'PASS: {checks} assertions; {platform.platform()}; sanitizer={args.sanitize}')
