#!/usr/bin/env python3
"""Build and validate the single project selected by PROJECT (no sibling checkout)."""
import argparse
import ctypes as C
import hmac
import json
import os
from pathlib import Path
import random
import shlex
import struct
import subprocess
import sys
import tempfile
from reference import block, ctr, original

ROOT = Path(__file__).resolve().parents[1]
os.chdir(ROOT)
PROJECT = (ROOT / 'PROJECT').read_text().strip()
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--sanitize', action='store_true')
args = parser.parse_args()
cc = shlex.split(os.environ.get('CC', 'cc'))
flags = shlex.split(os.environ.get('CFLAGS', '-O2 -Wall -Wextra -Werror'))
stems = dict(A='xxtea128', B='txxtea128', C='txxtea128_rs', D='txxtea128', E='txxtea128', F='txxtea128', G='txxtea128_h')
wrappers = dict(D='txxtea_etm', E='txxtea_etm_ctx', F='txxtea_etm_aad')
sources = ['src/xxtea.c'] if PROJECT == 'original' else ['src/' + stems[PROJECT] + '.c']
openssl = []
if PROJECT in wrappers:
    sources.append('src/' + wrappers[PROJECT] + '.c')
    try:
        openssl = shlex.split(subprocess.check_output(
            ['pkg-config', '--cflags', '--libs', 'openssl'], text=True,
            stderr=subprocess.DEVNULL))
    except (OSError, subprocess.CalledProcessError):
        prefix = next((p for p in (Path('/opt/homebrew/opt/openssl'),
                                  Path('/usr/local/opt/openssl')) if p.exists()), None)
        openssl = [f'-I{prefix}/include', f'-L{prefix}/lib', '-lcrypto'] if prefix else ['-lcrypto']
P, Z = C.c_void_p, C.c_size_t
class Context(C.Structure):
    _fields_ = [('enc', C.c_ubyte * 16), ('mac', C.c_ubyte * 32)]
rng = random.Random(20261010)
checks = 0
lengths = list(range(66)) + [127, 128, 129, 255, 256, 257, 1023, 1024, 4095, 4096]
def rand(n):
    return bytes(rng.randrange(256) for _ in range(n))
def buf(data):
    return C.create_string_buffer(max(data, 1)) if isinstance(data, int) else C.create_string_buffer(data, max(len(data), 1))
def check(condition, message):
    global checks
    checks += 1
    if not condition:
        raise AssertionError(message)
def api(lib, name, types, result=C.c_int):
    fn = getattr(lib, name)
    fn.argtypes, fn.restype = types, result
    return fn
free = api(C.CDLL(None), 'free', [P], None)

def test_original(lib):
    encrypt = api(lib, 'xxtea_encrypt_raw', [P, Z, P, C.POINTER(Z)], P)
    decrypt = api(lib, 'xxtea_decrypt_raw', [P, Z, P, C.POINTER(Z)], P)
    legacy = api(lib, 'xxtea_encrypt', [P, Z, P, C.POINTER(Z)], P)
    def call(fn, data, key):
        n = Z(99)
        out = fn(buf(data), len(data), buf(key), C.byref(n))
        if not out:
            return None, n.value
        data = C.string_at(out, n.value)
        free(out)
        return data, n.value
    for n in lengths[1:]:
        pt, key = rand(n), rand(16)
        ct, size = call(encrypt, pt, key)
        check(ct == original(pt, key), f'original reference length {n}')
        check(call(decrypt, ct, key) == (pt, n), f'original inverse length {n}')
    for key in [b'', b'k', b'abc\0ignored', b'0123456789abcdef']:
        check(call(legacy, b'hello', key)[0] == original(b'hello', key.split(b'\0')[0][:16].ljust(16, b'\0')), 'legacy string key')
    for n in [0, 1, 2, 3, 4, 5, 6, 7, 9, 10, 11, 13]:
        check(call(decrypt, bytes(n), bytes(16)) == (None, 0), 'invalid ciphertext size')
    n = Z(99)
    check(not encrypt(None, 1, buf(bytes(16)), C.byref(n)) and n.value == 0, 'null input')
    check(not encrypt(buf(b'x'), 1, None, C.byref(n)), 'null key')
    check(not encrypt(buf(b'x'), 1, buf(bytes(16)), None), 'null length')
    for size in ([2**32, 2**64 - 1] if C.sizeof(Z) == 8 else [2**32 - 1]):
        check(not encrypt(buf(b'x'), size, buf(bytes(16)), C.byref(n)), 'overflow')
    check(call(encrypt, b'hello', b'\0' + b'A'*15)[0] != call(encrypt, b'hello', b'\0' + b'B'*15)[0], 'binary-key tail')

def test_core(lib):
    stem = stems[PROJECT]
    spec = PROJECT if PROJECT in 'ABCG' else 'B'
    enc = api(lib, stem + '_encrypt_block', [P, P, P] + ([] if PROJECT == 'A' else [P]), None)
    dec = api(lib, stem + '_decrypt_block', [P, P, P] + ([] if PROJECT == 'A' else [P]), None)
    stream = api(lib, stem + '_ctr_xor', [P, Z, P, P])
    fixture = json.loads((ROOT / 'tests/known_answers.json').read_text())[PROJECT]
    for i in range(200):
        pt, key, tweak = ((bytes.fromhex(fixture[k]) for k in ('plaintext', 'key', 'tweak'))
                          if i == 0 else (rand(16), rand(16), rand(16)))
        out = buf(pt)
        tail = [buf(key)] + ([] if PROJECT == 'A' else [buf(tweak)])
        enc(out, out, *tail)
        expected = block(pt, key, tweak, spec)
        check(out.raw[:16] == expected, 'block reference/in-place')
        if i == 0:
            check(out.raw[:16].hex() == fixture['ciphertext'], 'frozen vector')
        dec(out, out, *tail)
        check(out.raw[:16] == pt, 'inverse/in-place')
        enc(out, buf(pt), *tail)
        check(out.raw[:16] == expected, 'disjoint block buffers')
    for n in lengths:
        pt, key, nonce = rand(n), rand(16), rand(12)
        out = buf(pt)
        check(stream(out, n, buf(key), buf(nonce)) == 1, 'stream success')
        check(out.raw[:n] == ctr(pt, key, nonce, spec), 'stream reference')
        check(stream(out, n, buf(key), buf(nonce)) == 1 and out.raw[:n] == pt, 'stream inverse')
    key, nonce, out = buf(bytes(16)), buf(bytes(12)), buf(b'canary')
    check(not stream(None, 1, key, nonce), 'null nonempty input')
    check(stream(None, 0, key, nonce) == 1, 'empty input')
    check(not stream(out, 1, None, nonce), 'null key')
    check(not stream(out, 1, key, None), 'null nonce')
    if C.sizeof(Z) == 8:
        check(not stream(out, 2**36 + 1, key, nonce) and out.raw[:6] == b'canary', 'counter overflow before write')

def test_envelope(lib):
    master, nonce = bytes(range(32)), bytes(range(12))
    ek, mk = hmac.digest(master, b'enc', 'sha256')[:16], hmac.digest(master, b'mac', 'sha256')
    context = Context()
    if PROJECT == 'D':
        seal = api(lib, 'txxtea_etm_seal', [P, Z, P, C.POINTER(P), C.POINTER(Z)])
        open_ = api(lib, 'txxtea_etm_open', [P, Z, P, C.POINTER(P), C.POINTER(Z)])
    else:
        prefix = 'txxtea_etm' + ('_aad' if PROJECT == 'F' else '')
        init = api(lib, prefix + '_ctx_init', [P, P])
        clear = api(lib, prefix + '_ctx_clear', [P], None)
        check(init(C.byref(context), buf(master)) == 1, 'context init')
        check(bytes(context.enc) == ek and bytes(context.mac) == mk, 'independent KDF')
        seal_types = [P, P, Z] + ([P, Z] if PROJECT == 'F' else []) + [P, P, Z, C.POINTER(Z)]
        open_types = [P, P, Z, P, Z, C.POINTER(Z)] + ([P, Z, C.POINTER(Z)] if PROJECT == 'F' else [])
        seal = api(lib, prefix + '_seal_into', seal_types)
        open_ = api(lib, prefix + '_open_into', open_types)
    def expected(pt, nonce, aad=b''):
        packet = (b'TX2' if PROJECT == 'F' else b'TX1') + b'\x01' + nonce + struct.pack('<I', len(pt))
        if PROJECT == 'F':
            packet += struct.pack('<I', len(aad)) + aad
        packet += ctr(pt, ek, nonce, 'B')
        return packet + hmac.digest(mk, packet, 'sha256')
    def open_packet(packet, wrong_key=False, capacity=5000, aad_capacity=5000):
        n, an = Z(99), Z(99)
        if PROJECT == 'D':
            out = P()
            ok = open_(buf(packet), len(packet), buf(bytes(32) if wrong_key else master), C.byref(out), C.byref(n))
            data = C.string_at(out, n.value) if out.value else None
            if out.value:
                free(out)
            if not ok:
                check(not out.value and n.value == 0, 'D rejection output reset')
            return ok, data, None
        out, aout = buf(b'Z'*5000), buf(b'Q'*5000)
        ctx = Context() if wrong_key else context
        tail = [aout, aad_capacity, C.byref(an)] if PROJECT == 'F' else []
        ok = open_(C.byref(ctx), buf(packet), len(packet), out, capacity, C.byref(n), *tail)
        if not ok:
            check(n.value == 0 and out.raw[:5000] == b'Z'*5000, 'no plaintext on rejection')
            if PROJECT == 'F':
                check(an.value == 0 and aout.raw[:5000] == b'Q'*5000, 'no AAD on rejection')
        return ok, out.raw[:n.value], aout.raw[:an.value] if PROJECT == 'F' else None
    for size in lengths:
        pt, aad, n = rand(size), rand(size % 33), Z()
        if PROJECT == 'D':
            out = P()
            ok = seal(buf(pt) if size else None, size, buf(master), C.byref(out), C.byref(n))
            check(ok == 1 and bool(out.value), 'D seal')
            packet = C.string_at(out, n.value)
            free(out)
        else:
            out = buf(size + len(aad) + 56)
            extra = [buf(aad), len(aad)] if PROJECT == 'F' else []
            ok = seal(C.byref(context), buf(pt), size, *extra, buf(nonce), out, len(out), C.byref(n))
            check(ok == 1, 'seal into')
            packet = out.raw[:n.value]
        check(packet == expected(pt, packet[4:16], aad), 'independent packet/HMAC')
        opened = open_packet(packet)
        check(opened[:2] == (1, pt), 'authenticated inverse')
        if PROJECT == 'F':
            check(opened[2] == aad, 'AAD inverse')
    packet = expected(b'authenticated message', nonce, b'metadata')
    for bit in range(len(packet)*8):
        changed = bytearray(packet)
        changed[bit//8] ^= 1 << (bit % 8)
        check(not open_packet(bytes(changed))[0], 'single-bit tamper')
    for size in range(len(packet)):
        check(not open_packet(packet[:size])[0], 'truncated packet')
    check(not open_packet(packet + b'\0')[0], 'trailing byte')
    check(not open_packet(packet, wrong_key=True)[0], 'wrong key')
    for offset in ([16, 20] if PROJECT == 'F' else [16]):
        changed = bytearray(packet)
        changed[offset:offset+4] = b'\xff'*4
        check(not open_packet(bytes(changed))[0], 'oversize length field')
    if PROJECT != 'D':
        check(not open_packet(packet, capacity=1)[0], 'short output capacity')
        if PROJECT == 'F':
            check(not open_packet(packet, aad_capacity=1)[0], 'short AAD capacity')
        out, n = buf(b'Z'*100), Z(99)
        extra = [buf(b'a'), 1] if PROJECT == 'F' else []
        check(not seal(C.byref(context), buf(b'x'), 1, *extra, buf(nonce), out, 1, C.byref(n)), 'short seal capacity')
        check(n.value == 0 and out.raw[:100] == b'Z'*100, 'no write on short seal')
        clear(C.byref(context))
        check(bytes(context) == bytes(48), 'context cleanup')

with tempfile.TemporaryDirectory(prefix='xxtea-project-') as temp:
    temp = Path(temp)
    target = temp / ('project.dylib' if sys.platform == 'darwin' else 'project.so')
    subprocess.run(cc + flags + ['-shared', '-fPIC', '-Iinclude'] + sources + openssl + ['-o', str(target)], check=True)
    library = C.CDLL(str(target))
    if PROJECT == 'original':
        test_original(library)
        fault = temp / 'allocation_failures'
        subprocess.run(cc + flags + (['-fsanitize=address,undefined'] if args.sanitize else []) + ['tests/allocation_failures.c', '-o', str(fault)], check=True)
        subprocess.run([str(fault)], check=True)
    else:
        test_core(library)
        if PROJECT in wrappers:
            test_envelope(library)
    if args.sanitize:
        driver = temp / 'sanitizer'
        extra = ['example/base64.c'] if PROJECT == 'original' else []
        subprocess.run(cc + ['-O1', '-g', '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined',
                       '-fno-omit-frame-pointer', '-Iinclude', '-DPROJECT_' + PROJECT.upper(),
                       'tests/sanitize.c'] + sources + extra + openssl + ['-o', str(driver)], check=True)
        subprocess.run([str(driver)], check=True, env={**os.environ, 'UBSAN_OPTIONS': 'halt_on_error=1'})
print(f'PASS: {PROJECT}, {checks} assertions, sanitizer={args.sanitize}')
