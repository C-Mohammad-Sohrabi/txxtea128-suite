# Correctness tests

Run `make test` or `make test-sanitize` from the repository root. Python 3,
a C compiler and OpenSSL development libraries are required. The runner
builds temporary shared libraries, so stale benchmark binaries cannot pass a
test accidentally. Temporary build artifacts are deleted after the run.

`reference.py` is a separate Python word-loop definition of original XXTEA,
A/B/C/G and their streams. D/E/F's embedded cores are each checked as B.
`known_answers.json` freezes sample outputs calculated from that reference
and compared with C; these are project regression vectors, not official
third-party vectors. Packet HMAC/KDF values are computed independently with
Python's `hmac` and checked against real OpenSSL output.

Coverage: 200 block cases per variant, inverse and exact in-place block
operations, lengths 0..65 plus 127/128/129, 255/256/257, 1023/1024,
4095/4096; malformed root lengths and argument checks; counter overflow;
D/E interoperability; all single-bit mutations and all truncations of one
representative packet per D/E/F; wrong keys, appended bytes, short buffers,
corrupted length fields, empty messages, context cleanup, binary-key tail
sensitivity, and legacy string compatibility. The allocation-failure driver
fails each of the three base encrypt/decrypt allocations (six paths).

The sanitizer driver tests 512 lengths, short-key safety, strict Base64,
5000 deterministic malformed inputs, and including E/F headers together.
Its 32-bit-only huge-length tests run only when actually built for 32 bits.
The current recorded run is ARM64/macOS; it is not a native 32-bit, Windows,
big-endian or microcontroller validation. No exhaustive OpenSSL fault
injection or constant-time/cryptanalytic evaluation is claimed.
