# Validation record — 2026-10-10

Environment: Apple Silicon/ARM64, macOS, Apple Clang 21, Python 3 and real
OpenSSL libcrypto. All recorded commands completed successfully. Test counts
refer to Python assertions; C assertion loops and sanitizer coverage are
additional and are not included in those counts.

## Aggregate suite

- `python3 tests/run_tests.py --sanitize`: **11,045 assertions** passed.
- ASan/UBSan: 512 message lengths, short string-key regression, strict Base64
  and 5,000 deterministic malformed inputs; no reported sanitizer errors.
- Allocation-failure driver: all six base encrypt/decrypt allocation paths.
- Independent Python block/CTR reference for A/B/C/G and the B cores in D/E/F.
- Independent HMAC/KDF/envelope checks, D/E interoperability, every-bit
  mutation, all truncations of representative packets, wrong keys, appended
  bytes, short buffers and oversized declared lengths.
- Combined E/F public headers compile with distinct header-size constants.
- `make -B all CFLAGS='-O2 -Wall -Wextra -Werror'`: all targets built.
- `make run`: all benchmark round trips reported success; D/F demos rejected
  tampering. Benchmarks are timing tools, not cryptanalytic evaluations.
- CMake shared/static library build and example CTest passed.

The aggregate tests and source tree are preserved on `archive/suite`.

## Independent projects

Each standalone candidate passed `make test-sanitize`, a forced Make build
with `-Wall -Wextra -Werror`, and a CMake build plus CTest. These candidates
are the source trees used for `main` and the A–G tags.

- Original XXTEA: **172** assertions, allocation-failure tests and sanitizers.
- A: **834** assertions and sanitizers.
- B: **834** assertions and sanitizers.
- C: **834** assertions and sanitizers.
- D: **2,382** assertions and sanitizers.
- E: **2,389** assertions and sanitizers.
- F: **3,456** assertions and sanitizers.
- G: **834** assertions and sanitizers.

Total standalone Python checks: **11,735**. Original CTest also runs the
example; other CTest targets run the selected project's reference tests.
Runtime sources and helper includes are local to each independent checkout.

## Interpretation

The checks establish agreement with the specified implementations on the
covered cases, rejection behavior and the absence of sanitizer findings in
those runs. They are not exhaustive and do not establish cryptanalytic
security, timing resistance or a safe deployment profile. Native Windows,
32-bit, big-endian and embedded execution have not been performed. No
exhaustive OpenSSL failure injection has been performed. The known-answer
fixtures are project regression vectors, not externally certified vectors.
