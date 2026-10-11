# XXTEA · original C library

Variable-length **Corrected Block TEA**, with a 128-bit key and a byte API
that stores the original message length. This is the original algorithm
with reviewed input validation and memory handling; the research variants
live in their own tags.

## Quick start

```sh
git clone https://github.com/C-Mohammad-Sohrabi/txxtea128-suite.git
cd txxtea128-suite
make
make test
make test-sanitize
./bench
./example/xxtea_example
```

Requires a C11-capable C compiler and Make. Tests additionally require
Python 3; **OpenSSL is not needed** for this project. ASan/UBSan needs a
compiler that supports those sanitizers.

## CMake

```sh
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
cmake --install build --prefix ./build/install
```

The build produces shared/static `xxtea` libraries, a benchmark and the
example. The public header is `xxtea.h`; `crypto_util.h` is an internal
source dependency. CTest runs the example and, when Python is available,
the independent reference tests. Source archives build without `.git`.

## API and compatibility

- `xxtea_encrypt` / `xxtea_decrypt` preserve historical string-key behavior:
  stop at the first NUL and pad to 16 bytes. A short terminated string is safe.
- `xxtea_encrypt_raw` / `xxtea_decrypt_raw` consume **exactly 16 readable
  key bytes**, including zeros. Use these for binary keys.
- Successful calls allocate a buffer; the caller must `free()` it. Output
  lengths are byte counts. Failure returns `NULL` and zeros a supplied length.
- Empty plaintext is unsupported by this envelope. Ciphertext must be at
  least 8 bytes and divisible by 4. Invalid lengths and overflow are rejected.
- Old ciphertext produced using string-key truncation still needs the legacy
  API. There is no automatic conversion from truncated to binary keys.

```c
#include <stdint.h>
#include <stdlib.h>
#include "xxtea.h"

int main(void) {
    const uint8_t key[16] = {0}; /* fixed example key only */
    const char message[] = "hello";
    size_t size = 0;
    void *ciphertext = xxtea_encrypt_raw(message, sizeof(message) - 1, key, &size);
    if (!ciphertext) return 1;
    free(ciphertext);
    return 0;
}
```

## Files and verification

`xxtea.c` / `xxtea.h` implement the library; `example/` provides Base64 and a
round-trip program; `bench.c` measures execution; `tests/` contains the
independent reference, failure injection and sanitizer checks. See
[CHANGELOG.md](CHANGELOG.md) for the reviewed fixes and API migration notes.

The algorithm here does not authenticate messages. Successful functional
checks do not prove cryptanalytic security or establish production suitability.
Native Windows, 32-bit, big-endian and embedded execution were not part of
the recorded macOS/ARM64 verification. Modern MinGW users can use
`build_windows.bat`; the script is provided but was not executed on Windows.

## Explore the family

[Original XXTEA (main)](https://github.com/C-Mohammad-Sohrabi/txxtea128-suite/tree/main) · [A](https://github.com/C-Mohammad-Sohrabi/txxtea128-suite/tree/A) · [B](https://github.com/C-Mohammad-Sohrabi/txxtea128-suite/tree/B) · [C](https://github.com/C-Mohammad-Sohrabi/txxtea128-suite/tree/C) · [D](https://github.com/C-Mohammad-Sohrabi/txxtea128-suite/tree/D) · [E](https://github.com/C-Mohammad-Sohrabi/txxtea128-suite/tree/E) · [F](https://github.com/C-Mohammad-Sohrabi/txxtea128-suite/tree/F) · [G](https://github.com/C-Mohammad-Sohrabi/txxtea128-suite/tree/G)

Each A–G tag is a standalone source tree. The letters identify research
variants, not security levels. [archive/suite](https://github.com/C-Mohammad-Sohrabi/txxtea128-suite/tree/archive/suite)
keeps the reviewed aggregate project and interoperability tests. The old
`v0.1.0`–`v0.9.0` tags remain unchanged historical milestones.

## Attribution

Based on `xxtea-c`, with the original algorithm and author notices retained.
See [LICENSE.md](LICENSE.md). The experimental variants are separate research
work; they are not upstream XXTEA releases.
