#!/usr/bin/env python3
"""Prepare standalone source trees; does not commit, tag, delete or push refs."""
from pathlib import Path
import json
import shutil

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / '.release-work/candidates'
DEST.mkdir(parents=True, exist_ok=True)
REPO = 'https://github.com/C-Mohammad-Sohrabi/txxtea128-suite'
META = {
    'A': ('XXTEA-128 · fixed block and CTR', 'xxtea128', ['bench_a']),
    'B': ('Tweakable XXTEA-128', 'txxtea128', ['bench_b']),
    'C': ('Tweakable XXTEA-128 · round-key schedule', 'txxtea128_rs', ['bench_c']),
    'D': ('Encrypt-then-MAC · allocating API', 'txxtea128', ['bench_etm', 'demo_etm']),
    'E': ('Encrypt-then-MAC · reusable context', 'txxtea128', ['bench_etm_ctx']),
    'F': ('Encrypt-then-MAC · associated data', 'txxtea128', ['demo_aad']),
    'G': ('XXTEA-128 · feedback schedule and whitening', 'txxtea128_h', ['bench_g']),
}
WRAPPER = {'D':'txxtea_etm', 'E':'txxtea_etm_ctx', 'F':'txxtea_etm_aad'}
NAV = ' · '.join(f'[{v}]({REPO}/tree/{v})' for v in META)
COMMON = f'''## Explore the family

[Original XXTEA (main)]({REPO}/tree/main) · {NAV}

Each A–G tag is a standalone source tree. The letters identify research
variants, not security levels. [archive/suite]({REPO}/tree/archive/suite)
keeps the reviewed aggregate project and interoperability tests. The old
`v0.1.0`–`v0.9.0` tags remain unchanged historical milestones.
'''
ORIGINAL = f'''# XXTEA · original C library

Variable-length **Corrected Block TEA**, with a 128-bit key and a byte API
that stores the original message length. This is the original algorithm
with reviewed input validation and memory handling; the research variants
live in their own tags.

## Quick start

```sh
git clone {REPO}.git
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

int main(void) {{
    const uint8_t key[16] = {{0}}; /* fixed example key only */
    const char message[] = "hello";
    size_t size = 0;
    void *ciphertext = xxtea_encrypt_raw(message, sizeof(message) - 1, key, &size);
    if (!ciphertext) return 1;
    free(ciphertext);
    return 0;
}}
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

{COMMON}
## Attribution

Based on `xxtea-c`, with the original algorithm and author notices retained.
See [LICENSE.md](LICENSE.md). The experimental variants are separate research
work; they are not upstream XXTEA releases.
'''

def put(folder, name, text):
    p = folder / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text.rstrip() + '\n')

def cp(folder, source, name=None):
    target = folder / (name or source)
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(ROOT/source, target)

def cmake(folder, project, sources, headers, programs):
    lib = 'xxtea' if project == 'original' else 'variant_' + project
    text = f'''cmake_minimum_required(VERSION 3.16)
project({lib} LANGUAGES C)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
include(GNUInstallDirs)
include(CTest)
add_library({lib} SHARED {' '.join(sources)})
add_library({lib}_static STATIC {' '.join(sources)})
set_target_properties({lib}_static PROPERTIES OUTPUT_NAME {lib})
'''
    if project in WRAPPER:
        text += 'find_package(OpenSSL REQUIRED COMPONENTS Crypto)\n'
        text += f'target_link_libraries({lib} PRIVATE OpenSSL::Crypto)\ntarget_link_libraries({lib}_static PUBLIC OpenSSL::Crypto)\n'
    text += f'''install(TARGETS {lib} {lib}_static
  LIBRARY DESTINATION ${{CMAKE_INSTALL_LIBDIR}}
  ARCHIVE DESTINATION ${{CMAKE_INSTALL_LIBDIR}}
  RUNTIME DESTINATION ${{CMAKE_INSTALL_BINDIR}})
install(FILES {' '.join(headers)} DESTINATION ${{CMAKE_INSTALL_INCLUDEDIR}})
'''
    for name in programs:
        text += f'add_executable({name} {name}.c)\ntarget_link_libraries({name} PRIVATE {lib}_static)\n'
    if project == 'original':
        text += '''add_executable(xxtea_example example/test.c example/base64.c)
target_include_directories(xxtea_example PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(xxtea_example PRIVATE xxtea_static)
if(BUILD_TESTING)
  add_test(NAME example COMMAND xxtea_example)
endif()
'''
    text += '''if(BUILD_TESTING)
  find_package(Python3 QUIET COMPONENTS Interpreter)
  if(Python3_Interpreter_FOUND)
    add_test(NAME correctness COMMAND ${CMAKE_COMMAND} -E env
      "CC=${CMAKE_C_COMPILER}" ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_tests.py)
  endif()
endif()
'''
    put(folder, 'CMakeLists.txt', text)

for project in ['original', *META]:
    folder = DEST/project
    folder.mkdir(exist_ok=True)
    for name in ['LICENSE.md', 'crypto_util.h', 'CHANGELOG.md', 'VALIDATION.md', '.gitignore']:
        cp(folder, name)
    put(folder, 'PROJECT', project)
    put(folder, '.gitattributes', '* text=auto\n*.c text eol=lf\n*.h text eol=lf\n*.py text eol=lf\n*.md text eol=lf\n*.bat text eol=crlf')
    cp(folder, 'tools/project_tests.py', 'tests/run_tests.py')
    cp(folder, 'tools/project_sanitize.c', 'tests/sanitize.c')
    cp(folder, 'tests/reference.py')
    if project == 'original':
        for name in ['xxtea.c', 'xxtea.h', 'bench.c', 'example/test.c', 'example/base64.c', 'example/base64.h', 'tests/allocation_failures.c']:
            cp(folder, name)
        put(folder, 'README.md', ORIGINAL)
        put(folder, 'Makefile', '''CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra
PYTHON ?= python3
.PHONY: all test test-sanitize run clean
all: bench example/xxtea_example
bench: bench.c xxtea.c xxtea.h crypto_util.h
	$(CC) $(CFLAGS) -o $@ bench.c xxtea.c
example/xxtea_example: example/test.c example/base64.c example/base64.h xxtea.c xxtea.h crypto_util.h
	$(CC) $(CFLAGS) -I. -o $@ example/test.c example/base64.c xxtea.c
run: all
	./example/xxtea_example
	./bench
test:
	$(PYTHON) tests/run_tests.py
test-sanitize:
	$(PYTHON) tests/run_tests.py --sanitize
clean:
	rm -f bench example/xxtea_example *.o
''')
        put(folder, 'build_windows.bat', '''@echo off
setlocal
gcc -O2 -Wall -Wextra -o bench.exe bench.c xxtea.c
if errorlevel 1 exit /b 1
gcc -O2 -Wall -Wextra -I. -o example\\xxtea_example.exe example\\test.c example\\base64.c xxtea.c
if errorlevel 1 exit /b 1
exit /b 0
''')
        cmake(folder, project, ['xxtea.c'], ['xxtea.h'], ['bench'])
        with (folder/'.gitignore').open('a') as f:
            f.write('\n/example/xxtea_example\n')
    else:
        title, stem, programs = META[project]
        source = ROOT/f'variants/variant_{project}'
        for p in source.iterdir():
            if p.suffix in {'.c', '.h'} or p.name == 'Makefile':
                text = p.read_text().replace('../../crypto_util.h', 'crypto_util.h')
                put(folder, p.name, text)
        with (folder/'Makefile').open('a') as f:
            f.write('''\nPYTHON ?= python3
.PHONY: all run clean test test-sanitize
test:
	$(PYTHON) tests/run_tests.py
test-sanitize:
	$(PYTHON) tests/run_tests.py --sanitize
''')
        text = (source/'README.md').read_text()
        # Keep the project's detailed API documentation; fix checkout-relative references.
        text = text[text.index('\n')+1:]
        text = text.replace('`../../tests`', '`tests/`')
        text = text.replace('OpenSSL **libcrypto** — same installs as variant D (see `../variant_D/README.md`).',
                            'OpenSSL **libcrypto** development headers and library are required.\nThe Makefile uses `pkg-config` or common Homebrew paths; CMake uses\n`find_package(OpenSSL)`. Set `OPENSSL_ROOT_DIR` for a custom CMake prefix.')
        text = text.replace('The source now includes the shared `../../crypto_util.h` helper; preserve\nthat relative path when copying a variant, or adapt the include explicitly.',
                            'The required `crypto_util.h` helper is included in this project root.')
        text = text.replace('For production, swap the core for AES-CTR or ChaCha20.',
                            'No production-security claim is made for this construction.')
        intro = f'''# Variant {project} · {title}

**Standalone tag `{project}`** · C implementation · Research project

```sh
git clone --branch {project} --single-branch {REPO}.git variant-{project}
cd variant-{project}
make
make test
make test-sanitize
```

This checkout includes only variant {project}'s runtime sources and its local
helpers. No sibling project or original-library checkout is needed. Building
requires Make and a C11 compiler; tests also need Python 3. ASan/UBSan requires
a supporting compiler. {'OpenSSL libcrypto is required.' if project in WRAPPER else 'OpenSSL is not required.'}

'''
        final = '''
## Standalone CMake build

```sh
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
cmake --install build --prefix ./build/install
```

## Verification and API contracts

`tests/` compares the C implementation with an independent Python reference
and frozen project vectors. `make test-sanitize` adds instrumented C execution.
These are functional tests, not official third-party vectors or a security
proof. Native Windows, 32-bit and big-endian execution are not claimed.

Stream calls return 1/0 and reject invalid input before writing. Every stream
call restarts the counter: never reuse a key/nonce pair, including by splitting
one message across calls. Low-level block calls require valid 16-byte buffers
and support exact in-place operation. Other partial overlap is unsupported.
'''
        if project in WRAPPER:
            final += '''
Packets have a 32-bit plaintext-length field. Outputs and lengths must follow
the public header contract; on errors supplied lengths are reset to zero.
Authentication is checked before releasing plaintext. D/E/F use the same B
core and derived encryption keys: never reuse a master-key/nonce pair across
these formats. TX1 carries a 20-byte header and a 32-byte tag; TX2 carries a
24-byte header, clear authenticated AAD and a 32-byte tag.
'''
        if project in 'EF':
            final += '''
Input/output/context/nonce/length storage must be disjoint. The caller manages
message buffers; OpenSSL may allocate internally. Clear the context after use
with the `*_ctx_clear` function declared in the public header.
'''
        final += '\nSee [CHANGELOG.md](CHANGELOG.md) for changes and migration notes.\n\n' + COMMON
        final += '\n## License\n\nSee [LICENSE.md](LICENSE.md); original source attributions are retained.\n'
        put(folder, 'README.md', intro+text+'\n'+final)
        vectors = json.loads((ROOT/'tests/known_answers.json').read_text())
        put(folder, 'tests/known_answers.json', json.dumps({project:vectors[project]}, indent=2))
        sources = [stem+'.c'] + ([WRAPPER[project]+'.c'] if project in WRAPPER else [])
        headers = [stem+'.h'] + ([WRAPPER[project]+'.h'] if project in WRAPPER else [])
        cmake(folder, project, sources, headers, programs)
    put(folder, 'tests/README.md', f'''# Tests for {project}

Run `make test` or `make test-sanitize` from this checkout. The runner builds
fresh temporary libraries from local sources; it never needs sibling projects.
Python 3 and a C compiler are required. {'OpenSSL is also required.' if project in WRAPPER else 'No OpenSSL dependency is used.'}

The independent Python reference checks exact outputs as well as inverse
operations. Original XXTEA additionally checks short/string/binary key
contracts and six injected allocation failures. Cipher projects test 200
block cases, exact in-place operation, boundary lengths and counter limits.
D/E/F additionally test independent KDF/HMAC/packet calculations, every-bit
mutation and every truncation of a representative packet, wrong keys,
malformed length fields and output-buffer rejection behavior.

ASan/UBSan runs a separate C driver over 512 message lengths. Original and
D/E/F also exercise 5000 deterministic malformed inputs. Original tests strict
Base64 and the short-key regression. Platform-specific 32-bit guards execute
only on an actual 32-bit build. No native Windows/big-endian validation,
cryptanalytic security proof or exhaustive OpenSSL fault injection is claimed.

The larger cross-project D/E interoperability and combined-header tests remain
on `archive/suite`; they are not silently skipped tests in this checkout.
''')
    print(f'Prepared {folder.relative_to(ROOT)}')
