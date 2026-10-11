# Changes — reviewed implementation (2026-10-10)

This review checks implementation behavior, not cryptanalytic security.
The original XXTEA arithmetic, A/B/C/G round functions, and D/E/F packet
formats remain unchanged for valid inputs under the same key semantics.

## Original XXTEA and example

- Replace the unconditional 16-byte read of a string key with bounded,
  NUL-aware copying. Short C strings no longer cause an out-of-bounds read.
- Preserve legacy string-key normalization; add `xxtea_encrypt_raw` and
  `xxtea_decrypt_raw` for exactly 16 binary key bytes, including zero bytes.
  Existing ciphertext generated with truncated binary keys still needs the
  legacy API. Switching to the raw API is an intentional key-semantics change.
- Validate null arguments, empty/oversized input and ciphertext alignment.
  Reject invalid input before allocation and reset supplied output lengths.
- Check output allocation failure before writing and clear temporary key and
  data arrays before release. Six injected allocation-failure paths are tested.
- Make the example check allocations and exact plaintext length, and return
  a failing exit status on round-trip failure so CTest can detect it.
- Make the benchmark include the public header and use the binary-key API.
- Reject malformed Base64, invalid padding, noncanonical pad bits and high-bit
  input bytes; avoid signed-char table ambiguity and invalid negative shifts.

## All cipher variants

- `*_ctr_xor` now returns `int`: 1 for success, 0 for invalid input or an
  exhausted counter space. More than 2^32 16-byte blocks are rejected before
  writes. This is a one-shot interface: every call starts the counter at zero.
- Replace optimizable clearing with volatile writes for temporary cipher
  state, key material and keystream. This does not erase every register copy.
- Add null/length validation to streams. Low-level block functions still
  require valid 16-byte buffers; exact in-place blocks are supported.

## Authenticated envelopes D, E and F

- Check packet-size arithmetic before allocation/copying. Parse lengths by
  subtraction after checking minimum length, preventing addition wraparound.
- Reset output pointers/lengths on errors; support empty plaintext in D.
- Wipe derived keys on allocation/RNG/HMAC failures; stop a zero-byte RNG read
  on Linux instead of looping indefinitely.
- Add `txxtea_etm_ctx_clear` and `txxtea_etm_aad_ctx_clear`.
- Rename F's constants to `TXXTEA_AAD_*` so E's 20-byte header and F's 24-byte
  header cannot collide when both headers are included. Update F callers.
- Keep TX1/TX2 wire formats and D/E interoperability. E/F buffers, context,
  nonce and length storage must be disjoint as documented in the headers.

## Tests, builds and documentation

- Add independent Python reference calculations and frozen project regression
  vectors; check blocks, inverse operations, streams, KDF, HMAC and packets.
- Add all-bit packet mutation, truncation, wrong-key, short-capacity and
  malformed-length tests. Check that rejected packets expose no plaintext.
- Add AddressSanitizer/UndefinedBehaviorSanitizer and allocation-failure drivers.
- Make D/F demos return failure when round-trip or tamper rejection fails;
  clear F's reusable context before leaving the demo.
- Add Make test targets and CMake example/CTest integration.
- Correct claims that B's tweak can be XORed away, that C removes the direct
  tweak injection, and that G has proven security superiority. Remove stale
  fixed benchmark timing claims. D/E/F use B, not C or G.
- Normalize changed C source line endings and exclude local build artifacts
  and personal documents from version control.

## Repository organization

`main` contains the original XXTEA project. Annotated tags A through G each
contain one independent variant with its own root README, source, helper,
Makefile, CMake build, tests, license and project identifier. `archive/suite`
retains the reviewed aggregate project and cross-variant tests. Existing
v0.1.0 through v0.9.0 tags keep their historical commit targets unchanged.

## Validation limits

Recorded local validation runs on Apple Silicon/macOS with Apple Clang and
real OpenSSL. Passing these checks is not a security proof. Native Windows,
32-bit, big-endian and embedded execution, exhaustive dependency-failure
injection, and a constant-time audit are outside the recorded results.
