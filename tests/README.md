# Tests for G

Run `make test` or `make test-sanitize` from this checkout. The runner builds
fresh temporary libraries from local sources; it never needs sibling projects.
Python 3 and a C compiler are required. No OpenSSL dependency is used.

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
