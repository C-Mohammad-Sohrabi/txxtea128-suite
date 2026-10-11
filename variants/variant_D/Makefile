# variant_D — Encrypt-then-MAC authenticated encryption
# (variant B cipher + HMAC-SHA256 + key separation via HMAC KDF)
#
# Targets: all (default: bench_etm + demo_etm), run, clean
# Requires OpenSSL (libcrypto). Auto-detected via pkg-config with a
# Homebrew fallback on macOS:
#   Linux: sudo apt install libssl-dev
#   macOS: brew install openssl

CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra

# --- OpenSSL detection ---
UNAME_S := $(shell uname -s 2>/dev/null)
ifeq ($(UNAME_S),Darwin)
  OPENSSL_CFLAGS := $(shell pkg-config --cflags openssl 2>/dev/null)
  OPENSSL_LIBS   := $(shell pkg-config --libs openssl 2>/dev/null)
  ifeq ($(strip $(OPENSSL_CFLAGS)),)
    # Homebrew fallback: probe for the real prefix (Apple Silicon / Intel)
    HOMEBREW_OPENSSL := $(shell ls -d /opt/homebrew/opt/openssl /usr/local/opt/openssl 2>/dev/null | head -1)
    ifneq ($(strip $(HOMEBREW_OPENSSL)),)
      OPENSSL_CFLAGS := -I$(HOMEBREW_OPENSSL)/include
      OPENSSL_LIBS   := -L$(HOMEBREW_OPENSSL)/lib -lcrypto
    else
      OPENSSL_LIBS := -lcrypto
    endif
  endif
else
  OPENSSL_CFLAGS := $(shell pkg-config --cflags openssl 2>/dev/null)
  OPENSSL_LIBS   := $(shell pkg-config --libs openssl 2>/dev/null || echo -lcrypto)
endif

CORE    := txxtea128.c txxtea_etm.c
HDRS    := ../../crypto_util.h txxtea128.h txxtea_etm.h

all: bench_etm demo_etm

bench_etm: $(CORE) bench_etm.c $(HDRS)
	$(CC) $(CFLAGS) $(OPENSSL_CFLAGS) -o $@ $(CORE) bench_etm.c $(OPENSSL_LIBS)

demo_etm: $(CORE) demo_etm.c $(HDRS)
	$(CC) $(CFLAGS) $(OPENSSL_CFLAGS) -o $@ $(CORE) demo_etm.c $(OPENSSL_LIBS)

run: all
	./bench_etm
	./demo_etm

clean:
	rm -f bench_etm demo_etm *.o