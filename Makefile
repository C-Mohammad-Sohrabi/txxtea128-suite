# variant_F — Encrypt-then-MAC with Associated Data (AAD) support
#
# Targets: all (default: demo_aad), run, clean
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

TARGET := demo_aad
SRCS   := src/txxtea128.c src/txxtea_etm_aad.c src/demo_aad.c
HDRS   := include/crypto_util.h include/txxtea128.h include/txxtea_etm_aad.h

all: $(TARGET)

$(TARGET): $(SRCS) $(HDRS)
	$(CC) $(CFLAGS) $(OPENSSL_CFLAGS) -o $@ $(SRCS) $(OPENSSL_LIBS)

run: all
	./$(TARGET)

clean:
	rm -f $(TARGET) *.o

PYTHON ?= python3
.PHONY: all run clean test test-sanitize
test:
	$(PYTHON) tests/run_tests.py
test-sanitize:
	$(PYTHON) tests/run_tests.py --sanitize
