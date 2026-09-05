# xxtea-c — top-level build for the base library and all variants
#
# Layout:
#   .                    original XXTEA library (xxtea.c/h, example/, CMake)
#   variants/variant_A..G  experimental cipher variants, each a self-contained project
#
# Usage:
#   make all            build the root bench, every variant (A..G) and the menu
#   make bench          build the root benchmark (original XXTEA library)
#   make menu           build the interactive test menu (./menu)
#   make variant_A      build one variant (same for variant_B .. variant_G)
#   make VARIANT=G      build a single variant chosen by name (A..G)
#   make demo           build the ETM demos (variant_D, variant_F)
#   make run            run the root bench + every variant bench/demo
#   make clean          remove all built binaries
#   make help           show this help
#
# Notes:
#   * Works on Linux and macOS out of the box (make + cc/clang/gcc).
#   * Variants D/E/F also require OpenSSL (libcrypto):
#       Linux:   sudo apt install libssl-dev        (or dnf/pacman equivalent)
#       macOS:   brew install openssl
#     The per-variant Makefiles auto-detect OpenSSL via pkg-config and
#     fall back to common Homebrew paths.
#   * Windows: use the bundled build_windows.bat (needs MinGW-w64 gcc),
#     or run these Makefiles from MSYS2/Git Bash (mingw32-make).

CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra

VARIANTS := A B C D E F G
VARIANT  ?=
VDIR     := variants

.PHONY: all bench demo run clean help $(addprefix variant_,$(VARIANTS))

all: bench menu $(addprefix variant_,$(VARIANTS))

# --- root benchmark (original src/xxtea.c library) ---
bench: src/bench.c src/xxtea.c include/xxtea.h
	$(CC) $(CFLAGS) -Iinclude -o $@ src/bench.c src/xxtea.c

# --- interactive test menu ---
menu: src/menu.c
	$(CC) $(CFLAGS) -o $@ src/menu.c

# --- one variant per target ---
variant_A:
	$(MAKE) -C $(VDIR)/variant_A
variant_B:
	$(MAKE) -C $(VDIR)/variant_B
variant_C:
	$(MAKE) -C $(VDIR)/variant_C
variant_D:
	$(MAKE) -C $(VDIR)/variant_D
variant_E:
	$(MAKE) -C $(VDIR)/variant_E
variant_F:
	$(MAKE) -C $(VDIR)/variant_F
variant_G:
	$(MAKE) -C $(VDIR)/variant_G

# --- choose a variant with: make VARIANT=G ---
ifneq ($(VARIANT),)
variant:
	$(MAKE) $(addprefix variant_,$(VARIANT))
endif

# --- demos (variant_D and variant_F) ---
demo: variant_D variant_F

# --- run everything ---
run: all
	@echo "== root bench ==";   ./bench
	@echo "== variant_A ==";    ./$(VDIR)/variant_A/bench_a
	@echo "== variant_B ==";    ./$(VDIR)/variant_B/bench_b
	@echo "== variant_C ==";    ./$(VDIR)/variant_C/bench_c
	@echo "== variant_D ==";    ./$(VDIR)/variant_D/bench_etm; ./$(VDIR)/variant_D/demo_etm
	@echo "== variant_E ==";    ./$(VDIR)/variant_E/bench_etm_ctx
	@echo "== variant_F ==";    ./$(VDIR)/variant_F/demo_aad
	@echo "== variant_G ==";    ./$(VDIR)/variant_G/bench_g

clean:
	rm -f bench menu
	$(MAKE) -C $(VDIR)/variant_A clean
	$(MAKE) -C $(VDIR)/variant_B clean
	$(MAKE) -C $(VDIR)/variant_C clean
	$(MAKE) -C $(VDIR)/variant_D clean
	$(MAKE) -C $(VDIR)/variant_E clean
	$(MAKE) -C $(VDIR)/variant_F clean
	$(MAKE) -C $(VDIR)/variant_G clean

help:
	@echo "Targets: all, bench, menu, variant_A..variant_G, VARIANT=X, demo, run, clean, help"
	@echo "Variants live in $(VDIR)/variant_A .. $(VDIR)/variant_G"
	@echo "Examples:"
	@echo "  make all              # build everything"
	@echo "  make variant_G        # build only variant_G"
	@echo "  make VARIANT=F        # same thing, by name"
	@echo "  make menu             # interactive test menu (pick a component)"
	@echo "  make run              # build + run every benchmark/demo"