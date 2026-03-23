# AethroSync — Makefile
CC      = gcc
CFLAGS  = -std=c11 -D_GNU_SOURCE -Wall -Wextra -O2 -Iinclude
LIBS    = -lsodium -lzstd -lm -lpthread
COLOUR  = -DMPCP_COLOUR_UI=1

SRCS = src/crypto.c \
       src/config.c \
       src/calibrate.c \
       src/disguise.c \
       src/keygen.c \
       src/exchange.c \
       src/tripwire.c \
       src/chunker.c \
       src/nat.c \
       src/pipeline.c \
       src/ui.c \
       src/cli.c \
       tests/test_core.c \
       tests/test_phase3.c

# ── Colour build (default) ───────────────────────────────────────────────
all: mpcp

mpcp: $(SRCS) src/main.c include/mpcp.h include/ui.h
	$(CC) $(CFLAGS) $(COLOUR) $(SRCS) src/main.c -o $@ $(LIBS)

# ── Headless/server build ────────────────────────────────────────────────
mpcp-plain: $(SRCS) src/main.c include/mpcp.h include/ui.h
	$(CC) $(CFLAGS) $(SRCS) src/main.c -o $@ $(LIBS)

# ── Test binary (includes unit test suites) ──────────────────────────────
TEST_SRCS = $(SRCS) tests/test_core.c tests/test_phase3.c

mpcp-test: $(TEST_SRCS) src/main.c include/mpcp.h
	$(CC) $(CFLAGS) $(COLOUR) $(TEST_SRCS) src/main.c -o $@ $(LIBS)

test: mpcp
	./mpcp --test

selftest: mpcp
	./mpcp --selftest

bench: mpcp
	./mpcp --bench

clean:
	rm -f mpcp mpcp-plain mpcp-test

.PHONY: all test selftest bench clean

# ── Windows cross-compile (requires mingw-w64) ───────────────────────────
# Build: make mpcp.exe
# Install MinGW: sudo apt install gcc-mingw-w64   OR   nix-shell -p mingw-w64
MINGW   = x86_64-w64-mingw32-gcc
WFLAGS  = -std=c11 -D_GNU_SOURCE -Wall -O2 -Iinclude
WLIBS   = -lsodium -lzstd -lws2_32 -lbcrypt -liphlpapi -lwinmm -lm

mpcp.exe: $(SRCS) src/main.c include/platform.h
	$(MINGW) $(WFLAGS) $(COLOUR) $(SRCS) src/main.c -o $@ $(WLIBS)

mpcp-plain.exe: $(SRCS) src/main.c include/platform.h
	$(MINGW) $(WFLAGS) $(SRCS) src/main.c -o $@ $(WLIBS)
