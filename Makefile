#
# Makefile - VPN Project Build System
# ====================================
#
# This Makefile builds our WireGuard-like VPN from source.
#
# TARGETS:
#   make        - Build everything
#   make clean  - Remove build artifacts
#   make test   - Build and run tests (when available)
#
# USAGE:
#   make                  # Default build
#   make CC=clang         # Use clang instead of gcc
#   make DEBUG=1          # Build with debug symbols
#   make RELEASE=1        # Build with optimizations
#

#
# Configuration
#

CC      ?= gcc
AR      ?= ar
CFLAGS  ?= -Wall -Wextra -Wpedantic -std=c99

# Directory structure
SRCDIR  := src
OBJDIR  := obj
BINDIR  := bin

# Output binary
TARGET  := $(BINDIR)/vpn

#
# Build mode flags
#

ifdef DEBUG
    CFLAGS += -g -O0 -DDEBUG
else ifdef RELEASE
    CFLAGS += -O3 -DNDEBUG
else
    # Default: moderate optimization with debug info
    CFLAGS += -g -O2
endif

# Security flags
CFLAGS += -fstack-protector-strong

# Platform detection
ifeq ($(OS),Windows_NT)
    # Windows-specific flags
    # ws2_32 - Winsock2 for networking
    # bcrypt - Cryptographic random number generation
    # iphlpapi - IP helper APIs for network configuration
    LDFLAGS += -lws2_32 -lbcrypt -liphlpapi
    EXE_EXT := .exe
else
    UNAME_S := $(shell uname -s)
    ifeq ($(UNAME_S),Linux)
        # Linux-specific flags
        LDFLAGS += -lpthread
    endif
    ifeq ($(UNAME_S),Darwin)
        # macOS-specific flags
    endif
    EXE_EXT :=
endif

#
# Source files
#

# Crypto modules
CRYPTO_SRCS := \
    $(SRCDIR)/crypto/chacha20.c \
    $(SRCDIR)/crypto/poly1305.c \
    $(SRCDIR)/crypto/aead.c \
    $(SRCDIR)/crypto/curve25519.c \
    $(SRCDIR)/crypto/blake2s.c

# Utility modules
UTIL_SRCS := \
    $(SRCDIR)/util/memory.c \
    $(SRCDIR)/util/random.c \
    $(SRCDIR)/util/log.c

# Protocol modules
PROTO_SRCS := \
    $(SRCDIR)/protocol/noise.c \
    $(SRCDIR)/protocol/peer.c \
    $(SRCDIR)/protocol/packet.c \
    $(SRCDIR)/protocol/replay.c \
    $(SRCDIR)/protocol/timers.c

# Network modules
NET_SRCS := \
    $(SRCDIR)/net/udp.c \
    $(SRCDIR)/net/tun.c

# Configuration and main program
APP_SRCS := \
    $(SRCDIR)/config.c \
    $(SRCDIR)/main.c

# All source files
SRCS := $(CRYPTO_SRCS) $(UTIL_SRCS) $(PROTO_SRCS) $(NET_SRCS) $(APP_SRCS)

# Object files (replace .c with .o, and src/ with obj/)
OBJS := $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.o,$(SRCS))

# Header dependencies
DEPS := $(OBJS:.o=.d)

#
# Targets
#

.PHONY: all clean test dirs lib

all: dirs $(TARGET)$(EXE_EXT)

# Create static library (useful for testing)
lib: dirs $(OBJDIR)/libvpn.a

$(OBJDIR)/libvpn.a: $(OBJS)
	$(AR) rcs $@ $^

# Link final binary
$(TARGET)$(EXE_EXT): $(OBJS)
	@mkdir -p $(BINDIR)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Compile source files
$(OBJDIR)/%.o: $(SRCDIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

# Include auto-generated dependencies
-include $(DEPS)

# Create necessary directories
dirs:
	@mkdir -p $(OBJDIR)/crypto
	@mkdir -p $(OBJDIR)/util
	@mkdir -p $(OBJDIR)/protocol
	@mkdir -p $(OBJDIR)/net
	@mkdir -p $(BINDIR)

# Clean build artifacts
clean:
	rm -rf $(OBJDIR) $(BINDIR)

# Build and run tests
test: lib
	@echo "Tests not yet implemented"
	# $(CC) $(CFLAGS) -o $(BINDIR)/test_crypto test/test_crypto.c -L$(OBJDIR) -lvpn
	# $(BINDIR)/test_crypto

#
# Deployment targets
#

# Verify build
.PHONY: verify
verify: all
	@./deploy/verify.sh

# Install binary (requires root)
.PHONY: install
install: all
	@install -d /usr/local/bin
	@install -m 755 $(TARGET) /usr/local/bin/hinkypunk
	@echo "Installed to /usr/local/bin/hinkypunk"

# Uninstall
.PHONY: uninstall
uninstall:
	@rm -f /usr/local/bin/hinkypunk
	@echo "Uninstalled hinkypunk"

#
# Development helpers
#

# Check code style
.PHONY: lint
lint:
	@echo "Running code checks..."
	@cppcheck --enable=all --std=c99 $(SRCDIR) 2>/dev/null || echo "cppcheck not installed"

# Format code (requires clang-format)
.PHONY: format
format:
	@find $(SRCDIR) -name '*.c' -o -name '*.h' | xargs clang-format -i

# Show build configuration
.PHONY: info
info:
	@echo "CC      = $(CC)"
	@echo "CFLAGS  = $(CFLAGS)"
	@echo "LDFLAGS = $(LDFLAGS)"
	@echo "SRCS    = $(SRCS)"
	@echo "OBJS    = $(OBJS)"
