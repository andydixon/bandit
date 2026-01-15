# Makefile for Bandit
#
# Targets:
#   make            - build debug binary for host
#   make debug      - same as above
#   make release    - build optimised release binary for host
#   make release-all - build release binaries for a set of common targets
#
# Note: cross-compilation requires the appropriate Rust targets and linkers
# to be installed, e.g. via `rustup target add <triple>`.

PACKAGE_NAME := bandit

# Common target triples; extend this list as needed.
TARGETS := \
	x86_64-apple-darwin \
	aarch64-apple-darwin \
	x86_64-unknown-linux-gnu \
	aarch64-unknown-linux-gnu \
	x86_64-pc-windows-gnu

.PHONY: all debug release release-all clean

all: debug

debug:
	cargo build

release:
	cargo build --release

release-all: $(TARGETS:%=release-%)

release-%:
	cargo build --release --target=$*

clean:
	cargo clean
