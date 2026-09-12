CC ?= cc
CFLAGS ?= -O2 -g -std=c11 -Wall -Wextra -Wpedantic
PKG_CFLAGS := $(shell pkg-config --cflags libbpf 2>/dev/null)
PKG_LIBS := $(shell pkg-config --libs libbpf 2>/dev/null)

.PHONY: all clean check-deps
all: recon_controller

check-deps:
	@pkg-config --exists libbpf || (echo "libbpf development files not found" >&2; exit 2)

recon_controller: recon_controller.c recon_controller.h state_machine.c state_machine.h ../xdp/xdp_common.h
	$(CC) $(CFLAGS) $(PKG_CFLAGS) recon_controller.c state_machine.c -o $@ $(PKG_LIBS) -lelf -lz

clean:
	rm -f recon_controller *.o
