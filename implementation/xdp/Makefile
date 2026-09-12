CLANG ?= clang
CFLAGS ?= -O2 -g -Wall -Werror -target bpf
ARCH_INC ?= /usr/include/$(shell uname -m)-linux-gnu
INCLUDES := -I. -I$(ARCH_INC)

.PHONY: all clean
all: xdp_recon.o xdp_pass.o

xdp_recon.o: xdp_recon.c xdp_common.h xdp_maps.h bpf_helpers_min.h
	$(CLANG) $(CFLAGS) $(INCLUDES) -c $< -o $@

xdp_pass.o: xdp_pass.c bpf_helpers_min.h
	$(CLANG) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -f xdp_recon.o xdp_pass.o
