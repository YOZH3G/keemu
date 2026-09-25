# Diagnostic m1c-26 native transport and target AArch64 decision prototype.
# No downloads. Requires the verified P0 Debian cross-toolchain.
include fixtures/recipes/aarch64/common.mk

TARGET_OUT ?= .runtime/m1c26/network-demo-ipc-aarch64
ADAPTER_OUT ?= .runtime/m1c26/nfqueue-transport-amd64
TARGET_SOURCE := fixtures/sources/network-demo/network_demo_ipc_m1c26.c
ADAPTER_SOURCE := fixtures/sources/network-demo/nfqueue_transport_m1c26.c
CONSUMER := fixtures/sources/nfqueue/nfqueue_consumer.c
HOST_CC ?= gcc
export LD_LIBRARY_PATH := $(KEEMU_TOOLCHAIN_ROOT)/usr/lib/x86_64-linux-gnu

all: $(TARGET_OUT) $(ADAPTER_OUT)

$(TARGET_OUT): $(TARGET_SOURCE) $(CONSUMER)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(LDFLAGS) -static -o $@ $<
	$(STRIP) --strip-unneeded $@

$(ADAPTER_OUT): $(ADAPTER_SOURCE) $(CONSUMER)
	@mkdir -p $(dir $@)
	$(HOST_CC) -static -O2 -g0 -fno-ident -ffile-prefix-map=$(CURDIR)=. -Wall -Wextra -Werror -std=c17 -Wl,--build-id=none -o $@ $<
