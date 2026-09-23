# P0 fixture cross-build common settings. Inputs are locked in locks/p0-fixtures-aarch64.json.
# This recipe never downloads. Stage the verified Debian cross-toolchain below first.
ifndef KEEMU_TOOLCHAIN_ROOT
$(error KEEMU_TOOLCHAIN_ROOT must name an extracted verified Debian cross-toolchain)
endif

TARGET := aarch64-linux-gnu
CC := $(KEEMU_TOOLCHAIN_ROOT)/usr/bin/$(TARGET)-gcc
STRIP := $(KEEMU_TOOLCHAIN_ROOT)/usr/bin/$(TARGET)-strip
# Debian cross GCC expects its target triplet below the supplied sysroot.
SYSROOT := $(KEEMU_TOOLCHAIN_ROOT)
CFLAGS := --sysroot=$(SYSROOT) -O2 -g0 -fno-ident -ffile-prefix-map=$(CURDIR)=. -Wall -Wextra -Werror -std=c17
LDFLAGS := --sysroot=$(SYSROOT) -Wl,--build-id=none
SOURCE_DATE_EPOCH ?= 0
export SOURCE_DATE_EPOCH

ifeq ($(wildcard $(CC)),)
$(error locked cross compiler not found: $(CC))
endif
