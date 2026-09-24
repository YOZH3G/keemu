# Independent static AArch64 TLS frontend. The OpenSSL SDK is a pinned Debian
# arm64 artifact, not part of the Entware rootfs; only the resulting static ELF
# and ephemeral server certificate/key need to enter the disposable target.
include fixtures/recipes/aarch64/common.mk
# Extracted cross binutils need their matching locked host-side shared objects.
export LD_LIBRARY_PATH := $(KEEMU_TOOLCHAIN_ROOT)/usr/lib/x86_64-linux-gnu:$(LD_LIBRARY_PATH)

SOURCE := fixtures/sources/web-demo/https_frontend_m1a15.c
OUT ?= .runtime/m1a15/https-frontend-aarch64
OPENSSL_DEB := .runtime/m1a15/libssl-dev_3.5.7-1~deb13u2_arm64.deb
OPENSSL_ROOT := .runtime/m1a15/openssl-sysroot
OPENSSL_URL := https://deb.debian.org/debian/pool/main/o/openssl/libssl-dev_3.5.7-1~deb13u2_arm64.deb
OPENSSL_SHA256 := b81910e8728fab596158c8384d6aa101c8249c1769eb2d33c73643b2be7a0bcf
ZLIB_DEB := .runtime/m1a15/zlib1g-dev_1.3.dfsg+really1.3.1-1+b1_arm64.deb
ZLIB_URL := https://deb.debian.org/debian/pool/main/z/zlib/zlib1g-dev_1.3.dfsg%2breally1.3.1-1%2bb1_arm64.deb
ZLIB_SHA256 := 745ebcf1fa115e230af76216355d7290a24f1790fe3780249b519c0e4d30534f
ZSTD_DEB := .runtime/m1a15/libzstd-dev_1.5.7+dfsg-1_arm64.deb
ZSTD_URL := https://deb.debian.org/debian/pool/main/libz/libzstd/libzstd-dev_1.5.7%2bdfsg-1_arm64.deb
ZSTD_SHA256 := 05cf42de5c9fdf17f49f663b47bfe736f10fbc7080fcc3a86ac43d5d670de149

.PHONY: all verify-openssl clean
all: $(OUT)

verify-openssl:
	@test -f $(OPENSSL_DEB) -a -f $(ZLIB_DEB) -a -f $(ZSTD_DEB) || (printf 'Missing pinned local SDK artifacts; no network fallback\n' >&2; exit 1)
	@printf '%s  %s\n' $(OPENSSL_SHA256) $(OPENSSL_DEB) | sha256sum -c -
	@printf '%s  %s\n' $(ZLIB_SHA256) $(ZLIB_DEB) | sha256sum -c -
	@printf '%s  %s\n' $(ZSTD_SHA256) $(ZSTD_DEB) | sha256sum -c -

$(OUT): $(SOURCE) verify-openssl
	@mkdir -p $(dir $@)
	@rm -rf $(OPENSSL_ROOT)
	dpkg-deb --extract $(OPENSSL_DEB) $(OPENSSL_ROOT)
	dpkg-deb --extract $(ZLIB_DEB) $(OPENSSL_ROOT)
	dpkg-deb --extract $(ZSTD_DEB) $(OPENSSL_ROOT)
	$(CC) $(CFLAGS) -I$(OPENSSL_ROOT)/usr/include -I$(OPENSSL_ROOT)/usr/include/aarch64-linux-gnu $(LDFLAGS) -static -pthread \
		-o $@ $(SOURCE) $(OPENSSL_ROOT)/usr/lib/aarch64-linux-gnu/libssl.a \
		$(OPENSSL_ROOT)/usr/lib/aarch64-linux-gnu/libcrypto.a \
		$(OPENSSL_ROOT)/usr/lib/aarch64-linux-gnu/libz.a \
		$(OPENSSL_ROOT)/usr/lib/aarch64-linux-gnu/libzstd.a -ldl
	$(STRIP) --strip-unneeded $@

clean:
	rm -f $(OUT)
