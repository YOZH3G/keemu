include fixtures/recipes/aarch64/common.mk

OUT ?= .runtime/p0/fixtures/aarch64/web-demo-p006
SOURCE := fixtures/sources/web-demo/web_demo_p006.c
# The Entware runtime libc predates the locked Debian cross sysroot. This P0
# experiment is deliberately static so target execution tests the fixture,
# not an unpinned libc compatibility assumption.
LDFLAGS += -static

all: $(OUT)

$(OUT): $(SOURCE)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<
	$(STRIP) --strip-unneeded $@

clean:
	rm -f $(OUT)
