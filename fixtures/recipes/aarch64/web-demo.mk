include fixtures/recipes/aarch64/common.mk

OUT ?= .runtime/p0/fixtures/aarch64/web-demo
SOURCE := fixtures/sources/web-demo/web_demo.c

all: $(OUT)

$(OUT): $(SOURCE)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<
	$(STRIP) --strip-unneeded $@

clean:
	rm -f $(OUT)
