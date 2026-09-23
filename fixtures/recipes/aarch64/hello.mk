include fixtures/recipes/aarch64/common.mk

OUT ?= .runtime/p0/fixtures/aarch64/hello
SOURCE := fixtures/sources/hello/hello.c

all: $(OUT)

$(OUT): $(SOURCE)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<
	$(STRIP) --strip-unneeded $@

clean:
	rm -f $(OUT)
