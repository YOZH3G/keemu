include fixtures/recipes/aarch64/common.mk

OUT ?= .runtime/p0/fixtures/aarch64/nfqueue-consumer
SOURCE := fixtures/sources/nfqueue/nfqueue_consumer.c

all: $(OUT)

$(OUT): $(SOURCE)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<
	$(STRIP) --strip-unneeded $@

clean:
	rm -f $(OUT)
