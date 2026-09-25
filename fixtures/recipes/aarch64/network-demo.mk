include fixtures/recipes/aarch64/common.mk

OUT ?= .runtime/m1c24/network-demo-aarch64
SOURCE := fixtures/sources/network-demo/network_demo.c
CONSUMER := fixtures/sources/nfqueue/nfqueue_consumer.c
LDFLAGS += -static

all: $(OUT)

$(OUT): $(SOURCE) $(CONSUMER)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<
	$(STRIP) --strip-unneeded $@

clean:
	rm -f $(OUT)
