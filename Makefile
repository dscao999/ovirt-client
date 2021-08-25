CFLAGS += -I./lib

.PHONY: all clean lib release

TARGET =

all: lib convirt b64

release: all

convirt: convirt.o
	$(LINK.o) $^ -L./lib -lovcurl -lcurl -lxml2 -ljson-c -o $@

b64: b64encode.o
	$(LINK.o) $^ -L./lib -lovcurl -lxml2 -ljson-c -o $@

lib:
	$(MAKE) -C lib $(TARGET)

clean:
	$(MAKE) -C lib $@
	rm -f convirt b64
	rm -f *.o

release: TARGET=release
release: CFLAGS += -O2
release: LDFLAGS += -Wl,-O,1

include Makefile.defs
