CFLAGS += -I./lib

.PHONY: all clean lib

all: lib curltx b64

curltx: curltx.o
	$(LINK.o) $^ -L./lib -lovcurl -lcurl -lxml2 -ljansson -o $@

b64: b64encode.o
	$(LINK.o) $^ -L./lib -lovcurl -o $@

lib:
	$(MAKE) -C lib

clean:
	$(MAKE) -C lib $@
	rm -f curltx b64
	rm -f *.o

include Makefile.defs
