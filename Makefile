CFLAGS += -I./lib

.PHONY: all clean lib

all: lib convirt b64

convirt: convirt.o
	$(LINK.o) $^ -L./lib -lovcurl -lcurl -o $@

b64: b64encode.o
	$(LINK.o) $^ -L./lib -lovcurl -o $@

lib:
	$(MAKE) -C lib

clean:
	$(MAKE) -C lib $@
	rm -f convirt b64
	rm -f *.o

include Makefile.defs
