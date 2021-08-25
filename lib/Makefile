CFLAGS = -fPIC -Wall -g -I/usr/include/libxml2

.PHONY: clean all

all: libovcurl.a

libovcurl.a: ovirt-client.o ovirt-client-internal.o ovirt-xml.o base64.o miscs.o
	$(AR) rsc $@ $^

xmlp: xmlp.o ovirt-xml.o
	$(LINK.o) $^ -lxml2 -o $@

clean:
	rm -f libovcurl.a xmlp
	rm -f *.o

include Makefile.defs
