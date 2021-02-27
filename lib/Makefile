CFLAGS = -fPIC -Wall -g -I/usr/include/libxml2

.PHONY: clean

libovcurl.so: ovirt-client.o ovirt-xml.o base64.o
	$(LINK.o) -shared $^ -lcurl -lxml2 -ljansson -o $@

xmlp: xmlp.o ovirt-xml.o
	$(LINK.o) $^ -lxml2 -o $@
clean:
	rm -f libovcurl.so xmlp
	rm -f *.o

include Makefile.defs
