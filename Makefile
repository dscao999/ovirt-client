CFLAGS +=-Wall -g -I/usr/include/libxml2

.PHONY: all clean

all: curltx b64 xmlp

curltx: curltx.o ovirt-client.o ovirt_xml.o base64.o
	$(LINK.o) $^ -lcurl -lxml2 -ljansson -o $@

b64: b64encode.o base64.o
	$(LINK.o) $^ -o $@

xmlp: xmlp.o ovirt_xml.o
	$(LINK.o) $^ -lxml2 -o $@

clean:
	rm -f curltx b64 xmlp
	rm -f *.o
