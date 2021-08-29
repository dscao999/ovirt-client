
xml_header = $(shell pkg-config --cflags libxml-2.0)
xml_lib = $(shell pkg-config --libs libxml-2.0)

CFLAGS += -Wall $(xml_header)
LIBS += $(xml_lib)

.PHONY: clean all release dclean

all: libovcurl.a

libovcurl.a: ovirt-client.o ovirt-client-internal.o ovirt-xml.o base64.o miscs.o
	$(AR) rsc $@ $^

xmlp: xmlp.o ovirt-xml.o miscs.o
	$(LINK.o) $^ $(LIBS) -o $@

clean:
	rm -f libovcurl.a xmlp
	rm -f *.o

dclean: clean
	rm -f *.d

release: all
release: CFLAGS += -O2
release: LDFLAGS += -Wl,-O,2

include Makefile.defs
