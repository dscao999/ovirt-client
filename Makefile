
CFLAGS = -Wall -g
#
#  Variables for cross compile
#
HOST_ARCH := $(shell $(CC) --print-multiarch)
OBJECT_ARCH = $(shell $(CC) --print-multiarch)

CC		= $(CROSS_COMPILE)gcc
LD		= $(CROSS_COMPILE)ld
AR		= $(CROSS_COMPILE)ar
NM		= $(CROSS_COMPILE)nm
OBJCOPY		= $(CROSS_COMPILE)objcopy
OBJDUMP		= $(CROSS_COMPILE)objdump
READELF		= $(CROSS_COMPILE)readelf
STRIP		= $(CROSS_COMPILE)strip

ifneq ($(CROSS_COMPILE),)
SYSROOT := $(shell $(CC) --print-sysroot)
PKG_CONFIG_SYSROOT_DIR := $(SYSROOT)
RPATH_LINK := -Xlinker -rpath-link=$(SYSROOT)/usr/lib/$(OBJECT_ARCH)
LDFLAGS += $(RPATH_LINK)
endif


.EXPORT_ALL_VARIABLES:

# end of variables for cross compile

CFLAGS += -I lib
LDFLAGS += -Wl,-L,lib

curl_lib = $(shell pkg-config --libs libcurl)
xml2_lib = $(shell pkg-config --libs libxml-2.0)
json_lib = $(shell pkg-config --libs json-c)

LIBS += $(curl_lib) $(xml2_lib) $(json_lib)

.PHONY: all clean release -lovcurl dclean

TARGET =

all: convirt

release: all

convirt: convirt.o -lovcurl
	$(LINK.o) $^ $(LIBS) -o $@

b64: b64encode.o
	$(LINK.o) $^ -L./lib -lovcurl -o $@

-lovcurl:
	$(MAKE) -C lib $(TARGET)

clean:
	$(MAKE) -C lib $@
	rm -f convirt b64
	rm -f *.o

dclean:
	$(MAKE) -C lib $@
	rm -f convirt b64
	rm -f *.o
	rm -f *.d

release: TARGET = release
release: CFLAGS += -O2
release: LDFLAGS += -Wl,-O,1

include Makefile.defs
