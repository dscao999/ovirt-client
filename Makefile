CFLAGS +=-Wall -g

.PHONY: all clean

all: curltx

curltx: curltx.o ovirt-client.o
	$(LINK.o) $^ -lcurl -lb64 -o $@

clean:
	rm -f curltx
	rm -f *.o
