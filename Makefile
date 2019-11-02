
CFLAGS += -Wall -pedantic
#CFLAGS += -ggdb

OBJS += dhcp.o
OBJS += dumphex.o
OBJS += ifc.o
OBJS += loop.o
OBJS += main.o
OBJS += pkt.o
OBJS += sock.o
OBJS += verbose.o
dhcp6relay: $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LIBS)

test_OBJS += test.o
test_OBJS += dumphex.o
test: $(test_OBJS)
	$(LINK.c) -o $@ $(test_OBJS) $(test_LIBS)

clean:
	rm -f dhcp6relay $(OBJS)
	rm -f test $(test_OBJS)

PREFIX ?= /usr
bindir = $(PREFIX)/bin
install:
	install -d $(DESTDIR)$(bindir)
	install -m 755 dhcp6relay $(DESTDIR)$(bindir)/dhcp6relay
