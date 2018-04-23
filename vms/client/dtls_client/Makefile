PREFIX=/usr
BINDIR=$(PREFIX)/bin

CC=gcc
INSTALL=ginstall

LDFLAGS = -L/usr/local/ssl/lib
LDLIBS = -lssl -lcrypto -lpthread

all:	client
distclean:	clean

clean:
	rm client


install: all
	$(INSTALL) -D client $(DESTDIR)$(BINDIR)/client

macmask:
	$(CC) client.c -o client $(LDFLAGS) $(LDLIBS) -g
