PREFIX=/usr
BINDIR=$(PREFIX)/bin

CC=gcc
INSTALL=ginstall

LDFLAGS = -L/usr/local/ssl/lib
LDLIBS = -lssl -lcrypto -lpthread

all:	server
distclean:	clean

clean:
	rm server


install: all
	$(INSTALL) -D server $(DESTDIR)$(BINDIR)/server

macmask:
	$(CC) server.c -o server $(LDFLAGS) $(LDLIBS) -g
