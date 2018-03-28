PREFIX=/usr
BINDIR=$(PREFIX)/bin

CC=gcc

LDFLAGS = -L/usr/local/ssl/lib
LDLIBS = -lssl -lcrypto

all: nossl withssl tlsserver
distclean:	clean

clean:
	rm nossl withssl

nossl: nossl.c
	$(CC) -o nossl nossl.c -g $(LDFLAGS) $(LDLIBS)

withssl: withssl.c
	$(CC) -o withssl withssl.c -g $(LDFLAGS) $(LDLIBS)

tlsserver: tls_server.c
	$(CC) -o tls_server tls_server.c -g $(LDFLAGS) $(LDLIBS)