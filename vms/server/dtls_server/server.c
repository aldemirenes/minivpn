/*
 * Copyright (C) 2009 - 2012 Robin Seggelmann, seggelmann@fh-muenster.de,
 *                           Michael Tuexen, tuexen@fh-muenster.de
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/select.h>
#include <sys/time.h>
#include <errno.h>
#include <stdarg.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>


#define BUFFER_SIZE          (1<<16)
#define COOKIE_SECRET_LENGTH 16

#define SSL_CERT "/vagrant/cert.pem"
#define SSL_KEY "/vagrant/key.pem"
#define TUN_IF_NAME "tun0"


typedef union {
	struct sockaddr_storage ss;
	struct sockaddr_in s4;
	struct sockaddr_in6 s6;
} RemoteAddress;

typedef struct PassInfo {
	RemoteAddress server_addr, client_addr;
	SSL *ssl;
} PassInfo;

int verbose = 1;
int veryverbose = 1;
unsigned char cookie_secret[COOKIE_SECRET_LENGTH];
int cookie_initialized=0;

char Usage[] =
"Usage: dtls_udp_echo [options] [address]\n"
"Options:\n"
"        -l      message length (Default: 100 Bytes)\n"
"        -p      port (Default: 23232)\n"
"        -n      number of messages to send (Default: 5)\n"
"        -L      local address\n"
"        -v      verbose\n"
"        -V      very verbose\n";

static pthread_mutex_t* mutex_buf = NULL;

static void 
locking_function(int mode, int n, const char *file, int line) 
{
	if (mode & CRYPTO_LOCK)
		pthread_mutex_lock(&mutex_buf[n]);
	else
		pthread_mutex_unlock(&mutex_buf[n]);
}

static unsigned long 
id_function(void) 
{
	return (unsigned long) pthread_self();
}

int 
THREAD_setup() 
{
	int i;

	mutex_buf = (pthread_mutex_t*) malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
	if (!mutex_buf)
		return 0;
	for (i = 0; i < CRYPTO_num_locks(); i++)
		pthread_mutex_init(&mutex_buf[i], NULL);
	CRYPTO_set_id_callback(id_function);
	CRYPTO_set_locking_callback(locking_function);
	return 1;
}

int 
THREAD_cleanup() 
{
	int i;

	if (!mutex_buf)
		return 0;

	CRYPTO_set_id_callback(NULL);
	CRYPTO_set_locking_callback(NULL);
	for (i = 0; i < CRYPTO_num_locks(); i++)
	pthread_mutex_destroy(&mutex_buf[i]);
	free(mutex_buf);
	mutex_buf = NULL;
	return 1;
}

int 
handle_socket_error() 
{
	switch (errno) {
		case EINTR:
			/* Interrupted system call.
			 * Just ignore.
			 */
			printf("Interrupted system call!\n");
			return 1;
		case EBADF:
			/* Invalid socket.
			 * Must close connection.
			 */
			printf("Invalid socket!\n");
			return 0;
			break;
#ifdef EHOSTDOWN
		case EHOSTDOWN:
			/* Host is down.
			 * Just ignore, might be an attacker
			 * sending fake ICMP messages.
			 */
			printf("Host is down!\n");
			return 1;
#endif
#ifdef ECONNRESET
		case ECONNRESET:
			/* Connection reset by peer.
			 * Just ignore, might be an attacker
			 * sending fake ICMP messages.
			 */
			printf("Connection reset by peer!\n");
			return 1;
#endif
		case ENOMEM:
			/* Out of memory.
			 * Must close connection.
			 */
			printf("Out of memory!\n");
			return 0;
			break;
		case EACCES:
			/* Permission denied.
			 * Just ignore, we might be blocked
			 * by some firewall policy. Try again
			 * and hope for the best.
			 */
			printf("Permission denied!\n");
			return 1;
			break;
		default:
			/* Something unexpected happened */
			printf("Unexpected error! (errno = %d)\n", errno);
			return 0;
			break;
	}
	return 0;
}

int 
generate_cookie(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len)
{
	unsigned char *buffer, result[EVP_MAX_MD_SIZE];
	unsigned int length = 0, resultlength;
	union {
		struct sockaddr_storage ss;
		struct sockaddr_in6 s6;
		struct sockaddr_in s4;
	} peer;

	/* Initialize a random secret */
	if (!cookie_initialized)
		{
		if (!RAND_bytes(cookie_secret, COOKIE_SECRET_LENGTH))
			{
			printf("error setting random cookie secret\n");
			return 0;
			}
		cookie_initialized = 1;
		}

	/* Read peer information */
	(void) BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);

	/* Create buffer with peer's address and port */
	length = 0;
	switch (peer.ss.ss_family) {
		case AF_INET:
			length += sizeof(struct in_addr);
			break;
		case AF_INET6:
			length += sizeof(struct in6_addr);
			break;
		default:
			OPENSSL_assert(0);
			break;
	}
	length += sizeof(in_port_t);
	buffer = (unsigned char*) OPENSSL_malloc(length);

	if (buffer == NULL)
		{
		printf("out of memory\n");
		return 0;
		}

	switch (peer.ss.ss_family) {
		case AF_INET:
			memcpy(buffer,
				   &peer.s4.sin_port,
				   sizeof(in_port_t));
			memcpy(buffer + sizeof(peer.s4.sin_port),
				   &peer.s4.sin_addr,
				   sizeof(struct in_addr));
			break;
		case AF_INET6:
			memcpy(buffer,
				   &peer.s6.sin6_port,
				   sizeof(in_port_t));
			memcpy(buffer + sizeof(in_port_t),
				   &peer.s6.sin6_addr,
				   sizeof(struct in6_addr));
			break;
		default:
			OPENSSL_assert(0);
			break;
	}

	/* Calculate HMAC of buffer using the secret */
	HMAC(EVP_sha1(), (const void*) cookie_secret, COOKIE_SECRET_LENGTH,
		 (const unsigned char*) buffer, length, result, &resultlength);
	OPENSSL_free(buffer);

	memcpy(cookie, result, resultlength);
	*cookie_len = resultlength;

	return 1;
}

int 
verify_cookie(SSL *ssl, const unsigned char *cookie, unsigned int cookie_len)
{
	unsigned char *buffer, result[EVP_MAX_MD_SIZE];
	unsigned int length = 0, resultlength;
	union {
		struct sockaddr_storage ss;
		struct sockaddr_in6 s6;
		struct sockaddr_in s4;
	} peer;

	/* If secret isn't initialized yet, the cookie can't be valid */
	if (!cookie_initialized)
		return 0;

	/* Read peer information */
	(void) BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);

	/* Create buffer with peer's address and port */
	length = 0;
	switch (peer.ss.ss_family) {
		case AF_INET:
			length += sizeof(struct in_addr);
			break;
		case AF_INET6:
			length += sizeof(struct in6_addr);
			break;
		default:
			OPENSSL_assert(0);
			break;
	}
	length += sizeof(in_port_t);
	buffer = (unsigned char*) OPENSSL_malloc(length);

	if (buffer == NULL)
		{
		printf("out of memory\n");
		return 0;
		}

	switch (peer.ss.ss_family) {
		case AF_INET:
			memcpy(buffer,
				   &peer.s4.sin_port,
				   sizeof(in_port_t));
			memcpy(buffer + sizeof(in_port_t),
				   &peer.s4.sin_addr,
				   sizeof(struct in_addr));
			break;
		case AF_INET6:
			memcpy(buffer,
				   &peer.s6.sin6_port,
				   sizeof(in_port_t));
			memcpy(buffer + sizeof(in_port_t),
				   &peer.s6.sin6_addr,
				   sizeof(struct in6_addr));
			break;
		default:
			OPENSSL_assert(0);
			break;
	}

	/* Calculate HMAC of buffer using the secret */
	HMAC(EVP_sha1(), (const void*) cookie_secret, COOKIE_SECRET_LENGTH,
		 (const unsigned char*) buffer, length, result, &resultlength);
	OPENSSL_free(buffer);

	if (cookie_len == resultlength && memcmp(result, cookie, resultlength) == 0)
		return 1;

	return 0;
	}

int dtls_verify_callback (int ok, X509_STORE_CTX *ctx) {
	/* This function should ask the user
	 * if he trusts the received certificate.
	 * Here we always trust.
	 */
	return 1;
}

int
create_socket(RemoteAddress* server_addr, char* local_address_str, int port)
{
	memset(server_addr, 0, sizeof(struct sockaddr_storage));
	
	if (strlen(local_address_str) == 0) {
		server_addr->s6.sin6_family = AF_INET6;
#ifdef HAVE_SIN6_LEN
		server_addr->s6.sin6_len = sizeof(struct sockaddr_in6);
#endif
		server_addr->s6.sin6_addr = in6addr_any;
		server_addr->s6.sin6_port = htons(port);
	} else {
		if (inet_pton(AF_INET, local_address_str, &server_addr->s4.sin_addr) == 1) {
			server_addr->s4.sin_family = AF_INET;
#ifdef HAVE_SIN_LEN
			server_addr->s4.sin_len = sizeof(struct sockaddr_in);
#endif
			server_addr->s4.sin_port = htons(port);
		} else if (inet_pton(AF_INET6, local_address_str, &server_addr->s6.sin6_addr) == 1) {
			server_addr->s6.sin6_family = AF_INET6;
#ifdef HAVE_SIN6_LEN
			server_addr->s6.sin6_len = sizeof(struct sockaddr_in6);
#endif
			server_addr->s6.sin6_port = htons(port);
		} else {
			return;
		}
	}

	int fd = socket(server_addr->ss.ss_family, SOCK_DGRAM, 0);
	if (fd < 0) {
		perror("socket can not be created\n");
		exit(-1);
	}

	return fd;
}

void 
init_openssl()
{
	OpenSSL_add_ssl_algorithms();
	SSL_load_error_strings();
}

SSL_CTX* 
create_context()
{
    const SSL_METHOD* method = DTLSv1_server_method();
	SSL_CTX* ctx = SSL_CTX_new(method);

	if (!ctx) {
		perror("Unable to create SSL context");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
    }

	return ctx;
}

void
configure_context(SSL_CTX* ctx)
{
	/* We accept all ciphers, including NULL.
	 * Not recommended beyond testing and debugging
	 */
	// SSL_CTX_set_cipher_list(ctx, "ALL:NULL:eNULL:aNULL");
	SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);

	if (!SSL_CTX_use_certificate_file(ctx, SSL_CERT, SSL_FILETYPE_PEM))
		printf("\nERROR: no certificate found!");

	if (!SSL_CTX_use_PrivateKey_file(ctx, SSL_KEY, SSL_FILETYPE_PEM))
		printf("\nERROR: no private key found!");

	if (!SSL_CTX_check_private_key (ctx))
		printf("\nERROR: invalid private key!");

	/* Client has to authenticate */
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE, dtls_verify_callback);

	SSL_CTX_set_read_ahead(ctx, 1);
	SSL_CTX_set_cookie_generate_cb(ctx, generate_cookie);
	SSL_CTX_set_cookie_verify_cb(ctx, &verify_cookie);
}

SSL_CTX*
create_configure_context()
{
	init_openssl();
	SSL_CTX* ctx = create_context();
	configure_context(ctx);
	return ctx;
}

SSL*
listen_with_ssl(int fd, SSL_CTX* ctx, RemoteAddress* client_addr) 
{
		SSL *ssl;
		BIO *bio;
		struct timeval timeout;
		
		memset(client_addr, 0, sizeof(struct sockaddr_storage));

		/* Create BIO */
		bio = BIO_new_dgram(fd, BIO_NOCLOSE);

		/* Set and activate timeouts */
		timeout.tv_sec = 5;
		timeout.tv_usec = 0;
		BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

		ssl = SSL_new(ctx);

		SSL_set_bio(ssl, bio, bio);
		SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);

		// block until there is a request from new client
		while (DTLSv1_listen(ssl, client_addr) <= 0);
		
		return ssl;
}

int
create_socket_connect_client(RemoteAddress* client_addr, RemoteAddress* server_addr)
{
	const int on = 1, off = 0;
	int fd;

	OPENSSL_assert(client_addr->ss.ss_family == server_addr->ss.ss_family);
	fd = socket(client_addr->ss.ss_family, SOCK_DGRAM, 0);
	if (fd < 0) {
		perror("socket");
		return -1;
	}

	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const void*) &on, (socklen_t) sizeof(on));
#ifdef SO_REUSEPORT
	setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, (const void*) &on, (socklen_t) sizeof(on));
#endif
	switch (client_addr->ss.ss_family) {
		case AF_INET:
			printf("AF_INET_CLIENT");
			// bind(fd, (const struct sockaddr *) &pinfo->server_addr, sizeof(struct sockaddr_in));
			connect(fd, (struct sockaddr *) client_addr, sizeof(struct sockaddr_in));
			break;
		case AF_INET6:
			printf("AF_INET6_CLIENT");		
			setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&off, sizeof(off));
			bind(fd, (const struct sockaddr *) server_addr, sizeof(struct sockaddr_in6));
			connect(fd, (struct sockaddr *) client_addr, sizeof(struct sockaddr_in6));
			break;
		default:
			OPENSSL_assert(0);
			break;
	}

	return fd;
}

int 
ssl_accept(SSL* ssl, int fd, RemoteAddress* client_addr)
{
	int ret;
	char buf[BUFFER_SIZE];	
	struct timeval timeout;

	/* Set new fd and set BIO to connected */
	BIO_set_fd(SSL_get_rbio(ssl), fd, BIO_NOCLOSE);
	BIO_ctrl(SSL_get_rbio(ssl), BIO_CTRL_DGRAM_SET_CONNECTED, 0, &client_addr->ss);

	/* Finish handshake */
	do { ret = SSL_accept(ssl); }
	while (ret == 0);
	if (ret < 0) {
		perror("SSL_accept");
		printf("%s\n", ERR_error_string(ERR_get_error(), buf));
		return -1;
	}

	/* Set and activate timeouts */
	timeout.tv_sec = 5;
	timeout.tv_usec = 0;
	BIO_ctrl(SSL_get_rbio(ssl), BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);
	
	return 0;
}

int 
ssl_write(SSL* ssl, char* buf, int length)
{
	int len = SSL_write(ssl, buf, length);

	switch (SSL_get_error(ssl, len)) {
		case SSL_ERROR_NONE:
			if (verbose) {
				printf("wrote %d bytes\n", (int) len);
			}
			break;
		case SSL_ERROR_WANT_WRITE:
			/* Just try again later */
			break;
		case SSL_ERROR_WANT_READ:
			/* continue with reading */
			break;
		case SSL_ERROR_SYSCALL:
			printf("Socket write error: ");
			if (!handle_socket_error()) return -1;
			break;
		case SSL_ERROR_SSL:
			printf("SSL write error: ");
			printf("%s (%d)\n", ERR_error_string(ERR_get_error(), buf), SSL_get_error(ssl, len));
			return -1;
			break;
		default:
			printf("Unexpected error while writing!\n");
			return -1;
			break;
	}

	return len;
}

int
ssl_read(SSL* ssl, char* buf, int length) 
{
	int len = SSL_read(ssl, buf, length);

	switch (SSL_get_error(ssl, len)) {
		case SSL_ERROR_NONE:
			if (verbose) {
				printf("read %d bytes\n", (int) len);
			}
			break;
		case SSL_ERROR_WANT_READ:
			/* Stop reading on socket timeout, otherwise try again */
			if (BIO_ctrl(SSL_get_rbio(ssl), BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP, 0, NULL)) {
				printf("Timeout! No response received.\n");
			}
			break;
		case SSL_ERROR_ZERO_RETURN:
			break;
		case SSL_ERROR_SYSCALL:
			printf("Socket read error: ");
			if (!handle_socket_error()) return -1;
			break;
		case SSL_ERROR_SSL:
			printf("SSL read error: ");
			printf("%s (%d)\n", ERR_error_string(ERR_get_error(), buf), SSL_get_error(ssl, len));
			return -1;
			break;
		default:
			printf("Unexpected error while reading!\n");
			return -1;
			break;
	}
	
	return len;
}

int 
cread(int fd, char *buf, int n)
{
  
  int nread;

  if((nread=read(fd, buf, n)) < 0){
    printf("Reading data\n");
    exit(1);
  }
  return nread;
}

int
cwrite(int fd, char *buf, int n)
{
  
  int nwrite;

  if((nwrite=write(fd, buf, n)) < 0){
    printf("Writing data\n");
    exit(1);
  }
  return nwrite;
}

int 
tun_alloc(char *dev, int flags) 
{
  struct ifreq ifr;
  int fd, err;
  char *clonedev = "/dev/net/tun";

  if( (fd = open(clonedev , O_RDWR)) < 0 ) {
    printf("Opening /dev/net/tun\n");
    return fd;
  }

  memset(&ifr, 0, sizeof(ifr));

  ifr.ifr_flags = flags;

  if (*dev) {
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
  }

  if( (err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0 ) {
    printf("ioctl(TUNSETIFF)\n");
    close(fd);
    return err;
  }

  strcpy(dev, ifr.ifr_name);

  return fd;
}

void* 
connection_handle(void *info) 
{
	ssize_t len;
	char buf[BUFFER_SIZE];
	char addrbuf[INET6_ADDRSTRLEN];
	PassInfo* pinfo = info;
	SSL *ssl = pinfo->ssl;
	int fd, tap_fd, max_fd, res;
	const int on = 1, off = 0;
	struct timeval timeout;
	int num_timeouts = 0, max_timeouts = 5;
	char if_name[IFNAMSIZ];

	fd = create_socket_connect_client(&pinfo->client_addr, &pinfo->server_addr);
	if (fd < 0) {
		goto cleanup;
	}

	res = ssl_accept(ssl, fd, &pinfo->client_addr);
	if (res < 0) {
		goto cleanup;
	}

	/* initialize tun/tap interface */
	strncpy(if_name, TUN_IF_NAME, IFNAMSIZ-1);
	if ( (tap_fd = tun_alloc(if_name, IFF_TUN | IFF_NO_PI)) < 0 ) {
		printf("Error connecting to tun/tap interface %s!\n", TUN_IF_NAME);
		exit(1);
	}

	max_fd = (tap_fd > fd) ? tap_fd : fd;

	if (verbose) {
		if (pinfo->client_addr.ss.ss_family == AF_INET) {
			printf ("\nThread %lx: accepted connection from %s:%d\n",
					id_function(),
					inet_ntop(AF_INET, &pinfo->client_addr.s4.sin_addr, addrbuf, INET6_ADDRSTRLEN),
					ntohs(pinfo->client_addr.s4.sin_port));
		} else {
			printf ("\nThread %lx: accepted connection from %s:%d\n",
					id_function(),
					inet_ntop(AF_INET6, &pinfo->client_addr.s6.sin6_addr, addrbuf, INET6_ADDRSTRLEN),
					ntohs(pinfo->client_addr.s6.sin6_port));
		}
	}

	if (veryverbose && SSL_get_peer_certificate(ssl)) {
		printf ("------------------------------------------------------------\n");
		X509_NAME_print_ex_fp(stdout, X509_get_subject_name(SSL_get_peer_certificate(ssl)),
							  1, XN_FLAG_MULTILINE);
		printf("\n\n Cipher: %s", SSL_CIPHER_get_name(SSL_get_current_cipher(ssl)));
		printf ("\n------------------------------------------------------------\n\n");
	}

	while(1) {
		int ret;
		fd_set rd_set;

		FD_ZERO(&rd_set);
		FD_SET(tap_fd, &rd_set); FD_SET(fd, &rd_set);

		ret = select(max_fd + 1, &rd_set, NULL, NULL, NULL);

		if (ret < 0 && errno == EINTR){
			continue;
		}

		if (ret < 0) {
			printf("select()\n");
			exit(1);
		}

    	if(FD_ISSET(tap_fd, &rd_set)) {
			len = cread(tap_fd, buf, BUFFER_SIZE);
			len = ssl_write(ssl, buf, len);
		}
		
		if(FD_ISSET(fd, &rd_set)) {
			len = ssl_read(ssl, buf, BUFFER_SIZE);
			len = cwrite(tap_fd, buf, len);
		}
	}
	
	SSL_shutdown(ssl);

cleanup:
	close(fd);
	free(info);
	SSL_free(ssl);
	if (verbose)
		printf("Thread %lx: done, connection closed.\n", id_function());
	pthread_exit( (void *) NULL );
}

void 
start_server(int port, char *local_address) 
{
	int fd;

	RemoteAddress server_addr, client_addr;
	pthread_t tid;
	SSL_CTX *ctx;
	SSL *ssl;
	BIO *bio;
	struct timeval timeout;
	PassInfo* info;
	const int on = 1, off = 0;

	fd = create_socket(&server_addr, local_address, port);
	THREAD_setup();
	ctx = create_configure_context();

	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const void*) &on, (socklen_t) sizeof(on));
#ifdef SO_REUSEPORT
	setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, (const void*) &on, (socklen_t) sizeof(on));
#endif

	if (server_addr.ss.ss_family == AF_INET) {
		printf("AF_INET\n");
		bind(fd, (const struct sockaddr *) &server_addr, sizeof(struct sockaddr_in));
	} else {
		printf("AF_INET6\n");
		setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&off, sizeof(off));
		bind(fd, (const struct sockaddr *) &server_addr, sizeof(struct sockaddr_in6));
	}
	while (1) {
		ssl = listen_with_ssl(fd, ctx, &client_addr);

		info = malloc (sizeof(PassInfo));
		memcpy(&info->server_addr, &server_addr, sizeof(struct sockaddr_storage));
		memcpy(&info->client_addr, &client_addr, sizeof(struct sockaddr_storage));
		info->ssl = ssl;

		if (pthread_create( &tid, NULL, connection_handle, info) != 0) {
			perror("pthread_create");
			exit(-1);
		}
	}

	THREAD_cleanup();
}

int 
main(int argc, char **argv)
{
	int port = 23232;
	char local_addr[INET6_ADDRSTRLEN+1];
	memset(local_addr, 0, INET6_ADDRSTRLEN+1);

	start_server(port, local_addr);
	return 0;
}
