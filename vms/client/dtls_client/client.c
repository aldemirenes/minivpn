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

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>


#define BUFFER_SIZE          (1<<16)
#define COOKIE_SECRET_LENGTH 16

#define SSL_CERT "/vagrant/cert.pem"
#define SSL_KEY "/vagrant/key.pem"

typedef union {
	struct sockaddr_storage ss;
	struct sockaddr_in s4;
	struct sockaddr_in6 s6;
} RemoteAddress;

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
create_socket(RemoteAddress* remote_addr, char* remote_address_str, int port) 
{
	memset((void *) remote_addr, 0, sizeof(struct sockaddr_storage));

	if (inet_pton(AF_INET, remote_address_str, &remote_addr->s4.sin_addr) == 1) {
		printf("AF_INET_CLIENT");
		remote_addr->s4.sin_family = AF_INET;
#ifdef HAVE_SIN_LEN
		remote_addr->s4.sin_len = sizeof(struct sockaddr_in);
#endif
		remote_addr->s4.sin_port = htons(port);
	} else if (inet_pton(AF_INET6, remote_address_str, &remote_addr->s6.sin6_addr) == 1) {
		printf("AF_INET_CLIENT6");
		remote_addr->s6.sin6_family = AF_INET6;
#ifdef HAVE_SIN6_LEN
		remote_addr->s6.sin6_len = sizeof(struct sockaddr_in6);
#endif
		remote_addr->s6.sin6_port = htons(port);
	} else {
		return;
	}

	int fd = socket(remote_addr->ss.ss_family, SOCK_DGRAM, 0);
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
    const SSL_METHOD* method = DTLSv1_client_method();
	SSL_CTX* ctx = SSL_CTX_new(method);

	if (!ctx) {
		perror("Unable to create SSL context");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
    }

	return ctx;
}

void
configure_context(SSL_CTX *ctx)
{
	SSL_CTX_set_cipher_list(ctx, "eNULL:!MD5");

	if (!SSL_CTX_use_certificate_file(ctx, SSL_CERT, SSL_FILETYPE_PEM))
		printf("\nERROR: no certificate found!");

	if (!SSL_CTX_use_PrivateKey_file(ctx, SSL_KEY, SSL_FILETYPE_PEM))
		printf("\nERROR: no private key found!");

	if (!SSL_CTX_check_private_key (ctx))
		printf("\nERROR: invalid private key!");

	SSL_CTX_set_verify_depth (ctx, 2);
	SSL_CTX_set_read_ahead(ctx, 1);
}

SSL*
connect_with_ssl(int fd, RemoteAddress* remote_addr)
{
	SSL_CTX *ctx;
	SSL *ssl;
	BIO *bio;
	struct timeval timeout;
	char buf[BUFFER_SIZE];
	
	init_openssl();
	ctx = create_context();
	configure_context(ctx);

	ssl = SSL_new(ctx);

	/* Create BIO, connect and set to already connected */
	bio = BIO_new_dgram(fd, BIO_CLOSE);
	if (remote_addr->ss.ss_family == AF_INET) {
		connect(fd, (struct sockaddr *) remote_addr, sizeof(struct sockaddr_in));
	} else {
		connect(fd, (struct sockaddr *) remote_addr, sizeof(struct sockaddr_in6));
	}
	BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &remote_addr->ss);

	SSL_set_bio(ssl, bio, bio);

	if (SSL_connect(ssl) < 0) {
		perror("SSL_connect");
		printf("%s\n", ERR_error_string(ERR_get_error(), buf));
		exit(-1);
	}

	/* Set and activate timeouts */
	timeout.tv_sec = 3;
	timeout.tv_usec = 0;
	BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

	return ssl;
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

void 
start_client(char *remote_address, int port, int length, int messagenumber) 
{
	int fd;
	char buf[BUFFER_SIZE];
	char addrbuf[INET6_ADDRSTRLEN];
	socklen_t len;
	SSL_CTX *ctx;
	SSL *ssl;
	BIO *bio;
	int reading = 0;
	struct timeval timeout;
	RemoteAddress remote_addr;
	fd = create_socket(&remote_addr, remote_address, port);
	ssl = connect_with_ssl(fd, &remote_addr);

	if (verbose) {
		if (remote_addr.ss.ss_family == AF_INET) {
			printf ("\nConnected to %s\n",
					 inet_ntop(AF_INET, &remote_addr.s4.sin_addr, addrbuf, INET6_ADDRSTRLEN));
		} else {
			printf ("\nConnected to %s\n",
					 inet_ntop(AF_INET6, &remote_addr.s6.sin6_addr, addrbuf, INET6_ADDRSTRLEN));
		}
	}

	if (veryverbose && SSL_get_peer_certificate(ssl)) {
		printf ("------------------------------------------------------------\n");
		X509_NAME_print_ex_fp(stdout, X509_get_subject_name(SSL_get_peer_certificate(ssl)),
							  1, XN_FLAG_MULTILINE);
		printf("\n\n Cipher: %s", SSL_CIPHER_get_name(SSL_get_current_cipher(ssl)));
		printf ("\n------------------------------------------------------------\n\n");
	}

	while (!(SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN)) {

		if (messagenumber > 0) {

			len = ssl_write(ssl, buf, length);
			messagenumber--;
			if (len < 0) {
				exit(-1);
			}
#if 0
			/* Send heartbeat. Requires Heartbeat extension. */
			if (messagenumber == 2)
				SSL_heartbeat(ssl);
#endif

			/* Shut down if all messages sent */
			if (messagenumber == 0)
				SSL_shutdown(ssl);
		}

		len = ssl_read(ssl, buf, sizeof(buf));
		if (len < 0) {
			exit(-1);
		}
	}

	close(fd);
	if (verbose)
		printf("Connection closed.\n");
}

int 
main(int argc, char **argv)
{
	int port = 23232;
	int length = 100;
	int messagenumber = 5;
	char remote_addr[INET6_ADDRSTRLEN+1] = "10.10.1.2";	

    start_client(remote_addr, port, length, messagenumber);
	return 0;
}
