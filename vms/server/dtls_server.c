#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#define PORT 5555
#define SSL_CERT "/vagrant/cert.pem"
#define SSL_KEY "/vagrant/key.pem"
#define BUFLEN 512
#define COOKIE_SECRET_LENGTH 16

int cookie_initialized=0;
unsigned char cookie_secret[COOKIE_SECRET_LENGTH];

void
init_openssl()
{
    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings(); /* readable error messages */
    // SSL_library_init(); /* initialize library */
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
verify_cookie(SSL *ssl, unsigned char *cookie, unsigned int cookie_len)
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

int
dtls_verify_callback (int ok, X509_STORE_CTX *ctx) 
{
	return 1;
}

SSL_CTX*
create_server_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = DTLSv1_server_method();

    ctx = SSL_CTX_new(method);
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
    SSL_CTX_set_cipher_list(ctx, "ALL:NULL:eNULL:aNULL");
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);

    /* Set the key and cert */
    if (!SSL_CTX_use_certificate_file(ctx, SSL_CERT, SSL_FILETYPE_PEM)) {
        ERR_print_errors_fp(stderr);
    	exit(EXIT_FAILURE);
    }
    if(!SSL_CTX_use_PrivateKey_file(ctx, SSL_KEY, SSL_FILETYPE_PEM)) {
        ERR_print_errors_fp(stderr);
	    exit(EXIT_FAILURE); 
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE, dtls_verify_callback);
	SSL_CTX_set_read_ahead(ctx, 1);
	SSL_CTX_set_cookie_generate_cb(ctx, generate_cookie);
	SSL_CTX_set_cookie_verify_cb(ctx, &verify_cookie);
}

int
main()
{
    struct timeval timeout;

    init_openssl();
    SSL_CTX* ctx = create_server_context();
    configure_context(ctx);

    char buf[BUFLEN];
    // struct sockaddr_in server_addr;
    // server_addr.sin_family = AF_INET;
    // server_addr.sin_port = htons(PORT);
    // server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    struct sockaddr_in6 server_addr;
    server_addr.sin6_family = AF_INET6;
    server_addr.sin6_port = htons(PORT);
    server_addr.sin6_addr = in6addr_any;

    int off = 0;
    int fd = socket(AF_INET6, SOCK_DGRAM, 0);
	setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&off, sizeof(off));    
    bind(fd, (struct sockaddr*)&server_addr, sizeof(struct sockaddr_in));

    struct sockaddr_in client_addr;    
    while(1) {
        memset(&client_addr, 0, sizeof(struct sockaddr_in));

        BIO *bio = BIO_new_dgram(fd, BIO_NOCLOSE);

		/* Set and activate timeouts */
		timeout.tv_sec = 5;
		timeout.tv_usec = 0;
		BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

        SSL *ssl = SSL_new(ctx);
        SSL_set_bio(ssl, bio, bio);
        /* Enable cookie exchange */
        SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);
        
        /* Wait for incoming connections */
        while (!DTLSv1_listen(ssl, &client_addr));
        printf("hey\n");
        
        /* Handle client connection */
        int client_fd = socket(AF_INET6, SOCK_DGRAM, 0);
		setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&off, sizeof(off));        
        bind(client_fd, (struct sockaddr*) &server_addr, sizeof(struct sockaddr_in6));
        connect(client_fd, (struct sockaddr*) &client_addr, sizeof(struct sockaddr_in6));
        /* Set new fd and set BIO to connected */
        BIO *cbio = SSL_get_rbio(ssl);
        BIO_set_fd(cbio, client_fd, BIO_NOCLOSE);
        BIO_ctrl(cbio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &client_addr);
        /* Finish handshake */
        SSL_accept(ssl);
        printf("hey\n");        

        /* Set and activate timeouts */
        timeout.tv_sec = 5;
        timeout.tv_usec = 0;
        BIO_ctrl(SSL_get_rbio(ssl), BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

        buf[0] = 'H';
        buf[1] = 'E';
        buf[2] = 'L';
        buf[3] = 'L';
        buf[4] = 'O';
        buf[5] = '\n';
        int len = strlen(buf);
        printf(buf);
        SSL_write(ssl, buf, len);
    }
}