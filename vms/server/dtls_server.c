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

void
init_openssl()
{
    SSL_load_error_strings(); /* readable error messages */
    SSL_library_init(); /* initialize library */
    OpenSSL_add_ssl_algorithms();
}

int 
verify_cookie(SSL *ssl, unsigned char *cookie, unsigned int cookie_len)
{
    return 1;
}

int 
generate_cookie(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len)
{
    return 1;
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

    SSL_CTX_set_cipher_list(ctx, "ALL:NULL:eNULL:aNULL");
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
}

int
main()
{
    struct timeval timeout;

    init_openssl();
    SSL_CTX* ctx = create_server_context();
    configure_context(ctx);

    char buf[BUFLEN];
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    bind(fd, (struct sockaddr*)&server_addr, sizeof(struct sockaddr_in));
    
    while(1) {
        struct sockaddr_storage client_addr;
        memset(&client_addr, 0, sizeof(struct sockaddr_storage));

        BIO *bio = BIO_new_dgram(fd, BIO_NOCLOSE);

        SSL *ssl = SSL_new(ctx);
        SSL_set_bio(ssl, bio, bio);
        /* Enable cookie exchange */
        SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);
        
        printf("hey\n");
        /* Wait for incoming connections */
        while (!DTLSv1_listen(ssl, (BIO_ADDR *) &client_addr));
        printf("hey\n");
        
        /* Handle client connection */
        int client_fd = socket(AF_INET, SOCK_DGRAM, 0);
        bind(client_fd, (struct sockaddr*)&server_addr, sizeof(struct sockaddr_in));
        connect(client_fd, (struct sockaddr*)&client_addr, sizeof(struct sockaddr_in));
        /* Set new fd and set BIO to connected */
        BIO *cbio = SSL_get_rbio(ssl);
        BIO_set_fd(cbio, client_fd, BIO_NOCLOSE);
        BIO_ctrl(cbio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &client_addr);
        /* Finish handshake */
        SSL_accept(ssl);

        buf[0] = 'H';
        buf[1] = 'E';
        buf[2] = 'L';
        buf[3] = 'L';
        buf[4] = 'O';
        buf[5] = '\n';
        int len = strlen(buf);
        SSL_write(ssl, buf, len);
    }
}