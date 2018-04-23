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

#define SERVER "10.10.1.2"
#define PORT 5555
#define SSL_CERT "/vagrant/cert.pem"
#define SSL_KEY "/vagrant/key.pem"
#define BUFLEN 512

void
init_openssl()
{
    OpenSSL_add_ssl_algorithms();        
    SSL_load_error_strings(); /* readable error messages */
    // SSL_library_init(); /* initialize library */
}

SSL_CTX*
create_client_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = DTLSv1_client_method();

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
    SSL_CTX_set_cipher_list(ctx, "eNULL:!MD5");

    /* Set the key and cert */
    if (!SSL_CTX_use_certificate_file(ctx, SSL_CERT, SSL_FILETYPE_PEM)) {
        ERR_print_errors_fp(stderr);
    	exit(EXIT_FAILURE);
    }
    if(!SSL_CTX_use_PrivateKey_file(ctx, SSL_KEY, SSL_FILETYPE_PEM)) {
        ERR_print_errors_fp(stderr);
	    exit(EXIT_FAILURE); 
    }
    
    SSL_CTX_set_verify_depth (ctx, 2);
	SSL_CTX_set_read_ahead(ctx, 1);
}

int 
main() 
{
    char buf[BUFLEN];
    struct sockaddr_in server_addr;
    memset((char *) &server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    if (inet_pton(AF_INET, SERVER , &server_addr.sin_addr) == 0) 
    {
        fprintf(stderr, "inet_aton() failed\n");
        exit(1);
    }
    // struct sockaddr_storage local_addr;
    // memset((char *) &local_addr, 0, sizeof(local_addr));
    // local_addr.sin_family = AF_INET;
    // local_addr.sin_port = htons(0);
    // //local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    // if (inet_pton(AF_INET, "127.0.0.1" , &local_addr.sin_addr) == 0) 
    // {
    //     fprintf(stderr, "inet_aton() failed\n");
    //     exit(1);
    // }
    

    init_openssl();
    SSL_CTX* ctx = create_client_context();
    configure_context(ctx);

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    // bind(fd, (const struct sockaddr *) &local_addr, sizeof(struct sockaddr_in));

    SSL *ssl = SSL_new(ctx);

    BIO *bio = BIO_new_dgram(fd, BIO_CLOSE);
    connect(fd, (struct sockaddr*)&server_addr, sizeof(struct sockaddr_in));
    BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, (struct sockaddr*)&server_addr);
    SSL_set_bio(ssl, bio, bio);
    /* Perform handshake */
    printf("hey\n");    
    SSL_connect(ssl);
    printf("hey\n");

    int reading = 1;
    int len;
    while (reading) {
        len = SSL_read(ssl, buf, BUFLEN);
        printf(buf);

        switch (SSL_get_error(ssl, len)) {
            case SSL_ERROR_NONE:
                reading = 0;
                break;
            case SSL_ERROR_WANT_READ:
                printf("Want read error: ");                        
                /* Stop reading on socket timeout, otherwise try again */
                if (BIO_ctrl(SSL_get_rbio(ssl), BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP, 0, NULL)) {
                    printf("Timeout! No response received.\n");
                    reading = 0;
                }
                break;
            case SSL_ERROR_ZERO_RETURN:
                printf("Zero return error: ");            
                reading = 0;
                break;
            case SSL_ERROR_SYSCALL:
                printf("Socket read error: ");
                reading = 0;
                break;
            case SSL_ERROR_SSL:
                printf("SSL read error: ");
                printf("%s (%d)\n", ERR_error_string(ERR_get_error(), buf), SSL_get_error(ssl, len));
                exit(1);
                break;
            default:
                printf("Unexpected error while reading!\n");
                exit(1);
                break;
        }
    }
}
