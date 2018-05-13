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

#define CERT_KEY_FILE_NAME_SIZE 500
#define SSL_CERT "/vagrant/cert.pem"
#define SSL_KEY "/vagrant/key.pem"
#define TUN_IF_NAME "tun0"

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
"Usage: client [options] [address]\n"
"Options:\n"
"        -i <ifacename>: Name of tun/tap interface to use \n"
"        -s <serverIP>: Server address to connect \n"
"        -p <port>: Port to connect to server\n"
"        -c <ssl_cert>: Path of the SSL cert\n"
"        -k <ssl_key>: Path of the SSL key\n"
"        -h help\n";

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
		printf("socket can not be created\n");
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
		printf("Unable to create SSL context");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
    }

	return ctx;
}

void
configure_context(SSL_CTX *ctx, char* ssl_cert, char* ssl_key)
{
	// SSL_CTX_set_cipher_list(ctx, "eNULL:!MD5");

	if (!SSL_CTX_use_certificate_file(ctx, ssl_cert, SSL_FILETYPE_PEM))
		printf("\nERROR: no certificate found!");

	if (!SSL_CTX_use_PrivateKey_file(ctx, ssl_key, SSL_FILETYPE_PEM))
		printf("\nERROR: no private key found!");

	if (!SSL_CTX_check_private_key (ctx))
		printf("\nERROR: invalid private key!");

	SSL_CTX_set_verify_depth (ctx, 2);
	SSL_CTX_set_read_ahead(ctx, 1);
}

SSL*
connect_with_ssl(int fd, RemoteAddress* remote_addr, char* ssl_cert, char* ssl_key)
{
	SSL_CTX *ctx;
	SSL *ssl;
	BIO *bio;
	struct timeval timeout;
	char buf[BUFFER_SIZE];
	
	init_openssl();
	ctx = create_context();
	configure_context(ctx, ssl_cert, ssl_key);

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
		printf("SSL_connect");
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

void 
start_client(char *remote_address, int port, char* tun_if_name, char* ssl_cert, char* ssl_key) 
{
	int fd, tap_fd, max_fd;
	char buf[BUFFER_SIZE];
	char addrbuf[INET6_ADDRSTRLEN];
	socklen_t len;
	SSL_CTX *ctx;
	SSL *ssl;
	BIO *bio;
	struct timeval timeout;
	RemoteAddress remote_addr;
	char if_name[IFNAMSIZ];

	fd = create_socket(&remote_addr, remote_address, port);
	ssl = connect_with_ssl(fd, &remote_addr, ssl_cert, ssl_key);

	/* initialize tun/tap interface */
	strncpy(if_name, tun_if_name, IFNAMSIZ-1);
	if ( (tap_fd = tun_alloc(if_name, IFF_TUN | IFF_NO_PI)) < 0 ) {
		printf("Error connecting to tun/tap interface %s!\n", if_name);
		exit(1);
	}

	max_fd = (tap_fd > fd) ? tap_fd : fd;

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

	close(fd);
	if (verbose)
		printf("Connection closed.\n");
}

void
usage()
{
	printf(Usage);
	exit(1);
}

void 
my_err(char *msg, ...) 
{
  va_list argp;
  
  va_start(argp, msg);
  vfprintf(stderr, msg, argp);
  va_end(argp);
}

int 
main(int argc, char **argv)
{
	char tun_if_name[IFNAMSIZ] = "";
	strncpy(tun_if_name, TUN_IF_NAME, IFNAMSIZ-1);	
	int port;
	char remote_addr[INET6_ADDRSTRLEN+1] = "";	
	int opt;
	char ssl_cert[CERT_KEY_FILE_NAME_SIZE] = "";
	char ssl_key[CERT_KEY_FILE_NAME_SIZE] = "";
	// int port = 23232;
	// char remote_addr[INET6_ADDRSTRLEN+1] = "10.10.1.2";		
	// char remote_addr[INET6_ADDRSTRLEN+1] = "167.99.32.110";

	/* Check command line options */
	int num_of_must_arguments = 5;
	while((opt = getopt(argc, argv, "i:s:p:h:c:k:")) > 0) {
		switch(opt) {
		case 'h':
			usage();
			break;
		case 'i':
			strncpy(tun_if_name, optarg, IFNAMSIZ-1);
			break;
		case 's':
			strncpy(remote_addr, optarg, INET6_ADDRSTRLEN+1);
			break;
		case 'p':
			port = atoi(optarg);
			break;
		case 'c':
			strncpy(ssl_cert, optarg, CERT_KEY_FILE_NAME_SIZE-1);
			break;
		case 'k':
			strncpy(ssl_key, optarg, CERT_KEY_FILE_NAME_SIZE-1);
			break;
		default:
			my_err("Unknown option %c\n");
			usage();
		}
	}

	// every arguments must have flag too, therefore every
	// one of them will add 2 to argc
	// also, progname will increase argc one more
	if(argc != num_of_must_arguments * 2 + 1) {
		my_err("Check it out the usage!\n");
		usage();
	}	

    start_client(remote_addr, port, tun_if_name, ssl_cert, ssl_key);
	return 0;
}
