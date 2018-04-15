/*
    Simple udp client
*/
#include<stdio.h> //printf
#include<string.h> //memset
#include<stdlib.h> //exit(0);
#include<arpa/inet.h>
#include<sys/socket.h>
#include <linux/if_tun.h>
#include <errno.h>
#include <stdarg.h>
#include <net/if.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define SERVER "10.10.1.2"
#define BUFLEN 512  //Max length of buffer
#define PORT 5555   //The port on which to send data
#define SSL_CERT "/vagrant/cert.pem"
#define SSL_KEY "/vagrant/key.pem"

typedef struct DataChannelInput { 
    char* if_name;
    int port; 
    char* remote_ip;
    int tun_tap_flag;
} DataChannelInput;

typedef struct ControlChannelInput { 
    int port; 
    char* remote_ip;
} ControlChannelInput;

void init_openssl() { 
    SSL_load_error_strings();	
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl() {
    EVP_cleanup();
}

SSL_CTX *create_context(){
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = SSLv3_client_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
      perror("Unable to create SSL context");
      ERR_print_errors_fp(stderr);
      exit(EXIT_FAILURE);
    }

    return ctx;
}

void configure_context(SSL_CTX *ctx) {
    /* Set the key and cert */
    if (SSL_CTX_use_certificate_file(ctx, SSL_CERT, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
	      exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, SSL_KEY, SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
	      exit(EXIT_FAILURE);
    }
}

/**************************************************************************
 * ssl_cread: read routine that checks for errors and exits if an error is    *
 *        returned.                                                       *
 **************************************************************************/
int ssl_cread(SSL *clientssl, char *buf, int n){
  
  int nread;

  if((nread=SSL_read(clientssl, buf, n)) < 0){
    perror("Reading data");
    exit(1);
  }
  return nread;
}

/**************************************************************************
 * ssl_cwrite: write routine that checks for errors and exits if an error is  *
 *         returned.                                                      *
 **************************************************************************/
int ssl_cwrite(SSL *clientssl, char *buf, int n){
  
  int nwrite;

  if((nwrite=SSL_write(clientssl, buf, n)) < 0){
    perror("Writing data");
    exit(1);
  }
  return nwrite;
}

/**************************************************************************
 * ssl_read_n: ensures we read exactly n bytes, and puts them into "buf".     *
 *         (unless EOF, of course)                                        *
 **************************************************************************/
int ssl_read_n(SSL *clientssl, char *buf, int n) {

  int nread, left = n;

  while(left > 0) {
    if ((nread = ssl_cread(clientssl, buf, left)) == 0){
      return 0 ;      
    }else {
      left -= nread;
      buf += nread;
    }
  }
  return n;  
}

/**************************************************************************
 * cread: read routine that checks for errors and exits if an error is    *
 *        returned.                                                       *
 **************************************************************************/
int cread(int fd, char *buf, int n){
  
  int nread;

  if((nread=read(fd, buf, n)) < 0){
    perror("Reading data");
    exit(1);
  }
  return nread;
}

/**************************************************************************
 * cwrite: write routine that checks for errors and exits if an error is  *
 *         returned.                                                      *
 **************************************************************************/
int cwrite(int fd, char *buf, int n){
  
  int nwrite;

  if((nwrite=write(fd, buf, n)) < 0){
    perror("Writing data");
    exit(1);
  }
  return nwrite;
}

/**************************************************************************
 * read_n: ensures we read exactly n bytes, and puts them into "buf".     *
 *         (unless EOF, of course)                                        *
 **************************************************************************/
int read_n(int fd, char *buf, int n) {

  int nread, left = n;

  while(left > 0) {
    if ((nread = cread(fd, buf, left)) == 0){
      return 0 ;      
    }else {
      left -= nread;
      buf += nread;
    }
  }
  return n;  
}

/**************************************************************************
 * my_err: prints custom error messages on stderr.                        *
 **************************************************************************/
void my_err(char *msg, ...) {

  va_list argp;
  
  va_start(argp, msg);
  vfprintf(stderr, msg, argp);
  va_end(argp);
}

/**************************************************************************
 * tun_alloc: allocates or reconnects to a tun/tap device. The caller     *
 *            must reserve enough space in *dev.                          *
 **************************************************************************/
int tun_alloc(char *dev, int flags) {

  struct ifreq ifr;
  int fd, err;
  char *clonedev = "/dev/net/tun";

  if( (fd = open(clonedev , O_RDWR)) < 0 ) {
    perror("Opening /dev/net/tun");
    return fd;
  }

  memset(&ifr, 0, sizeof(ifr));

  ifr.ifr_flags = flags;

  if (*dev) {
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
  }

  if( (err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0 ) {
    perror("ioctl(TUNSETIFF)");
    close(fd);
    return err;
  }

  strcpy(dev, ifr.ifr_name);

  return fd;
}
 
void die(char *s)
{
    perror(s);
    exit(1);
}

void* startDataChannel(void* args) {
    int tap_fd;
    int flags = IFF_TUN;
    char* if_name;
    int maxfd;
    char* remote_ip;
    unsigned short int port = PORT;

    struct sockaddr_in si_other;
    int net_fd, i, slen=sizeof(si_other), recv_len, send_len;
    char buf[BUFLEN];
    char message[BUFLEN];

    DataChannelInput* input = (DataChannelInput*) args;
    port = input->port;
    if_name = input->if_name;
    remote_ip = input->remote_ip;
    flags = input->tun_tap_flag;

    printf("%d\n", input->port);

    /* initialize tun/tap interface */
    if ( (tap_fd = tun_alloc(if_name, flags | IFF_NO_PI)) < 0 ) {
        my_err("Error connecting to tun/tap interface %s! for UDP connection \n", if_name);
        exit(1);
    }
 
    if ( (net_fd=socket(AF_INET, SOCK_DGRAM, 0)) == -1)
    {
        die("socket");
    }
 
    memset((char *) &si_other, 0, sizeof(si_other));
    si_other.sin_family = AF_INET;
    si_other.sin_port = htons(PORT);
     
    if (inet_aton(remote_ip , &si_other.sin_addr) == 0) 
    {
        fprintf(stderr, "inet_aton() failed\n");
        exit(1);
    }

    /* use select() to handle two descriptors at once */
    maxfd = (tap_fd > net_fd)?tap_fd:net_fd;
    
    while(1)
    {        
        int ret;
        fd_set rd_set;

        FD_ZERO(&rd_set);
        FD_SET(tap_fd, &rd_set); FD_SET(net_fd, &rd_set);

        ret = select(maxfd + 1, &rd_set, NULL, NULL, NULL);

        if (ret < 0 && errno == EINTR){
            continue;
        }

        if (ret < 0) {
            perror("select()");
            exit(1);
        }

        if(FD_ISSET(tap_fd, &rd_set)) {
            printf("tun\n");
            /* data from tun/tap: just read it and write it to the network */
            
            recv_len = cread(tap_fd, buf, BUFLEN);

            //now reply the client with the same data
            if (sendto(net_fd, buf, recv_len, 0, (struct sockaddr*) &si_other, slen) == -1)
            {
                die("sendto()");
            }
        }

        if(FD_ISSET(net_fd, &rd_set)) {
            printf("net\n");
            /* data from the network: read it, and write it to the tun/tap interface. 
            * We need to read the length first, and then the packet */

            //try to receive some data, this is a blocking call
            if ((recv_len = recvfrom(net_fd, buf, BUFLEN, 0, (struct sockaddr *) &si_other, &slen)) == -1)
            {
                die("recvfrom()");
            }
            printf("Data: %s\n" , buf);

            /* now buffer[] contains a full packet or frame, write it into the tun/tap interface */ 
            send_len = cwrite(tap_fd, buf, recv_len);
        }
    }
 
    close(net_fd);

    pthread_exit(0);
}

void* startControlChannel(void* args) {
    uint16_t nread, nwrite, plength;
    char buffer[BUFLEN];
    struct sockaddr_in remote;
    char* remote_ip;            /* dotted quad IP string */
    unsigned short int port = PORT;
    int net_fd;
    SSL_CTX *ctx;
    SSL *clientssl;
    int ret;

    ControlChannelInput* input = (ControlChannelInput*) args;
    port = input->port;
    remote_ip = input->remote_ip;

    printf("%d\n", input->port);    

    if ((net_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket()");
        pthread_exit(0);        
    }

    /* openssl related things */
    init_openssl();
    ctx = create_context();
    configure_context(ctx);

    /* assign the destination address */
    memset(&remote, 0, sizeof(remote));
    remote.sin_family = AF_INET;
    remote.sin_addr.s_addr = inet_addr(remote_ip);
    remote.sin_port = htons(port);

    /* connection request */
    if (connect(net_fd, (struct sockaddr*) &remote, sizeof(remote)) < 0) {
        perror("connect()");
        pthread_exit(0);                
    }

    clientssl = SSL_new(ctx);
    if(!clientssl)
    {
        printf("Error SSL_new\n");
        pthread_exit(0);        
    }
    SSL_set_fd(clientssl, net_fd);
        
    if((ret = SSL_connect(clientssl)) != 1)
    {
        printf("Handshake Error %d\n", SSL_get_error(clientssl, ret));
        pthread_exit(0);        
    }

    /* write length + packet */
    buffer[0] = 'H';
    buffer[1] = 'E';
    buffer[2] = 'L';
    buffer[3] = 'L';
    buffer[4] = 'O';
    buffer[5] = '\n';
    plength = htons(strlen(buffer));
    nwrite = ssl_cwrite(clientssl, (char *)&plength, sizeof(plength));
    nwrite = ssl_cwrite(clientssl, buffer, plength);

    while(1) {
        fd_set rd_set;
        FD_ZERO(&rd_set);
        FD_SET(net_fd, &rd_set);
        ret = select(net_fd + 1, &rd_set, NULL, NULL, NULL);

        if (ret < 0 && errno == EINTR){
            continue;
        }

        if (ret < 0) {
            perror("select()");
            pthread_exit(0);        
        }

        if(FD_ISSET(net_fd, &rd_set)) {
            nread = ssl_read_n(clientssl, (char *)&plength, sizeof(plength));
            if(nread == 0) {
                /* ctrl-c at the other end */
                break;
            }

            /* read packet */
            nread = ssl_read_n(clientssl, (char *)&plength, sizeof(plength));
            printf(buffer);
        }
    }

    SSL_shutdown(clientssl);
	close(net_fd);
	SSL_free(clientssl);
	SSL_CTX_free(ctx);

    pthread_exit(0);    
}
 
int main(int argc, char *argv[])
{
    int option;
    int flags = IFF_TUN;
    char if_name[IFNAMSIZ] = "";
    char remote_ip[16] = SERVER;
    unsigned short int port = PORT;
    int err;

    /* Check command line options */
    while((option = getopt(argc, argv, "i:s:p:ua")) > 0) {
        switch(option) {
        case 'i':
            strncpy(if_name,optarg, IFNAMSIZ-1);
            break;
        case 'p':
            port = atoi(optarg);
            break;
        case 's':
            strncpy(remote_ip,optarg,15);
            break;
        case 'u':
            flags = IFF_TUN;
            break;
        case 'a':
            flags = IFF_TAP;
            break;
        default:
            my_err("Unknown option %c\n", option);
        }
    }

    // construct and start thread for data channel
    pthread_t dataChannelTid;
    DataChannelInput* dataChannelInput = malloc(sizeof(DataChannelInput));
    dataChannelInput->port = port;
    dataChannelInput->if_name = &if_name;
    dataChannelInput->remote_ip = &remote_ip;
    dataChannelInput->tun_tap_flag = flags;
    err = pthread_create(&dataChannelTid, NULL, startDataChannel, (void*) dataChannelInput);
    if (err != 0) {
        printf("can't create thread :[%s]\n", strerror(err));
    }

    // construct and start thread for control channel
    pthread_t controlChannelTid;
    ControlChannelInput* controlChannelInput = malloc(sizeof(ControlChannelInput));
    controlChannelInput->port = port;
    controlChannelInput->remote_ip = &remote_ip;
    err = pthread_create(&controlChannelTid, NULL, startControlChannel, (void*) controlChannelInput);
    if (err != 0) {
        printf("can't create thread :[%s]\n", strerror(err));
    }

    pthread_join(dataChannelTid, NULL);     
    pthread_join(controlChannelTid, NULL); 

    return 0;
}