/*
    Simple udp server
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

#define BUFLEN 512  //Max length of buffer
#define PORT 8888   //The port on which to listen for incoming data
 
typedef struct DataChannelInput { 
    char* if_name;
    int port; 
    int tun_tap_flag;
} DataChannelInput;

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
    unsigned short int port = PORT;

    struct sockaddr_in si_me, si_other;
     
    int net_fd, i, slen = sizeof(si_other) , recv_len, send_len;
    char buf[BUFLEN];

    DataChannelInput* input = (DataChannelInput*) args;
    port = input->port;
    if_name = input->if_name;
    flags = input->tun_tap_flag;

    /* initialize tun/tap interface */
    if ( (tap_fd = tun_alloc(if_name, flags | IFF_NO_PI)) < 0 ) {
        my_err("Error connecting to tun/tap interface %s!\n", if_name);
        exit(1);
    }
     
    //create a UDP socket
    if ((net_fd=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
    {
        die("socket");
    }
     
    // zero out the structure
    memset((char *) &si_me, 0, sizeof(si_me));
     
    si_me.sin_family = AF_INET;
    si_me.sin_port = htons(PORT);
    si_me.sin_addr.s_addr = htonl(INADDR_ANY);
     
    //bind socket to port
    if( bind(net_fd , (struct sockaddr*)&si_me, sizeof(si_me) ) == -1)
    {
        die("bind");
    }

    /* use select() to handle two descriptors at once */
    maxfd = (tap_fd > net_fd)?tap_fd:net_fd;
     
    //keep listening for data
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

        printf("Waiting for data...");
        fflush(stdout);

        if(FD_ISSET(tap_fd, &rd_set)) {
            /* data from tun/tap: just read it and write it to the network */
            
            recv_len = cread(tap_fd, buf, BUFLEN);

            //now reply the client with the same data
            if (sendto(net_fd, buf, recv_len, 0, (struct sockaddr*) &si_other, slen) == -1)
            {
                die("sendto()");
            }
        }

        if(FD_ISSET(net_fd, &rd_set)) {
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
                  
        //print details of the client/peer and the data received
        printf("Received packet from %s:%d\n", inet_ntoa(si_other.sin_addr), ntohs(si_other.sin_port));
        printf("Data: %s\n" , buf);
         
    }
 
    close(net_fd);
    pthread_exit(0);    

}

int main(int argc, char *argv[])
{
    int tap_fd, option;
    int flags = IFF_TUN;
    char if_name[IFNAMSIZ] = "";
    unsigned short int port = PORT;
    int err;

    /* Check command line options */
    while((option = getopt(argc, argv, "i:sc:p:ua")) > 0) {
        switch(option) {
        case 'i':
            strncpy(if_name,optarg, IFNAMSIZ-1);
            break;
        case 'p':
            port = atoi(optarg);
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

    pthread_t tid;
    DataChannelInput* dataChannelInput = malloc(sizeof(DataChannelInput));
    dataChannelInput->port = PORT;
    dataChannelInput->if_name = &if_name;
    dataChannelInput->tun_tap_flag = flags;
    err = pthread_create(&tid, NULL, startDataChannel, (void*) dataChannelInput);
    if (err != 0) {
        printf("can't create thread :[%s]\n", strerror(err));
    }
    pthread_join(tid, NULL); 

   
    return 0;
}