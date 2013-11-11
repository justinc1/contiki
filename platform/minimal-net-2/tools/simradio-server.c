/*
A simple simulated radio. A server is listening on SIMRADIO_HOST:SIMRADIO_PORT.
Clients connect to the server during platform initialization.
A single client then transmits radio frame to the server, and server forwards the frame to remaining clients.  

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>

#define QLEN 5

#define SIMRADIO_HOST "localhost"
#define SIMRADIO_PORT 4432
#define MAX_CLIENTS 5

int echo(int fd);
int echo_all(int fd);
#define errexit(...) { fprintf(stderr, __VA_ARGS__); exit(1); }
#if 1
  #define PRINTF(...) printf(__VA_ARGS__)
#else
  #define PRINTF(...)
#endif
int passivesock(const char *service, const char *transport, int qlen)
{
    struct servent  *pse;
    struct protoent *ppe;
    struct sockaddr_in sin;
    int     s, type;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = INADDR_ANY;
    sin.sin_port = htons(SIMRADIO_PORT);

/*
    /* Map service name to port number * /
    if(pse = getservbyname(service, transport))
        sin.sin_port = htons(ntohs((u_short)pse->s_port) + portbase);
    else if((sin.sin_port = htons((u_short)atoi(service))) == 0)
        errexit("can't get \"%s\" service entry\n", service);
    /* Map protocol name to protocol number * /
    if((ppe = getprotobyname(transport)) == 0)
        errexit("can't get \"%s\" protocol entry\n", transport);
    /* Use protocol to choose a socket type * /
    if(strcmp(transport, "udp") == 0)
        type = SOCK_DGRAM;
    else
        type = SOCK_STREAM;
*/
    type = SOCK_STREAM;
    /* Allocate a socket */
    s = socket(PF_INET, type, 0);
    if(s < 0)
        errexit("can't create socket: %s\n", strerror(errno));
    int on = 1;
    if(setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on) ))
        errexit("opt SO_REUSEADDR failed\n");
    /* Bind the socket */
    if(bind(s, (struct sockaddr *)&sin, sizeof(sin)) < 0)
        errexit("can't bind to %s port: %s\n", service, strerror(errno));
    if(type == SOCK_STREAM && listen(s, qlen) < 0)
        errexit("can't listen on %s port: %s\n", service, strerror(errno));
    PRINTF("Listen on port %d\n", SIMRADIO_PORT);
    return s;
}

int passiveTCP(const char *service, int qlen)
{
    return passivesock(service, "tcp", qlen);
}


int sock_all[MAX_CLIENTS] = {0};
void allfd_add(int fd) {
    int ii;
    for(ii=0; ii<MAX_CLIENTS; ii++) {
        if(sock_all[ii] == 0) {
            sock_all[ii] = fd;
            return;
        }
    }
    errexit("hja\n");
}
void allfd_del(int fd) {
    int ii;
    for(ii=0; ii<MAX_CLIENTS; ii++) {
        if(sock_all[ii] == fd) {
            sock_all[ii] = 0;
            return;
        }
    }
    errexit("hja 2\n");
}
int allfd_get(int *ii) {
    int sock=0;
    for( ; *ii<MAX_CLIENTS; (*ii)++) {
        sock = sock_all[*ii];
        if(sock != 0) {
            (*ii)++;
            return sock;
        }
    }
    // end of list
    return 0;
}

int    msock;
fd_set rfds;
fd_set afds;
int    nfds;

int main(int argc, char *argv[ ])
{
    char   *service = "echo";
    struct sockaddr_in fsin;
    int    alen;
    int    fd;
    msock = passiveTCP(service, QLEN);

    nfds = getdtablesize();
    FD_ZERO(&afds);
    FD_SET(msock, &afds);

    while (1) {
        memcpy(&rfds, &afds, sizeof(rfds));
        if(select(nfds, &rfds, (fd_set *)0, (fd_set *)0, (struct timeval *)0) < 0)
            errexit("select: %s\n", strerror(errno));
        if(FD_ISSET(msock, &rfds)) {
            int ssock;
            alen = sizeof(fsin);
            ssock = accept(msock, (struct sockaddr *)&fsin, &alen);
            if(ssock < 0)
                errexit("accept: %s\n", strerror(errno));
            PRINTF("accept on FD %d\n", ssock);
            FD_SET(ssock, &afds);
            allfd_add(ssock);
        }
        for(fd=0; fd < nfds; ++fd)
            if(fd != msock && FD_ISSET(fd, &rfds))
                if(echo_all(fd) <= 0) {
                    (void) close(fd);
                    FD_CLR(fd, &afds);
                    PRINTF("Socket %d closed\n", fd);
                    allfd_del(fd);
                }
    }
}

int echo_all(int fd)
{
    char buf[BUFSIZ];
    int  cc, ret;
    int fd2;

    cc = read(fd, buf, sizeof buf);
    PRINTF("reading %d, len=%d\n", fd, cc);
    /* if(cc < 0)
        errexit("echo read: %s\n", strerror(errno)); */
    if(cc>0) {
        int ii = 0;
        do {
            fd2 = allfd_get(&ii);
            //PRINTF("  ii=%d, fd=%d, fd2=%d\n", ii, fd, fd2);
            if(fd2==0)
                break;
            if(fd2 != fd ) { //&& FD_ISSET(fd, &rfds))
                ret = write(fd2, buf, cc);
                PRINTF("  write %d, len=%d\n", fd2, ret);
                if(ret < 0)
                    errexit("echo write: %s\n", strerror(errno));
            }
        } while(fd2 != 0);
    }
    if(cc <= 0) { // client closed socket
    }
    return cc;
}
int echo(int fd)
{
    char buf[BUFSIZ];
    int  cc;
    cc = read(fd, buf, sizeof buf);
    if(cc < 0)
        errexit("echo read: %s\n", strerror(errno));
    if(cc && write(fd, buf, cc) < 0)
        errexit("echo write: %s\n", strerror(errno));
    return cc;
}
