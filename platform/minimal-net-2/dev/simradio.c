
// Unix
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>

// Contiki
#include "contiki.h"
#include "net/packetbuf.h"
#include "net/netstack.h"


#include "dev/simradio.h"

/*
 * Simulate radio via UNIX net socket.
 */

#define DEBUG 1

#define SIMRADIO_HOST "localhost"
#define SIMRADIO_PORT 4432

#define errexit(...) { fprintf(stderr, __VA_ARGS__); exit(1); }
#ifdef DEBUG
  #define PRINTF(...) printf(__VA_ARGS__)
#else
  #define PRINTF(...)
#endif // DEBUG

#define BUF_LEN 1024
static uint8_t tx_buf[BUF_LEN];
static uint8_t rx_buf[BUF_LEN];

void dump_data(char *msg, uint8_t *buf, int len) {
  int ii;

  char *cur_time;
  time_t tm;
  time(&tm);
  cur_time = ctime(&tm);

  printf("%s%s (%d): ", cur_time, msg, len);
  for(ii=0; ii<len; ii++)
    printf("%02x ", buf[ii]);
  printf("\n");
}

static int sock = -1;
PROCESS(simradio_process, "sim radio process");
/*---------------------------------------------------------------------------*/
static int
init(void)
{
	struct sockaddr_in sin;
	int    type;

	PRINTF("simradio init\n");
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = INADDR_ANY;
 	sin.sin_port = htons(SIMRADIO_PORT);

	type = SOCK_STREAM;
	/* Allocate a socket */
	sock = socket(PF_INET, type, 0);
	if(sock < 0)
		errexit("simradio can't create socket: %s\n", strerror(errno));

	/* Bind the socket */
	if(connect(sock, (struct sockaddr *)&sin, sizeof(sin)) < 0)
		errexit("simradio can't connect to %s:%d: %s\n", SIMRADIO_HOST, SIMRADIO_PORT, strerror(errno));
	PRINTF("simradio connected to %s:%d\n", SIMRADIO_HOST, SIMRADIO_PORT);

	process_start(&simradio_process, NULL);
	return 0;
}
/*---------------------------------------------------------------------------*/
#define AUX_LEN 2
#define CHECKSUM_LEN 2
static int
prepare(const void *payload, unsigned short payload_len)
{
  uint16_t checksum;
  uint8_t total_len,*pbuf;

  //checksum = crc16_data(payload, payload_len, 0);
  //total_len = payload_len + AUX_LEN;

  pbuf = &tx_buf[0];
  memcpy(pbuf, payload, payload_len);
  pbuf += payload_len;

  //memcpy(pbuf,&checksum,CHECKSUM_LEN);
  //pbuf+=CHECKSUM_LEN;

  return 0;
}
/*---------------------------------------------------------------------------*/
static int
transmit(unsigned short transmit_len)
{
    size_t      nleft;
    ssize_t     nwritten;
    const uint8_t *buffer;

    PRINTF("simradio transmit\n");
    dump_data("  TX", tx_buf, transmit_len);

    buffer = tx_buf;
    nleft  = transmit_len;

    while ( nleft > 0 ) {
		if ( (nwritten = write(sock, buffer, nleft)) <= 0 ) {
			if ( errno == EINTR )
			nwritten = 0;
			else
			return -1;
		}
		nleft  -= nwritten;
		buffer += nwritten;
    }

    return nleft == 0? RADIO_TX_OK: RADIO_TX_ERR;
}
/*---------------------------------------------------------------------------*/
static int
simradio_send(const void *payload, unsigned short payload_len)
{
  prepare(payload, payload_len);
  return transmit(payload_len);
}
/*---------------------------------------------------------------------------*/
static int
simradio_read(void *buf, unsigned short buf_len)
{
  int len;
  //PRINTF("simradio simradio_read\n");

  len = read(sock, rx_buf, sizeof(rx_buf));
  //PRINTF("simradio reading %d, len=%d\n", sock, len);
  if(len < 0)
    errexit("simradio echo read: %s\n", strerror(errno));
  dump_data("  RX", rx_buf, len);
  memcpy(buf, rx_buf, len);
  return len;
}
/*---------------------------------------------------------------------------*/
static int
channel_clear(void)
{
  return 1;
}
/*---------------------------------------------------------------------------*/
static int
receiving_packet(void)
{
  return 0;
}
/*---------------------------------------------------------------------------*/
static int
pending_packet(void)
{
  //PRINTF("simradio pending_packet\n");
  int nfds;
  fd_set rfds;
  int fd;
  struct timeval tv;

  nfds = getdtablesize();
  FD_ZERO(&rfds);
  FD_SET(sock, &rfds);
  tv.tv_sec = 0;
  tv.tv_usec = 0;

  usleep(20000);
  if(select(sock+1, &rfds, (fd_set *)0, (fd_set *)0, &tv) < 0)
      errexit("select: %s\n", strerror(errno));
  if(FD_ISSET(sock, &rfds)) {
	  PRINTF("  simradio pending\n");
	  return 1;
  }
  else
	  return 0;

  return 0;
}
/*---------------------------------------------------------------------------*/
static int
on(void)
{
  return 0;
}
/*---------------------------------------------------------------------------*/
static int
off(void)
{
  return 0;
}
/*---------------------------------------------------------------------------*/
//static int init(void);
const struct radio_driver simradio_driver =
  {
    init,
    prepare,
    transmit,
    simradio_send,
    simradio_read,
    channel_clear,
    receiving_packet,
    pending_packet,
    on,
    off,
  };
/*---------------------------------------------------------------------------*/


/*---------------------------------------------------------------------------*/
PROCESS_THREAD(simradio_process, ev, data)
{
  int len;

  PROCESS_BEGIN();

  while(1) {
    PROCESS_YIELD_UNTIL(ev == PROCESS_EVENT_POLL);

    packetbuf_clear();
    len = simradio_read(packetbuf_dataptr(), PACKETBUF_SIZE);
    PRINTF("simradio process_read: %u bytes \n", len);
    if(len > 0) {
      packetbuf_set_datalen(len);
      NETSTACK_RDC.input();
    }
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/

/*---------------------------------------------------------------------------*/
void simradio_interrupt() {
  int len;
  if(pending_packet()) {
    process_poll(&simradio_process);
  }
}
