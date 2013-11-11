/*
 * Copyright (c) 2002, Adam Dunkels.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above
 *    copyright notice, this list of conditions and the following
 *    disclaimer in the documentation and/or other materials provided
 *    with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * This file is part of the Contiki OS
 *
 *
 */

#include <stdio.h>
#include <time.h>
#include <sys/select.h>
#include <unistd.h>
#include <memory.h>

#include "contiki.h"
#include "contiki-net.h"

#include "dev/serial-line.h"
#include "init-net-uipv6.h"

#include "net/uip.h"
#ifdef __CYGWIN__
#include "net/wpcap-drv.h"
#else /* __CYGWIN__ */
#include "net/tapdev-drv.h"
#endif /* __CYGWIN__ */

#ifdef __CYGWIN__
PROCINIT(&etimer_process, &tcpip_process, &wpcap_process, &serial_line_process);
#else /* __CYGWIN__ */
//PROCINIT(&etimer_process, &tapdev_process, &tcpip_process, &serial_line_process);
//PROCINIT(&etimer_process, &tcpip_process, &serial_line_process); // tukaj radio transmita, OK
PROCINIT(&etimer_process, &tcpip_process);
#endif /* __CYGWIN__ */

#if UIP_CONF_IPV6
/*---------------------------------------------------------------------------*/
static void
sprint_ip6(uip_ip6addr_t addr)
{
  unsigned char i = 0;
  unsigned char zerocnt = 0;
  unsigned char numprinted = 0;
  unsigned char notskipped = 0;
  char thestring[40];
  char *result = thestring;

  *result++ = '[';
  while(numprinted < 8) {
    if((addr.u16[i] == 0) && (zerocnt == 0)) {
      while(addr.u16[zerocnt + i] == 0) {
	zerocnt++;
      }
      if(zerocnt == 1 && notskipped) {
        *result++ = '0';
         numprinted++;
         notskipped = 1;
         continue;
      }
      i += zerocnt;
      numprinted += zerocnt;
    } else {
      result += sprintf(result, "%x", (unsigned int)(uip_ntohs(addr.u16[i])));
      i++;
      numprinted++;
    }
    if(numprinted != 8) {
      *result++ = ':';
    }
  }
  *result++=']';
  *result=0;
  printf("%s", thestring);
}
#endif /* UIP_CONF_IPV6 */
/*---------------------------------------------------------------------------*/
#include "aes-test.h"
#if 0
uint8_t* stack_1=0;
uint8_t* stack_2=0;
#define TT2_SZ (1024*16)
int
main(void) {
  {
    uint8_t tt;
    stack_1 = &tt;
  }
  {
    uint16_t ii;
    uint8_t tt2a[TT2_SZ +4], *tt2;
    uint8_t tt3[4] = {0xDE, 0xAD, 0xBE, 0xEF};

    // align tt2
    tt2 = (uint8_t*)(void*) ( (((uint32_t)(void*)(tt2a))+3) & 0xFFFFFFFC );
    for(ii=0; ii<TT2_SZ; ii+=4) {
      memcpy(tt2 + ii, tt3, 4);
    }

  }
  return main_2();
}
/*---------------------------------------------------------------------------*/
void check_stack() {
  uint16_t ii;
  uint8_t tt2a[TT2_SZ +4], *tt2;
  uint8_t tt3[4] = {0xDE, 0xAD, 0xBE, 0xEF};

  tt2 = (uint8_t*)(void*) ( (((uint32_t)(void*)(tt2a))+3) & 0xFFFFFFFC );
  for(ii=TT2_SZ; ii>=0; ) {
    ii -= 4;
    if( 0 != memcmp(tt2 + ii*4, tt3, 4) ) {
      break;
    }
  }
  if(tt2 > stack_2) {
    printf("INC tt2 stack_1 0x%08x 0x%08x  %d\n", tt2, stack_1, tt2 - stack_1 );
    stack_2 = tt2;
  }
}
#endif
/*---------------------------------------------------------------------------*/
int
main(void)
{
  aes_test();
  clock_init();

  node_id_restore();
  printf("node ID is: %d.%d\n", node_id & 0xFF, node_id >> 8);

#if UIP_CONF_IPV6
/* A hard coded address overrides the stack default MAC address to
   allow multiple instances. uip6.c defines it as
   {0x00,0x06,0x98,0x00,0x02,0x32} giving an ipv6 address of
   [fe80::206:98ff:fe00:232] We make it simpler, {0x02,0x00,0x00 + the
   last three bytes of the hard coded address (if any are nonzero).
   HARD_CODED_ADDRESS can be defined in the contiki-conf.h file, or
   here to allow quick builds using different addresses.  If
   HARD_CODED_ADDRESS has a prefix it also applied, unless built as a
   RPL end node.  E.g. bbbb::12:3456 becomes fe80::ff:fe12:3456 and
   prefix bbbb::/64 if non-RPL ::10 becomes fe80::ff:fe00:10 and
   prefix awaits RA or RPL formation bbbb:: gives an address of
   bbbb::206:98ff:fe00:232 if non-RPL */
#ifdef HARD_CODED_ADDRESS
  uip_ipaddr_t ipaddr;
  {
  //uip_ipaddr_t ipaddr;
  //uiplib_ipaddrconv(HARD_CODED_ADDRESS, &ipaddr);
  uiplib_ipaddrconv("bbbb::12:3456", &ipaddr);
  if((ipaddr.u8[13] != 0) ||
     (ipaddr.u8[14] != 0) ||
     (ipaddr.u8[15] != 0)) {
    if(sizeof(uip_lladdr) == 6) {  /* Minimal-net uses ethernet MAC */
      uip_lladdr.addr[0] = 0x02;
      uip_lladdr.addr[1] = 0;
      uip_lladdr.addr[2] = 0;
      uip_lladdr.addr[3] = ipaddr.u8[13];
      uip_lladdr.addr[4] = ipaddr.u8[14];
      uip_lladdr.addr[5] = ipaddr.u8[15];
    }
  }
 }
#endif /* HARD_CODED_ADDRESS */

    /* Some stuff related to rime init is common/used with uIPv6 too. Do something about it */
    init_net_uipv6();
#endif /* UIP_CONF_IPV6 */

  process_init();
/* procinit_init initializes RPL which sets a ctimer for the first DIS */
/* We must start etimers and ctimers,before calling it */
  process_start(&etimer_process, NULL);
  ctimer_init();

  netstack_init();

#if RPL_BORDER_ROUTER
  process_start(&border_router_process, NULL);
  printf("Border Router Process started\n");
#elif UIP_CONF_IPV6_RPL
  printf("RPL enabled\n");
#endif

  //procinit_init();
  //autostart_start(autostart_processes);

  /* Set default IP addresses if not specified */
#if !UIP_CONF_IPV6
  {
    uip_ipaddr_t addr;

    uip_gethostaddr(&addr);
    if(addr.u8[0] == 0) {
      uip_ipaddr(&addr, 10,1,1,1);
    }
    printf("IP Address:  %d.%d.%d.%d\n", uip_ipaddr_to_quad(&addr));
    uip_sethostaddr(&addr);
    
    uip_getnetmask(&addr);
    if(addr.u8[0] == 0) {
      uip_ipaddr(&addr, 255,0,0,0);
      uip_setnetmask(&addr);
    }
    printf("Subnet Mask: %d.%d.%d.%d\n", uip_ipaddr_to_quad(&addr));
    
    uip_getdraddr(&addr);
    if(addr.u8[0] == 0) {
      uip_ipaddr(&addr, 10,1,1,100);
      uip_setdraddr(&addr);
    }
    printf("Def. Router: %d.%d.%d.%d\n", uip_ipaddr_to_quad(&addr));
  }
#else /* UIP_CONF_IPV6 */

#if !UIP_CONF_IPV6_RPL
  {
    uip_ipaddr_t ipaddr;
#ifdef HARD_CODED_ADDRESS
    uiplib_ipaddrconv(HARD_CODED_ADDRESS, &ipaddr);
#else
    uip_ip6addr(&ipaddr, 0xaaaa, 0, 0, 0, 0, 0, 0, 0);
#endif
    if((ipaddr.u16[0] != 0) ||
       (ipaddr.u16[1] != 0) ||
       (ipaddr.u16[2] != 0) ||
       (ipaddr.u16[3] != 0)) {
#if UIP_CONF_ROUTER
      uip_ds6_prefix_add(&ipaddr, UIP_DEFAULT_PREFIX_LEN, 0, 0, 0, 0);
#else /* UIP_CONF_ROUTER */
      uip_ds6_prefix_add(&ipaddr, UIP_DEFAULT_PREFIX_LEN, 0);
#endif /* UIP_CONF_ROUTER */

      uip_ds6_set_addr_iid(&ipaddr, &uip_lladdr);
      uip_ds6_addr_add(&ipaddr, 0, ADDR_AUTOCONF);
    }
  }
#endif /* !UIP_CONF_IPV6_RPL */

#endif /* !UIP_CONF_IPV6 */

  procinit_init();
  autostart_start(autostart_processes);
aes_test_2();

  /* Make standard output unbuffered. */
  setvbuf(stdout, (char *)NULL, _IONBF, 0);

  printf("\n*******%s online*******\n",CONTIKI_VERSION_STRING);

#if UIP_CONF_IPV6 && !RPL_BORDER_ROUTER  /* Border router process prints addresses later */
  {
    uint8_t i;
    for(i = 0; i < UIP_DS6_ADDR_NB; i++) {
      if(uip_ds6_if.addr_list[i].isused) {
	printf("IPV6 Addresss: (not router)");
	sprint_ip6(uip_ds6_if.addr_list[i].ipaddr);
	printf("\n");
      }
    }
  }
#endif

  while(1) {
    fd_set fds;
    int n;
    struct timeval tv;
    int cnt = 0;
    
    while( (n = process_run()) ) {
    	//printf(" cnt=%d\n", cnt++);
    	if(cnt>20) break;
    };

/*
    tv.tv_sec = 0;
    tv.tv_usec = 1000;
    FD_ZERO(&fds);
    FD_SET(STDIN_FILENO, &fds);
    select(1, &fds, NULL, NULL, &tv);

    if(FD_ISSET(STDIN_FILENO, &fds)) {
      char c;
      if(read(STDIN_FILENO, &c, 1) > 0) {
        serial_line_input_byte(c);
      }
    } */
    simradio_interrupt();
    etimer_request_poll();
    //check_stack();
  }
  
  return 0;
}
/*---------------------------------------------------------------------------*/
void
log_message(char *m1, char *m2)
{
  printf("%s%s\n", m1, m2);
}
/*---------------------------------------------------------------------------*/
void
uip_log(char *m)
{
  printf("uIP: '%s'\n", m);
}
/*---------------------------------------------------------------------------*/
unsigned short
sensors_light1(void)
{
  static unsigned short count;
  return count++;
}
/*---------------------------------------------------------------------------*/
