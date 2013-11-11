/*
 * ping6.c
 *
 *  Created on: Sep 20, 2011
 *      Author: Owner
 */

/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 *
 */

#include <string.h>

#include "contiki.h"
#include "contiki-lib.h"
#include "contiki-net.h"
//#include "vsn-sensors.h"
#include "sensors.h"
#include "autostart.h"

#include "net/uip-icmp6.h"
#include "uip.h"

#define DEBUG DEBUG_PRINT
#include "uip-debug.h"

#define PING6_NB 5
//#define PING6_DATALEN 16
#define PING6_DATALEN 12

#define UIP_IP_BUF                ((struct uip_ip_hdr *)&uip_buf[UIP_LLH_LEN])
#define UIP_ICMP_BUF            ((struct uip_icmp_hdr *)&uip_buf[uip_l2_l3_hdr_len])

static struct etimer ping6_periodic_timer;
static u8_t count = 0;
static uip_ipaddr_t dest_addr;
/*---------------------------------------------------------------------------*/
PROCESS(myping6_process, "PING6 process");
AUTOSTART_PROCESSES(&myping6_process);
/*---------------------------------------------------------------------------*/
static void
ping6handler()
{
	if(count < PING6_NB) {
		PRINTF("count %d\n", count);
		UIP_IP_BUF->vtc = 0x60;
		UIP_IP_BUF->tcflow = 1;
		UIP_IP_BUF->flow = 0;
		UIP_IP_BUF->proto = UIP_PROTO_ICMP6;
		UIP_IP_BUF->ttl = uip_ds6_if.cur_hop_limit;
		uip_ipaddr_copy(&UIP_IP_BUF->destipaddr, &dest_addr);
		uip_ds6_select_src(&UIP_IP_BUF->srcipaddr, &UIP_IP_BUF->destipaddr);

		UIP_ICMP_BUF->type = ICMP6_ECHO_REQUEST;
		UIP_ICMP_BUF->icode = 0;
		/* set identifier and sequence number to 0 */
		memset((uint8_t *)UIP_ICMP_BUF + UIP_ICMPH_LEN, 0, 4);
		/* put one byte of data */
		memset((uint8_t *)UIP_ICMP_BUF + UIP_ICMPH_LEN + UIP_ICMP6_ECHO_REQUEST_LEN,
			count, PING6_DATALEN);


		uip_len = UIP_ICMPH_LEN + UIP_ICMP6_ECHO_REQUEST_LEN + UIP_IPH_LEN + PING6_DATALEN;
		UIP_IP_BUF->len[0] = (u8_t)((uip_len - 40) >> 8);
		UIP_IP_BUF->len[1] = (u8_t)((uip_len - 40) & 0x00FF);

		UIP_ICMP_BUF->icmpchksum = 0;
		UIP_ICMP_BUF->icmpchksum = ~uip_icmp6chksum();

		putchar('\n');
		PRINTF("Echo Request to ");
		PRINT6ADDR(&UIP_IP_BUF->destipaddr);
		PRINTF(" from ");
		PRINT6ADDR(&UIP_IP_BUF->srcipaddr);
		PRINTF("\n");
		UIP_STAT(++uip_stat.icmp.sent);

		tcpip_ipv6_output();

		count++;
		etimer_set(&ping6_periodic_timer, 3 * CLOCK_SECOND);
		PRINTF("  Timer 3 sec\n");
	} else {
    count = 0;
		etimer_set(&ping6_periodic_timer, 20 * CLOCK_SECOND);
		PRINTF("  Timer 20 sec\n");
	}
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(myping6_process, ev, data)
{
  PROCESS_BEGIN();
  PRINTF("ping6 running...\n");
  PRINTF("Button: %d pings %d byte payload.\n",PING6_NB,PING6_DATALEN);

  /* Hard coded destination */
  //uip_ip6addr(&dest_addr,0x2001,0x0470,0x0055,0,0x0212,0x4b00,0x0006,0xa03c);
//  uip_ip6addr(&dest_addr,0x2001,0x0470,0x0055,0,0x0212,0x4b00,0x0006,0x498a);
//  uip_ip6addr(&dest_addr,0x2001,0x0470,0x0055,0,0x0212,0x4b00,0x0006,0xa796);
  ;
  PRINTF("  srcipaddr"); {int ii; for(ii=0; ii<8; ii++) PRINTF(" 0x%04x", ((uint16_t*)(void*)&(UIP_IP_BUF->srcipaddr))[ii]); } PRINTF("\n");
  PRINTF("  rimeaddr "); {int ii; for(ii=0; ii<8; ii++) PRINTF(" 0x%02x", rimeaddr_node_addr.u8[ii]); } PRINTF("\n");
  // if( rimeaddr_node_addr.u8[7] == 0x33) {
  if(MY_NODE_ID == 0x1133) {
    PRINTF("  rimeaddr is ...0x8a 0x33\n");
    //uip_ip6addr(&dest_addr,0xfe80,0,0,0,0x0212,0x4bff,0xfe00,0x0006);
    uip_ip6addr(&dest_addr,0xfe80,0,0,0,0x0212,0x4b00,0x0006,0x2211);
  }
  else {
    PRINTF("  rimeaddr not ...0x8a 0x33\n");
    //uip_ip6addr(&dest_addr,0xfe80,0,0,0,0x0212,0x4b00,0x0006,0x498a);
      uip_ip6addr(&dest_addr,0xfe80,0,0,0,0x0212,0x4b00,0x0006,0x3311);
  }

  count = 0;

  etimer_set(&ping6_periodic_timer, 10 * CLOCK_SECOND);
  while(1) {
    PROCESS_YIELD();

    	if(etimer_expired(&ping6_periodic_timer)) {
	    	//if(count == 0) {
			//etimer_set(&ping6_periodic_timer, 20 * CLOCK_SECOND);
			//PRINTF("  Timer 20 sec\n");
    		//} else
		if(MY_NODE_ID == 0x1133)
			ping6handler();
    	}
  }
  PROCESS_END();
}

/*---------------------------------------------------------------------------*/
