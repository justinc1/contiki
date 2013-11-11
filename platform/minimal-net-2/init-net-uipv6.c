/*
 * init-net-uipv6.c
 *
 *  Created on: Jul 12, 2011
 *      Author: Owner
 *
 *  TODO: -	Merge with init-net-uip.c ?
 *  			- Do clean up !!!
 */
#include <stdio.h>
#include <string.h>

#include "contiki.h"
#include "contiki-net.h"

#define DEBUG DEBUG_PRINT
#include "uip-debug.h"

#include "init-net-uipv6.h"

/*---------------------------------------------------------------------------*/
/* TODO: move to some utils ? */
	uip_ipaddr_t ipaddr;
/* static void */
static uip_ipaddr_t*
set_global_address(void) {

	uip_ip6addr(&ipaddr, 0x2001, 0x470, 0x55, 0, 0, 0, 0, 0);
	uip_ds6_set_addr_iid(&ipaddr, &uip_lladdr);
	uip_ds6_addr_add(&ipaddr, 0, ADDR_AUTOCONF);

	return &ipaddr;
}
/*---------------------------------------------------------------------------*/
/* TODO: More to some utils ? */
static void
print_local_addresses(void)
{
  int i;
  uint8_t state;

  PRINTF("Host IPv6 addresses:\n");
  for(i = 0; i < UIP_DS6_ADDR_NB; i++) {
    state = uip_ds6_if.addr_list[i].state;
    if(uip_ds6_if.addr_list[i].isused && (state == ADDR_TENTATIVE || state
        == ADDR_PREFERRED)) {
      PRINT6ADDR(&uip_ds6_if.addr_list[i].ipaddr);
      /* Tentative -> Preferred to finalise our address */
      if (state == ADDR_TENTATIVE) {
        uip_ds6_if.addr_list[i].state = ADDR_PREFERRED;
      }
      PRINTF(" state: %u.\n", uip_ds6_if.addr_list[i].state);
    }
  }
  return;
}
/*---------------------------------------------------------------------------*/
void
init_net_uipv6(void)
{
	int i;
	/* Rime address */
	rimeaddr_t rimeaddr;
	/* Build some MAC */
	PRINTF("node_id 0x%04x %d\n", node_id, node_id);
	uint8_t mac_addr[8] = {0, 0x12, 0x4B, 0, 0, 0x06, (node_id & 0xff), (node_id >> 8)};

	/* Radio - Ugly */
//	rf230_set_pan_addr(IEEE802154_CONF_PANID, 0, (uint8_t *)mac_addr);
//	rf230_set_txpower(TX_PWR_17_2DBM); /* min power */

	/* Rime address: *must* be set to the same value as uip_lladdr.addr  - check, e.g. sicslowmac.c:150 to see why */
	memcpy(&rimeaddr, &mac_addr, sizeof(rimeaddr_t));
	rimeaddr_set_node_addr(&rimeaddr);
	printf("Rime started with address: ");
	for(i = 0; i < sizeof(rimeaddr_node_addr.u8) - 1; i++) {
		printf("%d.", rimeaddr_node_addr.u8[i]);
	}
	printf("%d\n", rimeaddr_node_addr.u8[i]);
	printf("\n");

	/* Host L2 address */
	PRINTF("\nSize of uip_lladdr.addr: %d", sizeof(uip_lladdr.addr));
	memcpy(&uip_lladdr.addr, mac_addr, sizeof(uip_lladdr.addr));
	PRINTF("\n802.15.4 64-bit address is now: ");
	for(i = 0; i < sizeof(uip_lladdr.addr) - 1; i++) {
				printf("%x.", uip_lladdr.addr[i]);
	}
	PRINTF("%x\n", uip_lladdr.addr[i]);

	queuebuf_init();

	process_start(&tcpip_process, NULL);
	printf("\ntcpip process started ..");

	/* Should now have one link-local IPv6 address */
	/* Set global address and print all local (on this node) addresses */
	set_global_address();
	print_local_addresses();

}
/*---------------------------------------------------------------------------*/



