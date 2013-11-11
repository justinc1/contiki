#include "contiki.h"
#include "aes.h"
#include "aes-test.h"
#include "frame802154-aes.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void xor_block( void *d, const void *s );
void copy_and_key( void *d, const void *s, const void *k );

#define DEBUG 1

#ifdef DEBUG
#  define PRINTF(...) printf(__VA_ARGS__)
#else
#  define PRINTF(...)
#endif

#define MY_ASSERT(v) {  if( (v) == 0 ) { printf("ERROR assert: %s %d\n", __FILE__, __LINE__); exit(1); } }

extern frame802154_key_desc key_table[FRAME802154_KEY_TABLE_SIZE];
extern frame802154_device_desc device_table[FRAME802154_DEVICE_TABLE_SIZE];
extern frame802154_security_level_desc security_level_table[FRAME802154_SECURITY_LEVEL_TABLE_SIZE];

#ifdef TEST_FRAME_802154_SECURITY

void aes_test() {
  printf("test aes\n");
  uint8_t key[16];
  uint8_t ii;
  for(ii=0; ii<16; ii++)
    key[ii] = 0xC0 + ii;
  frame802154_aes_setup_key(key);

  printf("==============================\n");
  printf("==============================\n");
  printf("==============================\n");
  aes_t6_a();
  printf("==============================\n");
  aes_t6_b();
  printf("==============================\n");
  aes_t6_c();
  printf("==============================\n");
  printf("==============================\n");
  printf("==============================\n");
  printf("test aes done\n");
  // exit(0);
}






void aes_t6_a() {
  // C.2.2.1
  uint8_t aa[26  +0] = {0x08, 0xD0, 0x84, 0x21, 0x43, 0x01, 0x00, 0x00, 0x00, 0x00, 0x48, 0xDE, 0xAC /*-*/, 0x02, 0x05, 0x00, 0x00, 0x00 /*-*/, 0x55, 0xCF, 0x00, 0x00, 0x51, 0x52, 0x53, 0x54};
  uint8_t a_len = 26;
  //uint8_t uu[16] = {0x00}, uu_len = 0;

  // L - message length, length of encoded message length
  uint8_t nonce[FRAME802154_AES_NONCE_LEN] = {0xAC, 0xDE, 0x48, 0x00, 0x00, 0x00, 0x00, 0x01, /*0x‖,*/ 0x00, 0x00, 0x00, 0x05, /*0x‖,*/ 0x02}; // length 15-L
  // have 0 B data - plain
  uint8_t mm[16] = {0x00}, m_len = 0;
  // encrypted
  uint8_t cc[16], tt[16];

  uint8_t M = 8;

  // correct result
  const uint8_t ref_cc[] = {};
  const uint8_t ref_tt[] = {0x22, 0x3B, 0xC1, 0xEC, 0x84, 0x1A, 0xB5, 0x53};

  printf("aes_t6_a\n");
  frame802154_aes_encrypt_msg(
      aa, a_len, nonce, mm, m_len, M,
      cc, tt);
  MY_ASSERT( 0 == memcmp(ref_cc, cc, sizeof(ref_cc)) );
  MY_ASSERT( 0 == memcmp(ref_tt, tt, sizeof(ref_tt)) );

  printf("-----------------\n");
  uint8_t mm2[16] = {0x00};
  frame802154_aes_decrypt_msg(
      aa, a_len, nonce, cc, m_len, tt, M,
      mm2);
  MY_ASSERT( 0 == memcmp(mm2, mm, sizeof(ref_cc)) );
}

void aes_t6_b() {
  // C.2.2.1
  uint8_t aa[26  +0] = {0x69, 0xDC, 0x84, 0x21, 0x43, 0x02, 0x00, 0x00, 0x00, 0x00, 0x48, 0xDE, 0xAC, 0x01, 0x00, 0x00, 0x00, 0x00, 0x48, 0xDE, 0xAC, /*0x‖,*/ 0x04, 0x05, 0x00, 0x00, 0x00};
  uint8_t a_len = 26;
  //uint8_t uu[16] = {0x00}, uu_len = 0;

  // L - message length, length of encoded message length
  uint8_t nonce[FRAME802154_AES_NONCE_LEN] = {0xAC, 0xDE, 0x48, 0x00, 0x00, 0x00, 0x00, 0x01, /*0x‖,*/ 0x00, 0x00, 0x00, 0x05, /*0x‖,*/ 0x04}; // length 15-L
  // have 4 B data - plain
  uint8_t mm[16] = {0x61, 0x62, 0x63, 0x64}, m_len = 4;
  // encrypted
  uint8_t cc[16], tt[16];

  uint8_t M = 0;

  // correct result
  const uint8_t ref_cc[] = {0xD4, 0x3E, 0x02, 0x2B};
  const uint8_t ref_tt[] = {};

  printf("aes_t6_b\n");
  frame802154_aes_encrypt_msg(
      aa, a_len, nonce, mm, m_len, M,
      cc, tt);
  MY_ASSERT( 0 == memcmp(ref_cc, cc, sizeof(ref_cc)) );
  MY_ASSERT( 0 == memcmp(ref_tt, tt, sizeof(ref_tt)) );

  printf("-----------------\n");
  uint8_t mm2[16] = {0x00};
  frame802154_aes_decrypt_msg(
      aa, a_len, nonce, cc, m_len, tt, M,
      mm2);
  MY_ASSERT( 0 == memcmp(mm2, mm, sizeof(ref_cc)) );
}

void aes_t6_c() {
  // C.2.2.1
  uint8_t aa[29] = {0x2B, 0xDC, 0x84, 0x21, 0x43, 0x02, 0x00, 0x00, 0x00, 0x00, 0x48, 0xDE, 0xAC, 0xFF, 0xFF, 0x01, 0x00, 0x00, 0x00, 0x00, 0x48, 0xDE, 0xAC, /*0x‖,*/ 0x06, 0x05, 0x00, 0x00, 0x00, /*0x‖,*/ 0x01 };
  uint8_t a_len = 29;
  //uint8_t uu[16] = {0x00}, uu_len = 0;

  // L - message length, length of encoded message length
  uint8_t nonce[FRAME802154_AES_NONCE_LEN] = {0xAC, 0xDE, 0x48, 0x00, 0x00, 0x00, 0x00, 0x01, /*0x‖,*/ 0x00, 0x00, 0x00, 0x05, /*0x‖,*/ 0x00}; // length 15-L
  nonce[12] = 0x06;
  // have 1 B data - plain
  uint8_t mm[16] = {0xCE}, m_len = 1;
  // encrypted
  uint8_t cc[16], tt[16];

  uint8_t M = 8;

  // correct result
  const uint8_t ref_cc[] = {0xD8};
  const uint8_t ref_tt[] = {0x4F, 0xDE, 0x52, 0x90, 0x61, 0xF9, 0xC6, 0xF1};

  printf("aes_t6_c\n");
  frame802154_aes_encrypt_msg(
      aa, a_len, nonce, mm, m_len, M,
      cc, tt);
  MY_ASSERT( 0 == memcmp(ref_cc, cc, sizeof(ref_cc)) );
  MY_ASSERT( 0 == memcmp(ref_tt, tt, sizeof(ref_tt)) );

  printf("-----------------\n");
  uint8_t mm2[16] = {0x00};
  frame802154_aes_decrypt_msg(
      aa, a_len, nonce, cc, m_len, tt, M,
      mm2);
  MY_ASSERT( 0 == memcmp(mm2, mm, sizeof(ref_cc)) );
}

/*---------------------------------------------------------------------------*/

/*
 * Test by injecting packets to NETWORK layer.
 */
#include <unistd.h>

#include "contiki-conf.h"
#include "rimeaddr.h"
#include "uip.h"
#include "sicslowpan.h"
#include "netstack.h"
#include "packetbuf.h"
#include "framer.h"
#include "frame802154-sec.h"

extern rimeaddr_t rimeaddr_node_addr;
void test_framer802154___set_parameters(uint8_t mac_dsn2, uint16_t mac_dst_pan_id2, uint16_t mac_src_pan_id2);
void test_nullmac___send_packet(mac_callback_t sent, void *ptr);
//extern struct framer framer_802154;

extern uint32_t frame802154_frame_counter;
extern uint8_t frame802154_security_enabled;
extern uint8_t frame802154_security_level;
extern uint8_t frame802154_key_id_mode;

void aes_inject_packet();
void aes_inject_packet_dfischer();



void aes_test_2() {
  /* save values */
  uint8_t ii;
  uint8_t key[16];
  rimeaddr_t rimeaddr_node_addr_old;
  rimeaddr_copy(&rimeaddr_node_addr_old, &rimeaddr_node_addr);

  {
    printf("test aes 2 - post net init\n");
    printf("==============================\n");
    printf("==============================\n");
    //aes_inject_packet_dfischer();
    printf("==============================\n");
    printf("==============================\n");
    //aes_inject_packet();
    printf("==============================\n");
    printf("==============================\n");
  }
  /* restore "normal" values */
  frame802154_security_enabled = 1;
  frame802154_security_level = 5;
  frame802154_frame_counter = 5;
  frame802154_key_id_mode = 0;
  test_framer802154___set_parameters(0x66, IEEE802154_PANID, IEEE802154_PANID);
  rimeaddr_copy( &rimeaddr_node_addr, &rimeaddr_node_addr_old);
  for(ii=0; ii<16; ii++)
    key_descriptor[0].key[ii] = 0xC0 + ii;

  printf("test aes 2 done\n");

  printf("==============================\n");
  printf("frame802154_sec_setup_test_keys\n");
  printf("==============================\n");
  frame802154_sec_setup_test_keys();
  // exit(0);
}

void aes_inject_packet() {
// annex B, 2.2 - mac data example frame
  printf("aes_inject_packet\n");
  // #define IEEE802154_PANID 0x4321 - mac_dst_pan_id, mac_src_pan_id;
  rimeaddr_t src_addr = { .u8 = {0xAC, 0xDE, 0x48, 0x00,   0x00, 0x00, 0x00, 0x01} };
  rimeaddr_t dst_addr = { .u8 = {0xAC, 0xDE, 0x48, 0x00,   0x00, 0x00, 0x00, 0x02} };
  uint8_t key[16];
  //

  uint8_t ii;
  uint8_t data[4] = {0x61, 0x62, 0x63, 0x64};
  //uip_lladdr_t uip_lladdr = { .addr = {0xAC, 0xDE, 0x48, 0x00,   0x00, 0x00, 0x00, 0x01} };
  uint8_t mac_dsn;
  uint16_t mac_src_pan_id;
  uint16_t mac_dst_pan_id;

/*  if( MY_NODE_ID == 0x1122 ) {
    src_addr.u8[7] = 0x01;
    dst_addr.u8[7] = 0x02;
  }
  else {
    src_addr.u8[7] = 0x02;
    dst_addr.u8[7] = 0x01;
  } */
  rimeaddr_copy(&rimeaddr_node_addr, &src_addr);

  //NETSTACK_CONF_NETWORK.send_packet(dst_addr);
  //NETSTACK_CONF_NETWORK output( uip_lladdr );
  // output( uip_lladdr );
  //tcpip_output( &uip_lladdr ); // valid after init...

  frame802154_security_enabled = 0;
  packetbuf_clear();
  framer_802154.create(); // to init mac_dsn to random value

  // setup security parameters
  frame802154_security_enabled = 1;
  frame802154_security_level = 4;
  frame802154_frame_counter = 5;
  frame802154_key_id_mode = 0;

  mac_src_pan_id = 0x4321;
  mac_dst_pan_id = 0x4321;

  for(ii=0; ii<16; ii++)
    key[ii] = 0xC0 + ii;
  frame802154_aes_setup_key(key);

  // prepare
  // frame802154_hdrlen();
  // packetbuf_set_hdrlen( frame802154_sec_get_auxiliary_security_header_len() );
  if( MY_NODE_ID == 0x1122 || 1) {
    uint8_t ind = 1;
    while(ind--) {
      // init counters etc
      packetbuf_clear();
    // 25 is max unsecured header len.
      packetbuf_set_attr(PACKETBUF_ATTR_MAC_ACK, 1);
      packetbuf_set_addr(PACKETBUF_ADDR_RECEIVER, &dst_addr);
      mac_dsn = 0x84;
      test_framer802154___set_parameters(mac_dsn, mac_dst_pan_id, mac_src_pan_id);
      packetbuf_set_datalen( 4 ); //+ frame802154_sec_get_authentication_tag_len() );
      memcpy(packetbuf_dataptr(), data, 4);
      test_nullmac___send_packet(NULL, packetbuf_hdrptr());

      // verify
      uint8_t ref_payload[] = {0x69, 0xDC, 0x84, 0x21, 0x43, 0x02, 0x00, 0x00, 0x00, 0x00, 0x48, 0xDE, 0xAC, 0x01, 0x00, 0x00, 0x00, 0x00, 0x48, 0xDE, 0xAC, /*0x‖,*/ 0x04, 0x05, 0x00, 0x00, 0x00,
          0xD4, 0x3E, 0x02, 0x2B};
      MY_ASSERT( sizeof(ref_payload) == packetbuf_totlen());
      if(frame802154_frame_counter == 5) {
        MY_ASSERT( 0 == memcmp(ref_payload, packetbuf_hdrptr(), sizeof(ref_payload)) );
      }

      usleep(1*1000*1000);
    }
  }
}

void aes_inject_packet_dfischer() {
// annex B, 2.2 - mac data example frame
  printf("aes_inject_packet_dfischer\n");
  // #define IEEE802154_PANID 0x4321 - mac_dst_pan_id, mac_src_pan_id;
  rimeaddr_t src_addr = { .u8 = {0x11, 0x11, 0x22, 0xff,   0xfe, 0x33, 0x44, 0x99} };
  // rimeaddr_t dst_addr = { .u8 = {0xff, 0xff, 0xff, 0xff,   0xff, 0xff, 0xff, 0xff} };
  uint8_t key[16];
  //

  uint8_t ii;
  uint8_t data[10] = {0x7a, 0x3b, 0x3a, 0x1a, 0x9b, 0x00, 0xee, 0x43, 0x00, 0x00};
  uint8_t mac_dsn;
  uint16_t mac_src_pan_id;
  uint16_t mac_dst_pan_id;

  rimeaddr_copy(&rimeaddr_node_addr, &src_addr);

  frame802154_security_enabled = 0;
  packetbuf_clear();
  framer_802154.create(); // init mac_dsn to random value

  // setup security parameters
  frame802154_security_enabled = 1;
  frame802154_security_level = 1;
  frame802154_frame_counter = 5;
  frame802154_key_id_mode = 0;

  mac_src_pan_id = 0xabcd;
  mac_dst_pan_id = 0xabcd;

  for(ii=0; ii<16; ii++)
    key_descriptor[0].key[ii] = 0x00 + ii;

  // prepare
  // frame802154_hdrlen();
  // packetbuf_set_hdrlen( frame802154_sec_get_auxiliary_security_header_len() );
  {
    // init counters etc
    packetbuf_clear();
    // 25 is max unsecured header len.
    packetbuf_set_attr(PACKETBUF_ATTR_MAC_ACK, 1);
    packetbuf_set_addr(PACKETBUF_ADDR_RECEIVER, &rimeaddr_null); // BROADCAST
    mac_dsn = 0xd9;
    test_framer802154___set_parameters(mac_dsn, mac_dst_pan_id, mac_src_pan_id);
    packetbuf_set_datalen( sizeof(data) ); //+ frame802154_sec_get_authentication_tag_len() );
    memcpy(packetbuf_dataptr(), data, sizeof(data));
    test_nullmac___send_packet(NULL, packetbuf_hdrptr());

    // verify
    uint8_t ref_payload[] = {0x49, 0xd8, 0xd9, 0xcd, 0xab, 0xff, 0xff, 0x99, 0x44, 0x33, 0xfe, 0xff, 0x22, 0x11, 0x11,
        0x01, 0x05, 0x00, 0x00, 0x00,
        0x7a, 0x3b, 0x3a, 0x1a, 0x9b, 0x00, 0xee, 0x43, 0x00, 0x00,
        0x8b, 0xb3, 0x42, 0x2a
        };
    MY_ASSERT( sizeof(ref_payload) == packetbuf_totlen());
    MY_ASSERT( 0 == memcmp(ref_payload, packetbuf_hdrptr(), sizeof(ref_payload)) );
  }
}

#else /* not TEST_FRAME_802154_SECURITY */


void aes_test() {
  printf("test aes\n");
  printf("==============================\n");
  printf("==============================\n");
  printf("nothing\n");
  printf("==============================\n");
  printf("==============================\n");
}
void aes_test_2() {
  printf("test aes 2 - post net init\n");
  printf("==============================\n");
  printf("==============================\n");
  printf("nothing\n");
  printf("==============================\n");
  printf("frame802154_sec_init\n");
  printf("==============================\n");
  frame802154_sec_setup_test_keys();
  printf("==============================\n");
  printf("==============================\n");
}

#endif /* TEST_FRAME_802154_SECURITY */

/*---------------------------------------------------------------------------*/
/*
 * Setup initial/test descriptors.
 **/
void frame802154_sec_setup_test_keys() {
  frame802154_security_level_desc *sl;
  frame802154_device_desc *dd;
  frame802154_key_desc *kd;
  uint8_t ii;
/*  uint8_t ext_addr1[8] = {
      0xfe, 0x80, 0, 0,
      0,0,0,0,
      0x02, 0x12, 0x4b, 0x00,
      0x00, 0x06, 0x22, 0x11};
  uint8_t ext_addr2[8] = {
      0xfe, 0x80, 0, 0,
      0,0,0,0,
      0x02, 0x12, 0x4b, 0x00,
      0x00, 0x06, 0x33, 0x11}; */
  uint8_t ext_addr1[8] = {0x00, 0x12, 0x4b, 0x00, 0x00, 0x06, 0x22, 0x11};
  uint8_t ext_addr2[8] = {0x00, 0x12, 0x4b, 0x00, 0x00, 0x06, 0x33, 0x11};
//  uint8_t ext_addr1[8] = {0x00, 0x00, 0x4b, 0x00, 0x00, 0x06, 0x22, 0x11};
//  uint8_t ext_addr2[8] = {0x00, 0x00, 0x4b, 0x00, 0x00, 0x06, 0x33, 0x11};
  uint8_t broad_addr2[8] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

  sl = security_level_table + 0;
  sl->frame_type = FRAME802154_DATAFRAME;
  ii = 0;
  sl->allowed_security_levels[ii++ ] = 1;
  sl->allowed_security_levels[ii++] = 2;
  sl->allowed_security_levels[ii++] = 3;
  sl->allowed_security_levels[ii++] = 5;
  sl->allowed_security_levels[ii++ ] = 6;
  sl->allowed_security_levels[ii++] = 7;
  sl->allowed_security_levels[ii++] = 0xFF;
  sl->allowed_security_levels[ii++] = 0xFF;

  security_level_table[1] = security_level_table[0];

  dd = device_table + 0;
  dd->pan_id = IEEE802154_PANID;
  dd->short_addr = (((uint16_t)ext_addr1[6]) << 8) + ext_addr1[7];
  memcpy(dd->ext_addr, ext_addr1, 8);
  dd->frame_counter = 0;
  dd->exempt = 0;

  dd = device_table + 1;
  dd->pan_id = IEEE802154_PANID;
  dd->short_addr = (((uint16_t)ext_addr2[6]) << 8) + ext_addr2[7];
  memcpy(dd->ext_addr, ext_addr2, 8);
  dd->frame_counter = 0;
  dd->exempt = 0;

#if 0
  /* for packets, send from ext_addr2, received by ext_addr1 */
  kd = key_table + 1;
  kd->key_lookup[0].key_id_mode = FRAME802154_KEYIDMODE_IMPLICIT;
  kd->key_lookup[0].m0.device_addr_mode = DEVICE_ADDR_MODE_EXT;
  kd->key_lookup[0].m0.device_pan_id = IEEE802154_PANID;
  memcpy(kd->key_lookup[0].m0.device_addr, ext_addr2, 8);
  //
  kd->key_usage[0].frame_type = FRAME802154_DATAFRAME;
  kd->key_usage[0].cmd_frame_id = 0xFF;
  //
  for(ii=0; ii<16; ii++) {
    kd->key[ii] = 0xC0 + ii;
  }

  /* for packets, send from ext_addr1, received by ext_addr2 */
  kd = key_table + 2;
  kd->key_lookup[0].key_id_mode = FRAME802154_KEYIDMODE_IMPLICIT;
  kd->key_lookup[0].m0.device_addr_mode = DEVICE_ADDR_MODE_EXT;
  kd->key_lookup[0].m0.device_pan_id = IEEE802154_PANID*1 + 0x0102*0;
  memcpy(kd->key_lookup[0].m0.device_addr, ext_addr1, 8);
  //
  kd->key_usage[0].frame_type = FRAME802154_DATAFRAME;
  kd->key_usage[0].cmd_frame_id = 0xFF;
  //
  for(ii=0; ii<16; ii++) {
    kd->key[ii] = 0xC0 + ii;
  }
#endif

  /* broadcast frames - short dev_addr 0xFFFF */
  kd = key_table + 3;
#if 0
  ii = 0;
  kd->key_lookup[ii].key_id_mode = FRAME802154_KEYIDMODE_MAC_4;
  kd->key_lookup[ii].m1.key_index = 0;
  set_key_source(kd->key_lookup[ii].m1.key_source,
      kd->key_lookup[ii].key_id_mode,
      IEEE802154_PANID,
      broad_addr2);
  print_key_lookup_desc(kd->key_lookup + ii);
  //
  kd->key_usage[ii].frame_type = FRAME802154_DATAFRAME;
  kd->key_usage[ii].cmd_frame_id = 0xFF;
  //
#endif
  ii = 2;
  set_key_lookup_descriptor_mode_123(kd->key_lookup + ii,
      FRAME802154_KEYIDMODE_MAC_4, 1, IEEE802154_PANID, ext_addr1);
  print_key_lookup_desc(kd->key_lookup + ii);
  //
  kd->key_usage[ii].frame_type = FRAME802154_DATAFRAME;
  kd->key_usage[ii].cmd_frame_id = 0xFF;
  //
  for(ii=0; ii<16; ii++) {
    kd->key[ii] = 0x30 + ii;
  }

  kd = key_table + 4;
  ii = 2;
  set_key_lookup_descriptor_mode_123(kd->key_lookup + ii,
      FRAME802154_KEYIDMODE_MAC_4, 1, IEEE802154_PANID, ext_addr2);
  print_key_lookup_desc(kd->key_lookup + ii);
  //
  kd->key_usage[ii].frame_type = FRAME802154_DATAFRAME;
  kd->key_usage[ii].cmd_frame_id = 0xFF;
  //
  for(ii=0; ii<16; ii++) {
    kd->key[ii] = 0x30 + ii;
  }


  /* short addr mode */
  /* FRAME802154_KEYIDMODE_IMPLICIT => long addr mode */
  /* posilajm kot short, prejmem kot ext addr mode? tu je nekaj narobe... */
  kd = key_table + 5;
  ii = 0;
  set_key_lookup_descriptor_mode_implicit(kd->key_lookup + ii,
      DEVICE_ADDR_MODE_EXT, IEEE802154_PANID, ext_addr1);
  print_key_lookup_desc(kd->key_lookup + ii);
  //
  ii = 1;
  set_key_lookup_descriptor_mode_implicit(kd->key_lookup + ii,
      DEVICE_ADDR_MODE_SHORT, IEEE802154_PANID, ext_addr1);
  print_key_lookup_desc(kd->key_lookup + ii);
  //
  kd->key_usage[ii].frame_type = FRAME802154_DATAFRAME;
  kd->key_usage[ii].cmd_frame_id = 0xFF;
  //
  for(ii=0; ii<16; ii++) {
    kd->key[ii] = 0x60 + ii;
  }

  kd = key_table + 6;
  ii = 0;
  set_key_lookup_descriptor_mode_implicit(kd->key_lookup + ii,
      DEVICE_ADDR_MODE_EXT, IEEE802154_PANID, ext_addr2);
  print_key_lookup_desc(kd->key_lookup + ii);
  //
  ii = 1;
  set_key_lookup_descriptor_mode_implicit(kd->key_lookup + ii,
      DEVICE_ADDR_MODE_SHORT, IEEE802154_PANID, ext_addr2);
  print_key_lookup_desc(kd->key_lookup + ii);
  //
  kd->key_usage[ii].frame_type = FRAME802154_DATAFRAME;
  kd->key_usage[ii].cmd_frame_id = 0xFF;
  //
  for(ii=0; ii<16; ii++) {
    kd->key[ii] = 0x70 + ii;
  }

}












































//
