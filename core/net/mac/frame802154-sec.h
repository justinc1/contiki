/**
 *   \addtogroup frame802154
 *   @{
*/
/**
 *  \file
 *  \brief Add AES security support to 802.15.4 frames.
 *
 *  \author Justin <justin.cinkelj@xlab.si>
 *
 *  This logicaly belongs to frame802154.c, but is here so that frame802154.c is
 *  more or less unmodified. Also, macro FRAME_802154_CONF_SECURITY is required to
 *  enable security support.
 */

#ifndef FRAME_802154_SEC_H
#define FRAME_802154_SEC_H




#include "frame802154.h"
#include "framer-802154.h"

/* #define FRAME802154_SECURITY_LEVEL_NONE  (0) */
#define FRAME802154_SECURITY_LEVEL_32       (1)
#define FRAME802154_SECURITY_LEVEL_64       (2)
/* #define FRAME802154_SECURITY_LEVEL_128   (3) */
#define FRAME802154_SECURITY_LEVEL_ENC_NONE (4)
#define FRAME802154_SECURITY_LEVEL_ENC_32   (5)
#define FRAME802154_SECURITY_LEVEL_ENC_64   (6)
#define FRAME802154_SECURITY_LEVEL_ENC_128  (7)

/* std 7.4.1.2 */
#define FRAME802154_KEYIDMODE_IMPLICIT  0
#define FRAME802154_KEYIDMODE_INDEX     1
#define FRAME802154_KEYIDMODE_MAC_4     2
#define FRAME802154_KEYIDMODE_MAC_8     3



#define FRAME802154_KEY_TABLE_SIZE                10
#define FRAME802154_DEVICE_TABLE_SIZE             7
#define FRAME802154_SECURITY_LEVEL_TABLE_SIZE     4
#define FRAME802154_KEY_LOOKUP_SIZE               5
#define FRAME802154_KEY_USAGE_SIZE                6
#define FRAME802154_ALLOWED_SECURITY_LEVELS_SIZE  8

/* table 54 */
#define DEVICE_ADDR_MODE_NO     0x00
#define DEVICE_ADDR_MODE_SHORT  0x02
#define DEVICE_ADDR_MODE_EXT    0x03

/* table 62 */
typedef struct frame802154_key_usage_desc {
  uint8_t frame_type;
  uint8_t cmd_frame_id;
} frame802154_key_usage_desc;

/* table 63 */
typedef struct frame802154_security_level_desc {
  uint8_t frame_type;
  uint8_t cmd_frame_id;
  uint8_t security_minimum;
  uint8_t device_override_security;
  /* TODO use 1 byte - 8 bits */
  uint8_t allowed_security_levels[FRAME802154_ALLOWED_SECURITY_LEVELS_SIZE];
} frame802154_security_level_desc;

/* table 64 */
typedef struct frame802154_device_desc {
  uint16_t pan_id;
  uint16_t short_addr;
  uint8_t ext_addr[8];
  uint32_t frame_counter;
  uint8_t exempt;
} frame802154_device_desc;

/* table 65 */
typedef struct frame802154_key_id_lookup_descXXX {
  uint8_t key_id_mode;
  uint8_t key_source[8]; /* in network order */
  uint8_t key_index;
  uint16_t device_pan_id;
  uint8_t device_addr_mode;
    uint8_t device_addr[8]; /* in host order. If short address mode, only bytes 0,1 are used. */
} frame802154_key_id_lookup_descXXX;

/* table 65 */
/* for KeyIdMode == 1,2,3 */
typedef struct frame802154_key_id_lookup_desc_m123 {
  uint8_t key_source[8]; /* in network order */
  uint8_t key_index;
} frame802154_key_id_lookup_desc_m123;
/* for KeyIdMode == 0 */
typedef struct frame802154_key_id_lookup_desc_m0 {
  uint8_t device_addr[8]; /* in host order. If short address mode, only bytes 0,1 are used. */
  uint8_t device_addr_mode;
  uint16_t device_pan_id;
} frame802154_key_id_lookup_desc_m0;
typedef struct frame802154_key_id_lookup_desc {
  uint8_t key_id_mode;
  union {
    frame802154_key_id_lookup_desc_m0 m0;
    frame802154_key_id_lookup_desc_m123 m1;
  };
} frame802154_key_id_lookup_desc;
/* table 61 */
typedef struct frame802154_key_desc {
  frame802154_key_id_lookup_desc key_lookup[FRAME802154_KEY_LOOKUP_SIZE]; /* should be pointer to variable length array */
  /* frame802154_device_descriptor_handle xx; */
  frame802154_key_usage_desc key_usage[FRAME802154_KEY_USAGE_SIZE];
  uint8_t key[16];
} frame802154_key_desc;



uint8_t frame802154_sec_get_authentication_tag_len();
uint8_t frame802154_sec_get_auxiliary_security_header_len();
uint8_t frame802154_sec_get_security_len();

/*
 * Add security auxilary header and encrpypt payload to the packetbuf.
 */
int8_t frame802154_sec_create(frame802154_t *p, uint8_t tx_frame_buffer[], uint8_t *pos);
int8_t frame802154_sec_parse(frame802154_t *pf, uint8_t *p);

int8_t
frame802154_sec_decrypt(
    uint8_t *data, uint8_t len, frame802154_t *pf, uint8_t *p, uint8_t *auth_tag_len,
    frame802154_key_desc *key_desc, frame802154_device_desc *device_desc,
    uint32_t frame_counter, uint8_t security_level);

int8_t
frame802154_sec_incoming_frame(uint8_t *data, uint8_t len, frame802154_t *pf,
    uint8_t *p, uint8_t *auth_tag_len, int8_t *aux_sec_hdrlen);

int8_t frame802154_sec_create_aux_header(frame802154_t *p, uint8_t tx_frame_buffer[], uint8_t *pos,
    frame802154_key_desc *key_desc, uint8_t key_index);
int8_t
frame802154_sec_encrypt(const frame802154_t *p);
void frame802154_sec_init();

#endif /* FRAME_802154_SEC_H */
