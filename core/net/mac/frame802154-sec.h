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

typedef struct frame802154_key_descriptor {
  uint8_t key[16];
} frame802154_key_descriptor;

uint8_t frame802154_sec_get_authentication_tag_len();
uint8_t frame802154_sec_get_auxiliary_security_header_len();
uint8_t frame802154_sec_get_security_len();

/*
 * Add security auxilary header and encrpypt payload to the packetbuf.
 */
int8_t frame802154_sec_create(frame802154_t *p, uint8_t tx_frame_buffer[], uint8_t *pos);
int8_t frame802154_sec_parse(uint8_t *data, uint8_t len, frame802154_t *pf, uint8_t *p, uint8_t *auth_tag_len);
#endif /* FRAME_802154_SEC_H */
