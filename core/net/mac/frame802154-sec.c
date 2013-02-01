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

#include "frame802154.h"
#include "frame802154-sec.h"
#include "frame802154-aes.h"
#include "packetbuf.h"

/* memcpy */
#include <string.h>

#define DEBUG 1
#ifdef DEBUG
#include <stdio.h>
  #define  PRINTF(...) printf(__VA_ARGS__)
  #define  PRINT_HEX(...) print_hex(__VA_ARGS__)
#else
  #define  PRINTF(...)
  #define  PRINT_HEX(...)
#endif
#define  PRINTE(...) printf(__VA_ARGS__)

#ifdef FRAME_802154_CONF_SECURITY
 uint8_t frame802154_security_enabled = 1;
 uint8_t frame802154_security_level = 5;
 uint8_t frame802154_key_id_mode = 0;
#else
 uint8_t frame802154_security_enabled = 0;
 uint8_t frame802154_security_level = 0;
 uint8_t frame802154_key_id_mode = 0;
#endif

/* TODO Should not be reset on reboot. */
#ifndef TEST_FRAME_802154_SECURITY
static
#endif
uint32_t frame802154_frame_counter = 0;

/*
key_id_mode
key_source
key_index
*/
static uint8_t frame802154_key_index = 1;

#ifndef TEST_FRAME_802154_SECURITY
static
#endif /* TEST_FRAME_802154_SECURITY */
frame802154_key_descriptor key_descriptor[2] = { {
    .key = {0x00},
    .key = {0x00}
} };

/*---------------------------------------------------------------------------*/
/**
 * \brief   How many octets will be required for the authentication tag.
 * \return  Authentication tag length
 *
 * Returned tag length depends on frame802154_security_enabled and frame802154_security_level.
 */
uint8_t frame802154_sec_get_authentication_tag_len() {
  if(frame802154_security_enabled==0) {
    return 0;
  }
  else {
    switch (frame802154_security_level & 0x03) {
    case 0:
      return 0;
    case 1:
      return 4;
    case 2:
      return 8;
    case 3:
      return 16;
    default:
      break;
    }
  }
  return 0;
}
/*---------------------------------------------------------------------------*/
/**
 * \brief   How many octets will be required for the auxiliary_security_header.
 * \return  Authentication tag length
 *
 * Returned length depends on frame802154_security_enabled and frame802154_key_id_mode.
 */
uint8_t frame802154_sec_get_auxiliary_security_header_len() {
  if(frame802154_security_enabled==0) {
    return 0;
  }
  else {
    switch (frame802154_key_id_mode & 0x03) {
    case FRAME802154_KEYIDMODE_IMPLICIT:
      return 5;
    case FRAME802154_KEYIDMODE_INDEX:
      return 6;
    case FRAME802154_KEYIDMODE_MAC_4:
      return 10;
    case FRAME802154_KEYIDMODE_MAC_8:
      return 14;
    default:
      break;
    }
  }
  return 0;
}
/*---------------------------------------------------------------------------*/
/**
 * \brief   How many octets will be required for the security related fields in
 *          the transmit buffer - size of auxiliary_security_header and
 *          authentication tag.
 * \return  Required length
 *
 * Returned value depends on current frame802154_security_enabled,
 * frame802154_security_level and frame802154_key_id_mode.
 */
uint8_t frame802154_sec_get_security_len() {
  /* TODO: could be key_id_mode dependent on the frame addressing mode?
   * If extended src_addr is already part of unsecured frame header, it wouldn't
   * make sense to repeat it in key_id field.
   */
  return frame802154_sec_get_auxiliary_security_header_len() + frame802154_sec_get_authentication_tag_len();
}
/*---------------------------------------------------------------------------*/
/*
 * Return pointer to key descriptor or NULL if error
 */
static frame802154_key_descriptor* frame802154_sec_get_key_descriptor(const frame802154_t *p, uint8_t is_outbound) {
  /* TODO 7.2.2 */
  return key_descriptor + 0;
}
/*---------------------------------------------------------------------------*/
/** \brief       Write auxiliary security header to tx_frame_buffer,
 *              replace plaintext data with encrypted data and append authentication tag.
 *              Also write values to aux sec header in frame802154_t p.
 * \param p     Frame being send.
 * \param tx_frame_buffer Transmitt buffer
 * \param pos   First unused octet in the transmit buffer.
 * \return      -1 if error, 0 otherwise.
 *
 * Part of data (802.15.4 non-secured header) was already written to transmitt buffer.
 * Unsecured data are in packet buffer (packetbuf_hdrptr, packetbuf_data).
 * Packet buffer packetbuf_datalen was already setup with additional space for the
 * trailing authentication tag.
 *
 * Here, auxilary security header is written to the transmitt buffer and pos is
 * updated with length of auxilary security header.
 *
 * Plaintext data in packet buffer are replaced with
 * encrypted data, and authentication tag is written at the end.
 */
int8_t frame802154_sec_create(frame802154_t *p, uint8_t tx_frame_buffer[], uint8_t *pos) {
  /* std 7.2.1 TODO */
  uint8_t key_identifier_len;

  PRINTF("15.4-sec create, security_level key_id_mode: %d %d\n", frame802154_security_level, frame802154_key_id_mode);
  p->aux_hdr.security_control.security_level = frame802154_security_level;
  p->aux_hdr.security_control.key_id_mode = frame802154_key_id_mode;
  p->aux_hdr.security_control.reserved = 0;
  /* dump data for security header to buf, and increment pos; */
  tx_frame_buffer[*pos] = (frame802154_security_level & 0x07) | ((frame802154_key_id_mode & 0x03) << 3);
  PRINTF("15.4-sec aux sec flags 0x%02x\n", tx_frame_buffer[*pos]);
  (*pos)++;
  /* set frame counter */
  PRINTF("15.4-sec frame_counter %d\n",  frame802154_frame_counter);
  p->aux_hdr.frame_counter = frame802154_frame_counter;
  *((uint32_t*)(void*)(tx_frame_buffer + *pos)) = UIP_HTOLE_32(frame802154_frame_counter); /* byte order - low byte first */
  (*pos) += 4;

  /* TODO search for key descriptor */
  frame802154_key_descriptor *key_desc = frame802154_sec_get_key_descriptor(p, 1);
  if( key_desc == NULL ) {
    PRINTE("15.4-sec ERROR get_key_descriptor\n");
    return -1;
  }
  frame802154_aes_setup_key(key_desc->key);

  /* TODO check p->fcf.src_addr_mode - are used 2 or 8 bytes */
  switch(frame802154_key_id_mode) {
  case FRAME802154_KEYIDMODE_IMPLICIT:
    key_identifier_len = 0;
    break;
  case FRAME802154_KEYIDMODE_INDEX:
    key_identifier_len = 1;
    p->aux_hdr.key[0] = frame802154_key_index;
    break;
  case FRAME802154_KEYIDMODE_MAC_4:
    /*
     * TODO 7.4.3.1 - is 'originator of the group key' always current node?
     * Or would be the original node, if we are only forwarding a packet?
     * If forwarding - unmodified packet could be forwarded, no need to open
     * the packet (it makes sense to check validity).
     */
    key_identifier_len = 5;
    /* FIXME Using little endian format - because frame_counter in little endian
     * format too, I guess it is correct */
    *((uint16_t*)(void*) (p->aux_hdr.key)) = UIP_HTOLE_16(p->src_pid);
    *((uint16_t*)(void*) (p->aux_hdr.key+2)) = UIP_HTOLE_16(p->src_addr);
    p->aux_hdr.key[4] = frame802154_key_index;
    break;
  case FRAME802154_KEYIDMODE_MAC_8:
    key_identifier_len = 9;
    /* FIXME byte order */
    *((uint64_t*)(void*) (p->aux_hdr.key)) = UIP_HTOLE_64(p->src_addr);
    p->aux_hdr.key[8] = frame802154_key_index;
    break;
  default:
    key_identifier_len = 0;
  }
  memcpy(tx_frame_buffer + *pos, p->aux_hdr.key, key_identifier_len);
  (*pos) += key_identifier_len;

  /*
   * Data is already at packetbuf_dataptr(), packetbuf_datalen().
   * Encrypt it depending on frame type.
   */
  uint8_t *aa;
  uint8_t a_len;
  uint8_t nonce[FRAME802154_AES_NONCE_LEN];
  uint8_t *mm, m_len;
  uint8_t cc[150];
  uint8_t tt[16];
  uint8_t *uu; /* where to put encrypted auth_tag */
  uint8_t auth_tag_len;
  auth_tag_len = AUTHTAGLEN_FROM_SECLEVEL(frame802154_security_level);
  PRINTF("15.4-sec security_level => auth_tag_len: 0x%02x %d\n", frame802154_security_level, auth_tag_len);

  /*
   * TODO pp 153, 7.3.4.2
   * packetbuf_hdrptr data is immediately followed by packetbuf_dataptr data.
   * The a data is packetbuf_hdrptr, plus N octets of packetbuf_dataptr if
   * packet is beacon or MAC commnad frame.
   *
   * packetbuf_datalen() already contails space for authentication_tag.
   */
  uint8_t mhr_open_payload_len = 0; /* MHR + open_payload */
  uint8_t private_payload_len = 0;
  switch(p->fcf.frame_type) {
  case FRAME802154_BEACONFRAME:
    /* TODO
    mhr_open_payload_len = packetbuf_hdrlen() + packetbuf_datalen() - frame802154_sec_get_authentication_tag_len() - beacon_payload_len;
    private_payload_len = beacon_payload_len;
    */
    break;
  case FRAME802154_DATAFRAME:
    mhr_open_payload_len = packetbuf_hdrlen();
    private_payload_len = packetbuf_datalen() - auth_tag_len;
    break;
  case FRAME802154_ACKFRAME:
    /* nothing to do - security is not possible anyway */
    break;
  case FRAME802154_CMDFRAME:
    /* MAC CMD, command frame identifier is 1 octet */
    mhr_open_payload_len = packetbuf_hdrlen() + 1;
    private_payload_len = packetbuf_datalen() - auth_tag_len - 1;
    break;
  default:
    break;
  }
  PRINTF("15.4-sec packetbuf_hdrlen packetbuf_datalen auth_tag_len - %d %d %d\n", packetbuf_hdrlen(), packetbuf_datalen(), auth_tag_len);
  PRINTF("15.4-sec mhr_open_payload_len private_payload_len - %d %d\n", mhr_open_payload_len, private_payload_len);

  switch(frame802154_security_level) {
  case 1:
  case 2:
  case 3:
    a_len = mhr_open_payload_len + private_payload_len;
    m_len = 0;
    aa = packetbuf_hdrptr();
    mm = NULL;
    uu = aa + a_len;
    break;
  case 4:
    a_len = 0;
    m_len = private_payload_len;
    aa = NULL;
    mm = packetbuf_hdrptr() + mhr_open_payload_len;
    uu = NULL;
    break;
  case 5:
  case 6:
  case 7:
    a_len = mhr_open_payload_len;
    m_len = private_payload_len;
    aa = packetbuf_hdrptr();
    mm = aa + mhr_open_payload_len;
    uu = aa + a_len + m_len;
    break;
  case 0:
  default:
    a_len = 0;
    m_len = 0;
    aa = NULL;
    mm = NULL;
    uu = NULL;
    break;
  }

  /* prepare nonce */
  /* p->src_addr is stored in big-endian order;
   * frame802154_create() reverses bytes when dumping to tx_frame_buffer */
  memcpy(nonce, p->src_addr, 8); /* TODO what if short addressing mode ? */
  *(uint32_t*)(void*)(nonce+8) = uip_htonl(frame802154_frame_counter);
  *(uint8_t*)(void*)(nonce+12) = frame802154_security_level;
  /* setup key */

  /* sicslowpan.c already allocated additional space for auth data in packetbuf_dataptr.
   * Here, we only have to copy the actual auth tag in the last few octets.
   */
  switch(p->fcf.frame_type) {
  case FRAME802154_BEACONFRAME:
    /* TODO */
    break;
  case FRAME802154_DATAFRAME:
  case FRAME802154_CMDFRAME:
    /*
     * aa is never modified. mm has to be replaced with cc (if encryption enabled - (sec_level & 0x40) is true), and then tt (U) has to be appended (if authentication enabled).
     *
     * frame802154_aes_encrypt_msg copies data to internal buffer auth_data and does 0x00 padding.
     * If there would be some additional space (2*16 octets?) in packetbuf, memmove would be sufficient.
     * And cc/tt could be written back to mm/aa.
     */
    frame802154_aes_encrypt_msg(
        aa, a_len, nonce, mm, m_len, auth_tag_len,
        cc, tt);
    memcpy(mm, cc, m_len); /* replace private_payload with ecrypted one */
    PRINTF("15.4-sec len a m t - %d %d %d, packetbuf_datalen %d\n", a_len, m_len, auth_tag_len, packetbuf_datalen());
    if(uu)
      memcpy(uu, tt, auth_tag_len); /* append authentication tag */
    break;
  case FRAME802154_ACKFRAME:
    /* nothing to do */
    break;
  default:
    break;
  }

  frame802154_frame_counter++;
  return 0;
}
/*---------------------------------------------------------------------------*/
/**
 * \brief               Parse auxilary security header in the received frame,
 *                      decrypt received data and check authentication tag.
 * \param data          Start of the received frame (including already parsed unsecured header).
 * \param len           Length of data.
 * \param pf            Frame to store result to.
 * \param p             First unparsed byte in data (start of auxilary security header)
 * \param auth_tag_len  Length of trailing authentication tag.
 * \return              Number of parsed octets in auxilary security header, or -1 if error.
 *
 * Unsecured part of header was already parsed, now continue parsing the
 * security header in the received frame. Then, decrypt data in the frame and
 * check authentication tag.
 *
 * Encrypted data in packetbuf_data are replaced with decrypted data, and
 * authentication tag is removed from the packetbuf_data.
 */
int8_t frame802154_sec_parse(uint8_t *data, uint8_t len, frame802154_t *pf, uint8_t *p, uint8_t *auth_tag_len) {

  PRINTF("15.4-sec parse, p[0] 0x%02X\n", p[0]);
  pf->aux_hdr.security_control.security_level = p[0] & 0x07;
  pf->aux_hdr.security_control.key_id_mode = (p[0] >> 3) & 0x03;
  pf->aux_hdr.security_control.reserved = (p[0] >> 5) & 0x07;
  p++;
  PRINTF("15.4-sec security_level %d\n", pf->aux_hdr.security_control.security_level);
  PRINTF("15.4-sec key_id_mode %d\n",  pf->aux_hdr.security_control.key_id_mode);

  pf->aux_hdr.frame_counter = UIP_HTOLE_32( *((uint32_t*)(void*)p) );
  p += 4;
  PRINTF("15.4-sec frame_counter %d\n",  pf->aux_hdr.frame_counter);

  uint8_t key_identifier_len;
  uint8_t /*key_source[8],*/ key_index = 0;

  /* TODO check p->fcf.src_addr_mode - are used 2 or 8 bytes
   * pf->aux_hdr.key is now opaque. How usefull wil this be?
   **/
  switch(pf->aux_hdr.security_control.key_id_mode) {
  case FRAME802154_KEYIDMODE_IMPLICIT:
    key_identifier_len = 0;
    break;
  case FRAME802154_KEYIDMODE_INDEX:
    key_identifier_len = 1;
    key_index = p[0];
    pf->aux_hdr.key[0] = key_index;
    break;
  case FRAME802154_KEYIDMODE_MAC_4:
    /* TODO 7.4.3.1 - is 'originator of the group key' always current node?
     * Or would be the original node, if we are only forwarding a packet?
     * If forwarding - unmodified packet could be forwarded, no need to open
     * the packet (it makes sense to only check validity)
     **/
    key_identifier_len = 5;
    memcpy(pf->aux_hdr.key, p, 5);
    key_index = p[4];
    break;
  case FRAME802154_KEYIDMODE_MAC_8:
    key_identifier_len = 9;
    memcpy(pf->aux_hdr.key, p, 9);
    key_index = p[8];
    break;
  default:
    key_identifier_len = 0;
  }
  p += key_identifier_len;
  PRINTF("15.4-sec key_mode %d, key_index %d\n", pf->aux_hdr.security_control.key_id_mode, key_index);
  PRINT_HEX("15.4-sec key_source: ", pf->aux_hdr.key, key_identifier_len>=1? key_identifier_len-1 : 0 );

  /* TODO search for key descriptor */
  frame802154_key_descriptor *key_desc = frame802154_sec_get_key_descriptor(pf, 0);
  if( key_desc == NULL ) {
    PRINTE("15.4-sec ERROR get_key_descriptor\n");
    return -1;
  }
  frame802154_aes_setup_key(key_desc->key);

  /* decrypt data */
  uint8_t *aa, a_len;
  uint8_t nonce[FRAME802154_AES_NONCE_LEN];
  uint8_t mm[150] ; /*, m_len; / * plaintext */
  /* uint8_t m_param; */
  uint8_t *cc, c_len; /* chiper */
  uint8_t *tt; /*, t_len;  auth tag */
  *auth_tag_len = AUTHTAGLEN_FROM_SECLEVEL(pf->aux_hdr.security_control.security_level & 0x03);
  PRINTF("15.4-sec auth_tag_len: %d\n", *auth_tag_len);

  /*
   * packetbuf_datalen() already contails authentication_tag.
   */
  uint8_t hdrlen;
  uint8_t mhr_open_payload_len; /* MHR + open_payload */
  uint8_t private_payload_len;
  hdrlen = p - data; /* whole header was processed */
  PRINTF("15.4-sec hdrlen %d, data 0x%08x,  p 0x%08x\n", hdrlen, data, (uint32_t)p);

  mhr_open_payload_len = 0;
  private_payload_len = 0;
  switch(pf->fcf.frame_type) {
  case FRAME802154_BEACONFRAME:
    /* TODO
     mhr_open_payload_len = packetbuf_hdrlen() + packetbuf_datalen() - frame802154_sec_get_authentication_tag_len() - beacon_payload_len;
     private_payload_len = beacon_payload_len;
     */
    break;
  case FRAME802154_DATAFRAME:
    mhr_open_payload_len = hdrlen;
    private_payload_len = len - hdrlen - *auth_tag_len;
    break;
  case FRAME802154_ACKFRAME:
    /* nothing to do - security is not possible anyway */
    break;
  case FRAME802154_CMDFRAME:
    /* MAC CMD, command frame identifier is 1 octet */
    mhr_open_payload_len = hdrlen + 1;
    private_payload_len = len - hdrlen - *auth_tag_len - 1;
    break;
  default:
    break;
  }
  PRINTF("15.4-sec mhr_open_payload_len private_payload_len - %d %d\n", mhr_open_payload_len, private_payload_len);

  switch(pf->aux_hdr.security_control.security_level) {
  case 1:
  case 2:
  case 3:
  case 4:
  case 5:
  case 6:
  case 7:
    a_len = mhr_open_payload_len;
    c_len = private_payload_len;
    aa = data; /* inbound packets are stored in data portion only */
    cc = aa + a_len;
    tt = cc + c_len;
    break;
  case 0:
  default:
    a_len = 0;
    c_len = 0;
    aa = NULL;
    cc = NULL;
    tt = cc + c_len;
    break;
  }
  PRINTF("15.4-sec a_len c_len t_len  %d %d %d, aa cc tt 0x%08x 0x%08x 0x%08x\n", a_len, c_len, *auth_tag_len, aa, cc, tt);

  /* prepare nonce */
  memcpy(nonce, pf->src_addr, 8); /* TODO what if short addressing mode ? */
  *(uint32_t*)(void*)(nonce+8) = uip_htonl(pf->aux_hdr.frame_counter);
  *(uint8_t*)(void*)(nonce+12) = pf->aux_hdr.security_control.security_level;

  /* Decrypt data and replace encrypted data with plaintext.
   */
  switch(pf->fcf.frame_type) {
  case FRAME802154_BEACONFRAME:
    /* TODO */
    break;
  case FRAME802154_DATAFRAME:
  case FRAME802154_CMDFRAME:
    PRINTF("15.4-sec a_len c_len  %d %d, aa mm 0x%08x 0x%08x (2)\n", a_len, c_len, aa, mm);
    PRINTF("15.4-sec auth_tag_len %d\n", *auth_tag_len);
    if( frame802154_aes_decrypt_msg(aa, a_len, nonce, cc, c_len, tt, *auth_tag_len, mm) < 0 ) {
      PRINTE("15.4-sec ERROR decrypt\n");
      return -1;
    }
    memcpy(cc, mm, c_len); /* replace encrypted payload with plain private_payload */
    packetbuf_set_datalen( packetbuf_totlen() - *auth_tag_len ); /* remove trailing authentication tag */
    break;
  case FRAME802154_ACKFRAME:
    /* nothing to do */
    break;
  default:
    break;
  }

  return 1 + 4 + key_identifier_len;
}

/** \}   */



