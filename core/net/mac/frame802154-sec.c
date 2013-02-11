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
 // uint8_t frame802154_key_id_mode = FRAME802154_KEYIDMODE_IMPLICIT; /* cannot be used with broadcast frames */
 uint8_t frame802154_key_id_mode = FRAME802154_KEYIDMODE_MAC_4;
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

frame802154_key_desc
key_table[FRAME802154_KEY_TABLE_SIZE];

frame802154_device_desc
device_table[FRAME802154_DEVICE_TABLE_SIZE];

frame802154_security_level_desc
security_level_table[FRAME802154_SECURITY_LEVEL_TABLE_SIZE];

/* global variables used by 802.15.4 std.  */
uint16_t mac_coord_short_address;
uint8_t mac_coord_extended_address[8];
uint8_t mac_default_key_source[8];

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
  if(frame802154_security_level==0) {
    /* 7.2.1.c, if security level == 0, then there is no security related fields. */
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
void
set_key_lookup_descriptor_mode_123(frame802154_key_id_lookup_desc* kid,
    uint8_t key_id_mode, uint8_t key_index, uint16_t pan_id, const uint8_t *addr) {
  kid->key_id_mode = key_id_mode;
  kid->m1.key_index = key_index;
  if(key_id_mode == FRAME802154_KEYIDMODE_INDEX) {
    memset(kid->m1.key_source, 0x00, 8);
  }
  else if(key_id_mode == FRAME802154_KEYIDMODE_MAC_4) {
    *((uint16_t*)(void*) (kid->m1.key_source)) = uip_htole_16(pan_id);
    *((uint16_t*)(void*) (kid->m1.key_source+2)) = uip_htole_16(*(uint16_t*)(void*)(addr+6));
    *((uint32_t*)(void*) (kid->m1.key_source+4)) = 0;
  }
  else /* FRAME802154_KEYIDMODE_MAC_8 */ {
    *((uint64_t*)(void*)(kid->m1.key_source)) = uip_htole_64(*(uint64_t*)(void*)addr);
  }
}
/*---------------------------------------------------------------------------*/
void
set_key_lookup_descriptor_mode_implicit(frame802154_key_id_lookup_desc* kid,
    uint8_t addr_mode, uint16_t pan_id, const uint8_t *addr) {
  uint8_t len = 0;
  kid->key_id_mode = FRAME802154_KEYIDMODE_IMPLICIT;
  kid->m0.device_addr_mode = addr_mode;
  kid->m0.device_pan_id = pan_id;
  if(addr_mode == DEVICE_ADDR_MODE_SHORT) {
    len = 2;
  }
  else if(addr_mode == DEVICE_ADDR_MODE_EXT) {
    len = 8;
  }
  memcpy(kid->m0.device_addr + 8-len, addr, len);
}
/*---------------------------------------------------------------------------*/
void
print_key_lookup_desc(const frame802154_key_id_lookup_desc* kid) {
  PRINTF("  kid mode %d", kid->key_id_mode);
  uint8_t len=-1;
  if(kid->key_id_mode == FRAME802154_KEYIDMODE_IMPLICIT) {
    if(kid->m0.device_addr_mode == DEVICE_ADDR_MODE_NO) {
      len = 0;
    }
    else if(kid->m0.device_addr_mode == DEVICE_ADDR_MODE_SHORT) {
      len = 2;
    }
    else if(kid->m0.device_addr_mode == DEVICE_ADDR_MODE_EXT) {
      len = 8;
    }
    if(kid->key_id_mode == FRAME802154_KEYIDMODE_IMPLICIT) {
      PRINTF("    addr_mode %d (len %d)", kid->m0.device_addr_mode, len);
      PRINTF("    pan_id %d", kid->m0.device_pan_id);
      PRINT_HEX("    addr: ", kid->m0.device_addr, 8);
    }
  }
  else {
    if(kid->key_id_mode == FRAME802154_KEYIDMODE_MAC_4) {
      len = 4;
    }
    else if(kid->key_id_mode == FRAME802154_KEYIDMODE_MAC_8) {
      len = 8;
    }
    else {
      len = 0;
    }
    PRINTF("    index %d", kid->m1.key_index);
    if(kid->key_id_mode == FRAME802154_KEYIDMODE_MAC_4 ||
        kid->key_id_mode == FRAME802154_KEYIDMODE_MAC_8) {
      PRINTF("    key_source (len %d) ", len);
      PRINT_HEX("", kid->m1.key_source, 8);
    }
    else
      PRINTF("\n");
  }
}
/*---------------------------------------------------------------------------*/
/*
 * TODO - load descriptors, frame_counter etc. from persistent storage.
 **/
void frame802154_sec_load() {
}
/*---------------------------------------------------------------------------*/
/*
 * TODO - save state to persistent storage.
 **/
void frame802154_sec_save() {
}
/*---------------------------------------------------------------------------*/
/*
 * Return pointer to key descriptor or NULL if error
 * 7.2.2
 */
static frame802154_key_desc* frame802154_sec_get_key_descriptor(
    uint8_t key_id_mode, uint8_t key_index, uint8_t *key_source,
    uint8_t device_addr_mode, uint16_t device_pan_id, uint8_t *device_addr,
    uint8_t frame_type) {

  uint8_t ii, jj;
  uint8_t key_source_len, *key_source_2;

  /* FIXME When changing input device_addr, input device_addr_mode should be changed too? */

  const frame802154_key_desc *key_desc;
  const frame802154_key_id_lookup_desc *key_lookup;
  if(key_id_mode == FRAME802154_KEYIDMODE_IMPLICIT) {
    for(ii = 0; ii < FRAME802154_KEY_TABLE_SIZE; ii++) {
      //PRINTF("  get_key_descriptor2 ii=%d/%d\n", ii, FRAME802154_KEY_TABLE_SIZE);
      key_desc = key_table + ii;
      for(jj = 0; jj < FRAME802154_KEY_LOOKUP_SIZE; jj++) {
        key_lookup = key_desc->key_lookup + jj;
/*
        PRINTF("  get_key_descriptor2 jj=%d/%d\n", jj, FRAME802154_KEY_LOOKUP_SIZE);
        PRINTF("    (a) d_addr_mode d_pan_id: %d  %d\n", device_addr_mode, device_pan_id);
        PRINTF("    kl->d_addr_mode kl->d_pan_id: %d  %d\n", key_lookup->device_addr_mode, key_lookup->device_pan_id);
        */
        if(device_addr_mode == DEVICE_ADDR_MODE_NO) {
          /* 7.2.2 a.1 - a.3 */
          device_pan_id = IEEE802154_PANID; /* e.g. mac_dst_pan_id / mac_src_pan_id */
          PRINTF("    set device_pan_id = %d\n", device_pan_id);
          if(frame_type == FRAME802154_BEACONFRAME) {
            PRINTF("    set d_addr = macCoordExtendedAddress\n");
            memcpy(device_addr, mac_coord_extended_address, 8); // TODO where would be that saved ???
            // change input device_addr_mode too?
            device_addr_mode = DEVICE_ADDR_MODE_EXT;
          }
          else {
            if(mac_coord_short_address == 0xFFFE) {
              PRINTF("    set d_addr = macCoordExtendedAddress 2\n");
              memcpy(device_addr, mac_coord_extended_address, 8); // TODO where would be that saved ???
              device_addr_mode = DEVICE_ADDR_MODE_EXT;
            }
            else if(mac_coord_short_address <= 0xFFFD) {
              PRINTF("    set d_addr = macCoordShortAddress\n");
              memcpy(device_addr, &mac_coord_short_address, 2); /* FIXME check byte order */
              device_addr_mode = DEVICE_ADDR_MODE_SHORT;
            }
            else {
              return NULL;
            }
          }
        }
        else if(device_addr_mode == DEVICE_ADDR_MODE_SHORT ||
                device_addr_mode == DEVICE_ADDR_MODE_EXT) {
          /* 7.2.2 a.4 */
          PRINTF("    leave d_addr = orig, mode = %d\n", device_addr_mode);
          /* device_addr is left at input value */
        }
        /* 7.2.2 a.5 */
        /* PRINTF("    (b) d_addr_mode d_pan_id: %d  %d\n", device_addr_mode, device_pan_id); */
        if(device_addr_mode == key_lookup->m0.device_addr_mode &&
            device_pan_id == key_lookup->m0.device_pan_id ) {
          uint8_t addr_len, tmp[4] = {0, 0, 2, 8};
          addr_len = tmp[device_addr_mode & 0x03];
          PRINTF("  get_key_descriptor ii, jj = %d/%d, %d/%d\n", ii, FRAME802154_KEY_TABLE_SIZE, jj, FRAME802154_KEY_LOOKUP_SIZE);
          PRINT_HEX("    dev_addr  : ", device_addr +8-addr_len, addr_len);
          PRINT_HEX("    dev_addr 8: ", device_addr , 8);
          print_key_lookup_desc(key_lookup);
          /* FIXME ce len=2, primerjam octete 0-1 ali 6-7  */
          if(memcmp(device_addr +8-addr_len, key_lookup->m0.device_addr, addr_len) == 0) {
            PRINTF("     x d_addr_mode d_pan_id: %d  %d\n", device_addr_mode, device_pan_id);
            return key_desc;
          }
        }
      } /* for jj */
    }
  }
  else {
    if(key_id_mode == FRAME802154_KEYIDMODE_INDEX) {
      /* 7.2.2 b */
      key_source_len = 8;
      key_source_2 = mac_default_key_source;
    }
    else if(key_id_mode == FRAME802154_KEYIDMODE_MAC_4) {
      /* 7.2.2 c */
      key_source_len = 4;
      key_source_2 = key_source;
    }
    else { /* key_id_mode == FRAME802154_KEYIDMODE_MAC_8 */
      /* 7.2.2 c */
      key_source_len = 8;
      key_source_2 = key_source;
    }
    PRINT_HEX("    k_source: ", key_source_2, key_source_len);

    for(ii = 0; ii < FRAME802154_KEY_TABLE_SIZE; ii++) {
      key_desc = key_table + ii;
      for(jj = 0; jj < FRAME802154_KEY_LOOKUP_SIZE; jj++) {
        key_lookup = key_desc->key_lookup + jj;
        PRINTF("    %d,%d ind %d-%d ", ii, jj, key_index, key_lookup->m1.key_index);
        PRINT_HEX("kl_source: ", key_lookup->m1.key_source, key_source_len);
        if(key_lookup->m1.key_index == key_index &&
            /* FIXME ce len=2, primerjam octete 0-1 ali 6-7  */
            memcmp(key_lookup->m1.key_source, key_source_2, key_source_len) == 0) {
          return key_desc;
        }
      }
    }
  }
  /* 7.2.2 d */
  return NULL;
}
/*---------------------------------------------------------------------------*/
/**
 *
 * @param device_addr_mode
 * @param device_pan_id
 * @param device_addr
 * @return NULL if error, pointer to device_desc if OK.
 *
 * 7.2.4
 */
frame802154_device_desc*
frame802154_sec_get_device_descriptor(
    uint8_t device_addr_mode, uint16_t device_pan_id, uint8_t* device_addr) {
  uint8_t device_addr_len = 0;
  frame802154_device_desc *device_desc;
  uint8_t ii;

  if(device_addr_mode == DEVICE_ADDR_MODE_NO) {
    /* 7.2.4 a */
    device_pan_id = IEEE802154_PANID;

    /* 7.2.4 b */
    if(mac_coord_short_address == 0xFFFE) {
      device_addr = mac_coord_extended_address;
      device_addr_len = 8;
    }
    else if(mac_coord_short_address <= 0xFFFD) {
      device_addr = (uint8_t*)(void*)&mac_coord_short_address; /* FIXME is byte order OK ? */
      device_addr_len = 2;
    }
    else {
      return NULL;
    }
  }
  /* 7.2.4 c, device_addr is left at input value */
  else if( device_addr_mode == DEVICE_ADDR_MODE_SHORT) {
    device_addr_len = 2;
  }
  else if( device_addr_mode == DEVICE_ADDR_MODE_EXT) {
    device_addr_len = 8;
  }
  /* 7.2.4 d */
  for(ii=0; ii<FRAME802154_DEVICE_TABLE_SIZE; ii++) {
    device_desc = device_table + ii;
    PRINTF("    %d, %d == %d\n", ii, device_pan_id, device_desc->pan_id );
    PRINTF("    (%d) dev_addr ", device_addr_len);
    PRINT_HEX("", device_addr, 8);
    PRINT_HEX("    d_desc dev_addr ", device_desc->ext_addr, 8);
    PRINT_HEX("    d_desc dev_addr ", (uint8_t*)(void*)&(device_desc->short_addr), 2);
    if(device_pan_id == device_desc->pan_id) {
      if(device_addr_len == 2 &&
          0 == memcmp(device_addr, &(device_desc->short_addr), 2)) {
        /* FIXME - is byte order in device_desc->short_addr OK ? */
        return device_desc;
      }
      if(device_addr_len == 8 &&
          0 == memcmp(device_addr, device_desc->ext_addr, 8)) {
        return device_desc;
      }
    }
  }
  /* 7.2.4 e */
  return NULL;
}
/*---------------------------------------------------------------------------*/
/**
 *
 * @param frame_type
 * @param cmd_frame_id
 * @return
 *
 * 7.2.5
 */
frame802154_security_level_desc*
frame802154_sec_get_security_level_descriptor(uint8_t frame_type, uint8_t cmd_frame_id) {
  uint8_t ii;
  frame802154_security_level_desc* security_level_desc;

  for(ii=0; ii<FRAME802154_SECURITY_LEVEL_TABLE_SIZE; ii++) {
    security_level_desc = security_level_table + ii;
    if(frame_type != FRAME802154_CMDFRAME) {
      /* 7.2.5. a.1 */
      if(frame_type == security_level_desc->frame_type ) {
        return security_level_desc;
      }
    }
    else {
      /* 7.2.5. a.2 */
      if(frame_type == security_level_desc->frame_type &&
          cmd_frame_id == security_level_desc->cmd_frame_id) {
        return security_level_desc;
      }
    }
  }
  /* 7.2.5. b */
  return NULL;
}
/*---------------------------------------------------------------------------*/
/*
 * Is security_level sl1 >= sl2 ?
 * */
int8_t sec_level_ge(uint8_t sl1, uint8_t sl2) {
  if( (sl1 & 0x04) >= (sl2 & 0x04) &&
      (sl1 & 0x03) >= (sl2 & 0x03) ) {
    return 1;
  }
  return 0;
}
/*---------------------------------------------------------------------------*/
/**
 *
 * @param security_level_desc
 * @param security_level
 * @return 0 - check failed, 1 - passed, 2 - conditionally passed.
 *
 * 7.2.6
 */
int8_t
frame802154_sec_check_incoming_security_level(
    frame802154_security_level_desc* security_level_desc, uint8_t security_level) {
  /* Empty allowed_security_levels are set to 0xFF,
   * valid elements are at beginning;
   */
  uint8_t ii;
  if(security_level_desc->allowed_security_levels[0] == 0xFF) {
    /* empty allowed_security_levels */
    if( sec_level_ge(security_level, security_level_desc->security_minimum) ) {
      return 1;
    }
  }
  else {
    /* not empty allowed_security_levels */
    for(ii=0; ii<FRAME802154_ALLOWED_SECURITY_LEVELS_SIZE; ii++) {
      if(security_level_desc->allowed_security_levels[ii] == 0xFF)
        break;
      if(security_level_desc->allowed_security_levels[ii] == security_level)
        return 1;
    }
  }
  if(security_level == FRAME802154_SECURITY_LEVEL_NONE &&
      security_level_desc->device_override_security)
    return 2;

  return 0;
}
/*---------------------------------------------------------------------------*/
/**
 *
 * @param key_desc
 * @param frame_type
 * @param cmd_frame_id
 * @return 0 if failed, 1 if passed.
 *
 * 7.2.7
 */
int8_t
frame802154_sec_check_incoming_key_usage(
    frame802154_key_desc* key_desc, uint8_t frame_type,
    uint8_t cmd_frame_id) {
  uint8_t ii;
  frame802154_key_usage_desc *key_usage_desc;

  for(ii=0; ii<FRAME802154_KEY_USAGE_SIZE; ii++) {
    key_usage_desc = key_desc->key_usage + ii;
    if(frame_type != FRAME802154_CMDFRAME &&
        frame_type == key_usage_desc->frame_type) {
      return 1;
    }
    if(frame_type == FRAME802154_CMDFRAME &&
        frame_type == key_usage_desc->frame_type &&
        cmd_frame_id == key_usage_desc->cmd_frame_id) {
      return 1;
    }
  }
  return 0;
}
/*---------------------------------------------------------------------------*/
/**
 *
 * @param pf
 * @return -1 if fail, 0 if OK.
 *
 * 7.2.3 Incoming frame security procedure
 */
int8_t
frame802154_sec_incoming_frame(uint8_t *data, uint8_t len, frame802154_t *pf,
    uint8_t *p, uint8_t *auth_tag_len, int8_t *aux_sec_hdrlen) {
  uint8_t device_addr_mode;
  uint16_t device_pan_id;
  uint8_t device_addr[8];

  uint8_t security_level;
  uint8_t key_id_mode;
  uint8_t *key_source;
  uint8_t key_index;

  frame802154_key_desc *key_desc;
  frame802154_device_desc *device_desc;
  frame802154_security_level_desc *security_level_desc;
  uint8_t cmd_frame_id;

  uint8_t key_source_len;

  /* some invalid value */
  key_index = 0;
  key_source = NULL;
  key_source_len = 0;

  if(pf->fcf.security_enabled == 0) {
    security_level = 0;
  }
  if(pf->fcf.security_enabled == 1) {
    if(pf->fcf.frame_version == FRAME802154_IEEE802154_2003) {
      PRINTE("15.4-sec UNSUPPORTED_LEGACY 7.2.3.b\n");
      return -1;
    }

    /* p[0] & 0x07 - incoming security level, aux_hdr is not parsed yet */
    if((p[0] & 0x07) == FRAME802154_SECURITY_LEVEL_NONE) {
      PRINTE("15.4-sec UNSUPPORTED_SECURITY 7.2.3.c\n");
      return -1;
    }

    /* parse aux_security header, before using  it */
    *aux_sec_hdrlen = frame802154_sec_parse(pf, p);
    if(*aux_sec_hdrlen <= 0) {
      PRINTE("15.4-sec ERROR frame802154_sec_parse\n");
      return -1;
    }

    security_level = pf->aux_hdr.security_control.security_level;
    /* this is set in 7.2.3.e, too.
    key_id_mode = pf->aux_hdr.security_control.key_id_mode;
    if(key_id_mode == FRAME802154_KEYIDMODE_INDEX) {
      key_index = pf->aux_hdr.key[0];
      key_source = pf->aux_hdr.key;
      key_source_len = 0;
    }
    else if(key_id_mode == FRAME802154_KEYIDMODE_MAC_4) {
      key_index = pf->aux_hdr.key[4];
      key_source = pf->aux_hdr.key;
      key_source_len = 4;
    }
    else if(key_id_mode == FRAME802154_KEYIDMODE_MAC_8) {
      key_index = pf->aux_hdr.key[8];
      key_source = pf->aux_hdr.key;
      key_source_len = 8;
    }
    else {
      /* leave invalid values
    } */
  }

  if(frame802154_security_enabled == 0) {
    if(security_level == 0) {
      /*
       * nothing to do, frame is already unsecured.
       **/
    }
    else {
      PRINTE("15.4-sec UNSUPPORTED_SECURITY 7.2.3.d\n");
      return -1;
    }
  }

  /* 7.2.3 e. */
  device_pan_id = pf->src_pid;
  device_addr_mode = pf->fcf.src_addr_mode;
  memcpy(device_addr, pf->src_addr, 8); /* if src addr present */
  key_id_mode = pf->aux_hdr.security_control.key_id_mode;
  PRINTF("  key_id_mode %d", key_id_mode);
  PRINT_HEX(", key: ", pf->aux_hdr.key, 8+1);
  if(key_id_mode == FRAME802154_KEYIDMODE_INDEX) {
    key_index = pf->aux_hdr.key[0];
    key_source = pf->aux_hdr.key;
    key_source_len = 0;
  }
  else if(key_id_mode == FRAME802154_KEYIDMODE_MAC_4) {
    key_index = pf->aux_hdr.key[4];
    key_source = pf->aux_hdr.key;
    key_source_len = 4;
  }
  else if(key_id_mode == FRAME802154_KEYIDMODE_MAC_8) {
    key_index = pf->aux_hdr.key[8];
    key_source = pf->aux_hdr.key;
    key_source_len = 8;
  }
  else {
    key_source = NULL;
  }

  /* get key, device, security_level_descriptor */
  /* 7.2.3 f */
  key_desc = frame802154_sec_get_key_descriptor(
      key_id_mode, key_index, key_source,
      device_addr_mode, device_pan_id, device_addr, pf->fcf.frame_type);
  if(key_desc == NULL) {
    PRINTE("15.4-sec UNAVAILABLE_KEY 7.2.3 f\n");
    return -1;
  }
  /* 7.2.3 g */
  device_desc = frame802154_sec_get_device_descriptor(
      device_addr_mode, device_pan_id, device_addr);
  if(device_desc == NULL) {
    PRINTE("15.4-sec UNAVAILABLE_DEVICE 7.2.3 g\n");
    return -1;
  }
  /* 7.2.3 h */
  /* cmd_frame_id - if packet is MAC CMD type, is the first octet in packetbuf_data */
  cmd_frame_id = 0xFF;
  if(pf->fcf.frame_type == FRAME802154_CMDFRAME &&
      packetbuf_datalen() >= 1) {
    cmd_frame_id = *(uint8_t*)packetbuf_dataptr();
  }
  security_level_desc = frame802154_sec_get_security_level_descriptor(
      pf->fcf.frame_type, cmd_frame_id);
  if(security_level_desc == NULL) {
    PRINTE("15.4-sec UNAVAILABLE_SECURITY_LEVEL 7.2.3 h\n");
    return -1;
  }

  /* 7.2.3 i */
  uint8_t security_level_check;
  security_level_check = frame802154_sec_check_incoming_security_level(security_level_desc, security_level);
  if(security_level_check <= 0) {
    PRINTE("15.4-sec IMPROPER_SECURITY_LEVEL 7.2.3 i\n");
    return -1;
  }
  else if(security_level_check == 1 && /* status_passed */
      security_level == FRAME802154_SECURITY_LEVEL_NONE) {
    return 0;
  }
  /* 7.2.3 j, k */
  else if(security_level_check == 2) {/* status_conditionally_passed */
    if(device_desc->exempt) {
      return 0;
    }
    else {
      PRINTE("15.4-sec IMPROPER_SECURITY_LEVEL 7.2.3 k\n");
      return -1;
    }
  }

  /* 7.2.3 l */
  uint32_t frame_counter;
  frame_counter = pf->aux_hdr.frame_counter;
  if(frame_counter == 0xFFFFFFFF) {
    PRINTE("15.4-sec COUNTER_ERROR 7.2.3 l\n");
    return -1;
  }
  /* 7.2.3 m */
  if(frame_counter < device_desc->frame_counter ) {
    PRINTE("15.4-sec COUNTER_ERROR 7.2.3 m");
    return -1;
  }
  /* 7.2.3 n */
  if( 0 >= frame802154_sec_check_incoming_key_usage(key_desc, pf->fcf.frame_type, cmd_frame_id) ) {
    PRINTE("15.4-sec IMPROPER_KEY_TYPE 7.2.3 n\n");
    return -1;
  }
  /* 7.2.3 o/p */
  p += *aux_sec_hdrlen; /* start of data */
  if( 0 != frame802154_sec_decrypt(data, len, pf, p, auth_tag_len,
      key_desc, device_desc, frame_counter, security_level) ) {
    PRINTE("15.4-sec SECURITY_ERROR 7.2.3 o/p\n");
    return -1;
  }
  /* 7.2.3 q/r */
  device_desc->frame_counter = frame_counter + 1; /* frame_counter is now next unused value */
  return 0;
}
/*---------------------------------------------------------------------------*/
/**
 *
 * @param pf
 * @return -1 if fail, 0 if OK.
 *
 * 7.2.3 Incoming frame security procedure
 */
int8_t
frame802154_sec_outgoing_frame(frame802154_t *p, uint8_t tx_frame_buffer[], uint8_t *pos
    ) {
  /* inputs, which are actually global variables
   * security_level, key_id_mode - were already written to frame *p.
   **/
  frame802154_key_desc *key_desc;
  /* uint8_t device_addr_mode;
  uint16_t device_pan_id;
  uint8_t *device_addr; */
  uint8_t key_index;
  uint8_t key_source[8];

  if(frame802154_security_enabled == 0 &&
      p->aux_hdr.security_control.security_level != 0) {
    PRINTE("15.4-sec UNSUPPORTED_SECURITY 7.2.1 a\n");
    return -1;
  }
  /* 7.2.1.b - should be already checked by higher layers */
  /* 7.2.1.c */
  if(p->aux_hdr.security_control.security_level == 0) {
    return 0;
  }
  /* 7.2.1.d */
  if(frame802154_frame_counter == 0xFFFFFFFF) {
    PRINTE("15.4-sec COUNTER_ERROR 7.2.1 d\n");
    return -1;
  }
  /* 7.2.1.d */
  /* device_addr_mode = p->fcf.dest_addr_mode;
  device_pan_id = p->dest_pid;
  device_addr = p->dest_addr; */
  if(p->aux_hdr.security_control.key_id_mode == FRAME802154_KEYIDMODE_MAC_4) {
    /*
     * TODO 7.4.3.1 - is 'originator of the group key' always current node?
     * Or would be the original node, if we are only forwarding a packet?
     * If forwarding - unmodified packet could be forwarded, no need to open
     * the packet (it makes sense to check validity).
     */
    /* FIXME Using little endian format - because frame_counter in little endian
     * format too, I guess it is correct */
    *((uint16_t*)(void*) (key_source)) = uip_htole_16(p->src_pid);
    *((uint16_t*)(void*) (key_source+2)) = uip_htole_16(*(uint16_t*)(void*)(p->src_addr+6));
    *((uint32_t*)(void*) (key_source+4)) = 0;
    PRINT_HEX("  key_source 4: ", key_source, 8);
    PRINT_HEX("  src_addr: ", p->src_addr, 8);
  }
  else if(p->aux_hdr.security_control.key_id_mode == FRAME802154_KEYIDMODE_MAC_8) {
    /* FIXME byte order */
    *((uint64_t*)(void*) (key_source)) = uip_htole_64(*(uint64_t*)(void*)(p->src_addr));
    PRINT_HEX("  key_source 8: ", key_source, 8);
  }
  PRINT_HEX("  key_source ?: ", key_source, 8);
  PRINT_HEX("  p->src_addr: ", p->src_addr, 8);
  key_index = frame802154_key_index;
  key_desc = frame802154_sec_get_key_descriptor(
      p->aux_hdr.security_control.key_id_mode, key_index,
      key_source, p->fcf.dest_addr_mode, p->dest_pid, p->dest_addr, p->fcf.frame_type);
  if(key_desc == NULL) {
    PRINTE("15.4-sec UNAVAILABLE_KEY 7.2.1 e\n");
    return -1;
  }

  /* 7.2.1. f */
  if(frame802154_sec_create_aux_header(p, tx_frame_buffer, pos, key_desc, key_index) < 0) {
    PRINTE("15.4-sec UNAVAILABLE_KEY 7.2.1 f\n");
    return -1;
  }
  /* 7.2.1. g */
  if(frame802154_sec_encrypt(p) < 0) {
    PRINTE("15.4-sec UNAVAILABLE_KEY 7.2.1 g\n");
    return -1;
  }
  /* 7.2.1. h */
  frame802154_frame_counter++;

  return 0;
}
/*---------------------------------------------------------------------------*/
/** \brief       Write auxiliary security header to tx_frame_buffer,
 *              replace plaintext data with encrypted data and append authentication tag.
 *              Also write values to aux sec header in frame802154_t p.
 * \param p     Frame being send.
 * \param tx_frame_buffer Transmitt buffer
 * \param pos   First unused octet in the transmit buffer.
 * \param       key_index - key index, value in matching key_desc->key_lookup[?].m1.key_index.
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
int8_t frame802154_sec_create_aux_header(frame802154_t *p, uint8_t tx_frame_buffer[], uint8_t *pos,
    frame802154_key_desc *key_desc, uint8_t key_index) {
  uint8_t key_identifier_len;
  uint8_t security_level;
  uint8_t key_id_mode;

  security_level = p->aux_hdr.security_control.security_level;
  key_id_mode = p->aux_hdr.security_control.key_id_mode;
  PRINTF("15.4-sec create, security_level key_id_mode: %d %d\n", security_level, key_id_mode);

  p->aux_hdr.security_control.reserved = 0;
  /* dump data for security header to buf, and increment pos; */
  tx_frame_buffer[*pos] = (security_level & 0x07) | ((key_id_mode & 0x03) << 3);
  PRINTF("15.4-sec aux sec flags 0x%02x\n", tx_frame_buffer[*pos]);
  (*pos)++;

  /* set frame counter */
  PRINTF("15.4-sec frame_counter %d\n",  frame802154_frame_counter);
  p->aux_hdr.frame_counter = frame802154_frame_counter;
  *((uint32_t*)(void*)(tx_frame_buffer + *pos)) = uip_htole_32(frame802154_frame_counter); /* byte order - low byte first */
  (*pos) += 4;

  /* Use key descriptor */
  frame802154_aes_setup_key(key_desc->key);

  /* TODO check p->fcf.src_addr_mode - are used 2 or 8 bytes */
  switch(key_id_mode) {
  case FRAME802154_KEYIDMODE_IMPLICIT:
    key_identifier_len = 0;
    break;
  case FRAME802154_KEYIDMODE_INDEX:
    key_identifier_len = 1;
    p->aux_hdr.key[0] = key_index;
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
    *((uint16_t*)(void*) (p->aux_hdr.key)) = uip_htole_16(p->src_pid);
    *((uint16_t*)(void*) (p->aux_hdr.key+2)) = uip_htole_16(*(uint16_t*)(void*)(p->src_addr+6));
    p->aux_hdr.key[4] = key_index;
    break;
  case FRAME802154_KEYIDMODE_MAC_8:
    key_identifier_len = 9;
    /* FIXME byte order */
    *((uint64_t*)(void*) (p->aux_hdr.key)) = uip_htole_64(*(uint64_t*)(void*)(p->src_addr));
    p->aux_hdr.key[8] = key_index;
    break;
  default:
    key_identifier_len = 0;
    break;
  }
  memcpy(tx_frame_buffer + *pos, p->aux_hdr.key, key_identifier_len);
  (*pos) += key_identifier_len;

  return 0;
}
/*---------------------------------------------------------------------------*/
/**
 * \brief   Encrypt packet payload.
 * \return  -1 if error, 0 if OK.
 * Data is already at packetbuf_dataptr(), packetbuf_datalen().
 * Encrypt data depending on frame type.
 */
int8_t
frame802154_sec_encrypt(const frame802154_t *p) {
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
  auth_tag_len = AUTHTAGLEN_FROM_SECLEVEL(p->aux_hdr.security_control.security_level);
  PRINTF("15.4-sec security_level => auth_tag_len: 0x%02x %d\n",
      p->aux_hdr.security_control.security_level, auth_tag_len);

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

  switch(p->aux_hdr.security_control.security_level) {
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
  *(uint8_t*)(void*)(nonce+12) = p->aux_hdr.security_control.security_level;
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
int8_t frame802154_sec_parse(frame802154_t *pf, uint8_t *p) {

  PRINTF("15.4-sec parse, p[0] 0x%02X\n", p[0]);
  pf->aux_hdr.security_control.security_level = p[0] & 0x07;
  pf->aux_hdr.security_control.key_id_mode = (p[0] >> 3) & 0x03;
  pf->aux_hdr.security_control.reserved = (p[0] >> 5) & 0x07;
  p++;
  PRINTF("15.4-sec security_level %d\n", pf->aux_hdr.security_control.security_level);
  PRINTF("15.4-sec key_id_mode %d\n",  pf->aux_hdr.security_control.key_id_mode);

  pf->aux_hdr.frame_counter = uip_htole_32( *((uint32_t*)(void*)p) );
  p += 4;
  PRINTF("15.4-sec frame_counter %d\n",  pf->aux_hdr.frame_counter);

  uint8_t key_identifier_len;
  uint8_t /*key_source[8],*/ key_index = 0;

  /* TODO check p->fcf.src_addr_mode - are used 2 or 8 bytes
   * pf->aux_hdr.key is now opaque. How useful will this be?
   **/
  switch(pf->aux_hdr.security_control.key_id_mode) {
  case FRAME802154_KEYIDMODE_IMPLICIT:
    key_identifier_len = 0;
    memset(pf->aux_hdr.key, 0x00, 9);
    break;
  case FRAME802154_KEYIDMODE_INDEX:
    key_identifier_len = 1;
    key_index = p[0];
    pf->aux_hdr.key[0] = key_index;
    memset(pf->aux_hdr.key+1, 0x00, 8);
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
    memset(pf->aux_hdr.key+5, 0x00, 4);
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

  return 1 + 4 + key_identifier_len;
}
/*---------------------------------------------------------------------------*/
/*
 * \return 0 if OK, -1 if error.
 * Do the actual frame decryption.
 **/
int8_t
frame802154_sec_decrypt(
    uint8_t *data, uint8_t len, frame802154_t *pf, uint8_t *p, uint8_t *auth_tag_len,
    frame802154_key_desc *key_desc, frame802154_device_desc *device_desc,
    uint32_t frame_counter, uint8_t security_level)
{
  frame802154_aes_setup_key(key_desc->key);

  /* decrypt data */
  uint8_t *aa, a_len;
  uint8_t nonce[FRAME802154_AES_NONCE_LEN];
  uint8_t mm[150] ; /*, m_len; / * plaintext */
  /* uint8_t m_param; */
  uint8_t *cc, c_len; /* chiper */
  uint8_t *tt; /*, t_len;  auth tag */
  *auth_tag_len = AUTHTAGLEN_FROM_SECLEVEL(security_level);
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

  switch(security_level) {
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
  *(uint32_t*)(void*)(nonce+8) = uip_htonl(frame_counter);
  *(uint8_t*)(void*)(nonce+12) = security_level;

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

  return 0;
}

/** \}   */



