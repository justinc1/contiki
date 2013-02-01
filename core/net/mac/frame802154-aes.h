/**
 *   \addtogroup frame802154
 *   @{
*/
/**
 *  \file
 *  \brief Add AES encryption/decryption of 802.15.4 frames.
 *
 *  \author Justin <justin.cinkelj@xlab.si>
 *
 *  Plaintext packets are encrypted here. Here is (will be) also key selection logic.
 *
 *  AES block encryption routine is in a separate file - so that it can be
 *  replaced with hardware implementation when available.
 *
 */

#ifndef FRAME_802154_AES_H
#define FRAME_802154_AES_H

#include "frame802154.h"
#include "frame802154-sec.h"
#include "packetbuf.h"

#include "aes.h"


#define FRAME802154_AES_NONCE_LEN 13
#define FRAME802154_AES_L 2

/* from aes.c */
void xor_block( void *d, const void *s );
void copy_and_key( void *d, const void *s, const void *k );

/* debug utility*/
void print_hex(const char msg[], const uint8_t buf[], int len);

/* UIP_HTOLE - host to little endian conversion.
 * AES nonce has some values in little endian format.
 **/
#include "uip.h"
#if UIP_BYTE_ORDER == UIP_BIG_ENDIAN
#  define UIP_HTOLE_16(n) (uint16_t)((((uint16_t) (n)) << 8) | (((uint16_t) (n)) >> 8))
#  define UIP_HTOLE_32(n) (((uint32_t)UIP_HTOLE_16(n) << 16) | UIP_HTOLE_16((uint32_t)(n) >> 16))
#  define UIP_HTOLE_64(n) (((uint64_t)UIP_HTOLE_32(n) << 32) | UIP_HTOLE_32((uint64_t)(n) >> 32))
#  define UIP_LETOH_16(n) UIP_HTOLE_16( (n) )
#  define UIP_LETOH_32(n) UIP_HTOLE_32( (n) )
#  define UIP_LETOH_64(n) UIP_HTOLE_64( (n) )
#else
#  define UIP_HTOLE_16(n) (n)
#  define UIP_HTOLE_32(n) (n)
#  define UIP_HTOLE_64(n) (n)
#  define UIP_LETOH_16(n) (n)
#  define UIP_LETOH_32(n) (n)
#  define UIP_LETOH_64(n) (n)
#endif /* UIP_BYTE_ORDER == UIP_BIG_ENDIAN */



/* flags for aes algorithm.  */
#define M_TO_FLAGS(M) ((M)==0 ? 0 : ((0x07 & ((M)-2)) << 2) )
#define M_FROM_FLAGS(F) ( (((F) & 0x38) == 0) ? 0 : (((F) & 0x38) >>2) + 2)
#define L_TO_FLAGS(L) ( 0x07 & ((L)-1) )
#define L_FROM_FLAGS(F) ( ((F) & 0x07) + 1 )
/* get auth_tag len (0, 4, 8 or 16) from security_level (0...7) */
#define AUTHTAGLEN_FROM_SECLEVEL( sl ) ( (0x02 << ((sl) & 0x03)) & 0x1C )

void frame802154_aes_setup_key(uint8_t key[16]);

void frame802154_aes_encrypt_msg(
    /* in */
        uint8_t *aa, uint8_t a_len, uint8_t *nonce, uint8_t *mm, uint8_t m_len,
        uint8_t M,
    /* out */
        uint8_t *cc,
        uint8_t *tt
        );
int8_t frame802154_aes_decrypt_msg(
/* in */
    uint8_t *aa, uint8_t a_len, uint8_t *nonce,
    uint8_t *cc, uint8_t c_len,
    uint8_t *tt,
    uint8_t M,
/* out */
    uint8_t *mm
    );


#endif /* FRAME_802154_AES_H */
