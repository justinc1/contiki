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

#include "frame802154-aes.h"
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
/* print error */
#define PRINTE(...) printf(__VA_ARGS__)

static aes_context ctx[1];
/*
   auth_data is made of
    - 16 bytes of (flags || nonce || m_len).
    - encoded length of a data, then a data, then 0x00 padding
    - plaintext data
 */
static uint8_t plaintext_ind;
static uint8_t auth_data_len = 0;
static uint8_t auth_data[128] = {0x00};

/*---------------------------------------------------------------------------*/
uint16_t
uip_htole_16(uint16_t val) {
  return UIP_HTOLE_16(val);
}
/*---------------------------------------------------------------------------*/
uint32_t
uip_htole_32(uint32_t val) {
  return UIP_HTOLE_32(val);
}
/*---------------------------------------------------------------------------*/
uint64_t uip_htole_64(uint64_t val) {
  return UIP_HTOLE_64(val);
}
/*---------------------------------------------------------------------------*/
/**
 * \brief Set AES key for frame encryption/decryption.
 * \param key AES key
 */
void frame802154_aes_setup_key(uint8_t key[16]) {
  PRINT_HEX("15.4-aes aes-key: ", key, 16);
  aes_set_key( key, 16, ctx );
}
/*---------------------------------------------------------------------------*/

void print_hex(const char msg[], const uint8_t buf[], int len) {
  int ii;
  printf("%s", msg);
  for(ii=0; ii<len; ii++) {
    if(ii%4 == 0)
      printf(" ");
    printf("%02x", buf[ii]);
  }
  printf("\n");
}
/*---------------------------------------------------------------------------*/


/*
 * Set m_len for encryption transformation.
 */
static void aes_set_m_len(uint8_t m_len) {
  auth_data[14] = 0x00;
  auth_data[15] = m_len;
}
/*---------------------------------------------------------------------------*/

/*
 * Insert a_len at beginnig of authorization data
 */
static void aes_set_a_len(uint8_t a_len) {
  /* messages cannot be longer that 127 octets */
  /* B.4.1.1 a */
  if(a_len == 0) {
    auth_data_len = 16;
  }
  else /* if(0 < a_len && a_len < 0xFF00) */ {
    /* network byte order */
    auth_data[16+0] = 0x00;
    auth_data[16+1] = a_len;
    /* auth_data_len points to first free byte */
    auth_data_len = 16+2;
  }
}
/*---------------------------------------------------------------------------*/

static void aes_input_trans(
/* in */
    uint8_t *aa, uint8_t a_len, uint8_t *nonce, uint8_t *mm, uint8_t m_len
/* out
    uint8_t *cc, uint8_t *c_len,
    uint8_t *tt, uint8_t *t_len */
    ) {
  PRINT_HEX("15.4-aes aa      : ", aa, a_len);
  PRINT_HEX("15.4-aes mm      : ", mm, m_len);
  PRINT_HEX("15.4-aes nonce   : ", nonce, FRAME802154_AES_NONCE_LEN);

  /* Set nonce. Flags are set later. */
  memcpy(auth_data+1, nonce, FRAME802154_AES_NONCE_LEN);

  auth_data_len = 0;
  aes_set_a_len(a_len);
  memcpy(auth_data + auth_data_len, aa, a_len);
  auth_data_len += a_len;
  /* 0x00 padding */
  for( ; (auth_data_len & 0x0F) != 0; auth_data_len++)
    auth_data[auth_data_len] = 0x00;

  /* append plaintext data */
  plaintext_ind = auth_data_len;
  memcpy(auth_data + auth_data_len, mm, m_len);
  auth_data_len += m_len;
  /* 0x00 padding */
  for( ; (auth_data_len & 0x0F) != 0; auth_data_len++)
    auth_data[auth_data_len] = 0x00;
}
/*---------------------------------------------------------------------------*/

static void aes_auth_trans(
/* in */
    uint8_t a_len, uint8_t m_len,
    uint8_t M,
/* out */
    uint8_t *tt
    ) {
  uint8_t ii;

  /* set flags */
  auth_data[0] = M_TO_FLAGS(M) + L_TO_FLAGS(FRAME802154_AES_L);
  if(a_len != 0)
    auth_data[0] |= 0x40;
  PRINTF("15.4-aes auth flags 0x%02x\n", auth_data[0]);
  /* aes_set_nonce(nonce); */
  aes_set_m_len(m_len);

  /* .d CBC-MAC */
  /* uint8_t xx[16]; // tt == xx */
  memset(tt, 0x00, 16); /* X0=0^128 */
  for(ii=1; ii<=auth_data_len/16; ii++) {
    PRINT_HEX("15.4-aes auth_data i: ", auth_data +(ii-1)*16, 16);
    copy_and_key(tt, tt, auth_data +(ii-1)*16); /* Xi+1 = Xi xor Bi */
    PRINT_HEX("15.4-aes xx         : ", tt, 16);
    aes_encrypt(tt, tt, ctx);
    PRINT_HEX("15.4-aes xx enc     : ", tt, 16);
  }
  PRINT_HEX("15.4-aes tt: ", tt, M);
}
/*---------------------------------------------------------------------------*/

void aes_encrypt_trans(
/* in */
    uint8_t m_len,
    uint8_t M,
/* out */
    uint8_t *tt,
    uint8_t *cc
    ) {
  uint8_t ii;

  /* set flags */
  auth_data[0] = L_TO_FLAGS(FRAME802154_AES_L);
  PRINTF("15.4-aes encryption flags 0x%02x\n", auth_data[0]);
  /* aes_set_nonce(nonce, nonce_len);
  aes_set_m_len(m_len); // set to index - later, in the for loop */

  /* TODO - is it ok to reuse auth_data[0:15] for ai[16] temp storage?
   * Eg, is plaintext_ind always at least 16 - it should be.
   */

  for(ii=1; ii<=(m_len+15)/16; ii++) {
    aes_set_m_len(ii); /* TODO - more than 1 byte; cannot be */
    PRINT_HEX("15.4-aes ai   : ", auth_data, 16);
    PRINT_HEX("15.4-aes plain: ", (auth_data+plaintext_ind) + (ii-1)*16, 16);
    aes_encrypt(auth_data, cc+(ii-1)*16, ctx);
    PRINT_HEX("15.4-aes aes  : ", cc+(ii-1)*16, 16);
    xor_block(cc+(ii-1)*16, (auth_data+plaintext_ind) + (ii-1)*16);
    PRINT_HEX("15.4-aes ci   : ", cc+(ii-1)*16, 16);
  }
  PRINT_HEX("15.4-aes chipr: ", cc, 16);
  PRINT_HEX("15.4-aes chipr: ", cc, m_len);
  /* B.4.1.3  .f .g */
  aes_set_m_len(0);
  uint8_t s0[16];
  aes_encrypt(auth_data, s0, ctx);
  PRINT_HEX("15.4-aes s0   : ", s0, 16);

  PRINT_HEX("15.4-aes tt: ", tt, M);
  xor_block(tt, s0);
  PRINT_HEX("15.4-aes  U: ", tt, M);
}
/*---------------------------------------------------------------------------*/
/*
 * \brief       Encrypt data before sending a packet.
 * \param aa    Authentication data
 * \param a_len Authentication data length
 * \param nonce Nonce (13 bytes)
 * \param mm    Plaintext data
 * \param m_len Plaintext data length
 * \param M     Requested length of authentication tag (0, 4, 8 or 16 octets)
 * \param cc    Buffer for encrypted plaintext data
 * \param tt    Buffer for encrypted authentication tag
 *
 * AES key should be setup before calling this function.
 */
void frame802154_aes_encrypt_msg(
    /* in */
        uint8_t *aa, uint8_t a_len, uint8_t *nonce, uint8_t *mm, uint8_t m_len,
        uint8_t M,
    /* out */
        uint8_t *cc,
        uint8_t *tt
        ) {
  aes_input_trans( aa, a_len, nonce, mm, m_len);
  aes_auth_trans( a_len, m_len, M, /* out */ tt);
  aes_encrypt_trans( m_len, M, /* out */ tt, cc);
}
/*---------------------------------------------------------------------------*/
/*
 * \brief       Decrypt data in received packet.
 * \param aa    Authentication data
 * \param a_len Authentication data length
 * \param nonce Nonce (13 bytes)
 * \param cc    Encrypted data
 * \param c_len Encrypted data length
 * \param M     Length of authentication tag tt (0, 4, 8 or 16 octets)
 * \param tt    Encrypted authentication tag
 * \param mm    Buffer for decrypted data
 * \return      -1 if error, 0 otherwise.
 *
 * AES key should be setup before calling this function.
 */
int8_t frame802154_aes_decrypt_msg(
    /* in */
        uint8_t *aa, uint8_t a_len, uint8_t *nonce,
        uint8_t *cc, uint8_t c_len,
        uint8_t *tt,
        uint8_t M,
    /* out */
        uint8_t *mm
        ) {
  uint8_t cc2[16*8];
  uint8_t tt2[16];
  uint8_t ii;

  memcpy(tt2, tt, M);
  PRINTF("15.4-aes auth_tag_len M : %d\n", M);
  aes_input_trans( aa, a_len, nonce, cc, c_len);
  /* decrypt authentication */
  aes_encrypt_trans( c_len, M, /* out */ tt2, cc2);

  PRINT_HEX("15.4-aes ** plain: ", cc2, c_len);
  PRINT_HEX("15.4-aes U/tt: ", tt, M);
  PRINT_HEX("15.4-aes tt2 : ", tt2, M);
  uint8_t tt3[16];
  /* check authentication. For mm, use original/decrypted plaintext */
  aes_input_trans( aa, a_len, nonce, cc2, c_len);
  aes_auth_trans( a_len, c_len, M, /* out */ tt3);
  PRINT_HEX("15.4-aes tt2 : ", tt2, M);
  PRINT_HEX("15.4-aes tt3 : ", tt3, M);

  for(ii=0; ii<M; ii++) {
    if(tt2[ii] != tt3[ii]) {
      PRINTE("15.4-aes ERROR: tt2 != tt3, ii=%d\n", ii);
      return -1;
    }
  }
  PRINTF("15.4-aes OK: tt2 == tt3\n");
  memcpy(mm, cc2, c_len);
  return 0;
}
/** \}   */
