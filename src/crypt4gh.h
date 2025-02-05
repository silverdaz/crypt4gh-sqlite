/**********************************************************************************
 * Read-only Crypt4GH file system, listing information from an SQLite "database".
 *
 *  Author:  Frédéric Haziza <silverdaz@gmail.com>
 *    Date:  October 2023
 *
 *  This program can be distributed under the terms of the GNU Affero GPL.
 *  See the LICENSE file.
 **********************************************************************************/

#pragma once

#include <sodium.h>

static char* MAGIC_NUMBER = "crypt4gh";
static uint32_t VERSION = 1U;

/* Crypt4GH contants */
#define CRYPT4GH_SESSION_KEY_SIZE   crypto_aead_chacha20poly1305_IETF_KEYBYTES
#define CRYPT4GH_NONCE_SIZE         crypto_aead_chacha20poly1305_IETF_NPUBBYTES /* 12 */
#define CRYPT4GH_MAC_SIZE           16
#define CRYPT4GH_SEGMENT_SIZE       65536
#define CIPHER_DIFF                 (CRYPT4GH_NONCE_SIZE + CRYPT4GH_MAC_SIZE)
#define CRYPT4GH_CIPHERSEGMENT_SIZE (CRYPT4GH_SEGMENT_SIZE + CIPHER_DIFF)

typedef enum {
  data_encryption_parameters = 0,
  data_edit_list = 1
} header_packet_type;

typedef enum {
  X25519_chacha20_ietf_poly1305 = 0
} header_packet_encryption_method;

typedef enum {
  chacha20_ietf_poly1305 = 0
} header_data_encryption_type;


/*
 * Read 8 bytes from p and 
 * get its integer representation in little-endian format
 */
#define PEEK_U64_LE(p) \
	(((uint64_t)(((const uint8_t *)(p))[0])      ) | \
	 ((uint64_t)(((const uint8_t *)(p))[1]) <<  8) | \
	 ((uint64_t)(((const uint8_t *)(p))[2]) << 16) | \
	 ((uint64_t)(((const uint8_t *)(p))[3]) << 24) | \
	 ((uint64_t)(((const uint8_t *)(p))[4]) << 32) | \
	 ((uint64_t)(((const uint8_t *)(p))[5]) << 40) | \
	 ((uint64_t)(((const uint8_t *)(p))[6]) << 48) | \
	 ((uint64_t)(((const uint8_t *)(p))[7]) << 56))
/* Left shift are filled with zeros */

/*
 * Read 4 bytes from p and 
 * get its integer representation in little-endian format
 */
#define PEEK_U32_LE(p) \
	(((uint32_t)(((const uint8_t *)(p))[0])      ) | \
	 ((uint32_t)(((const uint8_t *)(p))[1]) << 8 ) | \
	 ((uint32_t)(((const uint8_t *)(p))[2]) << 16) | \
	 ((uint32_t)(((const uint8_t *)(p))[3]) << 24))




int c4gh_header_parse(uint8_t* header, unsigned int header_size,
		      const uint8_t seckey[crypto_box_SECRETKEYBYTES],
		      const uint8_t pubkey[crypto_box_PUBLICKEYBYTES],
		      uint8_t** session_keys, unsigned int* nkeys,
		      uint64_t** edit_list, unsigned int* edit_list_len)
__nonnull__()
;
