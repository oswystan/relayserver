/*
 **************************************************************************************
 *       Filename:  stun.h
 *    Description:   header file
 *
 *        Version:  1.0
 *        Created:  2018-02-10 14:24:31
 *
 *       Revision:  initial draft;
 **************************************************************************************
 */

#ifndef STUN_H_INCLUDED
#define STUN_H_INCLUDED

#include <inttypes.h>
#include <netinet/in.h>
#if __BYTE_ORDER == __BIG_ENDIAN
#elif __BYTE_ORDER == __LITTLE_ENDIAN
#endif

#define __packed __attribute__ ((aligned))

typedef struct stun_header {
#if __BYTE_ORDER == __BIG_ENDIAN
    uint16_t zero:2;
    uint16_t type:14;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
    uint16_t type:14;
    uint16_t zero:2;
#endif
    uint16_t len;
    uint32_t cookie;
    uint8_t  trans_id[12];
} stun_header __packed;

typedef struct stun_attr_header {
    uint16_t type;
    uint16_t len;
} stun_attr_header __packed;

typedef struct stun_attr_username {
    stun_attr_header header;
    char username[0];
} stun_attr_username __packed;

typedef struct stun_attr_unknown {
    stun_attr_header header;
    uint16_t attrs[0];
} stun_attr_unknown __packed;

typedef struct stun_attr_xor_mapped_address_ipv4 {
    stun_attr_header header;
    uint8_t          resvered;
    uint8_t          family;
    uint16_t         port;
    struct in_addr   addr;
} stun_attr_xor_mapped_address_ipv4 __packed;

typedef struct stun_attr_xor_mapped_address_ipv6 {
    stun_attr_header header;
    uint8_t          resvered;
    uint8_t          family;
    uint16_t         port;
    struct in6_addr  addr;
} stun_attr_xor_mapped_address_ipv6 __packed;

typedef struct stun_attr_message_integrity {
    stun_attr_header header;
    uint8_t sha1[20];
} stun_attr_message_integrity __packed;

typedef struct stun_attr_fingerprint {
    stun_attr_header header;
    uint32_t crc32;
} stun_attr_fingerprint __packed;

typedef struct stun_attr_ice_controlling {
    stun_attr_header header;
    uint64_t tiebreaker;
} stun_attr_ice_controlling __packed;

typedef struct stun_attr_use_candidate {
    stun_attr_header header;
} stun_attr_use_candidate __packed;

typedef struct stun_attr_priority {
    stun_attr_header header;
    uint32_t priority;
} stun_attr_priority __packed;

#endif /*STUN_H_INCLUDED*/

/********************************** END **********************************************/

