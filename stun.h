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

#define STUN_COOKIE 0x2112A442
#define STUN_ALIGNED(x) ((x+3)/4*4)

enum stun_method {
    STUN_METHOD_BINDING = 0x1,
};
enum stun_class {
    STUN_REQUEST        = 0x0000,
    STUN_INDICATION     = 0x0010,
    STUN_SUCC_RESPONSE  = 0x0100,
    STUN_ERROR_RESPONSE = 0x0110,
};


enum stun_attr_type {
    MAPPED_ADDRESS = 0x0001,
    RESPONSE_ADDRESS,
    CHANGE_ADDRESS,
    SOURCE_ADDRESS,
    CHANGED_ADDRESS,
    USERNAME,
    PASSWORD,
    MESSAGE_INTEGRITY,
    ERROR_CODE,
    UNKNOWN,
    REFLECTED_FROM,
    REALM = 0x0014,
    NONCE = 0x0015,
    XOR_MAPPED_ADDRESS = 0x0020,
    SOFTWARE = 0x8022,
    ALTERNATE_SERVER = 0x8023,
    PRIORITY = 0x0024,
    USE_CANDIDATE = 0x0025,
    FINGERPRINT = 0x8028,
    ICE_CONTROLLED = 0x8029,  /* https://tools.ietf.org/html/rfc5245#section-21.2 */
    ICE_CONTROLLING = 0x802A,
};

typedef struct stun_header {
#if __BYTE_ORDER == __BIG_ENDIAN
    uint16_t zero:2;
    uint16_t type:14;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
    uint16_t type:14;
    uint16_t zero:2;
#endif
    uint16_t len;           /* length of the message not including the header aligned by 4 bytes */
    uint32_t cookie;        /* fixed to 0x2112A442 according to the protocol */
    uint8_t  trans_id[12];  /* unique id */
} stun_header __packed;

typedef struct stun_attr_header {
    uint16_t type;
    uint16_t len;           /* should by aligned by 4 bytes */
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
    uint8_t  resvered;
    uint8_t  family;
    uint16_t port;
    uint32_t addr;
} stun_attr_xor_mapped_address_ipv4 __packed;

typedef struct stun_attr_xor_mapped_address_ipv6 {
    stun_attr_header header;
    uint8_t  resvered;
    uint8_t  family;
    uint16_t port;
    uint8_t  addr[8];
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

typedef struct _stun_message_t {
    char*        buf;
    uint32_t     len;
    uint32_t     used;
    stun_header* header;
} stun_message_t;

stun_message_t* stun_alloc_message();
void stun_free_message(stun_message_t* msg);
int stun_add_attr(stun_message_t* msg, stun_attr_header* attr);
int stun_set_method_and_class(stun_message_t* msg, uint16_t method, uint16_t cls);

int stun_parse(stun_message_t* msg, char* buf, uint32_t len);
int stun_serilize(stun_message_t* msg, char* buf, uint32_t* len);

#endif /*STUN_H_INCLUDED*/

/********************************** END **********************************************/

