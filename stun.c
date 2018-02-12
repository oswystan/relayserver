/*
 **************************************************************************************
 *       Filename:  stun.c
 *    Description:   source file
 *
 *        Version:  1.0
 *        Created:  2018-02-11 21:49:20
 *
 *       Revision:  initial draft;
 **************************************************************************************
 */

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <openssl/rand.h>
#include "stun.h"

#define DEFAULT_SIZE 1024

static uint64_t stun_ntohll(uint64_t n) {
    if (__BYTE_ORDER == __LITTLE_ENDIAN) {
        uint64_t h = ntohl(n>>32) | ((uint64_t)ntohl(n&0xFFFFFFFF) << 32);
        return h;
    } else {
        return n;
    }
}
static uint64_t stun_htonll(uint64_t h) {
    if (__BYTE_ORDER == __LITTLE_ENDIAN) {
        uint64_t n = htonl(h>>32) | ((uint64_t)htonl(h&0xFFFFFFFF) << 32);
        return n;
    } else {
        return h;
    }
}

stun_message_t* stun_alloc_message() {
    stun_message_t* msg = (stun_message_t*)malloc(sizeof(stun_message_t));
    if(msg) {
        msg->buf = (char*)malloc(DEFAULT_SIZE);
        if(!msg->buf) {
            free(msg);
            msg = NULL;
        }
        memset(msg->buf, 0x00, DEFAULT_SIZE);
        stun_header* header = (stun_header*)msg->buf;
        header->cookie = STUN_COOKIE;
        RAND_bytes(header->trans_id, sizeof(header->trans_id));
        header->len = 0;
        msg->header = header;
        msg->used += sizeof(stun_header);
        msg->len = DEFAULT_SIZE;
    }
    return msg;
}

void stun_free_message(stun_message_t* msg) {
    if(msg) {
        if(msg->buf) free(msg->buf);
        free(msg);
    }
}

int stun_add_attr(stun_message_t* msg, stun_attr_header* attr) {
    if(!msg || !attr || !msg->buf) {
        return -EINVAL;
    }

    uint16_t copylen = STUN_ALIGNED(attr->len);
    if(msg->len - msg->used < copylen) {
        /* NO enough buffer avaliable, then realloc the buffer */
        char* buf = (char*)malloc(msg->len*2);
        if(!buf) {
            return -ENOMEM;
        }
        memcpy(buf, msg->buf, msg->used);
        free(msg->buf);
        msg->buf = buf;
        msg->len = msg->len * 2;
    }
    memcpy(msg->buf + msg->used, attr, copylen);
    msg->used += copylen;
    msg->header->len += copylen;
    return 0;
}
int stun_set_method_and_class(stun_message_t* msg, uint16_t method, uint16_t cls) {
    if(!msg || method != STUN_METHOD_BINDING) return -EINVAL;
    msg->header->type = (method | cls);
    return 0;
}

int stun_parse(stun_message_t* msg, char* buf, uint32_t len) {
    if(!msg || !buf || !len || len%4!=0) return -EINVAL;
    if(len >  msg->len) {
        char* ptr = (char*)malloc(len);
        if(!ptr) {
            return -ENOMEM;
        }
        free(msg->buf);
        msg->buf  = ptr;
    }
    memcpy(msg->buf, buf, len);
    msg->len = msg->used = len;
    msg->header = (stun_header*)msg->buf;

    /* check header */
    stun_header* header = msg->header;
    uint16_t reallen = 0;
    header->cookie = ntohl(header->cookie);
    if(header->cookie != STUN_COOKIE) {
        return -EBADMSG;
    }
    header->len = ntohs(header->len);

    char* ptr = msg->buf + sizeof(stun_header);
    stun_attr_header* attr = NULL;
    while(ptr < msg->buf+msg->len) {
        attr = (stun_attr_header*)ptr;
        attr->type = ntohs(attr->type);
        attr->len = ntohs(attr->len);
        reallen = STUN_ALIGNED(attr->len);

        switch(attr->type) {
            case USERNAME: {
                break;
            };
            case UNKNOWN: {
                stun_attr_unknown* a = (stun_attr_unknown*)attr;
                for(uint16_t i=0; i<attr->len; i++) {
                    a->attrs[i] = ntohs(a->attrs[i]);
                }
                break;
            };
            case XOR_MAPPED_ADDRESS: {
                stun_attr_xor_mapped_address_ipv4* a = (stun_attr_xor_mapped_address_ipv4*)attr;
                a->port = ntohs(a->port);
                if(a->family == 0x01) {
                    a->addr = ntohl(a->addr);
                }
                break;
            };
            case ICE_CONTROLLING: {
                stun_attr_ice_controlling* a = (stun_attr_ice_controlling*)attr;
                a->tiebreaker = stun_ntohll(a->tiebreaker);
                break;
            };
            case USE_CANDIDATE: {
                break;
            };
            case PRIORITY: {
                stun_attr_priority* a = (stun_attr_priority*)attr;
                a->priority = ntohl(a->priority);
                break;
            };
            case MESSAGE_INTEGRITY: {
                break;
            };
            case FINGERPRINT: {
                stun_attr_fingerprint* a = (stun_attr_fingerprint*)attr;
                a->crc32 = ntohl(a->crc32);
                break;
            };
            default: {
                return -EBADMSG;
            }
        }

        ptr += reallen;
    }

    return 0;
}
int stun_serialize(stun_message_t* msg, char* buf, uint32_t* len) {
    if(!msg || !len || *len == 0) return -EINVAL;
    if(!buf) {
        *len = msg->used;
        return 0;
    }

    if(*len < msg->used) {
        return -ENOMEM;
    }
    memcpy(buf, msg->buf, msg->used);

    stun_header* header = (stun_header*)buf;
    header->len = htons(header->len);
    header->cookie = htonl(header->cookie);
    char* ptr = buf + sizeof(stun_header);
    stun_attr_header* attr = NULL;
    uint16_t reallen = 0;
    while(ptr < buf + msg->used) {
        attr = (stun_attr_header*)ptr;
        attr->type = htons(attr->type);
        attr->len = htons(attr->len);
        reallen = STUN_ALIGNED(attr->len);

        switch(attr->type) {
            case USERNAME: {
                break;
            };
            case UNKNOWN: {
                stun_attr_unknown* a = (stun_attr_unknown*)attr;
                for(uint16_t i=0; i<attr->len; i++) {
                    a->attrs[i] = htons(a->attrs[i]);
                }
                break;
            };
            case XOR_MAPPED_ADDRESS: {
                stun_attr_xor_mapped_address_ipv4* a = (stun_attr_xor_mapped_address_ipv4*)attr;
                a->port = htons(a->port);
                if(a->family == 0x01) {
                    a->addr = htonl(a->addr);
                }
                break;
            };
            case ICE_CONTROLLING: {
                stun_attr_ice_controlling* a = (stun_attr_ice_controlling*)attr;
                a->tiebreaker = stun_htonll(a->tiebreaker);
                break;
            };
            case USE_CANDIDATE: {
                break;
            };
            case PRIORITY: {
                stun_attr_priority* a = (stun_attr_priority*)attr;
                a->priority = htonl(a->priority);
                break;
            };
            case MESSAGE_INTEGRITY: {
                break;
            };
            case FINGERPRINT: {
                stun_attr_fingerprint* a = (stun_attr_fingerprint*)attr;
                a->crc32 = htonl(a->crc32);
                break;
            };
            default: {
                return -EBADMSG;
            }
        }
        ptr += reallen;
    }

    return 0;
}

/********************************** END **********************************************/

