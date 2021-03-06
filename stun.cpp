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

#define LOG_TAG "stun"
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <zlib.h>
#include "stun.h"
#include "log.h"

#define DEFAULT_SIZE  1024
#define STUN_BLK_SIZE 64
#define STUN_CRC32_FACTOR 0x5354554e

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
static void hexdump(uint8_t* ptr, uint32_t cnt) {
    if(!ptr || !cnt) return;
    for(uint32_t i=0; i<cnt; i++, ptr++) {
        if(i % 16 == 0) {
            if(i != 0) log("\n");
            log("%08x  ", i);
        }
        if(i % 8 == 0 && i % 16 != 0)
            log(" %02x ", *ptr);
        else
            log("%02x ", *ptr);
    }
    log("\n");
}

stun_message_t* stun_alloc_message() {
    stun_message_t* msg = (stun_message_t*)malloc(sizeof(stun_message_t));
    if(msg) {
        memset(msg, 0x00, sizeof(*msg));
        msg->buf = (uint8_t*)malloc(DEFAULT_SIZE);
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
        msg->used = sizeof(stun_header);
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

    uint16_t copylen = STUN_ALIGNED(attr->len) + sizeof(stun_attr_header);
    if(msg->len - msg->used < copylen) {
        logd("%s: resize mem", __func__);
        /* NO enough buffer avaliable, then realloc the buffer */
        uint8_t* buf = (uint8_t*)malloc(msg->len*2);
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
stun_attr_header* stun_get_attr(stun_message_t* msg, uint16_t atype) {
    if(!msg) return NULL;

    uint8_t* ptr = msg->buf + sizeof(stun_header);
    uint16_t reallen = 0;
    while(ptr < msg->buf + msg->used) {
        stun_attr_header* attr = (stun_attr_header*)ptr;
        reallen = STUN_ALIGNED(attr->len);
        if(attr->type == atype) return attr;
        ptr = ptr + reallen + sizeof(stun_attr_header);
    }
    return NULL;
}
int stun_set_method_and_class(stun_message_t* msg, uint16_t method, uint16_t cls) {
    if(!msg || method != STUN_METHOD_BINDING) return -EINVAL;
    msg->header->type = (method | cls);
    logd("type: %x %x", msg->header->type, (method | cls));
    return 0;
}

int stun_parse(stun_message_t* msg, uint8_t* buf, uint32_t len) {
    if(!msg || !buf || !len || len%4!=0) return -EINVAL;
    if(len >  msg->len) {
        logd("parse resize");
        uint8_t* ptr = (uint8_t*)malloc(len);
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
    header->type = ntohs(header->type);
    header->len = ntohs(header->len);

    uint8_t* ptr = msg->buf + sizeof(stun_header);
    stun_attr_header* attr = NULL;
    while(ptr < msg->buf+msg->len) {
        attr = (stun_attr_header*)ptr;
        attr->type = ntohs(attr->type);
        attr->len = ntohs(attr->len);
        reallen = STUN_ALIGNED(attr->len);

        switch(attr->type) {
            case USERNAME: {
                /*logd("USERNAME");*/
                break;
            };
            case WRTC_UNKNOWN: {
                /*logd("WRTC_UNKNOWN");*/
                stun_attr_unknown* a = (stun_attr_unknown*)attr;
                for(uint16_t i=0; i<(attr->len/2); i++) {
                    a->attrs[i] = ntohs(a->attrs[i]);
                }
                break;
            };
            case XOR_MAPPED_ADDRESS: {
                /*logd("XOR_MAPPED_ADDRESS");*/
                stun_attr_xor_mapped_address_ipv4* a = (stun_attr_xor_mapped_address_ipv4*)attr;
                a->port = ntohs(a->port);
                if(a->family == 0x01) {
                    a->addr = ntohl(a->addr);
                }
                break;
            };
            case ICE_CONTROLLING: {
                /*logd("ICE_CONTROLLING");*/
                stun_attr_ice_controlling* a = (stun_attr_ice_controlling*)attr;
                a->tiebreaker = stun_ntohll(a->tiebreaker);
                break;
            };
            case USE_CANDIDATE: {
                /*logd("USE_CANDIDATE");*/
                break;
            };
            case PRIORITY: {
                /*logd("PRIORITY");*/
                stun_attr_priority* a = (stun_attr_priority*)attr;
                a->priority = ntohl(a->priority);
                break;
            };
            case MESSAGE_INTEGRITY: {
                /*logd("MESSAGE_INTEGRITY");*/
                break;
            };
            case FINGERPRINT: {
                /*logd("FINGERPRINT");*/
                stun_attr_fingerprint* a = (stun_attr_fingerprint*)attr;
                a->crc32 = ntohl(a->crc32);
                break;
            };
            default: {
                loge("parse: invalid type: 0x%02x %u", attr->type, len);
                hexdump(msg->buf, msg->used);
                return -EBADMSG;
            }
        }

        ptr = ptr + reallen + sizeof(stun_attr_header);
    }

    return 0;
}
int stun_serialize(stun_message_t* msg, uint8_t* buf, uint32_t* len) {
    if(!msg || !len || *len == 0) return -EINVAL;
    if(!buf) {
        *len = msg->used;
        return 0;
    }

    if(*len < msg->used) {
        logd("serialize: not enough memory");
        return -ENOMEM;
    }
    *len = 0;
    memcpy(buf, msg->buf, msg->used);

    stun_header* header = (stun_header*)buf;
    header->type = htons(header->type);
    header->len = htons(header->len);
    header->cookie = htonl(header->cookie);
    uint8_t* ptr = buf + sizeof(stun_header);
    stun_attr_header* attr = NULL;
    uint16_t reallen = 0;
    uint16_t attrlen = 0;
    uint16_t type = 0;
    while(ptr < buf + msg->used) {
        attr = (stun_attr_header*)ptr;
        type = attr->type;
        reallen = STUN_ALIGNED(attr->len);
        attrlen = attr->len;

        attr->type = htons(attr->type);
        attr->len = htons(attr->len);

        switch(type) {
            case USERNAME: {
                /*logd("serialize: USERNAME");*/
                break;
            };
            case WRTC_UNKNOWN: {
                /*logd("serialize: WRTC_UNKNOWN");*/
                stun_attr_unknown* a = (stun_attr_unknown*)attr;
                for(uint16_t i=0; i<(attrlen/2); i++) {
                    a->attrs[i] = htons(a->attrs[i]);
                }
                break;
            };
            case XOR_MAPPED_ADDRESS: {
                /*logd("serialize: XOR_MAPPED_ADDRESS");*/
                stun_attr_xor_mapped_address_ipv4* a = (stun_attr_xor_mapped_address_ipv4*)attr;
                a->port = htons(a->port ^ (STUN_COOKIE >> 16));
                a->addr = htonl(a->addr ^ htonl(STUN_COOKIE));
                if(a->family == 0x01) {
                    a->addr = htonl(a->addr);
                }
                break;
            };
            case ICE_CONTROLLED:
            case ICE_CONTROLLING: {
                /*logd("serialize: ICE_CONTROLLING");*/
                stun_attr_ice_controlling* a = (stun_attr_ice_controlling*)attr;
                a->tiebreaker = stun_htonll(a->tiebreaker);
                break;
            };
            case USE_CANDIDATE: {
                /*logd("serialize: USE_CANDIDATE");*/
                break;
            };
            case PRIORITY: {
                /*logd("serialize: PRIORITY");*/
                stun_attr_priority* a = (stun_attr_priority*)attr;
                a->priority = htonl(a->priority);
                break;
            };
            case MESSAGE_INTEGRITY: {
                /*logd("serialize: MESSAGE_INTEGRITY");*/
                break;
            };
            case FINGERPRINT: {
                /*logd("serialize: FINGERPRINT");*/
                stun_attr_fingerprint* a = (stun_attr_fingerprint*)attr;
                a->crc32 = htonl(a->crc32);
                break;
            };
            default: {
                loge("serialize: invalid type: 0x%02x @%p %d %d", attr->type, attr, msg->len, msg->used);
                hexdump(msg->buf, msg->used);
                return -EBADMSG;
            }
        }
        ptr = ptr + sizeof(stun_attr_header) + reallen;
    }
    *len = msg->used;

    return 0;
}

int stun_get_buf(stun_message_t* msg, uint16_t type, uint8_t* out, uint32_t* len) {
    stun_attr_header* attr = stun_get_attr(msg, type);
    if(!attr) {
        return -EINVAL;
    }
    uint8_t buf[4096];
    uint32_t buflen = sizeof(buf);
    int ret = stun_serialize(msg, buf, &buflen);
    if(ret != 0) return ret;

    stun_header* header = (stun_header*)buf;
    uint32_t size = (uint8_t*)attr - msg->buf;
    header->len = htons(size - sizeof(stun_header) + sizeof(stun_attr_header) + STUN_ALIGNED(attr->len));
    memcpy(out, buf, size);
    *len = size;
}
int stun_calculate_crc32(stun_message_t* msg) {
    stun_attr_fingerprint* attr = (stun_attr_fingerprint*)stun_get_attr(msg, FINGERPRINT);
    if(!attr) return -EINVAL;

    uint8_t buf[1024];
    uint32_t len = sizeof(buf);
    stun_get_buf(msg, FINGERPRINT, buf, &len);
    attr->crc32 = crc32(0, buf, len) ^ STUN_CRC32_FACTOR;
    return 0;
}

int calculate_sha1(uint8_t* in, uint32_t inlen, uint8_t* key, uint32_t keylen, uint8_t* out) {
    if(!in ||!inlen || !key || !out || !keylen) return -EINVAL;
    logd("calculate_sha1: %u %u", inlen, keylen);

    uint8_t ipad[STUN_BLK_SIZE], opad[STUN_BLK_SIZE], newkey[STUN_BLK_SIZE];
    uint8_t sha1[20];
    memset(ipad, 0x00, sizeof(ipad));
    memset(opad, 0x00, sizeof(opad));
    memset(newkey, 0x00, sizeof(newkey));
    memcpy(newkey, key, keylen);
    memset(sha1, 0x00, sizeof(sha1));
    for(int i=0; i<STUN_BLK_SIZE; i++) {
        opad[i] = 0x5c ^ newkey[i];
        ipad[i] = 0x36 ^ newkey[i];
    }
    SHA_CTX ctx;
    SHA1_Init(&ctx);
    SHA1_Update(&ctx, ipad, sizeof(ipad));
    SHA1_Update(&ctx, in, inlen);
    SHA1_Final(sha1, &ctx);

    SHA1_Init(&ctx);
    SHA1_Update(&ctx, opad, sizeof(opad));
    SHA1_Update(&ctx, sha1, sizeof(sha1));
    SHA1_Final(out, &ctx);
    return 0;
}
int stun_calculate_integrity(stun_message_t* msg, uint8_t* key, uint32_t keylen) {
    if(!msg || !key || !keylen) return -EINVAL;

    if(keylen > STUN_BLK_SIZE) {
        loge("unimplemented feature.");
        return -ENOSYS;
    }

    // serialize the data first
    uint8_t buf[1024];
    uint32_t len = sizeof(buf);
    stun_attr_message_integrity* attr = (stun_attr_message_integrity*)stun_get_attr(msg, MESSAGE_INTEGRITY);
    if(!attr) return -EINVAL;
    stun_get_buf(msg, MESSAGE_INTEGRITY, buf, &len);
    calculate_sha1(buf, len, key, keylen, attr->sha1);

    return 0;
}

#if 0
int main()
{
    const char* datafile = "stun.request";
    char buf[1024];
    char dst[1024];
    int fsize = 0;
    int ret = 0;
    FILE* fp = fopen(datafile, "r");
    if(!fp) {
        loge("fail to open file: %s", datafile);
        return -1;
    }
    fsize = fread(buf, 1, sizeof(buf), fp);
    if(fsize < 0) {
        loge("fail to read data:%s", strerror(errno));
        fclose(fp);
        return -1;
    }
    fclose(fp);
    stun_message_t* msg = stun_alloc_message();
    ret = stun_parse(msg, (uint8_t*)buf, fsize);
    logd("parse ret: %d", ret);

    uint32_t len = sizeof(dst);
    ret = stun_serialize(msg, (uint8_t*)dst, &len);
    logd("serialize ret: %d", ret);
    if((uint32_t)fsize != len) {
        loge("incorrect length: %u!=%u", fsize, len);
    } else if(memcmp(buf, dst, len) != 0) {
        loge("buf != dst");
        hexdump((uint8_t*)buf, len);
        hexdump((uint8_t*)dst, len);
    }

    uint8_t fpbuf[1024];
    uint8_t integritybuf[1024];
    uint32_t outlen = sizeof(fpbuf);

    stun_attr_header* attr = NULL;
    attr = stun_get_attr(msg, FINGERPRINT);
    if(attr) {
        stun_attr_fingerprint* fp = (stun_attr_fingerprint*)attr;
        logd("fp=%08x", fp->crc32);
    }
    stun_get_buf(msg, FINGERPRINT, fpbuf, &outlen);
    logd("outlen=%u", outlen);
    uint32_t rst = crc32(0, fpbuf, outlen) ^ STUN_CRC32_FACTOR;
    logd("calculated fp=%08x", rst);

    stun_get_buf(msg, MESSAGE_INTEGRITY, integritybuf, &outlen);
    attr = stun_get_attr(msg, MESSAGE_INTEGRITY);
    if(attr) {
        stun_attr_message_integrity* integrity = (stun_attr_message_integrity*)attr;
        hexdump(integrity->sha1, 20);
    }
    uint8_t sha1[20];
    memset(sha1, 0x00, sizeof(sha1));
    //uint8_t key[] = "BJp/UDVlcIEWecVeBWTw+8Pu";
    uint8_t key[] = "0pXkZeRzvMuO7ID0ZVCU+K";
    ret = calculate_sha1(integritybuf, outlen, key, sizeof(key)-1, sha1);
    if(ret != 0) {
        loge("fail to calculate sha1: %d", ret);
    } else {
        hexdump(sha1, 20);
    }

    return 0;
}
#endif
/********************************** END **********************************************/

