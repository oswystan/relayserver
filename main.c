/*
 **************************************************************************************
 *       Filename:  main.c
 *    Description:   source file
 *
 *        Version:  1.0
 *        Created:  2017-09-14 21:51:55
 *
 *       Revision:  initial draft;
 **************************************************************************************
 */

#define LOG_TAG "relayserver"

#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <srtp2/srtp.h>

#include "log.h"
#include "stun.h"
#include "rtp.h"

#define MASTER_KEY  16
#define MASTER_SALT 14
#define MASTER_LEN  (MASTER_KEY+MASTER_SALT)

uint16_t srv_port = 8881;
uint16_t cli_port = 8882;
const char* srv_ip = "192.168.1.102";
char password[64];
char username[64];

#define STUN_MSG_RECEIVED 0x01
#define HANDSHAKE_SUCC    0x02
#define NORMAL_STATUS     (STUN_MSG_RECEIVED|HANDSHAKE_SUCC)
uint32_t status = 0;

int udp_new_server() {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;

    struct sockaddr_in addr_srv;
    bzero(&addr_srv, sizeof(addr_srv));
    addr_srv.sin_family = AF_INET;
    addr_srv.sin_port   = htons(srv_port);
    addr_srv.sin_addr.s_addr = inet_addr(srv_ip);
    int ret = bind(fd, (struct sockaddr*)&addr_srv, sizeof(struct sockaddr));
    if(ret != 0) {
        loge("fail to bind addr: %s %d [%s]", srv_ip, srv_port, strerror(errno));
        close(fd);
        return -1;
    }
    logd("server is running on: %s:%d fd:%d", srv_ip, srv_port, fd);
    return fd;
}
int is_stun(char* buf, int32_t len) {
    if(!buf || !len) return -EINVAL;
    stun_header* header = (stun_header*)buf;
    if(header->cookie == ntohl(STUN_COOKIE)) return 1;
    return 0;
}
int is_rtp(char* buf, int32_t len) {
    if(!buf || !len) return -EINVAL;
    rtp_header* header = (rtp_header*)buf;
    if(header->type < 64 || header->type >= 96) return 1;
    return 0;
}
int is_rtcp(char* buf, int32_t len) {
    if(!buf || !len) return -EINVAL;
    rtp_header* header = (rtp_header*)buf;
    if(header->type >= 64 || header->type < 96) return 1;
    return 0;
}
int is_password(char* buf, int32_t len) {
    if(!buf || !len) return -EINVAL;
    uint32_t* magic = (uint32_t*)buf;
    if(*magic == 0xabcdabcd) {
        return 1;
    } else {
        return 0;
    }
}
void handle_password(uint8_t* buf, int32_t len, int fd, struct sockaddr* addr, socklen_t socklen) {
    logfunc();
    if(!buf || !len || fd < 0 || !addr || !socklen) return;
    char* un = (char*)(buf + sizeof(uint32_t));
    char* pwd = un + sizeof(username);

    memset(username, 0x00, sizeof(username));
    memset(password, 0x00, sizeof(password));
    strcpy(username, un);
    strcpy(password, pwd);
    logd("get password:[%s]", pwd);
    logd("get username:[%s]", username);
}

void handle_stun(uint8_t* buf, int32_t len, int fd, struct sockaddr* addr, socklen_t socklen) {
    logfunc();
    status |= STUN_MSG_RECEIVED;
    stun_message_t* req = stun_alloc_message();
    stun_message_t* resp = stun_alloc_message();
    stun_message_t* ind = stun_alloc_message();
    if(!req || !resp || !ind) {
        loge("fail to allocate message: %p %p %p", req, resp, ind);
        return;
    }
    stun_parse(req, buf, len);
    stun_set_method_and_class(resp, STUN_METHOD_BINDING, STUN_SUCC_RESPONSE);
    memcpy(resp->header->trans_id, req->header->trans_id, sizeof(resp->header->trans_id));

    /*stun_attr_header* attr = stun_get_attr(req, USERNAME);*/
    /*if(!attr) {                                           */
    /*    loge("can not find username in request");         */
    /*    return;                                           */
    /*}                                                     */
    /*stun_add_attr(resp, attr);                            */
    int ulen = STUN_ALIGNED(strlen(username));
    stun_attr_username* usrname = (stun_attr_username*)malloc(sizeof(stun_attr_username) + ulen);
    usrname->header.type = USERNAME;
    usrname->header.len = strlen(username);
    memset(usrname->username, 0x00, ulen);
    strcpy(usrname->username, username);
    stun_add_attr(resp, &usrname->header);
    free(usrname);

    struct sockaddr_in* addrin = (struct sockaddr_in*)addr;
    stun_attr_xor_mapped_address_ipv4 ipv4;
    ipv4.header.type = XOR_MAPPED_ADDRESS;
    ipv4.header.len  = 8;
    ipv4.family  = 0x01;
    ipv4.addr  = addrin->sin_addr.s_addr;
    ipv4.port  = ntohs(addrin->sin_port);
    stun_add_attr(resp, &ipv4.header);

    stun_attr_message_integrity integrity;
    integrity.header.type = MESSAGE_INTEGRITY;
    integrity.header.len  = 20;
    uint8_t sha1[20];
    /*uint8_t key[] = "password"; //TODO get password from webrtc*/
    stun_calculate_integrity(resp, (uint8_t*)password, strlen(password), sha1);
    memcpy(integrity.sha1, sha1, sizeof(sha1));
    stun_add_attr(resp, &integrity.header);

    stun_attr_fingerprint fp;
    fp.header.type = FINGERPRINT;
    fp.header.len = 4;
    fp.crc32 = stun_calculate_crc32(resp);
    stun_add_attr(resp, &fp.header);

    //indication message to client
    stun_set_method_and_class(ind, STUN_METHOD_BINDING, STUN_INDICATION);
    fp.header.type = FINGERPRINT;
    fp.header.len = 4;
    fp.crc32 = stun_calculate_crc32(ind);
    stun_add_attr(ind, &fp.header);

    if(fd) {
        uint8_t content[1024];
        uint32_t size = sizeof(content);
        int ret = stun_serialize(resp, content, &size);
        if(ret < 0) {
            loge("fail to serialize resp: %d", ret);
        } else {
            logd("send: %d", size);
            sendto(fd, content, size, 0, addr, socklen);
        }

        size = sizeof(content);
        ret = stun_serialize(ind, content, &size);
        if(ret < 0) {
            loge("fail to serialize indication message: %d", ret);
        } else {
            sendto(fd, content, size, 0, addr, socklen);
        }
    }

    stun_free_message(resp);
    stun_free_message(req);
    stun_free_message(ind);
}
void handle_rtp(char* buf, int32_t len) {
    logfunc();
    if(!buf || !len) return;
}
void handle_rtcp(char* buf, int32_t len) {
    logfunc();
    if(!buf || !len) return;
}

int run_srv() {
    logfunc();
    int fd = udp_new_server();
    int ret = 0;
    char buf[4096];
    if(fd < 0) return -1;

    while(1) {
        bzero(buf, sizeof(buf));
        struct sockaddr fromaddr;
        socklen_t socklen;
        ret = recvfrom(fd, buf, sizeof(buf), 0, &fromaddr, &socklen);
        if(ret < 0) {
            loge("fail to recv data: %s", strerror(errno));
            break;
        }
        if(is_stun(buf, ret)) {
            handle_stun((uint8_t*)buf, ret, fd, &fromaddr, socklen);
        } else if(is_password(buf, ret)) {
            handle_password((uint8_t*)buf, ret, fd, &fromaddr, socklen);
        }
        if(status == NORMAL_STATUS) {
            if(is_rtp(buf, ret)) {
                handle_rtp(buf, ret);
            } else if(is_rtcp(buf, ret)) {
                handle_rtcp(buf, ret);
            }
        } else {
            loge("recv msg from status: %08x %d", status, ret);
        }
    }

    logi("server exit.");
    close(fd);
    return 0;
}

int main() {
    return run_srv();
}

/********************************** END **********************************************/
