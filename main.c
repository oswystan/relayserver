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

#define LOG_TAG "srtp"

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

#define MASTER_KEY  16
#define MASTER_SALT 14
#define MASTER_LEN  (MASTER_KEY+MASTER_SALT)

uint16_t srv_port = 8881;
uint16_t cli_port = 8882;
const char* srv_ip = "127.0.0.1";

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
int udp_new_client() {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;

    struct sockaddr_in addr_srv;
    bzero(&addr_srv, sizeof(addr_srv));
    addr_srv.sin_family = AF_INET;
    addr_srv.sin_port   = htons(srv_port);
    addr_srv.sin_addr.s_addr = inet_addr(srv_ip);
    int ret = connect(fd, (struct sockaddr*)&addr_srv, sizeof(struct sockaddr));
    if(ret != 0) {
        loge("fail to connect server: %s, %d <%s>", srv_ip, srv_port, strerror(errno));
        close(fd);
        return -1;
    }
    logd("server connected");
    return fd;
}

int run_srv() {
    logfunc();
    int fd = udp_new_server();
    int ret = 0;
    size_t len = 0;
    char buf[4096];
    if(fd < 0) return -1;

    while(1) {
        bzero(buf, sizeof(buf));
        ret = recv(fd, buf, len, 0);
        if(ret < 0) {
            loge("fail to recv data: %s", strerror(errno));
            break;
        }
        //handle data
        logd("get msg.");
    }

    close(fd);
    return 0;
}
int run_client() {
    logfunc();
    int fd = udp_new_client();
    int ret = 0;
    char buf[4096];
    if(fd < 0) return -1;

    sprintf(buf, "hello");
    ret = send(fd, buf, strlen(buf), 0);
    if(ret < 0) {
        loge("fail to send data.");
    } else {
        logd("send: %s", buf);
    }


    close(fd);
    return 0;
}

int usage(const char* prog) {
    log("usage: %s <c|s>\n", prog);
    return -1;
}
int main(int argc, const char *argv[]) {
    if(argc == 2) {
        if(strcmp(argv[1], "s") == 0) return run_srv();
        if(strcmp(argv[1], "c") == 0) return run_client();
    }
    return usage(argv[0]);
}

/********************************** END **********************************************/
