/*
 **************************************************************************************
 *       Filename:  uv.c
 *    Description:   source file
 *
 *        Version:  1.0
 *        Created:  2018-02-24 10:43:19
 *
 *       Revision:  initial draft;
 **************************************************************************************
 */
#define LOG_TAG "uv"

#include <errno.h>
#include <string.h>
#include <uv.h>
#include "log.h"

const char* srvip = "127.0.0.1";
uint16_t srvport = 8888;

void alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t* buf) {
    if(!handle || !suggested_size) loge("invali parameter");
    static char data[1024];
    buf->base = data;
    buf->len = sizeof(data);
}

void on_recv(uv_udp_t *req, ssize_t nread, const uv_buf_t* buf, const struct sockaddr *addr, unsigned flags) {
    if(!req || nread == -1 || !addr) return;
    char ip[32];
    const struct sockaddr_in* addrin = (const sockaddr_in*)addr;
    uv_ip4_name(addrin, ip, sizeof(ip));
    logd("%s:%d->%s", ip, ntohs(addrin->sin_port), buf->base);
}
int run_srv() {
    uv_loop_t *loop = uv_default_loop();
    uv_udp_t srv;
    struct sockaddr_in localaddr;
    uv_ip4_addr(srvip, srvport, &localaddr);
    uv_udp_init(loop, &srv);
    uv_udp_bind(&srv, (struct sockaddr*)&localaddr, 0);
    uv_udp_recv_start(&srv, alloc_buffer, on_recv);
    return uv_run(loop, UV_RUN_DEFAULT);
}
int run_cli() {
    uv_loop_t *loop = uv_default_loop();
    uv_udp_t cli;
    uv_udp_send_t req;
    uv_buf_t buf;
    char hello[] = "hello,world";
    buf.base = hello;
    buf.len = sizeof(hello);
    struct sockaddr_in localaddr;
    struct sockaddr_in remoteaddr;
    uv_ip4_addr("0.0.0.0", 4000, &localaddr);
    uv_ip4_addr(srvip, srvport, &remoteaddr);
    uv_udp_init(loop, &cli);
    uv_udp_bind(&cli, (struct sockaddr*)&localaddr, 0);
    uv_udp_send(&req, &cli, &buf, 1, (const struct sockaddr*)&remoteaddr, NULL);
    return uv_run(loop, UV_RUN_DEFAULT);
}

int main(int argc, char *argv[])
{
    if(argc != 2) {
        loge("usage: %s <c|s>", argv[0]);
        return -EINVAL;
    }
    if(strcmp(argv[1], "c") == 0)
        return run_cli();
    else if(strcmp(argv[1], "s") == 0)
        return run_srv();
    loge("usage: %s <c|s>", argv[0]);
    return -EINVAL;
}

/********************************** END **********************************************/

