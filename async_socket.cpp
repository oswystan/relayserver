/*
 **************************************************************************************
 *       Filename:  async_socket.cpp
 *    Description:   source file
 *
 *        Version:  1.0
 *        Created:  2018-02-24 15:10:17
 *
 *       Revision:  initial draft;
 **************************************************************************************
 */

#define LOG_TAG "AsyncSocket"
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "async_socket.h"

static void alloc_buf(uv_handle_t *handle, size_t size, uv_buf_t* buf) {
    AsyncSocket* socket = (AsyncSocket*)handle->data;
    if(!socket) return;
    socket->getbuf(buf);
}
static void on_recv(uv_udp_t *req, ssize_t nread,
        const uv_buf_t* buf, const struct sockaddr *addr,
        unsigned flags) {
    if(!req || !req->data) return;
    AsyncSocket* socket = (AsyncSocket*)req->data;
    socket->onrecv((uint8_t*)buf->base, nread, addr, flags);
}
static void on_close(uv_handle_t* handle) {
    if(!handle || !handle->data) return;
    AsyncSocket* socket = (AsyncSocket*)handle->data;
    socket->onclose();
}

int AsyncSocket::init(uv_loop_t* loop, DataHandler* dataHandler, uint32_t bufSize) {
    if(!loop || !handler) {
        loge("invalid param: %p %p", loop, handler);
        return -EINVAL;
    }
    recvbuf = (uint8_t*)malloc(bufSize);
    if(!recvbuf) return -ENOMEM;

    this->bufSize = bufSize;
    looper = loop;
    handler = dataHandler;
    memset(&handle, 0x00, sizeof(handle));
    handle.data = this;
    served = false;
    return 0;
}
int AsyncSocket::connect(const char* addr, uint16_t port) {
    if(!addr) {
        loge("null addr");
        return -EINVAL;
    }

    struct sockaddr_in localaddr;
    int ret = uv_ip4_addr(addr, port, &localaddr);
    if(ret != 0) {
        loge("invalid ip or port: %s, %d", addr, port);
        goto out;
    }
    uv_udp_init(looper, &handle);
    ret = uv_udp_bind(&handle, (struct sockaddr*)&localaddr, 0);
    if(ret != 0) {
        loge("fail to bind: %s", uv_strerror(ret));
        goto out;
    }
    if(handler) handler->onconnected();

out:
    return ret;
}
int AsyncSocket::listen(const char* addr, uint16_t port) {
    if(!addr) {
        loge("null addr");
        return -EINVAL;
    }

    struct sockaddr_in localaddr;
    int ret = uv_ip4_addr(addr, port, &localaddr);
    if(ret != 0) {
        loge("invalid ip or port: %s, %d", addr, port);
        goto out;
    }
    uv_udp_init(looper, &handle);
    ret = uv_udp_bind(&handle, (struct sockaddr*)&localaddr, 0);
    if(ret != 0) {
        loge("fail to bind: %s", uv_strerror(ret));
        goto out;
    }

out:
    return ret;
}
int AsyncSocket::serve() {
    int ret = uv_udp_recv_start(&handle, alloc_buf, on_recv);
    if(ret != 0) {
        loge("fail to serve: %s", uv_strerror(ret));
        return ret;
    }
    served = true;
    if(handler) handler->onconnected();
    return 0;
}
int AsyncSocket::send(uint8_t* buf, uint32_t len, const sockaddr_in* addr) {
    uv_buf_t uvbuf;
    uv_udp_send_t req;
    uvbuf.base = (char*)buf;
    uvbuf.len = len;
    return uv_udp_send(&req, &handle, &uvbuf, 1, (const sockaddr*)addr, NULL);
}
int AsyncSocket::close() {
    if(served) {
        uv_udp_recv_stop(&handle);
        served = false;
    }
    uv_close((uv_handle_t*)&handle, on_close);
    return 0;
}
int AsyncSocket::getbuf(uv_buf_t* buf) {
    buf->base = (char*)recvbuf;
    buf->len = bufSize;
    return 0;
}
void AsyncSocket::onrecv(uint8_t* buf, uint32_t len, const sockaddr* addr, uint32_t flags) {
    if(handler) handler->onmsg(buf, len, (const sockaddr_in*)addr);
}
void AsyncSocket::onclose() {
    if(handler) handler->onclose();
}

/********************************** END **********************************************/

