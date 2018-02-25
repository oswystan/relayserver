/*
 **************************************************************************************
 *       Filename:  udp_socket.h
 *    Description:   header file
 *
 *        Version:  1.0
 *        Created:  2018-02-25 17:34:01
 *
 *       Revision:  initial draft;
 **************************************************************************************
 */

#ifndef UDP_SOCKET_H_INCLUDED
#define UDP_SOCKET_H_INCLUDED

#include <inttypes.h>
#include <uv.h>
#include <list>

class DataHandler {
public:
    virtual ~DataHandler() {}
    virtual void onclose() = 0;
    virtual void onconnected() = 0;
    virtual void onmsg(uint8_t* buf, uint32_t len, const sockaddr_in* addr) = 0;
};

class UdpSocket {
public:
    int init(uv_loop_t* loop, DataHandler* handler, uint32_t bufSize);
    int connect(const char* addr, uint16_t port);
    int listen(const char* addr, uint16_t port);
    int serve();
    int send(uint8_t* buf, uint32_t len, const sockaddr_in* addr);
    int close();
    int getbuf(uv_buf_t* buf);
    void onrecv(uint8_t* buf, uint32_t len, const sockaddr* addr, uint32_t flags);
    void onclose();

protected:
    uv_loop_t* looper    = nullptr;
    uint8_t* recvbuf     = nullptr;
    uint32_t bufSize     = 0;
    DataHandler* handler = nullptr;
    uv_udp_t handle;
    bool served = false;
};

#endif /*UDP_SOCKET_H_INCLUDED*/

/********************************** END **********************************************/
