#include <string>
#include <map>
using namespace std;

namespace wrtc {
//------------------------------------------
//
// internal data structures
//
//------------------------------------------

#define STREAM_CREATED 0x01
#define STREAM_INITED  0x02
#define STREAM_STARTED 0x04

class WrtcStream
{
    int init() {
        return initLocalCfg(localCfg);
    }
    void onMediaData(uint8_t* buf, uint32_t len) {
        if(srtp->unprotect(buf, relayBuffer, len) <= 0) {
            if(fdRelay >= 0) sendRelayData(relayBuffer, len);
            return;
        }
        if(stun->handleMessage(buf, len) <= 0) return;
        if(dtls->handleMessage(buf, len) <= 0) return;
        log("invalid package");
    }
    void onRelayData(uint8_t* buf, uint32_t len) {
        srtp->protect(buf, mediaBuffer, len);
        sendMediaData(mediaBuffer, len);
    }

    int config(req) {
        setRemoteCfg(req);
        return 0;
    }
    int start(req) {
        if(status & STREAM_STARTED) return 0;
        mediaFd = createUdpClient(mediaPort);
        relayFd = createUdpClient(relayPort);
        rtcp->sendFir();
    };
    int relay(req) {
        if(streamType == PUSH) {
            if(getAddr(req->addr_dst, req->port_dst)) return 0;
            addRelay(req->addr_dst, req->port_dst);
        } else {
            if(relayAddrs.size() > 0) {
                addr = relayAddrs.begin();
            } else {
                addr = new sockaddr_in;
            }
            setAddr(req->addr_src, req->port_src, AF_INET);
        }
    }
    int stop(req) {
        if(!(status & STREAM_STARTED)) return 0;
        rtcp->sendBye();
        close(mediaFd) && close(relayFd);
    }

private:
    int sendMediaData(uint8_t* buf, uint32_t len);
    int sendRelayData(uint8_t* buf, uint32_t len) {
        for(auto &i : relayAddrs) {
            sendto(fdRelay, buf, len, 0, i, sizeof(struct sockaddr_in));
        }
    }

public:
    WrtcPeerCfg remoteCfg;
    WrtcPeerCfg localCfg;
    uint16_t    mediaPort;
    uint16_t    relayPort;
    int         mediaFd;
    int         relayFd;

    uint8_t* mediaBuffer;
    uint8_t* relayBuffer;

    list<struct sockaddr_in*> relayAddrs;

    WrtcSRTP* srtp;
    WrtcDTLS* dtls;
    WrtcSTUN* stun;
    WrtcRTCP* rtcp;
};


class WrtcPeerCfg
{
public:
    string   ufrag;
    string   password;
    string   fringerprint;
};

class WrtcMediaCfg
{
public:
    uint32_t audioSsrc;
    uint32_t videoSsrc;
    uint32_t operation;   // 1-push; 2-pull;
};

class WrtcProtocolSTUN {
public:
    int handleMessage(uint8_t* buf, uint32_t len);
    void sendBindingRequest();
    void sendIndication();
    int getPeerConnection();
};

class WrtcProtocolDTLS {
    int init(const char* certfile, const char* keyfile);
    int config(WrtcPeerCfg* cfg);
    int handleMessage(uint8_t* buf, uint32_t len);
    int exportMasterKey(uint8_t* material, uint32_t len);
    int getStatus();
};

class WrtcProtocolSRTP {
    int handleMessage(uint8_t* buf, uint32_t len);
    int unprotect(uint8_t* in, uint8_t* out, uint32_t len);
    int protect(uint8_t* in, uint8_t* out, uint32_t len);
    int init(uint8_t* masterKey, uint32_t* len);
};
class WrtcProtocolRTCP {
    void sendFir();
    void sendReport();
    void sendBye();
};

//------------------------------------------
//
// an udp message adapter
//
//------------------------------------------
class WrtcOperatorAdapter {
    bool init() {
        wrtcOperator = new WrtcOperator();
        return wrtcOperator != NULL;
    }
    int createServer(uint16_t port) {
        return createUdpServer(port);
    }
    void onMessage(uint8_t* buf, uint32_t len) {
        req = parse(buf, len);
        if(req->type != REQUEST) logerror() && return;
        switch(req->command) {
            case CREATE:
                wrtcOperator->create(req); break;
            case CONFIG:
                wrtcOperator->config(req); break;
            case START:
                wrtcOperator->start(req); break;
            case STOP:
                wrtcOperator->stop(req); break;
            case RELAY:
                wrtcOperator->relay(req); break;
            case DESTROY:
                wrtcOperator->destroy(req); break;
            case PING:
                wrtcOperator->ping(req); break;
            default:
                sendresp(EINVAL);
        }
    }

private:
    WrtcOperator* wrtcOperator;
};

};

//------------------------------------------
//
// operator methods
//
//------------------------------------------
class WrtcOperator{
    void create(req) {
        stream = new WrtcStream();
        addStream(stream);
        sendresp(OK, stream->ID());
    }

    void config(req){
        stream = getStream(req->stream_id);
        if(!stream) sendresp(ENORES);
        stream->config(req);
        sendresp(ESUCC, stream->localCfg);
    }

    void start(req) {
        stream = getStream(req->stream_id);
        if(!stream) sendresp(ENORES) && return;
        stream->start();
        sendresp(ESUCC);
    }

    void relay(req) {
        stream = getStream(req->stream_id_src);
        if(!stream) {
            stream = getStream(req->stream_id_dst);
        }
        if(!stream) sendresp(ENORES) && return;
        stream->relay(req)
        sendresp(ESUCC);
    }

    void stop(req) {
        stream = getStream(req->stream_id);
        if(!stream) sendresp(ENORES) && return;
        stream->stop();
        sendresp(ESUCC);
    }

    void destroy(req) {
        stream = getStream(req->stream_id);
        if(!stream) sendresp(ENORES) && return;
        removeStream(stream);
        delete stream;
        sendresp(ESUCC);
    }
    void ping(req) {
        sendresp(ESUCC);
    }

private:
    map<uint32_t, WrtcStream*> localStreams;
};

//------------------------------------------
//
// operator protocol
//
//------------------------------------------
struct operator_protocol_header{
    uint32_t type;
    uint32_t command;
    uint32_t transaction;
};
struct operator_request_header {
    operator_protocol_header header;
};
struct operator_reponse_header {
    operator_protocol_header header;
    uint32_t error;
};

struct operator_request_create {
    operator_request_header header;
};
struct operator_response_create {
    operator_reponse_header header;
    uint32_t stream_id;
};
struct operator_request_config {
    operator_request_header header;
    uint32_t stream_id;
    uint8_t  ufrag[8];
    uint8_t  password[32];
    uint8_t  fingerprint[128];
    uint32_t ssrc_audio;    // 0-means inactive; other-means active
    uint32_t ssrc_video;
    uint16_t media_port;
    uint16_t relay_port;
    uint32_t operation;     // 1-push; 2-pull;
};
struct operator_response_create {
    operator_reponse_header header;
    uint32_t stream_id;
    uint8_t  ufrag[8];
    uint8_t  password[32];
    uint8_t  fingerprint[128];
    uint32_t ssrc_audio;    // 0-means inactive; other-means active
    uint32_t ssrc_video;
};
struct operator_request_relay {
    operator_request_header header;
    uint32_t stream_id_src;
    uint32_t stream_id_dst;
    uint8_t  addr_src[64];
    uint8_t  addr_dst[64];
    uint16_t port_src;
    uint16_t port_dst;
    uint32_t audio_ssrc;
    uint32_t video_ssrc;
};
struct operator_response_create {
    operator_reponse_header header;
};
struct operator_request_start {
    operator_request_header header;
    uint32_t stream_id;
};
struct operator_response_start {
    operator_reponse_header header;
    uint32_t stream_id;
};
struct operator_request_stop {
    operator_request_header header;
    uint32_t stream_id;
};
struct operator_response_stop {
    operator_reponse_header header;
    uint32_t stream_id;
};
struct operator_request_destroy {
    operator_request_header header;
    uint32_t stream_id;
};
struct operator_response_destroy {
    operator_reponse_header header;
    uint32_t stream_id;
};
struct operator_request_ping {
    operator_request_header header;
};
struct operator_response_ping {
    operator_reponse_header header;
};
