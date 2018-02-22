#include <string>
#include <map>
using namespace std;

namespace wrtc {
//------------------------------------------
//
// internal data structures
//
//------------------------------------------
class WrtcStream
{
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

private:
    int sendMediaData(uint8_t* buf, uint32_t len);
    int sendRelayData(uint8_t* buf, uint32_t len);

public:
    WrtcPeerCfg remoteCfg;
    WrtcPeerCfg localCfg;
    uint16_t    mediaPort;
    uint16_t    relayPort;
    int         fdMedia;
    int         fdRelay;

    uint8_t* mediaBuffer;
    uint8_t* relayBuffer;

    list<WrtcRelayAddr*> relayAddrs;

    WrtcSRTP* srtp;
    WrtcDTLS* dtls;
    WrtcSTUN* stun;
    WrtcRTCP* rtcp;
};

class WrtcRelayAddr {
    struct sockaddr addr;
    uint16_t port;
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

class WrtcSTUN {
public:
    int handleMessage(uint8_t* buf, uint32_t len);
    void sendBindingRequest();
    void sendIndication();
    int getPeerConnection();
};

class WrtcDTLS {
    int handleMessage(uint8_t* buf, uint32_t len);
    int exportMasterKey(uint8_t* material, uint32_t len);
    int getStatus();
};

class WrtcSRTP {
    int handleMessage(uint8_t* buf, uint32_t len);
    int unprotect(uint8_t* in, uint8_t* out, uint32_t len);
    int protect(uint8_t* in, uint8_t* out, uint32_t len);
    int init(uint8_t* masterKey, uint32_t* len);
};
class WrtcRTCP {
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
