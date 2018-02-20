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

#include <string>
using namespace std;

#include "log.h"
#include "stun.h"
#include "rtp.h"
#include "bio.h"

#define MASTER_KEY  16
#define MASTER_SALT 14
#define MASTER_LEN  (MASTER_KEY+MASTER_SALT)

static SSL_CTX *ssl_ctx  = NULL;
static X509* ssl_cert    = NULL;
static EVP_PKEY* ssl_key = NULL;
static DH* ssl_dh        = NULL;
static SSL* ssl          = NULL;
static srtp_policy_t policy_remote;
static srtp_policy_t policy_local;
static srtp_t        stream_in;
static srtp_t        stream_out;
const char* cafile = "cacert.pem";
const char* pkfile = "cakey.pem";
static unsigned char rtp_buf[4096];
static unsigned char srtp_buf[4096];
uint16_t srv_port = 8881;
uint16_t cli_port = 8882;
const char* srv_ip = "192.168.1.102";
char password[64];
char username[64];

#define STUN_MSG_RECEIVED 0x01
#define HANDSHAKING       0x02
#define HANDSHAKE_SUCC    0x04
#define NORMAL_STATUS     (STUN_MSG_RECEIVED|HANDSHAKE_SUCC)
uint32_t status = 0;

class IceCoreCfg {
public:
    string localusername;
    string localpassword;;
    string remoteusername;
    string remotepassword;;
};
IceCoreCfg ice;

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
int sec_verify_callback(int preverify_ok, X509_STORE_CTX *ctx) {
    logd("preverify: %d ctx:%p", preverify_ok, ctx);
    return 1;
}
int sec_cert_verify_callback(X509_STORE_CTX* store, void* arg) {
    if(!store || !arg) {
        return 1;
    }
    return 1;
}
void sec_info_callback(const SSL* ssl, int where, int ret) {
    if(!ssl || !ret) {}
    if(where & SSL_CB_LOOP) logd("SSL_CB_LOOP");
    if(where & SSL_CB_EXIT) logd("SSL_CB_EXIT");
    if(where & SSL_CB_READ) logd("SSL_CB_READ");
    if(where & SSL_CB_WRITE) logd("SSL_CB_WRITE");
    if(where & SSL_CB_ALERT) logd("SSL_CB_ALERT");
    if(where & SSL_CB_HANDSHAKE_START) logd("SSL_CB_HANDSHAKE_START");
    if(where & SSL_CB_HANDSHAKE_DONE) logd("SSL_CB_HANDSHAKE_DONE");
}
int sec_load_key() {
    FILE* fp = fopen(cafile, "r");
    if(!fp) {
        loge("fail to open ca file: %s", cafile);
        return -1;
    }
    ssl_cert = PEM_read_X509(fp, NULL, NULL, NULL);
    if(!ssl_cert) {
        loge("fail to read ca file: %s", cafile);
        goto error;
    }
    fclose(fp);

    fp = fopen(pkfile, "r");
    if(!fp) {
        loge("fail to open private key: %s", pkfile);
        goto error;
    }
    ssl_key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    if(!ssl_key) {
        loge("fail to read private key: %s", pkfile);
        goto error;
    }
    fclose(fp);
    return 0;

error:
    if(fp) fclose(fp);
    if(ssl_cert) X509_free(ssl_cert);
    if(ssl_key) EVP_PKEY_free(ssl_key);
    if(ssl_dh) DH_free(ssl_dh);
    ssl_cert = NULL;
    ssl_key  = NULL;
    return -1;
}
int sec_env_init(int isserver) {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    if(isserver) {
        ssl_ctx = SSL_CTX_new(DTLS_server_method());
    } else {
        ssl_ctx = SSL_CTX_new(DTLS_client_method());
    }
    if(!ssl_ctx) {
        loge("fail to create SSL_CTX");
        return -1;
    }
    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, sec_verify_callback);
    if(0 != sec_load_key()) return -1;
    if(!SSL_CTX_use_certificate(ssl_ctx, ssl_cert)) {
        loge("fail to use certificate");
        return -1;
    }
    if(!SSL_CTX_use_PrivateKey(ssl_ctx, ssl_key)) {
        loge("fail to use priv key");
        return -1;
    }
    if(!SSL_CTX_check_private_key(ssl_ctx)) {
        loge("fail to check priv key");
        return -1;
    }
    SSL_CTX_set_read_ahead(ssl_ctx, 1);
    SSL_CTX_set_cipher_list(ssl_ctx, "ALL:NULL:eNULL:aNULL");
    SSL_CTX_set_tlsext_use_srtp(ssl_ctx, "SRTP_AES128_CM_SHA1_80");

    if(0 != srtp_init()) {
        loge("fail to init srtp");
    }

    logi("secure env setup ok.");
    return 0;
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
int is_dtls(char* buf, int32_t len) {
    if(!buf || !len) return -EINVAL;
    return (*buf >= 20 && *buf <= 64);
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
    char* ptr = (char*)(buf + sizeof(uint32_t));

    ice.localusername = ptr;
    ptr += 64;
    ice.localpassword = ptr;
    ptr += 64;
    ice.remoteusername = ptr;
    ptr += 64;
    ice.remotepassword = ptr;
    logd("ice: [%s][%s][%s][%s]", ice.localusername.c_str(), \
                                ice.localpassword.c_str(),
                                ice.remoteusername.c_str(),
                                ice.remotepassword.c_str());
    string lu = ice.localusername;
    string ru = ice.remoteusername;
    ice.localusername = ru + ":" + ice.localusername;
    ice.remoteusername = lu + ":" + ice.remoteusername;
}
void handle_dtls(uint8_t* buf, int32_t len, int fd, struct sockaddr* addr, socklen_t socklen) {
    logfunc();
    if(!buf || !len || fd < 0 || !addr || !socklen) return;
    if(status & HANDSHAKE_SUCC) return;
    if(!(status & HANDSHAKING)) return;

    BIO* bio = SSL_get_rbio(ssl);
    BIO* wio = SSL_get_wbio(ssl);
    if(bio) {
        BIO_write(bio, buf, len);
        int ret = SSL_do_handshake(ssl);
        if(ret == 1) {
            status = status & (~HANDSHAKING);
            status |= HANDSHAKE_SUCC;
        }
    }
    if(wio) {
        char buf[4096];
        int pending = 0;
        while((pending = BIO_ctrl_pending(wio)) > 0) {
            int ret = BIO_read(wio->next_bio, buf, pending);
            if(ret > 0) {
                logd("dtls: send handshake data: %d", ret);
                sendto(fd, buf, ret, 0, addr, socklen);
            }
        }
    }
    return;
}

void send_stun_requst(int fd, struct sockaddr* addr, socklen_t socklen) {
    static int sended = 0;
    if(sended) return;
    sended = 1;
    if(fd < 0 || !addr || !socklen) return;
    stun_message_t* req = stun_alloc_message();
    stun_set_method_and_class(req, STUN_METHOD_BINDING, STUN_REQUEST);

    int ulen = STUN_ALIGNED(ice.localusername.size());
    stun_attr_username* username = (stun_attr_username*)malloc(sizeof(stun_attr_username) + ulen);
    username->header.type = USERNAME;
    username->header.len = ice.localusername.size();
    memset(username->username, 0x00, ulen);
    strcpy(username->username, ice.localusername.c_str());
    stun_add_attr(req, &username->header);
    free(username);

    stun_attr_ice_controlling ice_controlled;
    ice_controlled.header.type = ICE_CONTROLLED;
    ice_controlled.header.len = 8;
    ice_controlled.tiebreaker = 0x1d23f31232ecdde4;
    stun_add_attr(req, &ice_controlled.header);

    stun_attr_priority priority;
    priority.header.type = PRIORITY;
    priority.header.len  = 4;
    priority.priority    = 5;
    stun_add_attr(req, &priority.header);

    stun_attr_message_integrity integrity;
    integrity.header.type = MESSAGE_INTEGRITY;
    integrity.header.len  = 20;
    stun_add_attr(req, &integrity.header);
    stun_calculate_integrity(req, (uint8_t*)ice.remotepassword.c_str(), ice.remotepassword.size());

    stun_attr_fingerprint fringerprint;
    fringerprint.header.type = FINGERPRINT;
    fringerprint.header.len  = 4;
    stun_add_attr(req, &fringerprint.header);
    stun_calculate_crc32(req);

    uint8_t buf[4096];
    uint32_t len = sizeof(buf);
    stun_serialize(req, buf, &len);
    sendto(fd, buf, len, 0, addr, socklen);
}
void send_stun_indication(int fd, struct sockaddr* addr, socklen_t socklen) {
    logfunc();
    if(fd < 0 || !addr || !socklen) return;
    stun_message_t* ind = stun_alloc_message();
    if(!ind) {
        loge("fail to alloc ind");
        return;
    }

    //indication message to client
    stun_attr_fingerprint fp;
    stun_set_method_and_class(ind, STUN_METHOD_BINDING, STUN_INDICATION);
    fp.header.type = FINGERPRINT;
    fp.header.len = 4;
    fp.crc32 = stun_calculate_crc32(ind);
    stun_add_attr(ind, &fp.header);

    uint32_t size = 0;
    uint8_t content[4096];
    int ret = 0;
    size = sizeof(content);
    ret = stun_serialize(ind, content, &size);
    if(ret < 0) {
        loge("fail to serialize indication message: %d", ret);
    } else {
        sendto(fd, content, size, 0, addr, socklen);
    }

    stun_free_message(ind);
    ind = NULL;
}
void send_dtls_clienthello(int fd, struct sockaddr* addr, socklen_t socklen) {
    logfunc();
    if(fd < 0 || !addr || !socklen) return;
    logd("starting handshaking...");
    BIO* bio = SSL_get_wbio(ssl);
    int ret = SSL_do_handshake(ssl);
    if(ret < 0) {
        loge("HANDSHAKE: %s", ERR_error_string(SSL_get_error(ssl, ret), NULL));
    } else {
        logd("HANDSHAKING: %d %s", ret, ERR_error_string(SSL_get_error(ssl, ret), NULL));
    }
    if(bio) {
        logd("get wio");
        char buf[4096];
        int pending = 0;
        while((pending = BIO_ctrl_pending(bio)) > 0) {
            int ret = BIO_read(bio->next_bio, buf, pending);
            if(ret > 0) {
                logd("send handshake data: %d", ret);
                sendto(fd, buf, ret, 0, addr, socklen);
            }
        }
        status |= HANDSHAKING;
    } else {
        loge("NO wio avaliable..");
    }
}

void handle_stun(uint8_t* buf, int32_t len, int fd, struct sockaddr* addr, socklen_t socklen) {
    logfunc();
    status |= STUN_MSG_RECEIVED;
    stun_message_t* req = stun_alloc_message();
    stun_message_t* resp = stun_alloc_message();
    if(!req || !resp) {
        loge("fail to allocate message: %p %p", req, resp);
        return;
    }
    stun_parse(req, buf, len);
    if(req->header->type == (STUN_SUCC_RESPONSE | STUN_METHOD_BINDING)) {
        stun_free_message(req);
        stun_free_message(resp);
        logd("get bind response.");
        send_stun_indication(fd, addr, socklen);
        send_dtls_clienthello(fd, addr, socklen);
        return;
    }
    stun_set_method_and_class(resp, STUN_METHOD_BINDING, STUN_SUCC_RESPONSE);
    memcpy(resp->header->trans_id, req->header->trans_id, sizeof(resp->header->trans_id));

    stun_attr_header* usrname = NULL;
    usrname = stun_get_attr(req, USERNAME);
    if(!usrname) {
        loge("fail to get username in request");
    } else {
        stun_add_attr(resp, usrname);
    }

    struct sockaddr_in* addrin = (struct sockaddr_in*)addr;
    stun_attr_xor_mapped_address_ipv4 ipv4;
    ipv4.header.type = XOR_MAPPED_ADDRESS;
    ipv4.header.len  = 8;
    ipv4.family  = 0x01;
    ipv4.addr  = addrin->sin_addr.s_addr;
    ipv4.port  = ntohs(addrin->sin_port);
    stun_add_attr(resp, &ipv4.header);

    stun_attr_message_integrity integrity;
    bzero(&integrity, sizeof(integrity));
    integrity.header.type = MESSAGE_INTEGRITY;
    integrity.header.len  = 20;
    stun_add_attr(resp, &integrity.header);

    stun_attr_fingerprint fp;
    fp.header.type = FINGERPRINT;
    fp.header.len = 4;
    stun_add_attr(resp, &fp.header);
    stun_calculate_integrity(resp, (uint8_t*)ice.remotepassword.c_str(), ice.remotepassword.size());
    stun_calculate_crc32(resp);

    if(fd) {
        uint8_t content[1024];
        uint32_t size = sizeof(content);
        int ret = stun_serialize(resp, content, &size);
        if(ret < 0) {
            loge("fail to serialize resp: %d", ret);
        } else {
            logd("send stun: %d", size);
            sendto(fd, content, size, 0, addr, socklen);
        }

        send_stun_requst(fd, addr, socklen);
    }

    stun_free_message(resp);
    stun_free_message(req);
    return;
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
    int ret = 0;
    BIO* ioread  = NULL;
    BIO* iowrite = NULL;
    BIO* iofilter = NULL;
    EC_KEY* ecdh = NULL;
    char buf[4096];
    in_addr_t firstaddr = 0;
    int fd = udp_new_server();
    if(fd < 0) return -1;

    ioread = BIO_new(BIO_s_mem());
    iowrite = BIO_new(BIO_s_mem());
    iofilter = BIO_new(BIO_dtls_filter());
    if(!ioread || !iowrite) {
        loge("fail to allocate io mem");
        return -1;
    }
    BIO_set_mem_eof_return(ioread, -1);
    BIO_set_mem_eof_return(iowrite, -1);
    BIO_push(iofilter, iowrite);

    if(0 != sec_env_init(0)) {
        return -1;
    }
    if(fd < 0) return -1;

    ssl = SSL_new(ssl_ctx);
    if(!ssl) {
        loge("fail to new ssl");
        goto exit;
    }
    SSL_set_ex_data(ssl, 0, NULL);
    SSL_set_info_callback(ssl, sec_info_callback);
    SSL_set_bio(ssl, ioread, iofilter);
    SSL_set_connect_state(ssl);

    ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if(!ecdh) {
        log("fail to create ECKEY");
        goto exit;
    }
    SSL_set_options(ssl, SSL_OP_SINGLE_ECDH_USE);
    SSL_set_tmp_ecdh(ssl, ecdh);
    EC_KEY_free(ecdh);
    SSL_set_read_ahead(ssl, 1);

    SSL_set_connect_state(ssl);
    while(1) {
        bzero(buf, sizeof(buf));
        struct sockaddr fromaddr;
        socklen_t socklen;
        ret = recvfrom(fd, buf, sizeof(buf), 0, &fromaddr, &socklen);
        if(ret < 0) {
            loge("fail to recv data: %s", strerror(errno));
            break;
        }
        struct sockaddr_in* addr =  (struct sockaddr_in*)&fromaddr;
        if(!firstaddr) firstaddr = addr->sin_addr.s_addr;
        if(firstaddr != addr->sin_addr.s_addr) {
            loge("discard data from: %s", inet_ntoa(addr->sin_addr));
            continue;
        }
        if(is_stun(buf, ret)) {
            static int saved = 0;
            if(!saved) {
                saved = 1;
                FILE* fp = fopen("stun.request", "w");
                if(fp) {
                    fwrite(buf, 1, ret, fp);
                    fclose(fp);
                }
            }
            handle_stun((uint8_t*)buf, ret, fd, &fromaddr, socklen);
        } else if(is_password(buf, ret)) {
            handle_password((uint8_t*)buf, ret, fd, &fromaddr, socklen);
        } else if(is_dtls(buf, ret)) {
            handle_dtls((uint8_t*)buf, ret, fd, &fromaddr, socklen);
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

exit:
    logi("server exit.");
    close(fd);
    return 0;
}

int main() {
    return run_srv();
}

/********************************** END **********************************************/
