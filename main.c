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

#define MASTER_KEY  16
#define MASTER_SALT 14
#define MASTER_LEN  (MASTER_KEY+MASTER_SALT)

uint16_t srv_port = 8881;
uint16_t cli_port = 8882;
const char* srv_ip = "127.0.0.1";
const char* cafile = "cacert.pem";
const char* pkfile = "cakey.pem";
static SSL_CTX *ssl_ctx  = NULL;
static X509* ssl_cert    = NULL;
static EVP_PKEY* ssl_key = NULL;
static DH* ssl_dh        = NULL;
static SSL* ssl          = NULL;
static srtp_policy_t policy_remote;
static srtp_policy_t policy_local;
static srtp_t        stream_in;
static srtp_t        stream_out;

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
void sec_env_uninit() {
    return;
}


int run_srv() {
    logfunc();
    int ret = 0;
    struct sockaddr_in addr;
    char buf[4096];
    unsigned char material[MASTER_LEN*2];
    size_t cnt = 0;
    BIO* bio = NULL;
    EC_KEY* ecdh = NULL;
    srtp_err_status_t res;

    if(0 != sec_env_init(1)) {
        return -1;
    }
    int fd = udp_new_server();
    if(fd < 0) return -1;

    ssl = SSL_new(ssl_ctx);
    if(!ssl) {
        loge("fail to new ssl");
        goto exit;
    }
    SSL_set_ex_data(ssl, 0, NULL);
    SSL_set_info_callback(ssl, sec_info_callback);
    bio = BIO_new_dgram(fd, BIO_NOCLOSE);
    SSL_set_bio(ssl, bio, bio);
    SSL_set_accept_state(ssl);

    ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if(!ecdh) {
        log("fail to create ECKEY");
        goto exit;
    }
    SSL_set_options(ssl, SSL_OP_SINGLE_ECDH_USE);
    SSL_set_tmp_ecdh(ssl, ecdh);
    EC_KEY_free(ecdh);
    SSL_set_read_ahead(ssl, 1);

    /* do handshake */
    logd("waiting for handshake %p ...", ssl->handshake_func);
    bzero(&addr, sizeof(addr));
    ret = SSL_accept(ssl);
    if(ret != 1) {
        loge("fail to accept: %d %s", ret, ERR_error_string(SSL_get_error(ssl, ret), NULL));
        goto exit;
    }
    logd("handshake ok.");

    /* export master and salt */
    bzero(material, sizeof(material));
    if(!SSL_export_keying_material(ssl, material, sizeof(material), "EXTRACTOR-dtls_srtp", 19, NULL, 0, 0)) {
        loge("fail to export key");
    } else {
        log("MASTER KEY:");
        log("\n---------------------\n");
        for(ret=0; ret<(int)sizeof(material); ret++) {
            if(ret > 0  && ret % 8 == 0) log("\n");
            log("%02x ", material[ret]);
        }
        log("\n---------------------\n");
    }
    bzero(&policy_remote, sizeof(policy_remote));
    srtp_crypto_policy_set_rtp_default(&policy_remote.rtp);
    srtp_crypto_policy_set_rtcp_default(&policy_remote.rtcp);
    policy_remote.ssrc.type = ssrc_any_inbound;
    unsigned char remote_policy_key[MASTER_LEN];
    policy_remote.key = remote_policy_key;
    policy_remote.window_size = 128;
    policy_remote.allow_repeat_tx = 0;
    memcpy(policy_remote.key, material, MASTER_KEY);
    memcpy(policy_remote.key+MASTER_KEY, material+MASTER_LEN, MASTER_SALT);
    res = srtp_create(&stream_in, &policy_remote);
    if(res != srtp_err_status_ok) {
        loge("fail to create srtp: %d", res);
        goto exit;
    }

    /* recv msg and exit */
    while(1) {
        bzero(buf, sizeof(buf));
        cnt = SSL_read(ssl, buf, sizeof(buf)-1);
        if(cnt == (size_t)-1 ) {
            loge("fail to recv data: %s", strerror(errno));
            break;
        }
        logd("msg: %s", buf);
        break;
    }

exit:
    if(ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    close(fd);
    logw("server exit.");
    return 0;
}
int run_client() {
    logfunc();
    int ret = 0;
    char buf[4096];

    if(0 != sec_env_init(0)) {
        return -1;
    }
    int fd = udp_new_client();
    size_t cnt = 0;
    EC_KEY* ecdh = NULL;
    if(fd < 0) return -1;

    ssl = SSL_new(ssl_ctx);
    if(!ssl) {
        loge("fail to new ssl");
        goto exit;
    }
    SSL_set_ex_data(ssl, 0, NULL);
    SSL_set_info_callback(ssl, sec_info_callback);
    SSL_set_fd(ssl, fd);
    SSL_set_read_ahead(ssl, 1);

    ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if(!ecdh) {
        log("fail to create ECKEY");
        goto exit;
    }
    SSL_set_options(ssl, SSL_OP_SINGLE_ECDH_USE);
    SSL_set_tmp_ecdh(ssl, ecdh);
    EC_KEY_free(ecdh);

    logd("starting handshake...");
    ret = SSL_connect(ssl);
    if(ret != 1) {
        loge("fail to do SSL_connect: %d => %d", ret, SSL_get_error(ssl, ret));
        goto exit;
    }
    logd("handshake DONE.");

    //send message to server
    snprintf(buf, sizeof(buf), "hello, world");
    logd("send: %s", buf);
    cnt = SSL_write(ssl, buf, strlen(buf));
    if(cnt == (size_t)-1) loge("fail to send: %s", strerror(errno));
    close(fd);

exit:
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
