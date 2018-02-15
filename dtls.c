/*
 **************************************************************************************
 *       Filename:  dtls.c
 *    Description:   source file
 *
 *        Version:  1.0
 *        Created:  2018-02-09 17:06:35
 *
 *       Revision:  initial draft;
 **************************************************************************************
 */

#define LOG_TAG "dtls"

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

#include "log.h"

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
    size_t cnt = 0;
    BIO* bio = NULL;
    EC_KEY* ecdh = NULL;

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

    logd("waiting for handshake %p ...", ssl->handshake_func);
    bzero(&addr, sizeof(addr));
    ret = SSL_accept(ssl);
    if(ret != 1) {
        loge("fail to accept: %d %s", ret, ERR_error_string(SSL_get_error(ssl, ret), NULL));
        goto exit;
    }
    logd("handshake ok.");

    while(1) {
        bzero(buf, sizeof(buf));
        cnt = SSL_read(ssl, buf, sizeof(buf)-1);
        if(cnt == (size_t)-1 ) {
            loge("fail to recv data: %s", strerror(errno));
            break;
        }
        logd("msg: %s", buf);
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
    BIO* ioread = NULL;
    BIO* iowrite = NULL;
    ioread = BIO_new(BIO_s_mem());
    iowrite = BIO_new(BIO_s_mem());
    if(!ioread || !iowrite) {
        loge("fail to allocate io mem");
        return -1;
    }

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
    SSL_set_bio(ssl, ioread, iowrite);
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
    SSL_set_connect_state(ssl);
    do {
        ret = SSL_do_handshake(ssl);
        logd("do handshake: %d", ret);
        int err = SSL_get_error(ssl, ret);
        if(err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            ret = 0;
        }
        while(BIO_ctrl_pending(iowrite) > 0) {
            int cnt = BIO_read(iowrite, buf, sizeof(buf));
            if(cnt > 0) {
                send(fd, buf, cnt, 0);
            }
        }
        if(err == SSL_ERROR_WANT_READ) {
            int cnt = recv(fd, buf, sizeof(buf), 0);
            if(cnt > 0) {
                BIO_write(ioread,  buf, cnt);
            }
        }
    }while(ret == 0);

    logd("handshake DONE. with %d", ret);

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

