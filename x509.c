/*
 **************************************************************************************
 *       Filename:  x509.c
 *    Description:   source file
 *
 *        Version:  1.0
 *        Created:  2018-02-23 21:43:12
 *
 *       Revision:  initial draft;
 **************************************************************************************
 */
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <stdio.h>

#define LOG_TAG "x509"
#include "log.h"

void generate_fingerprint() {
    FILE* fp = fopen("cacert.pem", "r");
    if(!fp) {
        loge("fail to open file");
        return;
    }
    const EVP_MD* md = NULL;
    md = EVP_sha256();
    unsigned char buf[32];
    int len = sizeof(buf);
    unsigned int i = 0;
    memset(buf, 0x00, sizeof(buf));

    X509* x = PEM_read_X509(fp, NULL, NULL, NULL);
    if(!x) {
        loge("fail to read x509");
        goto out;
    }

    X509_digest(x, md, buf, &len);
    for(i=0; i<len; i++) {
        printf("%02X:", buf[i]);
    }
    printf("\n");

out:
    if(fp) fclose(fp);
    if(x) X509_free(x);
}

int main()
{
    generate_fingerprint();
    return 0;
}


/********************************** END **********************************************/

