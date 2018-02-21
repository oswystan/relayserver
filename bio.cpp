
#define LOG_TAG "bio"

#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <list>

#include "log.h"
using namespace std;

static int mtu = 1440;

/* Helper struct to keep the filter state */
typedef struct dtls_bio_filter {
    list<uint32_t> packets;
} dtls_bio_filter;


int dtls_bio_filter_new(BIO *bio) {
    /* Create a filter state struct */
    dtls_bio_filter *filter = new dtls_bio_filter;

    bio->init = 1;
    bio->ptr = filter;
    bio->flags = 0;
    return 1;
}

int dtls_bio_filter_free(BIO *bio) {
    if(bio == NULL)
        return 0;

    /* Get rid of the filter state */
    dtls_bio_filter *filter = (dtls_bio_filter *)bio->ptr;
    if(filter != NULL) {
        filter->packets.clear();
        delete filter;
    }
    bio->ptr = NULL;
    bio->init = 0;
    bio->flags = 0;
    return 1;
}

int dtls_bio_filter_write(BIO *bio, const char *in, int inl) {
    /* Forward data to the write BIO */
    int32_t ret = BIO_write(bio->next_bio, in, inl);
    logd("bio write: %d %d", ret, inl);

    dtls_bio_filter *filter = (dtls_bio_filter *)bio->ptr;
    if(filter != NULL) {
        filter->packets.push_back(ret);
    }
    return ret;
}

long dtls_bio_filter_ctrl(BIO *bio, int cmd, long num, void *ptr) {
    switch(cmd) {
        case BIO_CTRL_FLUSH:
            return 1;
        case BIO_CTRL_DGRAM_QUERY_MTU:
            return mtu;
        case BIO_CTRL_WPENDING:
            return 0L;
        case BIO_CTRL_PENDING: {
            /* We only advertize one packet at a time, as they may be fragmented */
            dtls_bio_filter *filter = (dtls_bio_filter *)bio->ptr;
            if(filter == NULL)
                return 0;
            if(filter->packets.empty()) return 0;

            /* Get the first packet that hasn't been read yet */
            int32_t size = *(filter->packets.begin());
            filter->packets.pop_front();
            return size;
        }
        default:
            loge("invalid ctrl cmd: %d", cmd);
    }
    return 0;
}

static BIO_METHOD dtls_bio_filter_methods = {
    BIO_TYPE_FILTER,
    "janus filter",
    dtls_bio_filter_write,
    NULL,
    NULL,
    NULL,
    dtls_bio_filter_ctrl,
    dtls_bio_filter_new,
    dtls_bio_filter_free,
    NULL
};

extern "C" BIO_METHOD *BIO_dtls_filter(void) {
    return(&dtls_bio_filter_methods);
}
