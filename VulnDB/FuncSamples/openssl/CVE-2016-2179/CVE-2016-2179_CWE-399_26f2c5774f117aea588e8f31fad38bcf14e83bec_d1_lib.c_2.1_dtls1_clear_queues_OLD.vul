static void dtls1_clear_queues(SSL *s)
{
    pitem *item = NULL;
    hm_fragment *frag = NULL;
    DTLS1_RECORD_DATA *rdata;

    while ((item = pqueue_pop(s->d1->unprocessed_rcds.q)) != NULL) {
        rdata = (DTLS1_RECORD_DATA *)item->data;
        if (rdata->rbuf.buf) {
            OPENSSL_free(rdata->rbuf.buf);
        }
        OPENSSL_free(item->data);
        pitem_free(item);
    }

    while ((item = pqueue_pop(s->d1->processed_rcds.q)) != NULL) {
        rdata = (DTLS1_RECORD_DATA *)item->data;
        if (rdata->rbuf.buf) {
            OPENSSL_free(rdata->rbuf.buf);
        }
        OPENSSL_free(item->data);
        pitem_free(item);
    }

    while ((item = pqueue_pop(s->d1->buffered_messages)) != NULL) {
        frag = (hm_fragment *)item->data;
        dtls1_hm_fragment_free(frag);
        pitem_free(item);
    }

    while ((item = pqueue_pop(s->d1->sent_messages)) != NULL) {
        frag = (hm_fragment *)item->data;
        dtls1_hm_fragment_free(frag);
        pitem_free(item);
    }

    while ((item = pqueue_pop(s->d1->buffered_app_data.q)) != NULL) {
        rdata = (DTLS1_RECORD_DATA *)item->data;
        if (rdata->rbuf.buf) {
            OPENSSL_free(rdata->rbuf.buf);
        }
        OPENSSL_free(item->data);
        pitem_free(item);
    }
}
