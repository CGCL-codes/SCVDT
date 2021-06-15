int tls1_process_ticket(SSL *s, unsigned char *session_id, int len,
                        const unsigned char *limit, SSL_SESSION **ret)
{
    /* Point after session ID in client hello */
    const unsigned char *p = session_id + len;
    unsigned short i;

    *ret = NULL;
    s->tlsext_ticket_expected = 0;

    /*
     * If tickets disabled behave as if no ticket present to permit stateful
     * resumption.
     */
    if (SSL_get_options(s) & SSL_OP_NO_TICKET)
        return 0;
    if ((s->version <= SSL3_VERSION) || !limit)
        return 0;
    if (p >= limit)
        return -1;
    /* Skip past DTLS cookie */
    if (s->version == DTLS1_VERSION || s->version == DTLS1_BAD_VER) {
        i = *(p++);

        if (limit - p <= i)
            return -1;

        p += i;
    }
    /* Skip past cipher list */
    n2s(p, i);
    if (limit - p <= i)
        return -1;
    p += i;

    /* Skip past compression algorithm list */
    i = *(p++);
    if (limit - p < i)
        return -1;
    p += i;

    /* Now at start of extensions */
    if (limit - p <= 2)
        return 0;
    n2s(p, i);
    while (limit - p >= 4) {
        unsigned short type, size;
        n2s(p, type);
        n2s(p, size);
        if (limit - p < size)
            return 0;
        if (type == TLSEXT_TYPE_session_ticket) {
            int r;
            if (size == 0) {
                /*
                 * The client will accept a ticket but doesn't currently have
                 * one.
                 */
                s->tlsext_ticket_expected = 1;
                return 1;
            }
            if (s->tls_session_secret_cb) {
                /*
                 * Indicate that the ticket couldn't be decrypted rather than
                 * generating the session from ticket now, trigger
                 * abbreviated handshake based on external mechanism to
                 * calculate the master secret later.
                 */
                return 2;
            }
            r = tls_decrypt_ticket(s, p, size, session_id, len, ret);
            switch (r) {
            case 2:            /* ticket couldn't be decrypted */
                s->tlsext_ticket_expected = 1;
                return 2;
            case 3:            /* ticket was decrypted */
                return r;
            case 4:            /* ticket decrypted but need to renew */
                s->tlsext_ticket_expected = 1;
                return 3;
            default:           /* fatal error */
                return -1;
            }
        }
        p += size;
    }
    return 0;
}
