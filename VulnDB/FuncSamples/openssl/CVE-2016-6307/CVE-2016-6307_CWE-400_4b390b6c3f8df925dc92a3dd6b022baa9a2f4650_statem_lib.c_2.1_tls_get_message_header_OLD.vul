int tls_get_message_header(SSL *s, int *mt)
{
    /* s->init_num < SSL3_HM_HEADER_LENGTH */
    int skip_message, i, recvd_type, al;
    unsigned char *p;
    unsigned long l;

    p = (unsigned char *)s->init_buf->data;

    do {
        while (s->init_num < SSL3_HM_HEADER_LENGTH) {
            i = s->method->ssl_read_bytes(s, SSL3_RT_HANDSHAKE, &recvd_type,
                                          &p[s->init_num],
                                          SSL3_HM_HEADER_LENGTH - s->init_num,
                                          0);
            if (i <= 0) {
                s->rwstate = SSL_READING;
                return 0;
            }
            if (recvd_type == SSL3_RT_CHANGE_CIPHER_SPEC) {
                /*
                 * A ChangeCipherSpec must be a single byte and may not occur
                 * in the middle of a handshake message.
                 */
                if (s->init_num != 0 || i != 1 || p[0] != SSL3_MT_CCS) {
                    al = SSL_AD_UNEXPECTED_MESSAGE;
                    SSLerr(SSL_F_TLS_GET_MESSAGE_HEADER,
                           SSL_R_BAD_CHANGE_CIPHER_SPEC);
                    goto f_err;
                }
                s->s3->tmp.message_type = *mt = SSL3_MT_CHANGE_CIPHER_SPEC;
                s->init_num = i - 1;
                s->s3->tmp.message_size = i;
                return 1;
            } else if (recvd_type != SSL3_RT_HANDSHAKE) {
                al = SSL_AD_UNEXPECTED_MESSAGE;
                SSLerr(SSL_F_TLS_GET_MESSAGE_HEADER, SSL_R_CCS_RECEIVED_EARLY);
                goto f_err;
            }
            s->init_num += i;
        }

        skip_message = 0;
        if (!s->server)
            if (p[0] == SSL3_MT_HELLO_REQUEST)
                /*
                 * The server may always send 'Hello Request' messages --
                 * we are doing a handshake anyway now, so ignore them if
                 * their format is correct. Does not count for 'Finished'
                 * MAC.
                 */
                if (p[1] == 0 && p[2] == 0 && p[3] == 0) {
                    s->init_num = 0;
                    skip_message = 1;

                    if (s->msg_callback)
                        s->msg_callback(0, s->version, SSL3_RT_HANDSHAKE,
                                        p, SSL3_HM_HEADER_LENGTH, s,
                                        s->msg_callback_arg);
                }
    } while (skip_message);
    /* s->init_num == SSL3_HM_HEADER_LENGTH */

    *mt = *p;
    s->s3->tmp.message_type = *(p++);

    if (RECORD_LAYER_is_sslv2_record(&s->rlayer)) {
        /*
         * Only happens with SSLv3+ in an SSLv2 backward compatible
         * ClientHello
         *
         * Total message size is the remaining record bytes to read
         * plus the SSL3_HM_HEADER_LENGTH bytes that we already read
         */
        l = RECORD_LAYER_get_rrec_length(&s->rlayer)
            + SSL3_HM_HEADER_LENGTH;
        if (l && !BUF_MEM_grow_clean(s->init_buf, (int)l)) {
            SSLerr(SSL_F_TLS_GET_MESSAGE_HEADER, ERR_R_BUF_LIB);
            goto err;
        }
        s->s3->tmp.message_size = l;

        s->init_msg = s->init_buf->data;
        s->init_num = SSL3_HM_HEADER_LENGTH;
    } else {
        n2l3(p, l);
        /* BUF_MEM_grow takes an 'int' parameter */
        if (l > (INT_MAX - SSL3_HM_HEADER_LENGTH)) {
            al = SSL_AD_ILLEGAL_PARAMETER;
            SSLerr(SSL_F_TLS_GET_MESSAGE_HEADER, SSL_R_EXCESSIVE_MESSAGE_SIZE);
            goto f_err;
        }
        if (l && !BUF_MEM_grow_clean(s->init_buf,
                                     (int)l + SSL3_HM_HEADER_LENGTH)) {
            SSLerr(SSL_F_TLS_GET_MESSAGE_HEADER, ERR_R_BUF_LIB);
            goto err;
        }
        s->s3->tmp.message_size = l;

        s->init_msg = s->init_buf->data + SSL3_HM_HEADER_LENGTH;
        s->init_num = 0;
    }

    return 1;
 f_err:
    ssl3_send_alert(s, SSL3_AL_FATAL, al);
 err:
    return 0;
}
