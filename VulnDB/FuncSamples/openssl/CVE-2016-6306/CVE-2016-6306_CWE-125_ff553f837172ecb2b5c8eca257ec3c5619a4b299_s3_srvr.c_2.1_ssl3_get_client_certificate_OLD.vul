int ssl3_get_client_certificate(SSL *s)
{
    int i, ok, al, ret = -1;
    X509 *x = NULL;
    unsigned long l, nc, llen, n;
    const unsigned char *p, *q;
    unsigned char *d;
    STACK_OF(X509) *sk = NULL;

    n = s->method->ssl_get_message(s,
                                   SSL3_ST_SR_CERT_A,
                                   SSL3_ST_SR_CERT_B,
                                   -1, s->max_cert_list, &ok);

    if (!ok)
        return ((int)n);

    if (s->s3->tmp.message_type == SSL3_MT_CLIENT_KEY_EXCHANGE) {
        if ((s->verify_mode & SSL_VERIFY_PEER) &&
            (s->verify_mode & SSL_VERIFY_FAIL_IF_NO_PEER_CERT)) {
            SSLerr(SSL_F_SSL3_GET_CLIENT_CERTIFICATE,
                   SSL_R_PEER_DID_NOT_RETURN_A_CERTIFICATE);
            al = SSL_AD_HANDSHAKE_FAILURE;
            goto f_err;
        }
        /*
         * If tls asked for a client cert, the client must return a 0 list
         */
        if ((s->version > SSL3_VERSION) && s->s3->tmp.cert_request) {
            SSLerr(SSL_F_SSL3_GET_CLIENT_CERTIFICATE,
                   SSL_R_TLS_PEER_DID_NOT_RESPOND_WITH_CERTIFICATE_LIST);
            al = SSL_AD_UNEXPECTED_MESSAGE;
            goto f_err;
        }
        s->s3->tmp.reuse_message = 1;
        return (1);
    }

    if (s->s3->tmp.message_type != SSL3_MT_CERTIFICATE) {
        al = SSL_AD_UNEXPECTED_MESSAGE;
        SSLerr(SSL_F_SSL3_GET_CLIENT_CERTIFICATE, SSL_R_WRONG_MESSAGE_TYPE);
        goto f_err;
    }
    p = d = (unsigned char *)s->init_msg;

    if ((sk = sk_X509_new_null()) == NULL) {
        SSLerr(SSL_F_SSL3_GET_CLIENT_CERTIFICATE, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    n2l3(p, llen);
    if (llen + 3 != n) {
        al = SSL_AD_DECODE_ERROR;
        SSLerr(SSL_F_SSL3_GET_CLIENT_CERTIFICATE, SSL_R_LENGTH_MISMATCH);
        goto f_err;
    }
    for (nc = 0; nc < llen;) {
        n2l3(p, l);
        if ((l + nc + 3) > llen) {
            al = SSL_AD_DECODE_ERROR;
            SSLerr(SSL_F_SSL3_GET_CLIENT_CERTIFICATE,
                   SSL_R_CERT_LENGTH_MISMATCH);
            goto f_err;
        }

        q = p;
        x = d2i_X509(NULL, &p, l);
        if (x == NULL) {
            SSLerr(SSL_F_SSL3_GET_CLIENT_CERTIFICATE, ERR_R_ASN1_LIB);
            goto err;
        }
        if (p != (q + l)) {
            al = SSL_AD_DECODE_ERROR;
            SSLerr(SSL_F_SSL3_GET_CLIENT_CERTIFICATE,
                   SSL_R_CERT_LENGTH_MISMATCH);
            goto f_err;
        }
        if (!sk_X509_push(sk, x)) {
            SSLerr(SSL_F_SSL3_GET_CLIENT_CERTIFICATE, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        x = NULL;
        nc += l + 3;
    }

    if (sk_X509_num(sk) <= 0) {
        /* TLS does not mind 0 certs returned */
        if (s->version == SSL3_VERSION) {
            al = SSL_AD_HANDSHAKE_FAILURE;
            SSLerr(SSL_F_SSL3_GET_CLIENT_CERTIFICATE,
                   SSL_R_NO_CERTIFICATES_RETURNED);
            goto f_err;
        }
        /* Fail for TLS only if we required a certificate */
        else if ((s->verify_mode & SSL_VERIFY_PEER) &&
                 (s->verify_mode & SSL_VERIFY_FAIL_IF_NO_PEER_CERT)) {
            SSLerr(SSL_F_SSL3_GET_CLIENT_CERTIFICATE,
                   SSL_R_PEER_DID_NOT_RETURN_A_CERTIFICATE);
            al = SSL_AD_HANDSHAKE_FAILURE;
            goto f_err;
        }
        /* No client certificate so digest cached records */
        if (s->s3->handshake_buffer && !ssl3_digest_cached_records(s)) {
            al = SSL_AD_INTERNAL_ERROR;
            goto f_err;
        }
    } else {
        i = ssl_verify_cert_chain(s, sk);
        if (i <= 0) {
            al = ssl_verify_alarm_type(s->verify_result);
            SSLerr(SSL_F_SSL3_GET_CLIENT_CERTIFICATE,
                   SSL_R_CERTIFICATE_VERIFY_FAILED);
            goto f_err;
        }
    }

    if (s->session->peer != NULL) /* This should not be needed */
        X509_free(s->session->peer);
    s->session->peer = sk_X509_shift(sk);
    s->session->verify_result = s->verify_result;

    /*
     * With the current implementation, sess_cert will always be NULL when we
     * arrive here.
     */
    if (s->session->sess_cert == NULL) {
        s->session->sess_cert = ssl_sess_cert_new();
        if (s->session->sess_cert == NULL) {
            SSLerr(SSL_F_SSL3_GET_CLIENT_CERTIFICATE, ERR_R_MALLOC_FAILURE);
            goto err;
        }
    }
    if (s->session->sess_cert->cert_chain != NULL)
        sk_X509_pop_free(s->session->sess_cert->cert_chain, X509_free);
    s->session->sess_cert->cert_chain = sk;
    /*
     * Inconsistency alert: cert_chain does *not* include the peer's own
     * certificate, while we do include it in s3_clnt.c
     */

    sk = NULL;

    ret = 1;
    if (0) {
 f_err:
        ssl3_send_alert(s, SSL3_AL_FATAL, al);
 err:
        s->state = SSL_ST_ERR;
    }

    if (x != NULL)
        X509_free(x);
    if (sk != NULL)
        sk_X509_pop_free(sk, X509_free);
    return (ret);
}
