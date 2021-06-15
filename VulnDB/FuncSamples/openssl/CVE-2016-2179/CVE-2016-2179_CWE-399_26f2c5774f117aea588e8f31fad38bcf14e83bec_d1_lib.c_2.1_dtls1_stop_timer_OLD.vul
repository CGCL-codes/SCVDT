void dtls1_stop_timer(SSL *s)
{
    /* Reset everything */
    memset(&(s->d1->timeout), 0, sizeof(struct dtls1_timeout_st));
    memset(&(s->d1->next_timeout), 0, sizeof(struct timeval));
    s->d1->timeout_duration = 1;
    BIO_ctrl(SSL_get_rbio(s), BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT, 0,
             &(s->d1->next_timeout));
    /* Clear retransmission buffer */
    dtls1_clear_record_buffer(s);
}
