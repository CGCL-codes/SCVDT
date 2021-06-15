guint64 get_signature_ts(const guint8 *m_ptr,int sig_off)
{
    int     ts_offset;
    guint64 sig_ts;

    if (m_ptr[sig_off + 15] == 0xe2)
        ts_offset = 5;
    else
        ts_offset = 8;

    sig_ts = pletoh32(&m_ptr[sig_off + ts_offset]);

    return (sig_ts & 0xffffffff);
}
